package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gh "github.com/google/go-github/v60/github"
	"github.com/north-echo/fluxgate/internal/scanner"
	"golang.org/x/oauth2"
)

// newAPITransport returns an HTTP transport tuned for many concurrent
// requests to api.github.com. The default MaxIdleConnsPerHost of 2 churns
// connections under a worker pool.
func newAPITransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 16
	return t
}

// httpTimeout bounds each API request. Without it a single stalled TCP
// connection hangs a batch scan indefinitely (gitlab/azure clients already
// set 30s).
const httpTimeout = 30 * time.Second

// Client wraps the GitHub API for fetching workflow files.
type Client struct {
	gh      *gh.Client
	raw     *http.Client // plain client for download_url fetches
	tokens  []string     // all available tokens
	clients []*gh.Client // one client per token
	mu      sync.Mutex
	idx     int // current token index

	// remaining tracks the most recently observed core rate-limit budget
	// across all goroutines. -1 means no response observed yet.
	remaining atomic.Int64
}

// NewClient creates a GitHub API client. If token is empty, uses unauthenticated access.
func NewClient(token string) *Client {
	if token != "" {
		return NewClientWithTokens([]string{token})
	}
	c := &Client{
		gh: gh.NewClient(&http.Client{
			Timeout:   httpTimeout,
			Transport: newAPITransport(),
		}),
		raw: &http.Client{Timeout: httpTimeout, Transport: newAPITransport()},
	}
	c.remaining.Store(-1)
	return c
}

// NewClientWithTokens creates a client that round-robins across multiple PATs.
// When one token hits rate limits, the client automatically switches to the next.
func NewClientWithTokens(tokens []string) *Client {
	if len(tokens) == 0 {
		return NewClient("")
	}

	transport := newAPITransport() // shared: one connection pool across all tokens
	clients := make([]*gh.Client, len(tokens))
	for i, t := range tokens {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: t})
		tc := &http.Client{
			Timeout:   httpTimeout,
			Transport: &oauth2.Transport{Source: ts, Base: transport},
		}
		clients[i] = gh.NewClient(tc)
	}

	c := &Client{
		gh:      clients[0],
		raw:     &http.Client{Timeout: httpTimeout, Transport: newAPITransport()},
		tokens:  tokens,
		clients: clients,
		idx:     0,
	}
	c.remaining.Store(-1)
	return c
}

// current returns the active gh client. Callers must go through this rather
// than reading c.gh directly: rotateToken swaps it under the mutex, and
// BatchScan runs API calls from concurrent workers.
func (c *Client) current() *gh.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gh
}

// rotateToken switches to the next token in the pool. Returns true if a new
// token was activated, false if only one token is available.
func (c *Client) rotateToken() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.clients) <= 1 {
		return false
	}
	c.idx = (c.idx + 1) % len(c.clients)
	c.gh = c.clients[c.idx]
	return true
}

// noteRate records the rate-limit budget from an API response.
func (c *Client) noteRate(resp *gh.Response) {
	if resp != nil && resp.Rate.Limit > 0 {
		c.remaining.Store(int64(resp.Rate.Remaining))
	}
}

// rateRemaining returns the most recently observed core rate-limit budget,
// or -1 if no authenticated response has been observed yet.
func (c *Client) rateRemaining() int64 {
	return c.remaining.Load()
}

// tokenCount returns the number of configured tokens.
func (c *Client) tokenCount() int {
	if len(c.tokens) == 0 {
		return 1
	}
	return len(c.tokens)
}

// WorkflowFile represents a fetched workflow file.
type WorkflowFile struct {
	Path    string
	Content []byte
}

// FetchWorkflows lists and fetches all workflow files from a repository.
func (c *Client) FetchWorkflows(ctx context.Context, owner, repo string) ([]WorkflowFile, error) {
	// List contents of .github/workflows/
	entries, err := withRetryRotate(ctx, c, func() retryableFunc[[]*gh.RepositoryContent] {
		return func(ctx context.Context) ([]*gh.RepositoryContent, *gh.Response, error) {
			_, dirContent, resp, err := c.current().Repositories.GetContents(ctx, owner, repo, ".github/workflows", nil)
			return dirContent, resp, err
		}
	})
	if err != nil {
		return nil, fmt.Errorf("listing workflows for %s/%s: %w", owner, repo, err)
	}

	var workflows []WorkflowFile
	for _, entry := range entries {
		name := entry.GetName()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		// Prefer the raw download URL from the directory listing: those
		// fetches do not count against the core API rate limit, unlike a
		// per-file Contents call.
		var content []byte
		var err error
		if url := entry.GetDownloadURL(); url != "" {
			content, err = c.fetchRaw(ctx, url)
		} else {
			content, err = c.fetchFileContent(ctx, owner, repo, entry.GetPath())
		}
		if err != nil {
			// Raw fetch can fail where the API succeeds (e.g. expired
			// signed URL on private repos); fall back before giving up.
			content, err = c.fetchFileContent(ctx, owner, repo, entry.GetPath())
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: could not fetch %s: %v\n", entry.GetPath(), err)
			continue
		}

		workflows = append(workflows, WorkflowFile{
			Path:    entry.GetPath(),
			Content: content,
		})
	}

	return workflows, nil
}

// maxRawFetch caps raw workflow downloads; the scanner rejects YAML over
// 10MB anyway (scanner.MaxYAMLSize).
const maxRawFetch = 10<<20 + 1

// fetchRaw downloads file content from a download_url (raw.githubusercontent.com).
func (c *Client) fetchRaw(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.raw.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("raw fetch %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxRawFetch))
}

// fetchFileContent fetches the content of a single file.
func (c *Client) fetchFileContent(ctx context.Context, owner, repo, path string) ([]byte, error) {
	file, err := withRetryRotate(ctx, c, func() retryableFunc[*gh.RepositoryContent] {
		return func(ctx context.Context) (*gh.RepositoryContent, *gh.Response, error) {
			fileContent, _, resp, err := c.current().Repositories.GetContents(ctx, owner, repo, path, nil)
			return fileContent, resp, err
		}
	})
	if err != nil {
		return nil, err
	}

	content, err := file.GetContent()
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}
	return []byte(content), nil
}

// ScanRemote fetches and scans all workflows in a repository.
func (c *Client) ScanRemote(ctx context.Context, owner, repo string, opts scanner.ScanOptions) (*scanner.ScanResult, error) {
	workflows, err := c.FetchWorkflows(ctx, owner, repo)
	if err != nil {
		return nil, err
	}

	result := &scanner.ScanResult{
		Path:      fmt.Sprintf("%s/%s", owner, repo),
		Workflows: len(workflows),
	}

	for _, wf := range workflows {
		findings, err := scanner.ScanWorkflowBytes(wf.Content, wf.Path, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: could not parse %s: %v\n", wf.Path, err)
			continue
		}
		result.Findings = append(result.Findings, findings...)
	}

	return result, nil
}

// RateLimit returns the current rate limit status.
func (c *Client) RateLimit(ctx context.Context) (*gh.RateLimits, error) {
	limits, _, err := c.current().RateLimit.Get(ctx)
	if err != nil {
		return nil, err
	}
	return limits, nil
}
