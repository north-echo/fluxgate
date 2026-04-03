package github

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	gh "github.com/google/go-github/v60/github"
	"github.com/north-echo/fluxgate/internal/scanner"
	"golang.org/x/oauth2"
)

// Client wraps the GitHub API for fetching workflow files.
type Client struct {
	gh      *gh.Client
	tokens  []string      // all available tokens
	clients []*gh.Client  // one client per token
	mu      sync.Mutex
	idx     int           // current token index
}

// NewClient creates a GitHub API client. If token is empty, uses unauthenticated access.
func NewClient(token string) *Client {
	if token != "" {
		return NewClientWithTokens([]string{token})
	}
	client := gh.NewClient(nil)
	return &Client{gh: client}
}

// NewClientWithTokens creates a client that round-robins across multiple PATs.
// When one token hits rate limits, the client automatically switches to the next.
func NewClientWithTokens(tokens []string) *Client {
	if len(tokens) == 0 {
		return &Client{gh: gh.NewClient(nil)}
	}

	clients := make([]*gh.Client, len(tokens))
	for i, t := range tokens {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: t})
		tc := oauth2.NewClient(context.Background(), ts)
		clients[i] = gh.NewClient(tc)
	}

	return &Client{
		gh:      clients[0],
		tokens:  tokens,
		clients: clients,
		idx:     0,
	}
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
			_, dirContent, resp, err := c.gh.Repositories.GetContents(ctx, owner, repo, ".github/workflows", nil)
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

		content, err := c.fetchFileContent(ctx, owner, repo, entry.GetPath())
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

// fetchFileContent fetches the content of a single file.
func (c *Client) fetchFileContent(ctx context.Context, owner, repo, path string) ([]byte, error) {
	file, err := withRetryRotate(ctx, c, func() retryableFunc[*gh.RepositoryContent] {
		return func(ctx context.Context) (*gh.RepositoryContent, *gh.Response, error) {
			fileContent, _, resp, err := c.gh.Repositories.GetContents(ctx, owner, repo, path, nil)
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
	limits, _, err := c.gh.RateLimit.Get(ctx)
	if err != nil {
		return nil, err
	}
	return limits, nil
}
