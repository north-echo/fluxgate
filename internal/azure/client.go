package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/north-echo/fluxgate/internal/cicd"
	"github.com/north-echo/fluxgate/internal/scanner"
)

// Client wraps the Azure DevOps API for fetching pipeline files.
type Client struct {
	orgURL     string
	token      string
	httpClient *http.Client
}

// RepoInfo represents basic Azure DevOps repository metadata.
type RepoInfo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	DefaultBranch string `json:"defaultBranch"`
	Project       string `json:"-"` // populated after fetch
}

// repoListResponse is the API response for listing repositories.
type repoListResponse struct {
	Value []repoEntry `json:"value"`
	Count int         `json:"count"`
}

type repoEntry struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	DefaultBranch string     `json:"defaultBranch"`
	Project       repoProject `json:"project"`
}

type repoProject struct {
	Name string `json:"name"`
}

// NewClient creates an Azure DevOps API client.
// orgURL should be like "https://dev.azure.com/myorg".
func NewClient(orgURL, token string) *Client {
	return &Client{
		orgURL: orgURL,
		token:  token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// FetchPipelineFile fetches the azure-pipelines.yml file from a repository.
func (c *Client) FetchPipelineFile(ctx context.Context, project, repoID string) ([]byte, error) {
	endpoint := fmt.Sprintf("/%s/_apis/git/repositories/%s/items",
		url.PathEscape(project), url.PathEscape(repoID))

	params := url.Values{
		"path":        {"azure-pipelines.yml"},
		"api-version": {"7.0"},
	}

	body, err := c.doGet(ctx, endpoint, params)
	if err != nil {
		return nil, fmt.Errorf("fetching azure-pipelines.yml for %s/%s: %w", project, repoID, err)
	}
	return body, nil
}

// ListProjectRepos lists all Git repositories in an Azure DevOps project.
func (c *Client) ListProjectRepos(ctx context.Context, project string) ([]RepoInfo, error) {
	endpoint := fmt.Sprintf("/%s/_apis/git/repositories", url.PathEscape(project))
	params := url.Values{
		"api-version": {"7.0"},
	}

	body, err := c.doGet(ctx, endpoint, params)
	if err != nil {
		return nil, fmt.Errorf("listing repos for project %s: %w", project, err)
	}

	var resp repoListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decoding repos response: %w", err)
	}

	repos := make([]RepoInfo, len(resp.Value))
	for i, r := range resp.Value {
		repos[i] = RepoInfo{
			ID:            r.ID,
			Name:          r.Name,
			DefaultBranch: r.DefaultBranch,
			Project:       r.Project.Name,
		}
	}

	return repos, nil
}

// ScanRemote fetches, parses, and scans a repository's azure-pipelines.yml file.
func (c *Client) ScanRemote(ctx context.Context, project, repoID string, opts scanner.ScanOptions) (*scanner.ScanResult, error) {
	data, err := c.FetchPipelineFile(ctx, project, repoID)
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf("%s/%s/azure-pipelines.yml", project, repoID)
	pipeline, err := cicd.ParseAzurePipeline(data, path)
	if err != nil {
		return nil, fmt.Errorf("parsing pipeline for %s/%s: %w", project, repoID, err)
	}

	azFindings := cicd.ScanAzurePipeline(pipeline)

	result := &scanner.ScanResult{
		Path:      fmt.Sprintf("%s/%s", project, repoID),
		Workflows: 1,
	}

	for _, azf := range azFindings {
		f := scanner.Finding{
			RuleID:   azf.RuleID,
			Severity: azf.Severity,
			File:     azf.File,
			Line:     azf.Line,
			Message:  azf.Message,
			Details:  azf.Details,
		}
		result.Findings = append(result.Findings, f)
	}

	// Apply severity filter
	if len(opts.Severities) > 0 {
		sevSet := make(map[string]bool)
		for _, s := range opts.Severities {
			sevSet[s] = true
		}
		var filtered []scanner.Finding
		for _, f := range result.Findings {
			if sevSet[f.Severity] {
				filtered = append(filtered, f)
			}
		}
		result.Findings = filtered
	}

	// Apply rule filter
	if len(opts.Rules) > 0 {
		ruleSet := make(map[string]bool)
		for _, r := range opts.Rules {
			ruleSet[r] = true
		}
		var filtered []scanner.Finding
		for _, f := range result.Findings {
			if ruleSet[f.RuleID] {
				filtered = append(filtered, f)
			}
		}
		result.Findings = filtered
	}

	return result, nil
}

// doGet performs an authenticated GET request with retry logic.
// Azure DevOps uses Basic auth with empty username and PAT as password.
func (c *Client) doGet(ctx context.Context, endpoint string, params url.Values) ([]byte, error) {
	u := c.orgURL + endpoint
	if params != nil {
		u += "?" + params.Encode()
	}

	const maxRetries = 5
	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}

		// Azure DevOps Basic auth: empty username, PAT as password
		if c.token != "" {
			auth := base64.StdEncoding.EncodeToString([]byte(":" + c.token))
			req.Header.Set("Authorization", "Basic "+auth)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return body, err
		}

		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("not found: %s (HTTP %d)", endpoint, resp.StatusCode)
		}

		// Retry on rate limits and transient errors
		if attempt < maxRetries && (resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode == http.StatusServiceUnavailable ||
			resp.StatusCode == http.StatusBadGateway) {

			wait := time.Duration(1<<uint(attempt)) * time.Second

			// Check Retry-After header
			if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
				if secs, err := time.ParseDuration(retryAfter + "s"); err == nil {
					wait = secs
				}
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
				continue
			}
		}

		return nil, fmt.Errorf("Azure DevOps API error: %s (HTTP %d): %s", endpoint, resp.StatusCode, string(body))
	}

	return nil, fmt.Errorf("exceeded maximum retries for %s", endpoint)
}
