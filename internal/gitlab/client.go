package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/north-echo/fluxgate/internal/cicd"
	"github.com/north-echo/fluxgate/internal/scanner"
)

// Client wraps the GitLab API for fetching pipeline files.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// ProjectInfo represents basic GitLab project metadata.
type ProjectInfo struct {
	ID                int    `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
	DefaultBranch     string `json:"default_branch"`
}

// NewClient creates a GitLab API client. If baseURL is empty, defaults to
// "https://gitlab.com".
func NewClient(baseURL, token string) *Client {
	if baseURL == "" {
		baseURL = "https://gitlab.com"
	}
	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// FetchPipelineFile fetches the .gitlab-ci.yml file from a project.
func (c *Client) FetchPipelineFile(ctx context.Context, projectID string) ([]byte, error) {
	encodedPath := url.PathEscape(".gitlab-ci.yml")
	endpoint := fmt.Sprintf("/api/v4/projects/%s/repository/files/%s/raw",
		url.PathEscape(projectID), encodedPath)

	body, err := c.doGet(ctx, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("fetching .gitlab-ci.yml for project %s: %w", projectID, err)
	}
	return body, nil
}

// ListGroupProjects lists all projects in a GitLab group with pagination.
func (c *Client) ListGroupProjects(ctx context.Context, groupID string) ([]ProjectInfo, error) {
	var allProjects []ProjectInfo
	page := 1
	perPage := 100

	for {
		params := url.Values{
			"page":     {strconv.Itoa(page)},
			"per_page": {strconv.Itoa(perPage)},
		}

		endpoint := fmt.Sprintf("/api/v4/groups/%s/projects", url.PathEscape(groupID))
		body, err := c.doGet(ctx, endpoint, params)
		if err != nil {
			return nil, fmt.Errorf("listing projects for group %s (page %d): %w", groupID, page, err)
		}

		var projects []ProjectInfo
		if err := json.Unmarshal(body, &projects); err != nil {
			return nil, fmt.Errorf("decoding projects response: %w", err)
		}

		allProjects = append(allProjects, projects...)

		if len(projects) < perPage {
			break
		}
		page++
	}

	return allProjects, nil
}

// ScanRemote fetches, parses, and scans a project's .gitlab-ci.yml file.
func (c *Client) ScanRemote(ctx context.Context, projectID string, opts scanner.ScanOptions) (*scanner.ScanResult, error) {
	data, err := c.FetchPipelineFile(ctx, projectID)
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf("%s/.gitlab-ci.yml", projectID)
	pipeline, err := cicd.ParseGitLabCI(data, path)
	if err != nil {
		return nil, fmt.Errorf("parsing pipeline for project %s: %w", projectID, err)
	}

	glFindings := cicd.ScanGitLabPipeline(pipeline)

	result := &scanner.ScanResult{
		Path:      projectID,
		Workflows: 1,
	}

	for _, glf := range glFindings {
		f := scanner.Finding{
			RuleID:   glf.RuleID,
			Severity: glf.Severity,
			File:     glf.File,
			Line:     glf.Line,
			Message:  glf.Message,
			Details:  glf.Details,
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

// doGet performs an authenticated GET request with rate limit handling.
func (c *Client) doGet(ctx context.Context, endpoint string, params url.Values) ([]byte, error) {
	u := c.baseURL + endpoint
	if params != nil {
		u += "?" + params.Encode()
	}

	const maxRetries = 5
	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		if c.token != "" {
			req.Header.Set("PRIVATE-TOKEN", c.token)
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

		// Check rate limiting
		if resp.StatusCode == http.StatusTooManyRequests {
			remaining := resp.Header.Get("X-RateLimit-Remaining")
			if remaining == "0" || remaining == "" {
				resetStr := resp.Header.Get("X-RateLimit-Reset")
				if resetStr != "" {
					if resetTime, err := strconv.ParseInt(resetStr, 10, 64); err == nil {
						wait := time.Until(time.Unix(resetTime, 0))
						if wait > 0 && wait < 60*time.Second {
							select {
							case <-ctx.Done():
								return nil, ctx.Err()
							case <-time.After(wait + time.Second):
								continue
							}
						}
					}
				}
				// Default backoff
				wait := time.Duration(1<<uint(attempt)) * time.Second
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(wait):
					continue
				}
			}
		}

		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("not found: %s (HTTP %d)", endpoint, resp.StatusCode)
		}

		if attempt < maxRetries && (resp.StatusCode == http.StatusServiceUnavailable ||
			resp.StatusCode == http.StatusBadGateway) {
			wait := time.Duration(1<<uint(attempt)) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
				continue
			}
		}

		return nil, fmt.Errorf("GitLab API error: %s (HTTP %d): %s", endpoint, resp.StatusCode, string(body))
	}

	return nil, fmt.Errorf("exceeded maximum retries for %s", endpoint)
}
