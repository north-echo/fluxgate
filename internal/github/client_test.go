package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	gh "github.com/google/go-github/v60/github"
	"github.com/north-echo/fluxgate/internal/scanner"
)

// newTestServer creates a mock GitHub API server with the given workflow files.
func newTestServer(workflows map[string]string) *httptest.Server {
	mux := http.NewServeMux()

	// List directory contents
	mux.HandleFunc("/api/v3/repos/testowner/testrepo/contents/.github/workflows", func(w http.ResponseWriter, r *http.Request) {
		var entries []map[string]interface{}
		for name := range workflows {
			entries = append(entries, map[string]interface{}{
				"name": name,
				"path": ".github/workflows/" + name,
				"type": "file",
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	})

	// Fetch individual files
	for name, content := range workflows {
		path := ".github/workflows/" + name
		encoded := base64.StdEncoding.EncodeToString([]byte(content))
		mux.HandleFunc("/api/v3/repos/testowner/testrepo/contents/"+path, func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"encoding": "base64",
				"content":  encoded,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})
	}

	return httptest.NewServer(mux)
}

func newTestClient(serverURL string) *Client {
	client := gh.NewClient(nil)
	baseURL, _ := client.BaseURL.Parse(serverURL + "/api/v3/")
	client.BaseURL = baseURL
	return &Client{gh: client}
}

func TestFetchWorkflows(t *testing.T) {
	workflows := map[string]string{
		"ci.yaml": `name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: go test ./...
`,
	}

	server := newTestServer(workflows)
	defer server.Close()

	client := newTestClient(server.URL)
	files, err := client.FetchWorkflows(context.Background(), "testowner", "testrepo")
	if err != nil {
		t.Fatalf("FetchWorkflows failed: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("expected 1 workflow, got %d", len(files))
	}
	if files[0].Path != ".github/workflows/ci.yaml" {
		t.Errorf("expected path .github/workflows/ci.yaml, got %s", files[0].Path)
	}
}

func TestScanRemote_PwnRequest(t *testing.T) {
	workflows := map[string]string{
		"vuln.yaml": `name: Vuln
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make build
        env:
          TOKEN: ${{ secrets.DEPLOY_KEY }}
`,
	}

	server := newTestServer(workflows)
	defer server.Close()

	client := newTestClient(server.URL)
	result, err := client.ScanRemote(context.Background(), "testowner", "testrepo", scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("ScanRemote failed: %v", err)
	}

	if result.Workflows != 1 {
		t.Errorf("expected 1 workflow, got %d", result.Workflows)
	}

	// Should detect FG-001
	found := false
	for _, f := range result.Findings {
		if f.RuleID == "FG-001" {
			found = true
			if f.Severity != "critical" {
				t.Errorf("expected critical severity for FG-001, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected FG-001 finding for pwn request pattern")
	}
}

func TestScanRemote_SafeWorkflow(t *testing.T) {
	workflows := map[string]string{
		"safe.yaml": `name: CI
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: go test ./...
`,
	}

	server := newTestServer(workflows)
	defer server.Close()

	client := newTestClient(server.URL)
	result, err := client.ScanRemote(context.Background(), "testowner", "testrepo", scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("ScanRemote failed: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for safe workflow, got %d", len(result.Findings))
	}
}

func TestScanRemote_NoWorkflowsDir(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/testowner/testrepo/contents/.github/workflows", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newTestClient(server.URL)
	_, err := client.ScanRemote(context.Background(), "testowner", "testrepo", scanner.ScanOptions{})
	if err == nil {
		t.Error("expected error for missing workflows directory")
	}
}

func TestRetryOnRateLimit(t *testing.T) {
	callCount := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/testowner/testrepo/contents/.github/workflows", func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"message":"rate limit exceeded"}`))
			return
		}
		// Return empty directory on third try
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newTestClient(server.URL)
	result, err := client.ScanRemote(context.Background(), "testowner", "testrepo", scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("ScanRemote failed after retry: %v", err)
	}
	if result.Workflows != 0 {
		t.Errorf("expected 0 workflows, got %d", result.Workflows)
	}
	if callCount < 3 {
		t.Errorf("expected at least 3 calls (2 rate limited + 1 success), got %d", callCount)
	}
}
