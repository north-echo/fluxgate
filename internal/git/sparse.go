package git

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

// CloneResult holds the outcome of a single clone-and-scan operation.
type CloneResult struct {
	Owner     string
	Name      string
	Err       error
	Findings  int // populated by ScanFunc via SetFindings
	Workflows int // populated by ScanFunc via SetFindings
}

// SetFindings records scan metrics in the result. Call this from ScanFunc.
func (r *CloneResult) SetFindings(findings, workflows int) {
	r.Findings = findings
	r.Workflows = workflows
}

// CheckGit verifies that git is available in PATH.
func CheckGit() error {
	_, err := exec.LookPath("git")
	if err != nil {
		return fmt.Errorf("git is required for --clone mode but was not found in PATH")
	}
	return nil
}

// runGit executes a git command in the given directory, suppressing output.
func runGit(ctx context.Context, dir string, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	return cmd.Run()
}

// SparseClone clones a GitHub repository using sparse checkout, fetching only
// the .github/ directory.
//
// If token is non-empty, it is injected via GIT_ASKPASS to avoid exposing
// credentials in process argument lists.
func SparseClone(ctx context.Context, owner, repo, destDir, token string) error {
	repoURL := fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)

	cloneCmd := exec.CommandContext(ctx, "git", "clone",
		"--filter=blob:none",
		"--no-checkout",
		"--depth=1",
		repoURL,
		destDir,
	)
	if token != "" {
		cloneCmd.Env = append(os.Environ(), tokenAskPassEnv(token)...)
	}
	if err := cloneCmd.Run(); err != nil {
		return fmt.Errorf("git clone %s/%s: %w", owner, repo, err)
	}

	// Non-cone mode excludes root-level files; cone mode always includes them.
	if err := runGit(ctx, destDir, "sparse-checkout", "init", "--no-cone"); err != nil {
		return fmt.Errorf("git sparse-checkout init for %s/%s: %w", owner, repo, err)
	}

	if err := runGit(ctx, destDir, "sparse-checkout", "set", "/.github/"); err != nil {
		return fmt.Errorf("git sparse-checkout set for %s/%s: %w", owner, repo, err)
	}

	if err := runGit(ctx, destDir, "checkout"); err != nil {
		return fmt.Errorf("git checkout for %s/%s: %w", owner, repo, err)
	}

	return nil
}

// tokenAskPassEnv returns environment variables that inject a GitHub token
// via GIT_ASKPASS, keeping the token out of process argument lists.
func tokenAskPassEnv(token string) []string {
	return []string{
		"GIT_ASKPASS=printf",
		"GIT_TERMINAL_PROMPT=0",
		fmt.Sprintf("GIT_PASSWORD=%s", token),
	}
}

// ScanFunc is called with the cloned repo directory and a result pointer.
// It should scan the directory, persist results, and call result.SetFindings
// to record metrics. Errors are recorded in CloneResult.
type ScanFunc func(owner, name, dir string, result *CloneResult) error

// Repo identifies a repository to clone.
type Repo struct {
	Owner string
	Name  string
}

// CloneAndScan clones repos concurrently, calling scanFn on each clone as it
// completes. Each clone is removed after scanning unless keepDir is non-empty.
// This bounds disk usage to O(concurrency) rather than O(total repos).
func CloneAndScan(ctx context.Context, repos []Repo, concurrency int, token, keepDir string, scanFn ScanFunc) []CloneResult {
	if concurrency < 1 {
		concurrency = 5
	}

	results := make([]CloneResult, len(repos))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i := range repos {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			owner, name := repos[idx].Owner, repos[idx].Name
			results[idx] = CloneResult{Owner: owner, Name: name}

			select {
			case <-ctx.Done():
				results[idx].Err = ctx.Err()
				return
			default:
			}

			var repoDir string
			if keepDir != "" {
				repoDir = filepath.Join(keepDir, owner, name)
				if err := os.MkdirAll(filepath.Dir(repoDir), 0o750); err != nil {
					results[idx].Err = err
					return
				}
			} else {
				tmpDir, err := os.MkdirTemp("", "fluxgate-*")
				if err != nil {
					results[idx].Err = err
					return
				}
				repoDir = filepath.Join(tmpDir, owner, name)
				defer os.RemoveAll(tmpDir)
			}

			if err := SparseClone(ctx, owner, name, repoDir, token); err != nil {
				results[idx].Err = err
				return
			}

			results[idx].Err = scanFn(owner, name, repoDir, &results[idx])
		}(i)
	}

	wg.Wait()
	return results
}
