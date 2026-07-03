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
// If token is non-empty, it is injected via GIT_ASKPASS (askPass must be a
// path from writeAskPass) to avoid exposing credentials in process argument
// lists.
func SparseClone(ctx context.Context, owner, repo, destDir, askPass, token string) error {
	repoURL := fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)

	cloneCmd := exec.CommandContext(ctx, "git", "clone",
		"--filter=blob:none",
		"--no-checkout",
		"--depth=1",
		repoURL,
		destDir,
	)
	if token != "" && askPass != "" {
		cloneCmd.Env = append(os.Environ(), tokenAskPassEnv(askPass, token)...)
	}
	if err := cloneCmd.Run(); err != nil {
		return fmt.Errorf("git clone %s/%s: %w", owner, repo, err)
	}

	// Non-cone mode excludes root-level files; cone mode always includes
	// them. `set --no-cone` (git >= 2.35) initializes and sets the pattern
	// in one subprocess instead of separate init + set calls.
	if err := runGit(ctx, destDir, "sparse-checkout", "set", "--no-cone", "/.github/"); err != nil {
		return fmt.Errorf("git sparse-checkout set for %s/%s: %w", owner, repo, err)
	}

	if err := runGit(ctx, destDir, "checkout"); err != nil {
		return fmt.Errorf("git checkout for %s/%s: %w", owner, repo, err)
	}

	return nil
}

// askPassScript answers git credential prompts: "x-access-token" for the
// username, the token (from the environment, never on disk or in argv) for
// the password.
const askPassScript = `#!/bin/sh
case "$1" in
  [Uu]sername*) printf 'x-access-token\n' ;;
  *) printf '%s\n' "$FLUXGATE_GIT_TOKEN" ;;
esac
`

// writeAskPass writes the askpass helper to a temp file and returns its path
// plus a cleanup func. The previous GIT_ASKPASS=printf approach echoed the
// prompt text back as the credential, so token auth never actually worked.
func writeAskPass() (string, func(), error) {
	dir, err := os.MkdirTemp("", "fluxgate-askpass-*")
	if err != nil {
		return "", nil, err
	}
	script := filepath.Join(dir, "askpass.sh")
	if err := os.WriteFile(script, []byte(askPassScript), 0o700); err != nil {
		os.RemoveAll(dir)
		return "", nil, err
	}
	return script, func() { os.RemoveAll(dir) }, nil
}

// tokenAskPassEnv returns environment variables that inject a GitHub token
// via GIT_ASKPASS, keeping the token out of process argument lists.
func tokenAskPassEnv(askPass, token string) []string {
	return []string{
		"GIT_ASKPASS=" + askPass,
		"GIT_TERMINAL_PROMPT=0",
		"FLUXGATE_GIT_TOKEN=" + token,
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
// Tokens are assigned to clones round-robin so a --tokens pool spreads git
// rate-limit load; pass nil for unauthenticated clones.
func CloneAndScan(ctx context.Context, repos []Repo, concurrency int, tokens []string, keepDir string, scanFn ScanFunc) []CloneResult {
	if concurrency < 1 {
		concurrency = 5
	}

	var askPass string
	if len(tokens) > 0 {
		var cleanup func()
		var err error
		askPass, cleanup, err = writeAskPass()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not set up git credentials, cloning unauthenticated: %v\n", err)
			tokens = nil
		} else {
			defer cleanup()
		}
	}

	results := make([]CloneResult, len(repos))
	idxCh := make(chan int)
	var wg sync.WaitGroup

	// Fixed worker pool: spawning one goroutine per repo up front allocates
	// N goroutines for a batch of N even though only `concurrency` run.
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range idxCh {
				cloneOne(ctx, repos[idx], &results[idx], tokens, askPass, keepDir, idx, scanFn)
			}
		}()
	}

	for i := range repos {
		idxCh <- i
	}
	close(idxCh)
	wg.Wait()
	return results
}

// cloneOne clones and scans a single repo within a CloneAndScan worker.
func cloneOne(ctx context.Context, repo Repo, result *CloneResult, tokens []string, askPass, keepDir string, idx int, scanFn ScanFunc) {
	owner, name := repo.Owner, repo.Name
	*result = CloneResult{Owner: owner, Name: name}

	if ctx.Err() != nil {
		result.Err = ctx.Err()
		return
	}

	var repoDir string
	if keepDir != "" {
		repoDir = filepath.Join(keepDir, owner, name)
		if err := os.MkdirAll(filepath.Dir(repoDir), 0o750); err != nil {
			result.Err = err
			return
		}
	} else {
		tmpDir, err := os.MkdirTemp("", "fluxgate-*")
		if err != nil {
			result.Err = err
			return
		}
		repoDir = filepath.Join(tmpDir, owner, name)
		defer os.RemoveAll(tmpDir)
	}

	token := ""
	if len(tokens) > 0 {
		token = tokens[idx%len(tokens)]
	}
	if err := SparseClone(ctx, owner, name, repoDir, askPass, token); err != nil {
		result.Err = err
		return
	}

	result.Err = scanFn(owner, name, repoDir, result)
}
