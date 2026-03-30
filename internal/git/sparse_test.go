package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCheckGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available in test environment")
	}
	if err := CheckGit(); err != nil {
		t.Fatalf("CheckGit() returned error: %v", err)
	}
}

func TestCheckGitMissingBinary(t *testing.T) {
	t.Setenv("PATH", "")
	err := CheckGit()
	if err == nil {
		t.Fatal("expected error when git is not in PATH")
	}
	want := "git is required for --clone mode but was not found in PATH"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestSparseClone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	ctx := context.Background()
	cloneDir := filepath.Join(t.TempDir(), "clone")

	err := SparseClone(ctx, "actions", "checkout", cloneDir, "")
	if err != nil {
		t.Fatalf("SparseClone() error: %v", err)
	}

	entries, err := os.ReadDir(cloneDir)
	if err != nil {
		t.Fatalf("reading clone dir: %v", err)
	}

	for _, entry := range entries {
		if entry.Name() == ".git" || entry.Name() == ".github" {
			continue
		}
		t.Errorf("unexpected file in sparse checkout: %s", entry.Name())
	}

	if _, err := os.Stat(filepath.Join(cloneDir, ".github", "workflows")); err != nil {
		t.Errorf(".github/workflows/ should exist: %v", err)
	}
}

func TestSparseCloneInvalidRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	ctx := context.Background()
	cloneDir := filepath.Join(t.TempDir(), "clone")

	err := SparseClone(ctx, "nonexistent-owner-xyzzy", "nonexistent-repo-xyzzy", cloneDir, "")
	if err == nil {
		t.Fatal("expected error for invalid repo, got nil")
	}
}

func TestCloneAndScan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	ctx := context.Background()
	repos := []Repo{
		{Owner: "actions", Name: "checkout"},
		{Owner: "nonexistent-owner-xyzzy", Name: "nonexistent-repo-xyzzy"},
	}

	var scannedDirs []string
	results := CloneAndScan(ctx, repos, 2, "", "",
		func(owner, name, dir string, cr *CloneResult) error {
			scannedDirs = append(scannedDirs, dir)
			cr.SetFindings(5, 2)
			return nil
		})

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	var success, failure int
	for _, r := range results {
		if r.Err != nil {
			failure++
		} else {
			success++
		}
	}

	if success != 1 {
		t.Errorf("expected 1 success, got %d", success)
	}
	if failure != 1 {
		t.Errorf("expected 1 failure, got %d", failure)
	}

	if len(scannedDirs) != 1 {
		t.Errorf("expected scanFn called once, got %d", len(scannedDirs))
	}

	// Verify findings were recorded
	for _, r := range results {
		if r.Err == nil {
			if r.Findings != 5 || r.Workflows != 2 {
				t.Errorf("expected findings=5, workflows=2, got %d, %d", r.Findings, r.Workflows)
			}
		}
	}
}
