package diff

import (
	"path/filepath"
	"testing"

	"github.com/north-echo/fluxgate/internal/scanner"
	"github.com/north-echo/fluxgate/internal/store"
)

// populateDB is a test helper that opens a database and saves scan results.
func populateDB(t *testing.T, path string, entries []struct {
	owner, repo string
	stars       int
	lang        string
	result      *scanner.ScanResult
}) *store.DB {
	t.Helper()
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("opening db: %v", err)
	}
	for _, e := range entries {
		if err := db.SaveResult(e.owner, e.repo, e.stars, e.lang, e.result); err != nil {
			t.Fatalf("saving result for %s/%s: %v", e.owner, e.repo, err)
		}
	}
	db.Close()
	return nil
}

func TestCompare_NewResolvedUnchanged(t *testing.T) {
	oldPath := filepath.Join(t.TempDir(), "old.db")
	newPath := filepath.Join(t.TempDir(), "new.db")

	type entry struct {
		owner, repo string
		stars       int
		lang        string
		result      *scanner.ScanResult
	}

	// Old DB: two findings in same repo.
	populateDB(t, oldPath, []struct {
		owner, repo string
		stars       int
		lang        string
		result      *scanner.ScanResult
	}{
		{
			owner: "acme", repo: "app", stars: 500, lang: "Go",
			result: &scanner.ScanResult{
				Path: "acme/app", Workflows: 1,
				Findings: []scanner.Finding{
					{RuleID: "FG-001", Severity: "critical", File: ".github/workflows/ci.yml", Line: 10, Message: "pwn request"},
					{RuleID: "FG-002", Severity: "high", File: ".github/workflows/ci.yml", Line: 20, Message: "script injection"},
				},
			},
		},
	})

	// New DB: FG-001 still present (unchanged), FG-002 gone (resolved), FG-003 added (new).
	populateDB(t, newPath, []struct {
		owner, repo string
		stars       int
		lang        string
		result      *scanner.ScanResult
	}{
		{
			owner: "acme", repo: "app", stars: 500, lang: "Go",
			result: &scanner.ScanResult{
				Path: "acme/app", Workflows: 1,
				Findings: []scanner.Finding{
					{RuleID: "FG-001", Severity: "critical", File: ".github/workflows/ci.yml", Line: 10, Message: "pwn request"},
					{RuleID: "FG-003", Severity: "medium", File: ".github/workflows/deploy.yml", Line: 5, Message: "oidc misconfig"},
				},
			},
		},
	})

	result, err := Compare(oldPath, newPath)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}

	if result.Unchanged != 1 {
		t.Errorf("expected 1 unchanged, got %d", result.Unchanged)
	}
	if result.Resolved != 1 {
		t.Errorf("expected 1 resolved, got %d", result.Resolved)
	}
	if result.New != 1 {
		t.Errorf("expected 1 new, got %d", result.New)
	}
	if result.Regressed != 0 {
		t.Errorf("expected 0 regressed, got %d", result.Regressed)
	}
	if result.OldCount != 2 {
		t.Errorf("expected OldCount=2, got %d", result.OldCount)
	}
	if result.NewCount != 2 {
		t.Errorf("expected NewCount=2, got %d", result.NewCount)
	}
}

func TestCompare_IdenticalDatabases(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "same.db")

	populateDB(t, dbPath, []struct {
		owner, repo string
		stars       int
		lang        string
		result      *scanner.ScanResult
	}{
		{
			owner: "org", repo: "lib", stars: 100, lang: "Python",
			result: &scanner.ScanResult{
				Path: "org/lib", Workflows: 1,
				Findings: []scanner.Finding{
					{RuleID: "FG-001", Severity: "critical", File: ".github/workflows/ci.yml", Line: 15, Message: "test"},
				},
			},
		},
	})

	result, err := Compare(dbPath, dbPath)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}

	if result.New != 0 {
		t.Errorf("expected 0 new, got %d", result.New)
	}
	if result.Resolved != 0 {
		t.Errorf("expected 0 resolved, got %d", result.Resolved)
	}
	if result.Unchanged != 1 {
		t.Errorf("expected 1 unchanged, got %d", result.Unchanged)
	}
	if result.Regressed != 0 {
		t.Errorf("expected 0 regressed, got %d", result.Regressed)
	}
}

func TestCompare_Regression(t *testing.T) {
	oldPath := filepath.Join(t.TempDir(), "old.db")
	newPath := filepath.Join(t.TempDir(), "new.db")

	type dbEntry struct {
		owner, repo string
		stars       int
		lang        string
		result      *scanner.ScanResult
	}

	// Old DB: finding with "high" severity.
	populateDB(t, oldPath, []struct {
		owner, repo string
		stars       int
		lang        string
		result      *scanner.ScanResult
	}{
		{
			owner: "acme", repo: "svc", stars: 200, lang: "Go",
			result: &scanner.ScanResult{
				Path: "acme/svc", Workflows: 1,
				Findings: []scanner.Finding{
					{RuleID: "FG-001", Severity: "high", File: ".github/workflows/ci.yml", Line: 10, Message: "was high"},
				},
			},
		},
	})

	// New DB: same finding now "critical" — regression.
	populateDB(t, newPath, []struct {
		owner, repo string
		stars       int
		lang        string
		result      *scanner.ScanResult
	}{
		{
			owner: "acme", repo: "svc", stars: 200, lang: "Go",
			result: &scanner.ScanResult{
				Path: "acme/svc", Workflows: 1,
				Findings: []scanner.Finding{
					{RuleID: "FG-001", Severity: "critical", File: ".github/workflows/ci.yml", Line: 10, Message: "now critical"},
				},
			},
		},
	})

	result, err := Compare(oldPath, newPath)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}

	if result.Regressed != 1 {
		t.Errorf("expected 1 regressed, got %d", result.Regressed)
	}
	if result.Unchanged != 0 {
		t.Errorf("expected 0 unchanged, got %d", result.Unchanged)
	}
}

func TestCompare_EmptyDatabases(t *testing.T) {
	oldPath := filepath.Join(t.TempDir(), "empty-old.db")
	newPath := filepath.Join(t.TempDir(), "empty-new.db")

	// Create empty databases with no findings.
	populateDB(t, oldPath, nil)
	populateDB(t, newPath, nil)

	result, err := Compare(oldPath, newPath)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}

	if result.New != 0 || result.Resolved != 0 || result.Unchanged != 0 || result.Regressed != 0 {
		t.Errorf("expected all zeros for empty DBs, got new=%d resolved=%d unchanged=%d regressed=%d",
			result.New, result.Resolved, result.Unchanged, result.Regressed)
	}
}
