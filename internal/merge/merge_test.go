package merge

import (
	"path/filepath"
	"testing"

	"github.com/north-echo/fluxgate/internal/scanner"
	"github.com/north-echo/fluxgate/internal/store"
)

// saveTestData is a helper that opens a DB, saves entries, and closes it.
func saveTestData(t *testing.T, path string, entries []struct {
	owner, repo string
	stars       int
	lang        string
	result      *scanner.ScanResult
}) {
	t.Helper()
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("opening db %s: %v", path, err)
	}
	defer db.Close()
	for _, e := range entries {
		if err := db.SaveResult(e.owner, e.repo, e.stars, e.lang, e.result); err != nil {
			t.Fatalf("saving result for %s/%s: %v", e.owner, e.repo, err)
		}
	}
}

func TestMergeDBs_OverlappingAndUnique(t *testing.T) {
	dir := t.TempDir()
	src1 := filepath.Join(dir, "src1.db")
	src2 := filepath.Join(dir, "src2.db")
	target := filepath.Join(dir, "target.db")

	type entry struct {
		owner, repo string
		stars       int
		lang        string
		result      *scanner.ScanResult
	}

	// Source 1: two repos.
	saveTestData(t, src1, []struct {
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
				},
			},
		},
		{
			owner: "acme", repo: "lib", stars: 200, lang: "Python",
			result: &scanner.ScanResult{
				Path: "acme/lib", Workflows: 1,
				Findings: []scanner.Finding{
					{RuleID: "FG-002", Severity: "high", File: ".github/workflows/build.yml", Line: 25, Message: "injection"},
				},
			},
		},
	})

	// Source 2: one overlapping repo (acme/app, same finding) and one unique.
	saveTestData(t, src2, []struct {
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
				},
			},
		},
		{
			owner: "beta", repo: "svc", stars: 1000, lang: "Rust",
			result: &scanner.ScanResult{
				Path: "beta/svc", Workflows: 2,
				Findings: []scanner.Finding{
					{RuleID: "FG-003", Severity: "medium", File: ".github/workflows/deploy.yml", Line: 5, Message: "oidc"},
					{RuleID: "FG-004", Severity: "low", File: ".github/workflows/deploy.yml", Line: 30, Message: "pinning"},
				},
			},
		},
	})

	stats, err := MergeDBs(target, []string{src1, src2})
	if err != nil {
		t.Fatalf("MergeDBs: %v", err)
	}

	if stats.SourcesProcessed != 2 {
		t.Errorf("expected 2 sources processed, got %d", stats.SourcesProcessed)
	}

	// Verify via the target database.
	tdb, err := store.Open(target)
	if err != nil {
		t.Fatalf("opening target: %v", err)
	}
	defer tdb.Close()

	reportStats, err := tdb.GetReportStats()
	if err != nil {
		t.Fatalf("GetReportStats: %v", err)
	}

	// 3 unique repos: acme/app, acme/lib, beta/svc.
	if reportStats.ReposScanned != 3 {
		t.Errorf("expected 3 repos, got %d", reportStats.ReposScanned)
	}

	// 3 unique repos: acme/app, acme/lib, beta/svc.
	if reportStats.ReposScanned != 3 {
		t.Errorf("expected 3 repos in target, got %d", reportStats.ReposScanned)
	}

	// All 5 findings across both sources should be processed.
	// src1: FG-001 + FG-002 (2), src2: FG-001 + FG-003 + FG-004 (3) = 5 total.
	totalProcessed := stats.FindingsMerged + stats.FindingsSkipped
	if totalProcessed != 5 {
		t.Errorf("expected 5 total findings processed (merged+skipped), got %d", totalProcessed)
	}

	// Target should have at least 4 findings (the 4 unique ones).
	if reportStats.TotalFindings < 4 {
		t.Errorf("expected at least 4 findings in target, got %d", reportStats.TotalFindings)
	}
}

func TestMergeDBs_SingleSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.db")
	target := filepath.Join(dir, "target.db")

	saveTestData(t, src, []struct {
		owner, repo string
		stars       int
		lang        string
		result      *scanner.ScanResult
	}{
		{
			owner: "org", repo: "tool", stars: 300, lang: "Go",
			result: &scanner.ScanResult{
				Path: "org/tool", Workflows: 1,
				Findings: []scanner.Finding{
					{RuleID: "FG-001", Severity: "critical", File: ".github/workflows/ci.yml", Line: 8, Message: "finding one"},
					{RuleID: "FG-005", Severity: "low", File: ".github/workflows/ci.yml", Line: 40, Message: "finding two"},
				},
			},
		},
	})

	stats, err := MergeDBs(target, []string{src})
	if err != nil {
		t.Fatalf("MergeDBs: %v", err)
	}

	if stats.SourcesProcessed != 1 {
		t.Errorf("expected 1 source, got %d", stats.SourcesProcessed)
	}
	if stats.ReposMerged != 1 {
		t.Errorf("expected 1 repo merged, got %d", stats.ReposMerged)
	}
	if stats.FindingsMerged != 2 {
		t.Errorf("expected 2 findings merged, got %d", stats.FindingsMerged)
	}
	if stats.FindingsSkipped != 0 {
		t.Errorf("expected 0 findings skipped, got %d", stats.FindingsSkipped)
	}
}

func TestMergeDBs_EmptySource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "empty.db")
	target := filepath.Join(dir, "target.db")

	// Create an empty source database (no repos, no findings).
	saveTestData(t, src, nil)

	stats, err := MergeDBs(target, []string{src})
	if err != nil {
		t.Fatalf("MergeDBs: %v", err)
	}

	if stats.ReposMerged != 0 {
		t.Errorf("expected 0 repos merged, got %d", stats.ReposMerged)
	}
	if stats.FindingsMerged != 0 {
		t.Errorf("expected 0 findings merged, got %d", stats.FindingsMerged)
	}
}
