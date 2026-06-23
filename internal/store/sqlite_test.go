package store

import (
	"path/filepath"
	"testing"

	"github.com/north-echo/fluxgate/internal/scanner"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// Regression for fluxgate #16: rescans must produce findings whose repo_id
// references the canonical repos.id, not a synthetic LastInsertId rowid.
func TestSaveResult_RescanRepoIDIsCanonical(t *testing.T) {
	db := newTestDB(t)
	owner, name := "redhat-cop", "test-repo"
	result := &scanner.ScanResult{
		Workflows: 1,
		Findings: []scanner.Finding{
			{File: ".github/workflows/ci.yaml", RuleID: "FG-001", Severity: "high",
				Line: 10, Message: "first", Details: "first"},
		},
	}
	if err := db.SaveResult(owner, name, 0, "Go", result); err != nil {
		t.Fatalf("first save: %v", err)
	}

	var firstRepoID int64
	if err := db.SqlxDB().Get(&firstRepoID,
		"SELECT id FROM repos WHERE owner = ? AND name = ?", owner, name); err != nil {
		t.Fatalf("looking up first repo id: %v", err)
	}

	result2 := &scanner.ScanResult{
		Workflows: 1,
		Findings: []scanner.Finding{
			{File: ".github/workflows/ci.yaml", RuleID: "FG-001", Severity: "high",
				Line: 12, Message: "second", Details: "second"},
			{File: ".github/workflows/ci.yaml", RuleID: "FG-022", Severity: "critical",
				Line: 20, Message: "compromised", Details: "compromised"},
		},
	}
	if err := db.SaveResult(owner, name, 1, "Go", result2); err != nil {
		t.Fatalf("rescan save: %v", err)
	}

	var rescanRepoID int64
	if err := db.SqlxDB().Get(&rescanRepoID,
		"SELECT id FROM repos WHERE owner = ? AND name = ?", owner, name); err != nil {
		t.Fatalf("looking up rescan repo id: %v", err)
	}
	if rescanRepoID != firstRepoID {
		t.Fatalf("repos.id changed across rescan: first=%d rescan=%d", firstRepoID, rescanRepoID)
	}

	var orphanCount int
	if err := db.SqlxDB().Get(&orphanCount,
		`SELECT COUNT(*) FROM findings f LEFT JOIN repos r ON r.id = f.repo_id WHERE r.id IS NULL`); err != nil {
		t.Fatalf("counting orphans: %v", err)
	}
	if orphanCount != 0 {
		t.Fatalf("expected 0 orphaned findings, got %d", orphanCount)
	}

	var totalFindings, joinedFindings int
	if err := db.SqlxDB().Get(&totalFindings, "SELECT COUNT(*) FROM findings"); err != nil {
		t.Fatalf("counting findings: %v", err)
	}
	if err := db.SqlxDB().Get(&joinedFindings,
		"SELECT COUNT(*) FROM findings f JOIN repos r ON r.id = f.repo_id"); err != nil {
		t.Fatalf("counting joined findings: %v", err)
	}
	if totalFindings != joinedFindings {
		t.Fatalf("JOIN drops rescanned findings: total=%d joined=%d", totalFindings, joinedFindings)
	}
	// Rescan replaced (not accumulated) — first scan had 1, rescan had 2.
	if totalFindings != 2 {
		t.Fatalf("expected 2 findings after rescan (replace, not accumulate), got %d", totalFindings)
	}
}

// workflow_hash must be persisted with each finding so template-propagation
// queries (`fluxgate templates`) can group identical workflows across repos.
func TestSaveResult_WorkflowHashPersisted(t *testing.T) {
	db := newTestDB(t)
	shared := "deadbeefcafef00d"
	for _, owner := range []string{"orgA", "orgB", "orgC"} {
		if err := db.SaveResult(owner, "repo", 0, "", &scanner.ScanResult{
			Workflows: 1,
			Findings: []scanner.Finding{
				{File: ".github/workflows/ci.yaml", RuleID: "FG-022",
					Severity: "critical", Line: 1, Message: "m", Details: "d",
					WorkflowHash: shared},
			},
		}); err != nil {
			t.Fatalf("save %s: %v", owner, err)
		}
	}
	var clusters int
	err := db.SqlxDB().Get(&clusters, `
		SELECT COUNT(*) FROM (
			SELECT workflow_hash, COUNT(DISTINCT repo_id) c
			FROM findings WHERE workflow_hash != ''
			GROUP BY workflow_hash HAVING c >= 2
		)`)
	if err != nil {
		t.Fatalf("cluster query: %v", err)
	}
	if clusters != 1 {
		t.Fatalf("expected 1 template cluster spanning 3 repos, got %d", clusters)
	}

	var repoCount int
	if err := db.SqlxDB().Get(&repoCount,
		`SELECT COUNT(DISTINCT repo_id) FROM findings WHERE workflow_hash = ?`, shared); err != nil {
		t.Fatalf("repo-count query: %v", err)
	}
	if repoCount != 3 {
		t.Fatalf("expected hash to span 3 repos, got %d", repoCount)
	}
}

// Fresh insert without rescan should also produce a canonical repo_id.
func TestSaveResult_FreshInsertRepoIDIsCanonical(t *testing.T) {
	db := newTestDB(t)
	if err := db.SaveResult("ansible", "galaxy_collection", 0, "Python",
		&scanner.ScanResult{
			Workflows: 1,
			Findings: []scanner.Finding{
				{File: ".github/workflows/x.yaml", RuleID: "FG-022", Severity: "critical",
					Line: 1, Message: "m", Details: "d"},
			},
		}); err != nil {
		t.Fatalf("save: %v", err)
	}
	var orphanCount int
	if err := db.SqlxDB().Get(&orphanCount,
		`SELECT COUNT(*) FROM findings f LEFT JOIN repos r ON r.id = f.repo_id WHERE r.id IS NULL`); err != nil {
		t.Fatalf("counting orphans: %v", err)
	}
	if orphanCount != 0 {
		t.Fatalf("expected 0 orphaned findings, got %d", orphanCount)
	}
}
