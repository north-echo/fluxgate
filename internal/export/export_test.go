package export

import (
	"bytes"
	"encoding/csv"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/north-echo/fluxgate/internal/scanner"
	"github.com/north-echo/fluxgate/internal/store"
)

// setupExportDB creates a database with known test data and returns its path.
func setupExportDB(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "export.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("opening db: %v", err)
	}
	defer db.Close()

	// Repo 1: high stars, Go.
	if err := db.SaveResult("acme-corp", "web-app", 15000, "Go", &scanner.ScanResult{
		Path: "acme-corp/web-app", Workflows: 1,
		Findings: []scanner.Finding{
			{RuleID: "FG-001", Severity: "critical", File: ".github/workflows/ci.yml", Line: 10, Message: "pwn request"},
			{RuleID: "FG-002", Severity: "high", File: ".github/workflows/ci.yml", Line: 75, Message: "injection"},
		},
	}); err != nil {
		t.Fatalf("saving result: %v", err)
	}

	// Repo 2: low stars, Python.
	if err := db.SaveResult("beta-org", "data-tool", 50, "Python", &scanner.ScanResult{
		Path: "beta-org/data-tool", Workflows: 1,
		Findings: []scanner.Finding{
			{RuleID: "FG-003", Severity: "medium", File: ".github/workflows/build.yml", Line: 150, Message: "oidc misconfig"},
		},
	}); err != nil {
		t.Fatalf("saving result: %v", err)
	}

	return dbPath
}

func TestExportAnonymizedCSV_NoRealNames(t *testing.T) {
	dbPath := setupExportDB(t)

	var buf bytes.Buffer
	if err := ExportAnonymizedCSV(dbPath, &buf); err != nil {
		t.Fatalf("ExportAnonymizedCSV: %v", err)
	}

	output := buf.String()

	// Real owner/repo names must not appear anywhere in the CSV.
	for _, forbidden := range []string{"acme-corp", "web-app", "beta-org", "data-tool"} {
		if strings.Contains(output, forbidden) {
			t.Errorf("CSV output contains real name %q", forbidden)
		}
	}
}

func TestExportAnonymizedCSV_AnonymousIDs(t *testing.T) {
	dbPath := setupExportDB(t)

	var buf bytes.Buffer
	if err := ExportAnonymizedCSV(dbPath, &buf); err != nil {
		t.Fatalf("ExportAnonymizedCSV: %v", err)
	}

	r := csv.NewReader(bytes.NewReader(buf.Bytes()))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("parsing CSV: %v", err)
	}

	// Header + 3 data rows.
	if len(records) != 4 {
		t.Fatalf("expected 4 rows (1 header + 3 data), got %d", len(records))
	}

	// Verify header.
	expectedHeader := []string{"anonymous_id", "rule_id", "severity", "line_range", "stars_range", "language", "source", "scanned_date"}
	for i, h := range expectedHeader {
		if records[0][i] != h {
			t.Errorf("header[%d]: expected %q, got %q", i, h, records[0][i])
		}
	}

	// All anonymous_id values should match REPO-XXXX pattern.
	ids := make(map[string]bool)
	for _, row := range records[1:] {
		id := row[0]
		if !strings.HasPrefix(id, "REPO-") {
			t.Errorf("anonymous_id %q does not start with REPO-", id)
		}
		ids[id] = true
	}

	// Two distinct repos should produce two distinct IDs.
	if len(ids) != 2 {
		t.Errorf("expected 2 distinct anonymous IDs, got %d", len(ids))
	}
}

func TestExportAnonymizedCSV_StarsBucketed(t *testing.T) {
	dbPath := setupExportDB(t)

	var buf bytes.Buffer
	if err := ExportAnonymizedCSV(dbPath, &buf); err != nil {
		t.Fatalf("ExportAnonymizedCSV: %v", err)
	}

	r := csv.NewReader(bytes.NewReader(buf.Bytes()))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("parsing CSV: %v", err)
	}

	// stars_range is column index 4.
	starsIdx := 4
	starsBuckets := make(map[string]bool)
	for _, row := range records[1:] {
		starsBuckets[row[starsIdx]] = true
	}

	// 15000 stars -> "10001+", 50 stars -> "0-100".
	if !starsBuckets["10001+"] {
		t.Error("expected stars bucket 10001+ for 15000-star repo")
	}
	if !starsBuckets["0-100"] {
		t.Error("expected stars bucket 0-100 for 50-star repo")
	}
}

func TestExportAnonymizedCSV_LinesBucketed(t *testing.T) {
	dbPath := setupExportDB(t)

	var buf bytes.Buffer
	if err := ExportAnonymizedCSV(dbPath, &buf); err != nil {
		t.Fatalf("ExportAnonymizedCSV: %v", err)
	}

	r := csv.NewReader(bytes.NewReader(buf.Bytes()))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("parsing CSV: %v", err)
	}

	// line_range is column index 3.
	lineIdx := 3
	lineBuckets := make(map[string]bool)
	for _, row := range records[1:] {
		lineBuckets[row[lineIdx]] = true
	}

	// Line 10 -> "1-50", Line 75 -> "51-100", Line 150 -> "101-200".
	for _, expected := range []string{"1-50", "51-100", "101-200"} {
		if !lineBuckets[expected] {
			t.Errorf("expected line bucket %q in output", expected)
		}
	}
}

func TestExportAnonymizedCSV_EmptyDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "empty.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("opening db: %v", err)
	}
	db.Close()

	var buf bytes.Buffer
	if err := ExportAnonymizedCSV(dbPath, &buf); err != nil {
		t.Fatalf("ExportAnonymizedCSV: %v", err)
	}

	r := csv.NewReader(bytes.NewReader(buf.Bytes()))
	records, err := r.ReadAll()
	if err != nil && err != io.EOF {
		t.Fatalf("parsing CSV: %v", err)
	}

	// Should have only the header row.
	if len(records) != 1 {
		t.Errorf("expected 1 row (header only) for empty DB, got %d", len(records))
	}
}
