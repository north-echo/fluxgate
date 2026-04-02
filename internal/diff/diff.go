package diff

import (
	"crypto/sha256"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/north-echo/fluxgate/internal/store"
)

// DiffFinding represents a single finding for comparison purposes.
type DiffFinding struct {
	Owner        string
	RepoName     string
	WorkflowPath string
	RuleID       string
	Severity     string
	LineNumber   int
	Description  string
}

// DiffSummary holds aggregate counts of the diff operation.
type DiffSummary struct {
	New       int
	Resolved  int
	Regressed int
	Unchanged int
}

// DiffResult holds the full output of a diff comparison.
type DiffResult struct {
	DiffSummary
	NewFindings      []DiffFinding
	ResolvedFindings []DiffFinding
	Regressions      []DiffFinding
	OldDB            string
	NewDB            string
	OldCount         int
	NewCount         int
}

// findingRow maps the joined query result.
type findingRow struct {
	Owner        string `db:"owner"`
	RepoName     string `db:"repo_name"`
	WorkflowPath string `db:"workflow_path"`
	RuleID       string `db:"rule_id"`
	Severity     string `db:"severity"`
	LineNumber   int    `db:"line_number"`
	Description  string `db:"description"`
}

// fingerprint generates a stable identity hash for a finding based on its
// location (owner, repo, workflow, rule). Line number is excluded so that
// fuzzy line matching can be applied separately.
func fingerprint(f findingRow) string {
	h := sha256.Sum256([]byte(f.Owner + "|" + f.RepoName + "|" + f.WorkflowPath + "|" + f.RuleID))
	return fmt.Sprintf("%x", h[:16])
}

// severityRank returns a numeric rank for severity comparison.
// Lower numbers are more severe.
func severityRank(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

const findingsQuery = `
	SELECT r.owner, r.name AS repo_name, f.workflow_path, f.rule_id,
	       f.severity, f.line_number, f.description
	FROM findings f
	JOIN repos r ON r.id = f.repo_id
	ORDER BY r.owner, r.name, f.workflow_path, f.rule_id
`

// queryFindings loads all findings from a store database.
func queryFindings(db *store.DB) ([]findingRow, error) {
	var rows []findingRow
	err := db.SqlxDB().Select(&rows, findingsQuery)
	return rows, err
}

// Compare opens two scan databases and categorizes findings as new, resolved,
// regressed, or unchanged using fingerprint matching and fuzzy line comparison.
func Compare(oldDBPath, newDBPath string) (*DiffResult, error) {
	oldDB, err := store.Open(oldDBPath)
	if err != nil {
		return nil, fmt.Errorf("opening old database %s: %w", oldDBPath, err)
	}
	defer oldDB.Close()

	newDB, err := store.Open(newDBPath)
	if err != nil {
		return nil, fmt.Errorf("opening new database %s: %w", newDBPath, err)
	}
	defer newDB.Close()

	oldRows, err := queryFindings(oldDB)
	if err != nil {
		return nil, fmt.Errorf("querying old findings: %w", err)
	}

	newRows, err := queryFindings(newDB)
	if err != nil {
		return nil, fmt.Errorf("querying new findings: %w", err)
	}

	// Build maps keyed by fingerprint. Multiple findings can share a
	// fingerprint if the same rule fires on different lines in the same file.
	type entry struct {
		row     findingRow
		matched bool
	}
	oldMap := make(map[string][]*entry)
	for _, r := range oldRows {
		fp := fingerprint(r)
		oldMap[fp] = append(oldMap[fp], &entry{row: r})
	}

	result := &DiffResult{
		OldDB:    oldDBPath,
		NewDB:    newDBPath,
		OldCount: len(oldRows),
		NewCount: len(newRows),
	}

	// Process new findings against the old set.
	for _, nr := range newRows {
		fp := fingerprint(nr)
		entries, exists := oldMap[fp]
		if !exists {
			// No match at all — this is a new finding.
			result.NewFindings = append(result.NewFindings, toDiffFinding(nr))
			result.New++
			continue
		}

		// Look for a fuzzy line match (within 5 lines).
		matched := false
		for _, e := range entries {
			if e.matched {
				continue
			}
			if abs(e.row.LineNumber-nr.LineNumber) <= 5 {
				e.matched = true
				matched = true

				// Check for regression (severity increased).
				if severityRank(nr.Severity) < severityRank(e.row.Severity) {
					result.Regressions = append(result.Regressions, toDiffFinding(nr))
					result.Regressed++
				} else {
					result.Unchanged++
				}
				break
			}
		}

		if !matched {
			// Same fingerprint but line moved beyond threshold — treat as new.
			result.NewFindings = append(result.NewFindings, toDiffFinding(nr))
			result.New++
		}
	}

	// Any unmatched old entries are resolved findings.
	for _, entries := range oldMap {
		for _, e := range entries {
			if !e.matched {
				result.ResolvedFindings = append(result.ResolvedFindings, toDiffFinding(e.row))
				result.Resolved++
			}
		}
	}

	// Sort resolved findings for deterministic output.
	sort.Slice(result.ResolvedFindings, func(i, j int) bool {
		a, b := result.ResolvedFindings[i], result.ResolvedFindings[j]
		if a.Owner != b.Owner {
			return a.Owner < b.Owner
		}
		if a.RepoName != b.RepoName {
			return a.RepoName < b.RepoName
		}
		return a.RuleID < b.RuleID
	})

	return result, nil
}

// WriteReport writes a human-readable diff report to the given writer.
func WriteReport(w io.Writer, result *DiffResult) {
	fmt.Fprintf(w, "Diff Report: %s → %s\n", result.OldDB, result.NewDB)
	fmt.Fprintf(w, "Old findings: %d | New findings: %d\n\n", result.OldCount, result.NewCount)

	// Summary table
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "Category\tCount")
	fmt.Fprintln(tw, "--------\t-----")
	fmt.Fprintf(tw, "New\t%d\n", result.New)
	fmt.Fprintf(tw, "Resolved\t%d\n", result.Resolved)
	fmt.Fprintf(tw, "Regressed\t%d\n", result.Regressed)
	fmt.Fprintf(tw, "Unchanged\t%d\n", result.Unchanged)
	tw.Flush()

	if len(result.NewFindings) > 0 {
		fmt.Fprintf(w, "\n--- New Findings (%d) ---\n", len(result.NewFindings))
		writeFindingTable(w, result.NewFindings)
	}

	if len(result.Regressions) > 0 {
		fmt.Fprintf(w, "\n--- Regressions (%d) ---\n", len(result.Regressions))
		writeFindingTable(w, result.Regressions)
	}

	if len(result.ResolvedFindings) > 0 {
		fmt.Fprintf(w, "\n--- Resolved Findings (%d) ---\n", len(result.ResolvedFindings))
		writeFindingTable(w, result.ResolvedFindings)
	}
}

// writeFindingTable writes a tabwriter-formatted table of findings.
func writeFindingTable(w io.Writer, findings []DiffFinding) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "Owner\tRepo\tRule\tSeverity\tLine\tWorkflow")
	fmt.Fprintln(tw, "-----\t----\t----\t--------\t----\t--------")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n",
			f.Owner, f.RepoName, f.RuleID, f.Severity, f.LineNumber, f.WorkflowPath)
	}
	tw.Flush()
}

func toDiffFinding(r findingRow) DiffFinding {
	return DiffFinding{
		Owner:        r.Owner,
		RepoName:     r.RepoName,
		WorkflowPath: r.WorkflowPath,
		RuleID:       r.RuleID,
		Severity:     r.Severity,
		LineNumber:   r.LineNumber,
		Description:  r.Description,
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
