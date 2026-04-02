package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"

	"github.com/north-echo/fluxgate/internal/store"
)

// AnonymizedRecord represents a single finding with identifying information
// stripped and numeric fields bucketed to prevent re-identification.
type AnonymizedRecord struct {
	AnonymousID string `json:"anonymous_id" csv:"anonymous_id"`
	RuleID      string `json:"rule_id" csv:"rule_id"`
	Severity    string `json:"severity" csv:"severity"`
	LineRange   string `json:"line_range" csv:"line_range"`
	StarsRange  string `json:"stars_range" csv:"stars_range"`
	Language    string `json:"language" csv:"language"`
	Source      string `json:"source" csv:"source"`
	ScannedDate string `json:"scanned_date" csv:"scanned_date"`
}

// exportRow maps the joined query result used for anonymized export.
type exportRow struct {
	Owner      string `db:"owner"`
	RepoName   string `db:"repo_name"`
	RuleID     string `db:"rule_id"`
	Severity   string `db:"severity"`
	LineNumber int    `db:"line_number"`
	Stars      int    `db:"stars"`
	Language   string `db:"language"`
	Source     string `db:"source"`
	ScannedAt  string `db:"scanned_at"`
}

const exportQuery = `
	SELECT r.owner, r.name AS repo_name, f.rule_id, f.severity,
	       f.line_number, r.stars, r.language,
	       COALESCE(r.source, '') AS source, r.scanned_at
	FROM findings f
	JOIN repos r ON r.id = f.repo_id
	ORDER BY r.owner, r.name, f.rule_id
`

// queryExportRows loads findings joined with repo info from the database.
func queryExportRows(dbPath string) ([]exportRow, error) {
	db, err := store.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	var rows []exportRow
	if err := db.SqlxDB().Select(&rows, exportQuery); err != nil {
		return nil, fmt.Errorf("querying findings: %w", err)
	}
	return rows, nil
}

// buildAnonymizedRecords converts raw rows into anonymized records with
// sequential IDs assigned per unique (owner, name) pair, sorted alphabetically.
func buildAnonymizedRecords(rows []exportRow) []AnonymizedRecord {
	// Assign sequential anonymous IDs per unique repo.
	type repoKey struct {
		Owner string
		Name  string
	}

	// Collect unique repos in sorted order.
	seen := make(map[repoKey]bool)
	var repos []repoKey
	for _, r := range rows {
		k := repoKey{r.Owner, r.RepoName}
		if !seen[k] {
			seen[k] = true
			repos = append(repos, k)
		}
	}
	sort.Slice(repos, func(i, j int) bool {
		if repos[i].Owner != repos[j].Owner {
			return repos[i].Owner < repos[j].Owner
		}
		return repos[i].Name < repos[j].Name
	})

	idMap := make(map[repoKey]string)
	for i, rk := range repos {
		idMap[rk] = fmt.Sprintf("REPO-%04d", i+1)
	}

	records := make([]AnonymizedRecord, 0, len(rows))
	for _, r := range rows {
		k := repoKey{r.Owner, r.RepoName}
		records = append(records, AnonymizedRecord{
			AnonymousID: idMap[k],
			RuleID:      r.RuleID,
			Severity:    r.Severity,
			LineRange:   bucketLines(r.LineNumber),
			StarsRange:  bucketStars(r.Stars),
			Language:    r.Language,
			Source:      r.Source,
			ScannedDate: stripTime(r.ScannedAt),
		})
	}
	return records
}

// ExportAnonymizedCSV writes anonymized findings as CSV to the given writer.
func ExportAnonymizedCSV(dbPath string, w io.Writer) error {
	rows, err := queryExportRows(dbPath)
	if err != nil {
		return err
	}

	records := buildAnonymizedRecords(rows)

	cw := csv.NewWriter(w)
	defer cw.Flush()

	// Write header.
	if err := cw.Write([]string{
		"anonymous_id", "rule_id", "severity", "line_range",
		"stars_range", "language", "source", "scanned_date",
	}); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	for _, r := range records {
		if err := cw.Write([]string{
			r.AnonymousID, r.RuleID, r.Severity, r.LineRange,
			r.StarsRange, r.Language, r.Source, r.ScannedDate,
		}); err != nil {
			return fmt.Errorf("writing CSV row: %w", err)
		}
	}

	return nil
}

// ExportAnonymizedJSON writes anonymized findings as a JSON array to the given writer.
func ExportAnonymizedJSON(dbPath string, w io.Writer) error {
	rows, err := queryExportRows(dbPath)
	if err != nil {
		return err
	}

	records := buildAnonymizedRecords(rows)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(records); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}

	return nil
}

// bucketLines maps a line number to an anonymized range bucket.
func bucketLines(line int) string {
	switch {
	case line <= 0:
		return "unknown"
	case line <= 50:
		return "1-50"
	case line <= 100:
		return "51-100"
	case line <= 200:
		return "101-200"
	default:
		return "201+"
	}
}

// bucketStars maps a star count to an anonymized range bucket.
func bucketStars(stars int) string {
	switch {
	case stars <= 100:
		return "0-100"
	case stars <= 1000:
		return "101-1000"
	case stars <= 10000:
		return "1001-10000"
	default:
		return "10001+"
	}
}

// stripTime extracts just the date portion (YYYY-MM-DD) from a timestamp string.
func stripTime(ts string) string {
	if len(ts) >= 10 {
		// Validate it looks like a date.
		if _, err := strconv.Atoi(ts[:4]); err == nil {
			return ts[:10]
		}
	}
	return ts
}
