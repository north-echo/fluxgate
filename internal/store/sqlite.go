package store

import (
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"

	"github.com/north-echo/fluxgate/internal/scanner"
)

// DB wraps the SQLite database for batch scan results.
type DB struct {
	db *sqlx.DB
}

// Repo represents a scanned repository record.
type Repo struct {
	ID             int64  `db:"id"`
	Owner          string `db:"owner"`
	Name           string `db:"name"`
	Stars          int    `db:"stars"`
	Language       string `db:"language"`
	ScannedAt      string `db:"scanned_at"`
	WorkflowsCount int    `db:"workflows_count"`
	FindingsCount  int    `db:"findings_count"`
}

// FindingRecord represents a stored finding.
type FindingRecord struct {
	ID           int64  `db:"id"`
	RepoID       int64  `db:"repo_id"`
	WorkflowPath string `db:"workflow_path"`
	RuleID       string `db:"rule_id"`
	Severity     string `db:"severity"`
	LineNumber   int    `db:"line_number"`
	Description  string `db:"description"`
	Details      string `db:"details"`
	CreatedAt    string `db:"created_at"`
}

// Open opens or creates the SQLite database and runs migrations.
func Open(path string) (*DB, error) {
	db, err := sqlx.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Serialize all access through a single connection to prevent SQLITE_BUSY
	// under concurrent goroutine writes. WAL mode still helps with read perf.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting WAL mode: %w", err)
	}

	if _, err := db.Exec("PRAGMA busy_timeout=30000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting busy timeout: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	// Run incremental migrations (idempotent)
	runMigrations(db)

	return &DB{db: db}, nil
}

// runMigrations applies incremental schema changes. Each is idempotent.
func runMigrations(db *sqlx.DB) {
	db.Exec(migration001AddSource)
	db.Exec(migration002AddRepoLists)
}

// RepoListEntry holds a cached repo from a saved list.
type RepoListEntry struct {
	Owner    string `db:"owner"`
	Name     string `db:"name"`
	Stars    int    `db:"stars"`
	Language string `db:"language"`
}

// SaveRepoList caches a fetched repo list under a query key (e.g. "top:5000").
func (d *DB) SaveRepoList(query string, repos []RepoListEntry) error {
	tx, err := d.db.Beginx()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM repo_list_entries WHERE list_id IN (SELECT id FROM repo_lists WHERE query = ?)", query); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM repo_lists WHERE query = ?", query); err != nil {
		return err
	}

	res, err := tx.Exec("INSERT INTO repo_lists (query) VALUES (?)", query)
	if err != nil {
		return err
	}
	listID, _ := res.LastInsertId()

	for i, r := range repos {
		_, err := tx.Exec(
			"INSERT INTO repo_list_entries (list_id, owner, name, stars, language, position) VALUES (?, ?, ?, ?, ?, ?)",
			listID, r.Owner, r.Name, r.Stars, r.Language, i,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// LoadRepoList loads a cached repo list by query key. Returns nil if not found.
func (d *DB) LoadRepoList(query string) ([]RepoListEntry, error) {
	var entries []RepoListEntry
	err := d.db.Select(&entries, `
		SELECT e.owner, e.name, e.stars, e.language
		FROM repo_list_entries e
		JOIN repo_lists l ON l.id = e.list_id
		WHERE l.query = ?
		ORDER BY e.position
	`, query)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	return entries, nil
}

// Close closes the database connection.
func (d *DB) Close() error {
	return d.db.Close()
}

// IsRepoScanned checks if a repo has already been scanned (for --resume).
func (d *DB) IsRepoScanned(owner, name string) (bool, error) {
	var count int
	err := d.db.Get(&count, "SELECT COUNT(*) FROM repos WHERE owner = ? AND name = ?", owner, name)
	return count > 0, err
}

// SaveResult stores a scan result for a repository.
func (d *DB) SaveResult(owner, name string, stars int, language string, result *scanner.ScanResult) error {
	return d.SaveResultWithSource(owner, name, stars, language, result, "")
}

// SaveResultWithSource stores a scan result with a source tag (e.g. "code-search", "redhat-org").
func (d *DB) SaveResultWithSource(owner, name string, stars int, language string, result *scanner.ScanResult, source string) error {
	tx, err := d.db.Beginx()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec(
		`INSERT INTO repos (owner, name, stars, language, workflows_count, findings_count, source)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(owner, name) DO UPDATE SET
		   stars = excluded.stars,
		   language = excluded.language,
		   scanned_at = CURRENT_TIMESTAMP,
		   workflows_count = excluded.workflows_count,
		   findings_count = excluded.findings_count,
		   source = COALESCE(NULLIF(excluded.source, ''), repos.source)`,
		owner, name, stars, language, result.Workflows, len(result.Findings), source,
	)
	if err != nil {
		return fmt.Errorf("inserting repo: %w", err)
	}

	repoID, err := res.LastInsertId()
	if err != nil {
		return err
	}
	// If it was an update (conflict), get the existing ID
	if repoID == 0 {
		err = tx.Get(&repoID, "SELECT id FROM repos WHERE owner = ? AND name = ?", owner, name)
		if err != nil {
			return err
		}
		// Clear old findings on rescan
		if _, err := tx.Exec("DELETE FROM findings WHERE repo_id = ?", repoID); err != nil {
			return err
		}
	}

	for _, f := range result.Findings {
		_, err := tx.Exec(
			`INSERT INTO findings (repo_id, workflow_path, rule_id, severity, line_number, description, details)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			repoID, f.File, f.RuleID, f.Severity, f.Line, f.Message, f.Details,
		)
		if err != nil {
			return fmt.Errorf("inserting finding: %w", err)
		}
	}

	return tx.Commit()
}

// ReportStats holds aggregate statistics for reporting.
type ReportStats struct {
	ReposScanned    int
	ReposWithFinds  int
	TotalFindings   int
	BySeverity      map[string]int
	ByRule          map[string]int
}

// GetReportStats returns aggregate statistics from the database.
func (d *DB) GetReportStats() (*ReportStats, error) {
	stats := &ReportStats{
		BySeverity: make(map[string]int),
		ByRule:     make(map[string]int),
	}

	if err := d.db.Get(&stats.ReposScanned, "SELECT COUNT(*) FROM repos"); err != nil {
		return nil, err
	}
	if err := d.db.Get(&stats.ReposWithFinds, "SELECT COUNT(*) FROM repos WHERE findings_count > 0"); err != nil {
		return nil, err
	}
	if err := d.db.Get(&stats.TotalFindings, "SELECT COUNT(*) FROM findings"); err != nil {
		return nil, err
	}

	// By severity
	rows, err := d.db.Query("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, err
		}
		stats.BySeverity[sev] = count
	}

	// By rule
	rows2, err := d.db.Query("SELECT rule_id, COUNT(*) FROM findings GROUP BY rule_id")
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var rule string
		var count int
		if err := rows2.Scan(&rule, &count); err != nil {
			return nil, err
		}
		stats.ByRule[rule] = count
	}

	return stats, nil
}

// GetCriticalFindings returns all critical findings with repo info.
type CriticalFinding struct {
	Owner        string `db:"owner"`
	Name         string `db:"name"`
	Stars        int    `db:"stars"`
	WorkflowPath string `db:"workflow_path"`
	Description  string `db:"description"`
}

// GetCriticalFindings returns all FG-001 findings with repo context.
func (d *DB) GetCriticalFindings() ([]CriticalFinding, error) {
	var findings []CriticalFinding
	err := d.db.Select(&findings, `
		SELECT r.owner, r.name, r.stars, f.workflow_path, f.description
		FROM findings f
		JOIN repos r ON r.id = f.repo_id
		WHERE f.rule_id = 'FG-001'
		ORDER BY r.stars DESC
	`)
	return findings, err
}
