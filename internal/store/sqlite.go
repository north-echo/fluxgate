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

	// Enable WAL mode for better concurrent access
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting WAL mode: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return &DB{db: db}, nil
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
	tx, err := d.db.Beginx()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec(
		`INSERT INTO repos (owner, name, stars, language, workflows_count, findings_count)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(owner, name) DO UPDATE SET
		   stars = excluded.stars,
		   language = excluded.language,
		   scanned_at = CURRENT_TIMESTAMP,
		   workflows_count = excluded.workflows_count,
		   findings_count = excluded.findings_count`,
		owner, name, stars, language, result.Workflows, len(result.Findings),
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
