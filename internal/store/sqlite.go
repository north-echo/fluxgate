package store

import (
	"database/sql"
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
	Source         string `db:"source"`
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

	// Run incremental migrations (idempotent)
	runMigrations(db)

	return &DB{db: db}, nil
}

// runMigrations applies incremental schema changes. Each is idempotent.
func runMigrations(db *sqlx.DB) {
	db.Exec(migration001AddSource)
	db.Exec(migration002Disclosures)
	db.Exec(migration003Patches)
	db.Exec(migration004NoWorkflows)
}

// Close closes the database connection.
func (d *DB) Close() error {
	return d.db.Close()
}

// SqlxDB returns the underlying *sqlx.DB for direct query access.
func (d *DB) SqlxDB() *sqlx.DB {
	return d.db
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

// --- Disclosure lifecycle tracking ---

// Disclosure represents a vulnerability disclosure filing.
type Disclosure struct {
	ID           int64          `db:"id"`
	FindingID    int64          `db:"finding_id"`
	Channel      string         `db:"channel"`
	DisclosureID sql.NullString `db:"disclosure_id"`
	Status       string         `db:"status"`
	FiledAt      sql.NullString `db:"filed_at"`
	ResponseAt   sql.NullString `db:"response_at"`
	PatchedAt    sql.NullString `db:"patched_at"`
	Notes        sql.NullString `db:"notes"`
	CreatedAt    sql.NullString `db:"created_at"`
	UpdatedAt    sql.NullString `db:"updated_at"`
}

// DisclosureWithContext joins a disclosure with its finding and repo info.
type DisclosureWithContext struct {
	Disclosure
	Owner        string `db:"owner"`
	RepoName     string `db:"repo_name"`
	RuleID       string `db:"rule_id"`
	Severity     string `db:"severity"`
	WorkflowPath string `db:"workflow_path"`
	Description  string `db:"description"`
}

// Patch represents a confirmed fix for a disclosed vulnerability.
type Patch struct {
	ID           int64  `db:"id"`
	DisclosureID int64  `db:"disclosure_id"`
	CommitURL    string `db:"commit_url"`
	ReleaseTag   string `db:"release_tag"`
	VerifiedAt   string `db:"verified_at"`
	CreatedAt    string `db:"created_at"`
}

// DisclosureStats holds aggregate disclosure statistics.
type DisclosureStats struct {
	Total        int
	Filed        int
	Acknowledged int
	Patched      int
	WontFix      int
	Timeout      int
}

// AddDisclosure creates a new disclosure record linked to a finding.
func (d *DB) AddDisclosure(findingID int64, channel, disclosureID string) (*Disclosure, error) {
	res, err := d.db.Exec(
		`INSERT INTO disclosures (finding_id, channel, disclosure_id, status, filed_at)
		 VALUES (?, ?, ?, 'filed', CURRENT_TIMESTAMP)`,
		findingID, channel, disclosureID,
	)
	if err != nil {
		return nil, fmt.Errorf("adding disclosure: %w", err)
	}
	id, _ := res.LastInsertId()
	var disc Disclosure
	err = d.db.Get(&disc, "SELECT * FROM disclosures WHERE id = ?", id)
	return &disc, err
}

// UpdateDisclosureStatus updates the status of a disclosure.
func (d *DB) UpdateDisclosureStatus(id int64, status string) error {
	extra := ""
	switch status {
	case "acknowledged":
		extra = ", response_at = COALESCE(response_at, CURRENT_TIMESTAMP)"
	case "patched":
		extra = ", patched_at = COALESCE(patched_at, CURRENT_TIMESTAMP), response_at = COALESCE(response_at, CURRENT_TIMESTAMP)"
	}
	_, err := d.db.Exec(
		fmt.Sprintf("UPDATE disclosures SET status = ?, updated_at = CURRENT_TIMESTAMP%s WHERE id = ?", extra),
		status, id,
	)
	return err
}

// ListDisclosures returns disclosures with full context, optionally filtered.
func (d *DB) ListDisclosures(status string, findingID int64) ([]DisclosureWithContext, error) {
	query := `
		SELECT d.*, r.owner, r.name AS repo_name, f.rule_id, f.severity, f.workflow_path, f.description
		FROM disclosures d
		JOIN findings f ON f.id = d.finding_id
		JOIN repos r ON r.id = f.repo_id
		WHERE 1=1`
	args := []interface{}{}

	if status != "" {
		query += " AND d.status = ?"
		args = append(args, status)
	}
	if findingID > 0 {
		query += " AND d.finding_id = ?"
		args = append(args, findingID)
	}
	query += " ORDER BY d.updated_at DESC"

	var results []DisclosureWithContext
	err := d.db.Select(&results, query, args...)
	return results, err
}

// GetDisclosure returns a single disclosure with context.
func (d *DB) GetDisclosure(id int64) (*DisclosureWithContext, error) {
	var disc DisclosureWithContext
	err := d.db.Get(&disc, `
		SELECT d.*, r.owner, r.name AS repo_name, f.rule_id, f.severity, f.workflow_path, f.description
		FROM disclosures d
		JOIN findings f ON f.id = d.finding_id
		JOIN repos r ON r.id = f.repo_id
		WHERE d.id = ?`, id)
	if err != nil {
		return nil, err
	}
	return &disc, nil
}

// AddPatch records a confirmed fix for a disclosure.
func (d *DB) AddPatch(disclosureID int64, commitURL, releaseTag string) (*Patch, error) {
	res, err := d.db.Exec(
		`INSERT INTO patches (disclosure_id, commit_url, release_tag)
		 VALUES (?, ?, ?)`,
		disclosureID, commitURL, releaseTag,
	)
	if err != nil {
		return nil, fmt.Errorf("adding patch: %w", err)
	}
	id, _ := res.LastInsertId()
	var p Patch
	err = d.db.Get(&p, "SELECT * FROM patches WHERE id = ?", id)
	return &p, err
}

// GetDisclosureStats returns aggregate counts by status.
func (d *DB) GetDisclosureStats() (*DisclosureStats, error) {
	stats := &DisclosureStats{}
	rows, err := d.db.Query("SELECT status, COUNT(*) FROM disclosures GROUP BY status")
	if err != nil {
		return stats, err
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return stats, err
		}
		stats.Total += count
		switch status {
		case "filed":
			stats.Filed = count
		case "acknowledged":
			stats.Acknowledged = count
		case "patched":
			stats.Patched = count
		case "wontfix":
			stats.WontFix = count
		case "timeout":
			stats.Timeout = count
		}
	}
	return stats, nil
}

// --- Dashboard query methods ---

// FindingWithRepo joins a finding with its repo context.
type FindingWithRepo struct {
	FindingRecord
	Owner    string `db:"owner"`
	RepoName string `db:"repo_name"`
	Stars    int    `db:"stars"`
}

// OrgSeverityCount holds severity counts per org for heatmap display.
type OrgSeverityCount struct {
	Owner    string `db:"owner"`
	Severity string `db:"severity"`
	Count    int    `db:"count"`
}

// RepoDetail holds a repo with all its findings.
type RepoDetail struct {
	Repo     Repo
	Findings []FindingRecord
}

// ListFindings returns paginated findings with repo context.
func (d *DB) ListFindings(offset, limit int, severity, ruleID, owner string) ([]FindingWithRepo, int, error) {
	where := "WHERE 1=1"
	args := []interface{}{}

	if severity != "" {
		where += " AND f.severity = ?"
		args = append(args, severity)
	}
	if ruleID != "" {
		where += " AND f.rule_id = ?"
		args = append(args, ruleID)
	}
	if owner != "" {
		where += " AND r.owner = ?"
		args = append(args, owner)
	}

	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM findings f JOIN repos r ON r.id = f.repo_id %s", where)
	if err := d.db.Get(&total, countQuery, args...); err != nil {
		return nil, 0, err
	}

	query := fmt.Sprintf(`
		SELECT f.*, r.owner, r.name AS repo_name, r.stars
		FROM findings f
		JOIN repos r ON r.id = f.repo_id
		%s
		ORDER BY CASE f.severity
			WHEN 'critical' THEN 0 WHEN 'high' THEN 1
			WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
			r.stars DESC
		LIMIT ? OFFSET ?`, where)
	args = append(args, limit, offset)

	var results []FindingWithRepo
	err := d.db.Select(&results, query, args...)
	return results, total, err
}

// GetSeverityByOrg returns finding counts grouped by org and severity.
func (d *DB) GetSeverityByOrg() ([]OrgSeverityCount, error) {
	var results []OrgSeverityCount
	err := d.db.Select(&results, `
		SELECT r.owner, f.severity, COUNT(*) AS count
		FROM findings f
		JOIN repos r ON r.id = f.repo_id
		GROUP BY r.owner, f.severity
		ORDER BY r.owner, f.severity`)
	return results, err
}

// GetRepoDetail returns a repo and all its findings.
func (d *DB) GetRepoDetail(owner, name string) (*RepoDetail, error) {
	var repo Repo
	err := d.db.Get(&repo, "SELECT * FROM repos WHERE owner = ? AND name = ?", owner, name)
	if err != nil {
		return nil, err
	}
	var findings []FindingRecord
	err = d.db.Select(&findings, `
		SELECT * FROM findings WHERE repo_id = ?
		ORDER BY CASE severity
			WHEN 'critical' THEN 0 WHEN 'high' THEN 1
			WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`,
		repo.ID)
	if err != nil {
		return nil, err
	}
	return &RepoDetail{Repo: repo, Findings: findings}, nil
}

// --- No-workflow cache ---

// HasNoWorkflows checks if a repo is cached as having no workflows.
// Returns true if cached and the cache entry is less than maxAge old.
func (d *DB) HasNoWorkflows(owner, name string, maxAgeDays int) bool {
	var count int
	err := d.db.Get(&count,
		`SELECT COUNT(*) FROM no_workflows
		 WHERE owner = ? AND name = ?
		 AND checked_at > datetime('now', ?)`,
		owner, name, fmt.Sprintf("-%d days", maxAgeDays))
	return err == nil && count > 0
}

// MarkNoWorkflows caches a repo as having no .github/workflows/ directory.
func (d *DB) MarkNoWorkflows(owner, name string) {
	d.db.Exec(
		`INSERT OR REPLACE INTO no_workflows (owner, name, checked_at)
		 VALUES (?, ?, CURRENT_TIMESTAMP)`,
		owner, name)
}

// NoWorkflowsCacheStats returns the number of cached no-workflow repos.
func (d *DB) NoWorkflowsCacheStats() (total int, expired int) {
	d.db.Get(&total, "SELECT COUNT(*) FROM no_workflows")
	d.db.Get(&expired, "SELECT COUNT(*) FROM no_workflows WHERE checked_at < datetime('now', '-7 days')")
	return
}

// ClearExpiredNoWorkflows deletes cache entries older than maxAgeDays and returns count deleted.
func (d *DB) ClearExpiredNoWorkflows(maxAgeDays int) (int, error) {
	res, err := d.db.Exec(
		"DELETE FROM no_workflows WHERE checked_at < datetime('now', ?)",
		fmt.Sprintf("-%d days", maxAgeDays))
	if err != nil {
		return 0, err
	}
	count, _ := res.RowsAffected()
	return int(count), nil
}

// GetTopRepos returns the top repos ordered by findings_count descending.
func (d *DB) GetTopRepos(limit int) ([]Repo, error) {
	var repos []Repo
	err := d.db.Select(&repos, `
		SELECT * FROM repos
		WHERE findings_count > 0
		ORDER BY findings_count DESC
		LIMIT ?`, limit)
	return repos, err
}

// GetFindingsForRepo returns all findings for a given owner/name.
func (d *DB) GetFindingsForRepo(owner, name string) ([]FindingRecord, error) {
	var findings []FindingRecord
	err := d.db.Select(&findings, `
		SELECT f.* FROM findings f
		JOIN repos r ON r.id = f.repo_id
		WHERE r.owner = ? AND r.name = ?
		ORDER BY CASE f.severity
			WHEN 'critical' THEN 0 WHEN 'high' THEN 1
			WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`,
		owner, name)
	return findings, err
}
