package merge

import (
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"

	"github.com/north-echo/fluxgate/internal/store"
)

// MergeStats tracks counts from a merge operation.
type MergeStats struct {
	SourcesProcessed int
	ReposMerged      int
	ReposSkipped     int
	FindingsMerged   int
	FindingsSkipped  int
}

// sourceRepo mirrors the repos table for reading from source databases.
type sourceRepo struct {
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

// sourceFinding mirrors the findings table for reading from source databases.
type sourceFinding struct {
	ID           int64  `db:"id"`
	RepoID       int64  `db:"repo_id"`
	WorkflowPath string `db:"workflow_path"`
	RuleID       string `db:"rule_id"`
	Severity     string `db:"severity"`
	LineNumber   int    `db:"line_number"`
	Description  string `db:"description"`
	Details      string `db:"details"`
	CreatedAt    string `db:"created_at"`
	WorkflowHash string `db:"workflow_hash"`
}

// sourceDisclosure mirrors the disclosures table.
type sourceDisclosure struct {
	ID           int64  `db:"id"`
	FindingID    int64  `db:"finding_id"`
	Channel      string `db:"channel"`
	DisclosureID string `db:"disclosure_id"`
	Status       string `db:"status"`
	FiledAt      string `db:"filed_at"`
	ResponseAt   string `db:"response_at"`
	PatchedAt    string `db:"patched_at"`
	Notes        string `db:"notes"`
	CreatedAt    string `db:"created_at"`
	UpdatedAt    string `db:"updated_at"`
}

// sourcePatch mirrors the patches table.
type sourcePatch struct {
	ID           int64  `db:"id"`
	DisclosureID int64  `db:"disclosure_id"`
	CommitURL    string `db:"commit_url"`
	ReleaseTag   string `db:"release_tag"`
	VerifiedAt   string `db:"verified_at"`
	CreatedAt    string `db:"created_at"`
}

// MergeDBs combines multiple source scan databases into a single target.
// The target is created if it does not exist. Source databases are opened
// read-only. Duplicate repos are skipped (by owner+name), but scanned_at
// is updated if the source has a more recent timestamp.
func MergeDBs(targetPath string, sourcePaths []string) (*MergeStats, error) {
	target, err := store.Open(targetPath)
	if err != nil {
		return nil, fmt.Errorf("opening target database: %w", err)
	}
	defer target.Close()

	stats := &MergeStats{}
	tdb := target.SqlxDB()

	for _, srcPath := range sourcePaths {
		src, err := sqlx.Open("sqlite", srcPath+"?mode=ro")
		if err != nil {
			return stats, fmt.Errorf("opening source %s: %w", srcPath, err)
		}

		// One transaction per source: without it every insert autocommits
		// (one fsync per row), which dominates merge time on large scans.
		tx, err := tdb.Beginx()
		if err != nil {
			src.Close()
			return stats, fmt.Errorf("beginning transaction: %w", err)
		}

		if err := mergeSource(tx, src, stats); err != nil {
			tx.Rollback()
			src.Close()
			return stats, fmt.Errorf("merging %s: %w", srcPath, err)
		}

		if err := tx.Commit(); err != nil {
			src.Close()
			return stats, fmt.Errorf("committing %s: %w", srcPath, err)
		}

		src.Close()
		stats.SourcesProcessed++
	}

	return stats, nil
}

// findingKey identifies a finding for cross-database deduplication.
type findingKey struct {
	RepoID       int64
	WorkflowPath string
	RuleID       string
	LineNumber   int
}

// mergeSource processes a single source database into the target.
func mergeSource(target *sqlx.Tx, source *sqlx.DB, stats *MergeStats) error {
	// Load repos from source.
	var repos []sourceRepo
	if err := source.Select(&repos, "SELECT * FROM repos"); err != nil {
		return fmt.Errorf("querying source repos: %w", err)
	}

	// Preload the target's existing repos so we can tell inserts from updates
	// without a per-repo SELECT. LastInsertId cannot distinguish the two:
	// modernc.org/sqlite returns a non-zero rowid even when the UPSERT took
	// the DO UPDATE path (same failure mode as fluxgate issue #16).
	type repoKey struct{ Owner, Name string }
	existingRepos := make(map[repoKey]int64)
	var targetRepos []struct {
		ID    int64  `db:"id"`
		Owner string `db:"owner"`
		Name  string `db:"name"`
	}
	if err := target.Select(&targetRepos, "SELECT id, owner, name FROM repos"); err != nil {
		return fmt.Errorf("querying target repos: %w", err)
	}
	for _, r := range targetRepos {
		existingRepos[repoKey{r.Owner, r.Name}] = r.ID
	}

	// Map old repo IDs to new repo IDs in target.
	repoIDMap := make(map[int64]int64)

	for _, repo := range repos {
		// Try to insert, ignoring conflicts on (owner, name).
		res, err := target.Exec(
			`INSERT INTO repos (owner, name, stars, language, scanned_at, workflows_count, findings_count, source)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(owner, name) DO UPDATE SET
			   scanned_at = CASE
			     WHEN excluded.scanned_at > repos.scanned_at THEN excluded.scanned_at
			     ELSE repos.scanned_at
			   END,
			   stars = CASE
			     WHEN excluded.scanned_at > repos.scanned_at THEN excluded.stars
			     ELSE repos.stars
			   END,
			   workflows_count = CASE
			     WHEN excluded.scanned_at > repos.scanned_at THEN excluded.workflows_count
			     ELSE repos.workflows_count
			   END,
			   findings_count = CASE
			     WHEN excluded.scanned_at > repos.scanned_at THEN excluded.findings_count
			     ELSE repos.findings_count
			   END,
			   source = COALESCE(NULLIF(excluded.source, ''), repos.source)`,
			repo.Owner, repo.Name, repo.Stars, repo.Language,
			repo.ScannedAt, repo.WorkflowsCount, repo.FindingsCount, repo.Source,
		)
		if err != nil {
			return fmt.Errorf("inserting repo %s/%s: %w", repo.Owner, repo.Name, err)
		}

		key := repoKey{repo.Owner, repo.Name}
		if existingID, ok := existingRepos[key]; ok {
			// Row already existed; the UPSERT updated it in place.
			repoIDMap[repo.ID] = existingID
			stats.ReposSkipped++
		} else {
			newID, _ := res.LastInsertId()
			existingRepos[key] = newID
			repoIDMap[repo.ID] = newID
			stats.ReposMerged++
		}
	}

	// Load and merge findings.
	var findings []sourceFinding
	if err := source.Select(&findings, "SELECT * FROM findings"); err != nil {
		return fmt.Errorf("querying source findings: %w", err)
	}

	// Preload the target's existing findings once for in-memory dedup —
	// a per-finding SELECT COUNT here was the dominant cost of large merges.
	existingFindings := make(map[findingKey]int64)
	var targetFindings []struct {
		ID           int64  `db:"id"`
		RepoID       int64  `db:"repo_id"`
		WorkflowPath string `db:"workflow_path"`
		RuleID       string `db:"rule_id"`
		LineNumber   int    `db:"line_number"`
	}
	if err := target.Select(&targetFindings, "SELECT id, repo_id, workflow_path, rule_id, line_number FROM findings"); err != nil {
		return fmt.Errorf("querying target findings: %w", err)
	}
	for _, tf := range targetFindings {
		existingFindings[findingKey{tf.RepoID, tf.WorkflowPath, tf.RuleID, tf.LineNumber}] = tf.ID
	}

	insertFinding, err := target.Preparex(
		`INSERT INTO findings (repo_id, workflow_path, rule_id, severity, line_number, description, details, created_at, workflow_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparing finding insert: %w", err)
	}
	defer insertFinding.Close()

	// Map old finding IDs to new finding IDs for disclosure remapping.
	findingIDMap := make(map[int64]int64)

	for _, f := range findings {
		targetRepoID, ok := repoIDMap[f.RepoID]
		if !ok {
			continue
		}

		key := findingKey{targetRepoID, f.WorkflowPath, f.RuleID, f.LineNumber}
		if existingID, ok := existingFindings[key]; ok {
			findingIDMap[f.ID] = existingID
			stats.FindingsSkipped++
			continue
		}

		res, err := insertFinding.Exec(
			targetRepoID, f.WorkflowPath, f.RuleID, f.Severity, f.LineNumber, f.Description, f.Details, f.CreatedAt, f.WorkflowHash,
		)
		if err != nil {
			return fmt.Errorf("inserting finding: %w", err)
		}
		newID, _ := res.LastInsertId()
		existingFindings[key] = newID
		findingIDMap[f.ID] = newID
		stats.FindingsMerged++
	}

	// Merge disclosures with remapped finding IDs.
	if err := mergeDisclosures(target, source, findingIDMap); err != nil {
		return err
	}

	return nil
}

// mergeDisclosures copies disclosures from source to target, remapping IDs.
func mergeDisclosures(target *sqlx.Tx, source *sqlx.DB, findingIDMap map[int64]int64) error {
	var disclosures []sourceDisclosure
	if err := source.Select(&disclosures, "SELECT * FROM disclosures"); err != nil {
		// Table may not exist in older databases.
		return nil
	}

	// Preload existing (finding_id, channel) pairs for in-memory dedup.
	type discKey struct {
		FindingID int64
		Channel   string
	}
	existing := make(map[discKey]bool)
	var targetDiscs []struct {
		FindingID int64  `db:"finding_id"`
		Channel   string `db:"channel"`
	}
	if err := target.Select(&targetDiscs, "SELECT finding_id, channel FROM disclosures"); err != nil {
		return fmt.Errorf("querying target disclosures: %w", err)
	}
	for _, td := range targetDiscs {
		existing[discKey{td.FindingID, td.Channel}] = true
	}

	discIDMap := make(map[int64]int64)

	for _, d := range disclosures {
		newFindingID, ok := findingIDMap[d.FindingID]
		if !ok {
			continue
		}

		// Skip duplicates by (finding_id, channel).
		key := discKey{newFindingID, d.Channel}
		if existing[key] {
			continue
		}
		existing[key] = true

		res, err := target.Exec(
			`INSERT INTO disclosures (finding_id, channel, disclosure_id, status, filed_at, response_at, patched_at, notes, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			newFindingID, d.Channel, d.DisclosureID, d.Status, d.FiledAt, d.ResponseAt, d.PatchedAt, d.Notes, d.CreatedAt, d.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf("inserting disclosure: %w", err)
		}
		newID, _ := res.LastInsertId()
		discIDMap[d.ID] = newID
	}

	// Merge patches with remapped disclosure IDs.
	var patches []sourcePatch
	if err := source.Select(&patches, "SELECT * FROM patches"); err != nil {
		return nil
	}

	for _, p := range patches {
		newDiscID, ok := discIDMap[p.DisclosureID]
		if !ok {
			continue
		}

		_, err := target.Exec(
			`INSERT INTO patches (disclosure_id, commit_url, release_tag, verified_at, created_at)
			 VALUES (?, ?, ?, ?, ?)`,
			newDiscID, p.CommitURL, p.ReleaseTag, p.VerifiedAt, p.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("inserting patch: %w", err)
		}
	}

	return nil
}
