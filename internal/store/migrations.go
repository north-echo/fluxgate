package store

const schema = `
CREATE TABLE IF NOT EXISTS repos (
    id INTEGER PRIMARY KEY,
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    stars INTEGER,
    language TEXT,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    workflows_count INTEGER,
    findings_count INTEGER,
    UNIQUE(owner, name)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    repo_id INTEGER REFERENCES repos(id),
    workflow_path TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    line_number INTEGER,
    description TEXT NOT NULL,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repo_id);
CREATE INDEX IF NOT EXISTS idx_repos_stars ON repos(stars DESC);
`

const migration001AddSource = `
ALTER TABLE repos ADD COLUMN source TEXT DEFAULT 'top-1000';
`
