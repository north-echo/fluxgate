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

const migration002Disclosures = `
CREATE TABLE IF NOT EXISTS disclosures (
    id INTEGER PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id),
    channel TEXT NOT NULL,
    disclosure_id TEXT,
    status TEXT NOT NULL DEFAULT 'filed',
    filed_at TIMESTAMP,
    response_at TIMESTAMP,
    patched_at TIMESTAMP,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(finding_id, channel)
);

CREATE INDEX IF NOT EXISTS idx_disclosures_finding ON disclosures(finding_id);
CREATE INDEX IF NOT EXISTS idx_disclosures_status ON disclosures(status);
`

const migration004NoWorkflows = `
CREATE TABLE IF NOT EXISTS no_workflows (
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(owner, name)
);
CREATE INDEX IF NOT EXISTS idx_no_workflows_repo ON no_workflows(owner, name);
`

const migration003Patches = `
CREATE TABLE IF NOT EXISTS patches (
    id INTEGER PRIMARY KEY,
    disclosure_id INTEGER REFERENCES disclosures(id),
    commit_url TEXT,
    release_tag TEXT,
    verified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_patches_disclosure ON patches(disclosure_id);
`
