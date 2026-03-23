-- Fluxgate Analysis Queries
-- Run against any scan SQLite database: sqlite3 <db> < analysis-queries.sql
-- Or use individual queries interactively.

-- =============================================================================
-- OVERVIEW
-- =============================================================================

-- Total repos scanned and findings
SELECT 'Repos scanned' AS metric, COUNT(*) AS value FROM repos
UNION ALL
SELECT 'Repos with findings', COUNT(*) FROM repos WHERE findings_count > 0
UNION ALL
SELECT 'Total findings', COUNT(*) FROM findings;

-- =============================================================================
-- FINDINGS BY RULE AND SEVERITY
-- =============================================================================

SELECT rule_id, severity, COUNT(*) AS count
FROM findings
GROUP BY rule_id, severity
ORDER BY rule_id,
  CASE severity
    WHEN 'critical' THEN 1
    WHEN 'high' THEN 2
    WHEN 'medium' THEN 3
    WHEN 'low' THEN 4
    WHEN 'info' THEN 5
  END;

-- =============================================================================
-- FG-001 (PWN REQUEST) DETAILS
-- =============================================================================

-- All FG-001 critical and high findings with repo context
SELECT r.owner || '/' || r.name AS repo,
       r.stars,
       f.severity,
       f.workflow_path,
       f.description
FROM findings f
JOIN repos r ON r.id = f.repo_id
WHERE f.rule_id = 'FG-001'
  AND f.severity IN ('critical', 'high')
ORDER BY
  CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 END,
  r.stars DESC;

-- FG-001 mitigated vs unmitigated breakdown
SELECT
  CASE
    WHEN f.description LIKE '%mitigated%' THEN 'mitigated'
    ELSE 'unmitigated'
  END AS status,
  f.severity,
  COUNT(*) AS count
FROM findings f
WHERE f.rule_id = 'FG-001'
GROUP BY status, f.severity
ORDER BY status,
  CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 END;

-- =============================================================================
-- NEW RULES (FG-008, FG-009, FG-010) PREVALENCE
-- =============================================================================

-- OIDC misconfiguration findings
SELECT r.owner || '/' || r.name AS repo, f.severity, f.description
FROM findings f
JOIN repos r ON r.id = f.repo_id
WHERE f.rule_id = 'FG-008'
ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END;

-- Self-hosted runner findings
SELECT r.owner || '/' || r.name AS repo, f.severity, f.description
FROM findings f
JOIN repos r ON r.id = f.repo_id
WHERE f.rule_id = 'FG-009'
ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END;

-- Cache poisoning findings
SELECT r.owner || '/' || r.name AS repo, f.severity, f.description
FROM findings f
JOIN repos r ON r.id = f.repo_id
WHERE f.rule_id = 'FG-010'
ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END;

-- =============================================================================
-- ECOSYSTEM COMPARISON (for cross-database analysis)
-- =============================================================================

-- Prevalence rate: % of repos with each rule
SELECT
  f.rule_id,
  COUNT(DISTINCT f.repo_id) AS repos_affected,
  (SELECT COUNT(*) FROM repos) AS total_repos,
  ROUND(100.0 * COUNT(DISTINCT f.repo_id) / (SELECT COUNT(*) FROM repos), 1) AS pct
FROM findings f
GROUP BY f.rule_id
ORDER BY repos_affected DESC;

-- Star-weighted severity: high-star repos with critical findings
SELECT r.owner || '/' || r.name AS repo,
       r.stars,
       COUNT(*) AS critical_findings
FROM findings f
JOIN repos r ON r.id = f.repo_id
WHERE f.severity = 'critical'
GROUP BY r.id
ORDER BY r.stars DESC
LIMIT 20;

-- =============================================================================
-- PERMISSIONS POSTURE
-- =============================================================================

-- Repos with no permissions block (FG-004/FG-006)
SELECT r.owner || '/' || r.name AS repo, r.stars, f.workflow_path, f.description
FROM findings f
JOIN repos r ON r.id = f.repo_id
WHERE f.rule_id IN ('FG-004', 'FG-006')
  AND f.severity IN ('high', 'medium')
ORDER BY r.stars DESC
LIMIT 30;

-- =============================================================================
-- TAG PINNING (FG-003)
-- =============================================================================

-- Unpinned actions by severity
SELECT f.severity, COUNT(*) AS count
FROM findings f
WHERE f.rule_id = 'FG-003'
GROUP BY f.severity
ORDER BY CASE f.severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'info' THEN 3 END;

-- High-severity unpinned actions (branch-pinned: @main/@master)
SELECT r.owner || '/' || r.name AS repo, f.workflow_path, f.description
FROM findings f
JOIN repos r ON r.id = f.repo_id
WHERE f.rule_id = 'FG-003' AND f.severity = 'high'
ORDER BY r.stars DESC
LIMIT 20;

-- =============================================================================
-- AGGREGATE STATS FOR BLOG POST / CFP
-- =============================================================================

-- Summary statistics
SELECT
  (SELECT COUNT(*) FROM repos) AS total_repos,
  (SELECT COUNT(*) FROM findings) AS total_findings,
  (SELECT COUNT(*) FROM findings WHERE severity = 'critical') AS critical,
  (SELECT COUNT(*) FROM findings WHERE severity = 'high') AS high,
  (SELECT COUNT(*) FROM findings WHERE rule_id = 'FG-001') AS pwn_requests,
  (SELECT COUNT(*) FROM findings WHERE rule_id = 'FG-001' AND severity = 'critical') AS unmitigated_pwn,
  (SELECT COUNT(DISTINCT repo_id) FROM findings WHERE rule_id = 'FG-001') AS repos_with_pwn,
  ROUND(100.0 * (SELECT COUNT(DISTINCT repo_id) FROM findings WHERE rule_id = 'FG-001')
    / (SELECT COUNT(*) FROM repos), 1) AS pwn_pct;
