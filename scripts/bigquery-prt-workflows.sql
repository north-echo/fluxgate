-- BigQuery: Extract all GitHub Actions workflows containing pull_request_target
-- Target table: bigquery-public-data.github_repos.contents + files
-- Free tier: 1 TiB/month processing
--
-- Usage:
--   1. Run this query in BigQuery console (console.cloud.google.com/bigquery)
--   2. Export results as JSONL to GCS or download directly
--   3. Feed into: fluxgate ingest exported.jsonl --db bigquery.db
--
-- Estimated cost: ~$2.50 (scans ~500GB of content table)
-- Estimated rows: 50K-200K workflows with pull_request_target

SELECT
  f.repo_name AS repo,
  f.path AS path,
  c.content AS content
FROM
  `bigquery-public-data.github_repos.files` f
JOIN
  `bigquery-public-data.github_repos.contents` c
ON
  f.id = c.id
WHERE
  f.path LIKE '.github/workflows/%.yml'
  AND c.content LIKE '%pull_request_target%'
  AND c.size < 1048576  -- Skip files > 1MB (likely generated)

UNION ALL

SELECT
  f.repo_name AS repo,
  f.path AS path,
  c.content AS content
FROM
  `bigquery-public-data.github_repos.files` f
JOIN
  `bigquery-public-data.github_repos.contents` c
ON
  f.id = c.id
WHERE
  f.path LIKE '.github/workflows/%.yaml'
  AND c.content LIKE '%pull_request_target%'
  AND c.size < 1048576
