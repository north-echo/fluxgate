# Fluxgate — Claude Code Instructions

## Project

Fluxgate is a CI/CD pipeline security static analysis tool. It scans GitHub Actions, GitLab CI, and Azure Pipelines workflow files for dangerous security patterns (pwn requests, script injection, OIDC misconfiguration, etc.).

## Security Boundaries

Before every push, ask: **"Does this commit contain anything that helps an attacker evade detection or identifies an unpatched target?"** If yes, do not push.

Never commit to this public repo:
- Prompt files, BigQuery queries, scan databases, triage briefs, or real scan output
- Specific unpatched repo names in commits, code, or documentation
- Disclosure tracking IDs (GHSA-*, VULN-*, HackerOne report numbers)
- SECURITY-BOUNDARIES.md or any file describing what we consider sensitive

Test fixtures must be synthetic — never copy real workflow files from scanned repos. When in doubt, keep it private.

## Code Structure

- `cmd/fluxgate/` — CLI entry point (cobra)
- `internal/scanner/` — GitHub Actions parser, rules (FG-xxx), scanner orchestration
- `internal/cicd/` — GitLab CI parser+rules (GL-xxx), Azure Pipelines parser+rules (AZ-xxx)
- `internal/github/` — GitHub API client, batch scanning, discovery
- `internal/report/` — Output formatters (table, JSON, SARIF, markdown)
- `internal/store/` — SQLite persistence
- `test/fixtures/` — Synthetic YAML fixtures for rule tests

## Testing

```bash
go test ./...
```

All rules must have corresponding test fixtures and test functions in `*_test.go`.

## Style

- Go standard library style, no unnecessary abstractions
- Rules are functions with signature `func(wf *Workflow) []Finding`
- Platform-specific rules live in their parser package (internal/cicd/)
- Bridge functions in scanner.go convert platform findings to common Finding type
