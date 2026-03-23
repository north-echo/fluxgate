# Fluxgate — Claude Code Instructions

## Project

Fluxgate is a CI/CD pipeline security static analysis tool. It scans GitHub Actions, GitLab CI, and Azure Pipelines workflow files for dangerous security patterns (pwn requests, script injection, OIDC misconfiguration, etc.).

## Security Boundaries

**READ [SECURITY-BOUNDARIES.md](SECURITY-BOUNDARIES.md) BEFORE EVERY COMMIT.**

Key constraints:
- Never commit prompt files, BigQuery queries, scan databases, triage briefs, or real scan output to this public repo.
- Never reference specific unpatched repos by name in commits or code.
- Never embed disclosure tracking IDs (GHSA-*, VULN-*) in public code.
- Test fixtures must be synthetic — never copy real workflow files from scanned repos.
- **Before every push, ask: "Does this commit contain anything that helps an attacker evade detection or identifies an unpatched target?"**

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
