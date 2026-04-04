# Fluxgate — Claude Code Instructions

## Project

Fluxgate is a CI/CD pipeline security static analysis tool with **53 detection rules across 6 platforms** (GitHub Actions, GitLab CI, Azure Pipelines, Jenkins, Tekton, CircleCI). Current version: **v0.7.0**.

## Security Boundaries

Before every push, ask: **"Does this commit contain anything that helps an attacker evade detection or identifies an unpatched target?"** If yes, do not push.

Never commit to this public repo:
- Prompt files, BigQuery queries, scan databases, triage briefs, or real scan output
- Specific unpatched repo names in commits, code, or documentation
- Disclosure tracking IDs (GHSA-*, VULN-*, HackerOne report numbers)
- SECURITY-BOUNDARIES.md or any file describing what we consider sensitive

Test fixtures must be synthetic — never copy real workflow files from scanned repos. When in doubt, keep it private.

A pre-push hook blocks commits containing disclosure ID patterns. Use `--no-verify` only when intentional and the content is public (e.g., referencing an already-published CVE).

## Code Structure

### Public API (v0.7.0+)
- `pkg/scanner/` — Importable as `github.com/north-echo/fluxgate/pkg/scanner`
  - Finding, ScanResult, Workflow types
  - ScanWorkflowBytes, ScanFile, ScanDirectory, ParseWorkflow
  - AllRules(), RuleDescriptions, all Check* functions
  - GitHub Actions rules (FG-001 through FG-023) live here

### Private packages
- `cmd/fluxgate/` — CLI entry point (cobra), 16 commands
- `internal/scanner/` — Thin re-export shims for `pkg/scanner` (backward compat)
- `internal/cicd/` — Platform-specific parsers+rules:
  - GitLab CI (GL-001 through GL-010)
  - Azure Pipelines (AZ-001 through AZ-010)
  - Jenkins (JK-001 through JK-009)
  - Tekton (TK-001 through TK-009)
  - CircleCI (CC-001 through CC-009)
- `internal/github/`, `internal/gitlab/`, `internal/azure/` — API clients with rate limiting, PAT rotation
- `internal/report/` — Output formatters (table, JSON, SARIF, markdown)
- `internal/store/` — SQLite persistence with migrations
- `internal/dashboard/` — Go/HTMX web UI (multi-DB switcher, CSV export)
- `internal/diff/`, `internal/merge/`, `internal/export/` — Longitudinal analysis
- `test/fixtures/` — Synthetic YAML fixtures for rule tests
- `research-station/` — Gitignored. Persistent scanning infrastructure on Dell OptiPlex.

## Available CLI Commands

```
scan          — Scan local workflow files (auto-detects all 6 platforms)
remote        — Scan a remote repo (--platform github|gitlab|azure)
batch         — Batch scan repos with --top or --list (supports --tokens for PAT rotation)
discover      — Discover repos by workflow pattern via GitHub code search
ingest        — Ingest workflow YAML from JSONL (BigQuery exports)
gatox-import  — Import Gato-X enumeration results
dashboard     — Launch Go/HTMX web UI (--db flag repeatable for multi-DB switcher)
diff          — Longitudinal diff between two scan databases
merge         — Merge multiple scan databases
export        — Export anonymized academic dataset
disclosure    — Track disclosure lifecycle (add/list/update/patch subcommands)
sarif-push    — Upload findings to GitHub Code Scanning API
cache         — Manage no-workflow cache (stats/clear)
```

## Testing

```bash
go test ./...      # All tests (scanner, cicd, github, gitlab, diff, merge, export, pkg/scanner)
go build ./...     # Must compile cleanly
```

All rules must have corresponding test fixtures and test functions in `*_test.go`. Rules in `pkg/scanner/rules.go` have tests in `pkg/scanner/rules_test.go`. Platform rules in `internal/cicd/` have tests in the same package.

## Style

- Go standard library style, no unnecessary abstractions
- Rules are functions with signature `func(wf *scanner.Workflow) []scanner.Finding`
- Platform-specific rules live in their parser package (internal/cicd/)
- Bridge functions in `pkg/scanner/scan.go` convert platform findings to common Finding type
- Mitigation-aware severity: rules should detect defensive controls (label gates, fork guards, permission checks, etc.) and adjust severity accordingly — see `MitigationAnalysis` in `pkg/scanner/rules.go`
- Echo/logging context downgrade: injection findings in `echo`/`printf`-only contexts should be downgraded to info
- Quoted CLI arguments are harder to exploit than unquoted — downgrade to medium

## Severity Tuning Lessons Learned

- **Compound guards**: actor guard + fork-origin check in the same `if:` = ForkGuard (suppress to info), not just ActorGuard (cap at high)
- **Trusted-ref isolation**: fork checkout to subdir + executed scripts from trusted ref checkout = info
- **Permission-gate jobs**: upstream job verifying `getCollaboratorPermissionLevel` = internal threat only, downgrade by 2
- **Ref-scoped cache keys**: `CI_COMMIT_REF_SLUG` is ref-scoped by default since GitLab 13.x — info, not medium
- **Rules vs scripts**: CI variables in GitLab `rules:` blocks are NOT shell injection, only in `script:` blocks

## Acknowledgements

Detection coverage informed by comparative analysis of:
- [Poutine](https://github.com/boostsecurityio/poutine) (BoostSecurity) — OPA/Rego rules, OSV integration
- [zizmor](https://github.com/zizmorcore/zizmor) (Trail of Bits) — impostor commit detection, cross-step taint tracking

Extends their patterns with mitigation-aware severity modeling, AI-assisted triage, and multi-platform coverage.
