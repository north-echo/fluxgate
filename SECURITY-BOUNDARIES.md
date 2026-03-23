# SECURITY BOUNDARIES — READ THIS BEFORE EVERY COMMIT

## Classification: What is PUBLIC vs PRIVATE

This project has a hard boundary between open-source tooling and private research infrastructure. Violating this boundary burns disclosure credibility and hands adversaries our methodology.

### PUBLIC (safe to commit to north-echo/fluxgate)

- Detection rules (rules.go, all FG-/GL-/AZ- rule logic)
- YAML parsers (workflow.go, gitlab.go, azure.go)
- CLI and command structure (cmd/)
- Report output formats (JSON, SARIF, table, markdown)
- Test fixtures (test/fixtures/) — synthetic only, never real workflow files from scanned repos
- Scanner architecture (scanner.go, finding.go)
- GitHub API client and batch scanning logic
- Containerfile, go.mod, go.sum, CI workflows
- README, CONTRIBUTING, LICENSE, SECURITY, DISCLOSURE
- .goreleaser.yaml

### PRIVATE (never commit to any public repository)

- **Triage agent prompts** (sonnet-triage.txt, haiku-filter.txt, any prompt files) — these encode exact triage methodology and mitigating factor weights. Publishing them teaches attackers how to evade our assessment.
- **BigQuery queries** (fg001-candidates.sql, risky-triggers.sql, any .sql files for target discovery) — these are target acquisition logic.
- **Scan databases** (*.db, *.db-wal, *.db-shm) — contain unpublished findings and repo-specific data.
- **Triage briefs and disclosure drafts** — any file containing repo-specific vulnerability details, advisory text, or disclosure tracking.
- **MEMORY.md and session state files** — contain disclosure status, maintainer contact info, and tracking IDs.
- **API keys, tokens, .env files** — obvious but stated for completeness.
- **GH Archive hit databases** — contain unpublished monitoring results.
- **Scan result JSON/SARIF from real repos** — any output from scanning real repositories, as opposed to test fixtures.

### RULES

1. **Never commit prompt files to a public repo.** The triage agent loads prompts from a mounted volume or a private repo. The Containerfile should COPY from a local path, but the prompts directory must be in .gitignore if the repo is public.

2. **Never commit .sql query files to a public repo.** BigQuery discovery queries go in a private repo or stay on the research station only.

3. **Never commit real scan output to a public repo.** Test fixtures are synthetic. If you need a regression test based on a real workflow, anonymize it — change the repo name, strip identifying details, keep only the structural pattern.

4. **Never reference specific unpatched repos by name in commit messages, comments, or documentation.** Use aggregate stats only ("20 confirmed criticals across 16 repos") until the disclosure window closes.

5. **Never embed disclosure tracking IDs (GHSA-*, VULN-*, HackerOne report numbers) in public code or commits.** These go in private tracking only.

6. **The .gitignore must exclude:** `*.db`, `*.db-wal`, `*.db-shm`, `.env`, `prompts/`, `queries/`, `scans/`, `findings/`, `reports/`, `MEMORY.md`, and any directory containing triage output.

7. **Before every push, ask:** "Does this commit contain anything that helps an attacker evade detection or identifies an unpatched target?" If yes, do not push.

8. **When in doubt, keep it private.** Moving something from private to public is easy. Moving it back is impossible.
