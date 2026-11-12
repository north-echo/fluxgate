# Fluxgate

CI/CD Pipeline Security Gate — static analysis for CI/CD pipeline configurations across 6 platforms.

Fluxgate scans workflow and pipeline files for dangerous security patterns,
including the exact misconfiguration class that enabled the
[Trivy supply chain compromise](https://github.com/aquasecurity/trivy/discussions/10425)
in March 2026.

## Quick Start

```bash
# Scan a local repository (auto-detects all 6 platforms)
fluxgate scan .

# Scan a remote repository
fluxgate remote aquasecurity/trivy

# Install
go install github.com/north-echo/fluxgate/cmd/fluxgate@latest
```

## What It Detects

### GitHub Actions (FG-xxx)

| Rule    | Severity | Description |
|---------|----------|-------------|
| FG-001  | Critical | Pwn Request: pull_request_target with fork checkout |
| FG-002  | High     | Script Injection via expression interpolation |
| FG-003  | Medium   | Tag-based action pinning (mutable references) |
| FG-004  | Medium   | Overly broad workflow permissions |
| FG-005  | Low      | Secrets exposed in workflow logs |
| FG-006  | Medium   | Fork PR code execution via build hooks |
| FG-007  | Medium   | Token exposure in build steps |
| FG-008  | Critical | OIDC misconfiguration on external triggers |
| FG-009  | High     | Self-hosted runner on external triggers |
| FG-010  | High     | Cache poisoning via shared cache on PR workflows |
| FG-011  | Medium   | Bot actor guard TOCTOU bypass risk |
| FG-012  | Medium   | If condition always true |
| FG-013  | High     | All secrets exposed to workflow |
| FG-014  | Medium   | Missing permissions on risky event triggers |
| FG-015  | High     | Unverified script execution (curl pipe bash) |
| FG-016  | High     | Local action after untrusted checkout |
| FG-017  | High     | GitHub Script injection |
| FG-018  | Medium   | Impostor commit detection |
| FG-019  | High     | Hardcoded container credentials |
| FG-020  | Medium   | Ref confusion |
| FG-021  | Medium   | Cross-step output taint |
| FG-022  | High     | Known vulnerable action version |
| FG-023  | High     | Artifact credential leak |
| FG-024  | High     | GitHub environment file injection |
| FG-025  | Critical | Known threat-actor IOC |
| FG-026  | High     | Lifecycle install before credentialed operation (npm, yarn, pnpm, pip, gem, cargo) |
| FG-027  | High     | TOCTOU label gate: label not stripped on synchronize |
| FG-028  | Critical | Secret exfiltration behavior: runner memory scrape, environment sweep, secrets or environment sent to the network |
| FG-029  | High     | Ungated cloud OIDC: cloud login reachable from refs any writer can create |

FG-026 covers dependency code that runs during install or build in a job that
also holds publish, cloud, or release credentials: npm/yarn/pnpm lifecycle
scripts, pip setup hooks, gem native extensions, and Rust `build.rs` and
proc-macros. Cargo has no separate install phase, so any compiling subcommand
(`cargo build`, `cargo test`, `cargo clippy`, `cargo install`) counts, and
there is no `--ignore-scripts` equivalent to suppress it. `release-plz/action`
counts as a publish operation, since it runs `cargo publish` internally.

Note that job separation alone is not a sufficient mitigation for cargo:
`cargo publish` runs a verification build by default, so even an isolated
publish job compiles the crate and its dependencies with the registry token in
scope. Pair a verified build in an uncredentialed job with `cargo publish
--no-verify` in the credentialed one. The remaining mitigations are provenance
rather than suppression: `--locked` with a committed `Cargo.lock`, vendoring
with `--offline`, and gating dependency changes with cargo-vet or cargo-deny.

FG-028 looks for workflows that behave like a credential stealer, as opposed
to the insecure designs the other rules cover. It fires on steps that read
`/proc/<pid>/maps` and `/proc/<pid>/mem` (the Runner.Worker memory dump used
by the tj-actions and Shai-Hulud payloads), point a memory dumper at the runner
process, sweep `/proc/*/environ` and keep the output, or send `toJSON(secrets)`
or a whole-environment dump to a network endpoint. `toJSON(secrets)` next to a
publicly routable raw-IP URL is also critical, since that is the shape a
stealer leaves in the YAML when its logic lives in a separate script. Findings
are not downgraded for label gates or fork guards: a gate does not mitigate a
workflow the attacker wrote.

Stealers pushed with compromised credentials often land on a throwaway branch
and are reverted within minutes, so scanning the default branch on a schedule
will miss them. Run FG-028 on every push that touches `.github/workflows/`, on
every branch.

FG-029 covers the same threat from the other side: what a stolen write token
could reach. A job that logs into AWS, Azure, GCP, or Vault through GitHub OIDC
with no `environment:` gate leaves the cloud trust policy as the only
boundary, and a writer can push a branch with their own workflow to request a
token. It is high when the workflow's own triggers show the trust policy must
admit refs any writer can create (`pull_request`, or `push` without an
exact-name branch filter), and medium otherwise. Fix it by binding the job to
an environment with a deployment branch rule, or by pinning the trust policy's
`sub` to a protected ref.

### GitLab CI (GL-xxx)

| Rule    | Severity | Description |
|---------|----------|-------------|
| GL-001  | High     | Merge request pipeline with privileged variables |
| GL-002  | High     | Script injection via CI predefined variables |
| GL-003  | Medium   | Unpinned include templates |
| GL-004  | Medium   | Broad pipeline permissions |
| GL-005  | High     | Secrets in job logs |
| GL-006  | Medium   | Unsafe artifacts exposure |
| GL-008  | Critical | OIDC misconfiguration |
| GL-009  | High     | Self-hosted runner on MR pipelines |
| GL-010  | High     | Cache poisoning |

### Azure Pipelines (AZ-xxx)

| Rule    | Severity | Description |
|---------|----------|-------------|
| AZ-001  | High     | Fork PR builds with secret/variable group exposure |
| AZ-002  | High     | Script injection via Azure predefined variables |
| AZ-003  | Medium   | Unpinned template extends and repository resources |
| AZ-004  | Medium   | Broad pipeline permissions |
| AZ-005  | High     | Secrets in pipeline logs |
| AZ-006  | Medium   | Unsafe artifacts exposure |
| AZ-008  | Critical | OIDC misconfiguration |
| AZ-009  | High     | Self-hosted agent pools on PR-triggered pipelines |
| AZ-010  | High     | Cache poisoning |

### Jenkins (JK-xxx)

| Rule    | Severity | Description |
|---------|----------|-------------|
| JK-001  | High     | Untrusted branch builds with credentials |
| JK-002  | High     | Script injection in pipeline parameters |
| JK-003  | Medium   | Unpinned shared library versions |
| JK-009  | High     | Insecure agent configuration |

### Tekton (TK-xxx)

| Rule    | Severity | Description |
|---------|----------|-------------|
| TK-001  | High     | Privileged task execution on external triggers |
| TK-002  | High     | Script injection via parameter interpolation |
| TK-003  | Medium   | Unpinned task references |
| TK-009  | High     | Insecure workload identity |

### CircleCI (CC-xxx)

| Rule    | Severity | Description |
|---------|----------|-------------|
| CC-001  | High     | Fork PR builds with secrets |
| CC-002  | High     | Script injection via pipeline parameters |
| CC-003  | Medium   | Unpinned orb versions |
| CC-009  | High     | Self-hosted runner on fork PRs |

**59 rules across 6 CI/CD platforms.**

## Why This Exists

On March 19, 2026, an autonomous AI agent exploited a `pull_request_target`
workflow misconfiguration in Trivy — the most popular open-source
vulnerability scanner — to steal credentials, publish a malicious release,
and poison 75 GitHub Actions version tags. The tool you trust to find
malware was delivering malware.

Fluxgate detects this class of vulnerability before an attacker does.

## Key Features

- **Mitigation-aware severity**: detects defensive controls (fork guards, label gates, permission checks, trusted-ref isolation) and adjusts severity accordingly
- **Multi-platform**: auto-detects GitHub Actions, GitLab CI, Azure Pipelines, Jenkins, Tekton, and CircleCI
- **Batch scanning**: scan thousands of repos with `fluxgate batch --top 1000`
- **Multiple output formats**: table, JSON, SARIF, markdown
- **SARIF upload**: push findings to GitHub Code Scanning API via `fluxgate sarif-push`
- **Web dashboard**: Go/HTMX UI with multi-DB switcher and CSV export
- **Disclosure tracking**: built-in lifecycle management for responsible disclosure
- **Public API**: importable as `github.com/north-echo/fluxgate/pkg/scanner`

## Research

Fluxgate includes a batch scanning mode for security research:

```bash
# Scan top 1000 GitHub repos, store findings
fluxgate batch --top 1000 --db findings.db

# Generate aggregate report
fluxgate batch --db findings.db --report report.md
```

For large surveys, `--clone` swaps the GitHub Contents API for `git clone`
with sparse checkout of `.github/` only. This avoids the 5,000 req/hr API
rate limit and is typically faster past a few thousand repos. Tune
parallelism with `--concurrency` (default 5):

```bash
fluxgate batch --top 10000 --clone --concurrency 10 --db findings.db
```

See [DISCLOSURE.md](DISCLOSURE.md) for our responsible disclosure protocol.

## License

Apache 2.0
