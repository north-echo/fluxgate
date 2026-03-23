# Fluxgate

CI/CD Pipeline Security Gate — static analysis for GitHub Actions workflows.

Fluxgate scans GitHub Actions workflow files for dangerous security patterns,
including the exact misconfiguration class that enabled the
[Trivy supply chain compromise](https://github.com/aquasecurity/trivy/discussions/10425)
in March 2026.

## Quick Start

```bash
# Scan a local repository
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
| FG-002  | High     | Script Injection via expression interpolation (PR context, dispatch inputs, reusable workflow inputs) |
| FG-003  | Medium   | Tag-based action pinning (mutable references) |
| FG-004  | Medium   | Overly broad workflow permissions |
| FG-005  | Low      | Secrets exposed in workflow logs |
| FG-006  | Medium   | Fork PR code execution via build hooks |
| FG-007  | Medium   | Inconsistent GITHUB_TOKEN blanking |
| FG-008  | Critical | OIDC misconfiguration on external triggers |
| FG-009  | High     | Self-hosted runner on external triggers |
| FG-010  | High     | Cache poisoning via shared cache on PR workflows |
| FG-011  | Medium   | Bot actor guard TOCTOU bypass risk |

### GitLab CI (GL-xxx)

| Rule    | Severity | Description |
|---------|----------|-------------|
| GL-001  | High     | Merge request pipeline with privileged variables |
| GL-002  | High     | Script injection via CI predefined variables |
| GL-003  | Medium   | Unpinned include templates |

### Azure Pipelines (AZ-xxx)

| Rule    | Severity | Description |
|---------|----------|-------------|
| AZ-001  | High     | Fork PR builds with secret/variable group exposure |
| AZ-002  | High     | Script injection via Azure predefined variables |
| AZ-003  | Medium   | Unpinned template extends and repository resources |
| AZ-009  | High     | Self-hosted agent pools on PR-triggered pipelines |

**21 rules across 3 CI/CD platforms.**

## Why This Exists

On March 19, 2026, an autonomous AI agent exploited a `pull_request_target`
workflow misconfiguration in Trivy — the most popular open-source
vulnerability scanner — to steal credentials, publish a malicious release,
and poison 75 GitHub Actions version tags. The tool you trust to find
malware was delivering malware.

Fluxgate detects this class of vulnerability before an attacker does.

## Research

Fluxgate includes a batch scanning mode for security research:

```bash
# Scan top 1000 GitHub repos, store findings
fluxgate batch --top 1000 --db findings.db

# Generate aggregate report
fluxgate batch --db findings.db --report report.md
```

See [DISCLOSURE.md](DISCLOSURE.md) for our responsible disclosure protocol.

## VibeShield Integration

Fluxgate rules map to [VibeShield](https://github.com/north-echo/vibeshield)
V-ID taxonomy entries.

## License

Apache 2.0
