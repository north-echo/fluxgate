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

| Rule    | Severity | Description |
|---------|----------|-------------|
| FG-001  | Critical | Pwn Request: pull_request_target with fork checkout |
| FG-002  | High     | Script Injection via expression interpolation |
| FG-003  | Medium   | Tag-based action pinning (mutable references) |
| FG-004  | Medium   | Overly broad workflow permissions |
| FG-005  | Low      | Secrets exposed in workflow logs |

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
V-ID taxonomy entries. See the case study:
[V-SC-2026-001: Trivy Supply Chain Compromise](https://github.com/north-echo/vibeshield/blob/main/case-studies/V-SC-2026-001-trivy-supply-chain.md).

## License

Apache 2.0
