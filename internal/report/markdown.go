package report

import (
	"fmt"
	"io"
	"time"

	"github.com/north-echo/fluxgate/internal/scanner"
	"github.com/north-echo/fluxgate/internal/store"
)

// WriteMarkdown generates a research report from batch scan statistics.
func WriteMarkdown(w io.Writer, stats *store.ReportStats, criticals []store.CriticalFinding) {
	fmt.Fprintln(w, "# Fluxgate Research Report")
	fmt.Fprintln(w, "## GitHub Actions Security Scan")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "**Scan date:** %s\n", time.Now().Format("2006-01-02"))
	fmt.Fprintf(w, "**Repos scanned:** %d\n", stats.ReposScanned)
	if stats.ReposScanned > 0 {
		pct := float64(stats.ReposWithFinds) / float64(stats.ReposScanned) * 100
		fmt.Fprintf(w, "**Repos with findings:** %d (%.1f%%)\n", stats.ReposWithFinds, pct)
	}
	fmt.Fprintf(w, "**Total findings:** %d\n", stats.TotalFindings)
	fmt.Fprintln(w)

	// Findings by severity
	fmt.Fprintln(w, "### Findings by Severity")
	fmt.Fprintln(w, "| Severity | Count | % of total |")
	fmt.Fprintln(w, "|----------|-------|------------|")
	for _, sev := range []string{
		scanner.SeverityCritical,
		scanner.SeverityHigh,
		scanner.SeverityMedium,
		scanner.SeverityLow,
		scanner.SeverityInfo,
	} {
		count := stats.BySeverity[sev]
		if count == 0 {
			continue
		}
		pct := float64(count) / float64(stats.TotalFindings) * 100
		fmt.Fprintf(w, "| %-8s | %d | %.1f%% |\n", sev, count, pct)
	}
	fmt.Fprintln(w)

	// Findings by rule
	fmt.Fprintln(w, "### Findings by Rule")
	fmt.Fprintln(w, "| Rule | Description | Count |")
	fmt.Fprintln(w, "|------|-------------|-------|")
	for _, ruleID := range []string{"FG-001", "FG-002", "FG-003", "FG-004", "FG-005"} {
		count := stats.ByRule[ruleID]
		if count == 0 {
			continue
		}
		desc := scanner.RuleDescriptions[ruleID]
		fmt.Fprintf(w, "| %s | %s | %d |\n", ruleID, desc, count)
	}
	fmt.Fprintln(w)

	// Critical findings summary
	if len(criticals) > 0 {
		fmt.Fprintf(w, "### FG-001 (Pwn Request) — Critical Findings\n\n")
		fmt.Fprintf(w, "%d repositories have the exact misconfiguration pattern that enabled\n", len(criticals))
		fmt.Fprintln(w, "the Trivy supply chain compromise. Maintainers have been notified")
		fmt.Fprintln(w, "via responsible disclosure (see DISCLOSURE.md).")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "[Individual findings redacted pending disclosure window]")
	}
}
