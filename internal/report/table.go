package report

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/north-echo/fluxgate/internal/scanner"
)

// WriteTable writes findings as a human-readable table.
func WriteTable(w io.Writer, result *scanner.ScanResult) {
	fmt.Fprintln(w, "fluxgate v0.5.0 — CI/CD Pipeline Security Gate")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Scanning: %s\n\n", result.Path)

	if len(result.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		fmt.Fprintf(w, "\n0 findings in %d workflows\n", result.Workflows)
		return
	}

	counts := map[string]int{}
	for _, f := range result.Findings {
		counts[f.Severity]++
		sev := strings.ToUpper(f.Severity)
		file := filepath.Base(f.File)
		location := fmt.Sprintf("%s:%d", file, f.Line)
		fmt.Fprintf(w, "%-9s %-7s %-20s %s\n", sev, f.RuleID, location, f.Message)
	}

	fmt.Fprintln(w)
	total := len(result.Findings)
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if c := counts[sev]; c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, sev))
		}
	}
	fmt.Fprintf(w, "%d findings (%s) in %d workflows\n", total, strings.Join(parts, ", "), result.Workflows)
}
