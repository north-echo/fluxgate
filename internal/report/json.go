package report

import (
	"encoding/json"
	"io"

	"github.com/north-echo/fluxgate/internal/scanner"
)

type jsonReport struct {
	Version   string            `json:"version"`
	Path      string            `json:"path"`
	Workflows int               `json:"workflows"`
	Total     int               `json:"total_findings"`
	Findings  []scanner.Finding `json:"findings"`
}

// WriteJSON writes findings as JSON.
func WriteJSON(w io.Writer, result *scanner.ScanResult) error {
	report := jsonReport{
		Version:   "0.1.0",
		Path:      result.Path,
		Workflows: result.Workflows,
		Total:     len(result.Findings),
		Findings:  result.Findings,
	}
	if report.Findings == nil {
		report.Findings = []scanner.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
