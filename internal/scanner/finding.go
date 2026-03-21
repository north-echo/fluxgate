package scanner

import "fmt"

// Severity levels for findings.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Confidence levels for findings.
const (
	ConfidenceConfirmed   = "confirmed"
	ConfidenceLikely      = "likely"
	ConfidencePatternOnly = "pattern-only"
)

// Finding represents a single security finding in a workflow file.
type Finding struct {
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence,omitempty"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Message    string `json:"message"`
	Details    string `json:"details,omitempty"`
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s %s:%d — %s", f.Severity, f.RuleID, f.File, f.Line, f.Message)
}

// SeverityRank returns a numeric rank for sorting (lower = more severe).
func SeverityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	case SeverityInfo:
		return 4
	default:
		return 5
	}
}
