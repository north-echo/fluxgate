package scanner

import pkgscanner "github.com/north-echo/fluxgate/pkg/scanner"

type Finding = pkgscanner.Finding
type ScanResult = pkgscanner.ScanResult
type ScanOptions = pkgscanner.ScanOptions

const (
	SeverityCritical  = pkgscanner.SeverityCritical
	SeverityHigh      = pkgscanner.SeverityHigh
	SeverityMedium    = pkgscanner.SeverityMedium
	SeverityLow       = pkgscanner.SeverityLow
	SeverityInfo      = pkgscanner.SeverityInfo
	ConfidenceConfirmed   = pkgscanner.ConfidenceConfirmed
	ConfidenceLikely      = pkgscanner.ConfidenceLikely
	ConfidencePatternOnly = pkgscanner.ConfidencePatternOnly
)

var SeverityRank = pkgscanner.SeverityRank
