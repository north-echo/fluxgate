package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/north-echo/fluxgate/internal/report"
	"github.com/north-echo/fluxgate/internal/scanner"
	"github.com/north-echo/fluxgate/internal/store"
)

// openOutput opens path for writing, or returns stdout when path is empty.
// The returned close func is a no-op for stdout.
func openOutput(path string) (io.Writer, func() error, error) {
	if path == "" {
		return os.Stdout, func() error { return nil }, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}

// resolveToken returns the flag value if set, else the first non-empty env var.
func resolveToken(flag string, envVars ...string) string {
	if flag != "" {
		return flag
	}
	for _, env := range envVars {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return ""
}

// outputResult writes the scan result in the requested format and exits non-zero if findings exist.
func outputResult(result *scanner.ScanResult, format, output string) error {
	w, closeFn, err := openOutput(output)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer closeFn()

	switch format {
	case "json":
		if err := report.WriteJSON(w, result); err != nil {
			return err
		}
	case "sarif":
		if err := report.WriteSARIF(w, result); err != nil {
			return err
		}
	default:
		report.WriteTable(w, result)
	}

	if len(result.Findings) > 0 {
		os.Exit(1)
	}
	return nil
}

func parseScanOpts(severities, rules string) scanner.ScanOptions {
	opts := scanner.ScanOptions{}
	if severities != "" {
		opts.Severities = strings.Split(severities, ",")
	}
	if rules != "" {
		opts.Rules = strings.Split(rules, ",")
	}
	return opts
}

func generateReport(db *store.DB, path string) error {
	stats, err := db.GetReportStats()
	if err != nil {
		return fmt.Errorf("getting report stats: %w", err)
	}

	criticals, err := db.GetCriticalFindings()
	if err != nil {
		return fmt.Errorf("getting critical findings: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating report file: %w", err)
	}
	defer f.Close()

	report.WriteMarkdown(f, stats, criticals)
	fmt.Printf("Report written to %s\n", path)
	return nil
}
