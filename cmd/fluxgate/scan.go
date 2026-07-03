package main

import (
	"fmt"

	"github.com/north-echo/fluxgate/internal/scanner"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	var (
		format     string
		output     string
		severities string
		rules      string
	)

	cmd := &cobra.Command{
		Use:   "scan [directory]",
		Short: "Scan local workflow files",
		Long:  "Scan .github/workflows/ in a local directory for CI/CD security issues.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := parseScanOpts(severities, rules)
			result, err := scanner.ScanDirectory(args[0], opts)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
			return outputResult(result, format, output)
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table, json, sarif")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().StringVar(&severities, "severity", "", "Filter by severity (comma-separated: critical,high,medium,low)")
	cmd.Flags().StringVar(&rules, "rules", "", "Filter by rule ID (comma-separated: FG-001,FG-002)")

	return cmd
}
