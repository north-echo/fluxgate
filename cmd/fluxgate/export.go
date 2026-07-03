package main

import (
	"fmt"

	"github.com/north-echo/fluxgate/internal/export"
	"github.com/spf13/cobra"
)

func newExportCmd() *cobra.Command {
	var dbPath, format, output string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export anonymized dataset for academic research",
		RunE: func(cmd *cobra.Command, args []string) error {
			w, closeFn, err := openOutput(output)
			if err != nil {
				return err
			}
			defer closeFn()
			switch format {
			case "anonymized-csv", "csv":
				return export.ExportAnonymizedCSV(dbPath, w)
			case "anonymized-json", "json":
				return export.ExportAnonymizedJSON(dbPath, w)
			default:
				return fmt.Errorf("unknown format %q (use anonymized-csv or anonymized-json)", format)
			}
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "findings.db", "Database path")
	cmd.Flags().StringVar(&format, "format", "anonymized-csv", "Export format (anonymized-csv, anonymized-json)")
	cmd.Flags().StringVar(&output, "output", "", "Output file (default: stdout)")
	return cmd
}
