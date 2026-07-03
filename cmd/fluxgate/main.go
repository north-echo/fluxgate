package main

import (
	"os"

	"github.com/north-echo/fluxgate/internal/scanner"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "fluxgate",
		Short:   "CI/CD Pipeline Security Gate",
		Long:    "Fluxgate scans GitHub Actions workflow files for dangerous security patterns.",
		Version: scanner.Version,
	}

	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newRemoteCmd())
	rootCmd.AddCommand(newBatchCmd())
	rootCmd.AddCommand(newDiscoverCmd())
	rootCmd.AddCommand(newIngestCmd())
	rootCmd.AddCommand(newGatoxImportCmd())
	rootCmd.AddCommand(newDisclosureCmd())
	rootCmd.AddCommand(newDashboardCmd())
	rootCmd.AddCommand(newDiffCmd())
	rootCmd.AddCommand(newMergeCmd())
	rootCmd.AddCommand(newExportCmd())
	rootCmd.AddCommand(newCacheCmd())
	rootCmd.AddCommand(newSARIFPushCmd())
	rootCmd.AddCommand(newTemplatesCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
