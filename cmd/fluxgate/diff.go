package main

import (
	"github.com/north-echo/fluxgate/internal/diff"
	"github.com/spf13/cobra"
)

func newDiffCmd() *cobra.Command {
	var oldPath, newPath, format, output string

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two scan databases for new, resolved, and regressed findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := diff.Compare(oldPath, newPath)
			if err != nil {
				return err
			}
			w, closeFn, err := openOutput(output)
			if err != nil {
				return err
			}
			defer closeFn()
			diff.WriteReport(w, result)
			return nil
		},
	}
	cmd.Flags().StringVar(&oldPath, "old", "", "Path to older scan database")
	cmd.Flags().StringVar(&newPath, "new", "", "Path to newer scan database")
	cmd.Flags().StringVar(&format, "format", "table", "Output format (table)")
	cmd.Flags().StringVar(&output, "output", "", "Output file (default: stdout)")
	cmd.MarkFlagRequired("old")
	cmd.MarkFlagRequired("new")
	return cmd
}
