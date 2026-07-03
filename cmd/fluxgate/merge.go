package main

import (
	"fmt"

	"github.com/north-echo/fluxgate/internal/merge"
	"github.com/spf13/cobra"
)

func newMergeCmd() *cobra.Command {
	var target string
	var sources []string

	cmd := &cobra.Command{
		Use:   "merge",
		Short: "Merge multiple scan databases into one",
		RunE: func(cmd *cobra.Command, args []string) error {
			stats, err := merge.MergeDBs(target, sources)
			if err != nil {
				return err
			}
			fmt.Printf("Merge complete: %d sources, %d repos merged (%d skipped), %d findings merged (%d skipped)\n",
				stats.SourcesProcessed, stats.ReposMerged, stats.ReposSkipped,
				stats.FindingsMerged, stats.FindingsSkipped)
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "Output database path")
	cmd.Flags().StringSliceVar(&sources, "sources", nil, "Source database paths (comma-separated)")
	cmd.MarkFlagRequired("target")
	cmd.MarkFlagRequired("sources")
	return cmd
}
