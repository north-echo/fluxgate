package main

import (
	"fmt"

	"github.com/north-echo/fluxgate/internal/store"
	"github.com/spf13/cobra"
)

func newCacheCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Manage the no-workflow cache",
	}
	cmd.AddCommand(newCacheStatsCmd())
	cmd.AddCommand(newCacheClearCmd())
	return cmd
}

func newCacheStatsCmd() *cobra.Command {
	var dbPath string

	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show cache statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("opening database: %w", err)
			}
			defer db.Close()

			total, expired := db.NoWorkflowsCacheStats()

			fmt.Printf("No-workflow cache statistics:\n")
			fmt.Printf("  Total cached repos:        %d\n", total)
			fmt.Printf("  Expired entries (>7 days):  %d\n", expired)
			fmt.Printf("  Active entries:             %d\n", total-expired)
			fmt.Printf("  Est. API calls saved/scan:  %d\n", total-expired)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "findings.db", "Database path")
	return cmd
}

func newCacheClearCmd() *cobra.Command {
	var dbPath string
	var maxAge int

	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Clear expired entries from the no-workflow cache",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("opening database: %w", err)
			}
			defer db.Close()

			cleared, err := db.ClearExpiredNoWorkflows(maxAge)
			if err != nil {
				return fmt.Errorf("clearing cache: %w", err)
			}

			fmt.Printf("Cleared %d expired cache entries (older than %d days)\n", cleared, maxAge)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "findings.db", "Database path")
	cmd.Flags().IntVar(&maxAge, "max-age", 7, "Maximum cache age in days")
	return cmd
}
