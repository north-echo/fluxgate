package main

import (
	"context"
	"fmt"
	"time"

	gitclone "github.com/north-echo/fluxgate/internal/git"
	ghclient "github.com/north-echo/fluxgate/internal/github"
	"github.com/north-echo/fluxgate/internal/store"
	"github.com/spf13/cobra"
)

func newDiscoverCmd() *cobra.Command {
	var (
		trigger     string
		minStars    int
		maxPages    int
		dbPath      string
		delay       time.Duration
		resume      bool
		token       string
		severities  string
		rules       string
		listOnly    bool
		output      string
		useClone    bool
		concurrency int
		keepDir     string
	)

	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover and scan repos by workflow pattern",
		Long:  "Use GitHub code search to find repos with specific workflow triggers, then scan them.",
		RunE: func(cmd *cobra.Command, args []string) error {
			token = resolveToken(token, "GITHUB_TOKEN")

			if useClone {
				if err := gitclone.CheckGit(); err != nil {
					return err
				}
			}

			client := ghclient.NewClient(token)
			ctx := context.Background()

			fmt.Printf("Discovering repos with '%s' in workflows", trigger)
			if minStars > 0 {
				fmt.Printf(" (>= %d stars)", minStars)
			}
			fmt.Println()

			discoverOpts := ghclient.DiscoverOptions{
				Trigger:  trigger,
				MinStars: minStars,
				MaxPages: maxPages,
				Delay:    delay,
			}

			repos, err := client.DiscoverRepos(ctx, discoverOpts)
			if err != nil {
				return fmt.Errorf("discovery failed: %w", err)
			}
			fmt.Printf("\nDiscovered %d unique repos\n\n", len(repos))

			// List-only mode: output repo list for use with --list
			if listOnly {
				return writeRepoList(repos, output)
			}

			// Full scan mode
			if dbPath == "" {
				dbPath = "targeted.db"
			}
			db, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("opening database: %w", err)
			}
			defer db.Close()

			if useClone {
				var cloneTokens []string
				if token != "" {
					cloneTokens = []string{token}
				}
				return batchScanWithClone(ctx, repos, cloneScanOptions{
					DB:          db,
					Tokens:      cloneTokens,
					ScanOpts:    parseScanOpts(severities, rules),
					Resume:      resume,
					Concurrency: concurrency,
					KeepDir:     keepDir,
				})
			}

			batchOpts := ghclient.BatchOptions{
				Resume:      resume,
				Delay:       delay,
				Concurrency: concurrency,
				DB:          db,
				Opts:        parseScanOpts(severities, rules),
			}

			return client.BatchScan(ctx, repos, batchOpts)
		},
	}

	cmd.Flags().StringVar(&trigger, "trigger", "pull_request_target", "Workflow trigger to search for")
	cmd.Flags().IntVar(&minStars, "min-stars", 0, "Minimum star count")
	cmd.Flags().IntVar(&maxPages, "max-pages", 10, "Max code search pages (100 results/page)")
	cmd.Flags().StringVar(&dbPath, "db", "targeted.db", "SQLite database path")
	cmd.Flags().BoolVar(&resume, "resume", false, "Skip repos already in the database")
	cmd.Flags().DurationVar(&delay, "delay", 7*time.Second, "Delay between API calls (code search is rate-limited to 10/min)")
	cmd.Flags().StringVarP(&token, "token", "t", "", "GitHub token (default: $GITHUB_TOKEN)")
	cmd.Flags().StringVar(&severities, "severity", "", "Filter by severity (comma-separated)")
	cmd.Flags().StringVar(&rules, "rules", "", "Filter by rule ID (comma-separated)")
	cmd.Flags().BoolVar(&listOnly, "list-only", false, "Output repo list without scanning")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file for --list-only (default: stdout)")
	cmd.Flags().BoolVar(&useClone, "clone", false, "Use git sparse checkout instead of API (avoids rate limits)")
	cmd.Flags().IntVar(&concurrency, "concurrency", 5, "Number of concurrent repo scans (API and --clone modes)")
	cmd.Flags().StringVar(&keepDir, "keep", "", "Keep cloned repos in this directory instead of cleaning up")

	return cmd
}

// writeRepoList writes discovered repos to a file or stdout.
func writeRepoList(repos []ghclient.RepoInfo, output string) error {
	w, closeFn, err := openOutput(output)
	if err != nil {
		return err
	}
	defer closeFn()

	for _, r := range repos {
		fmt.Fprintf(w, "%s/%s\n", r.Owner, r.Name)
	}
	return nil
}
