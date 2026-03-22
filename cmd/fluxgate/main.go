package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	ghclient "github.com/north-echo/fluxgate/internal/github"
	"github.com/north-echo/fluxgate/internal/report"
	"github.com/north-echo/fluxgate/internal/scanner"
	"github.com/north-echo/fluxgate/internal/store"
	"github.com/spf13/cobra"
)

var version = "0.4.0"

func main() {
	rootCmd := &cobra.Command{
		Use:     "fluxgate",
		Short:   "CI/CD Pipeline Security Gate",
		Long:    "Fluxgate scans GitHub Actions workflow files for dangerous security patterns.",
		Version: version,
	}

	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newRemoteCmd())
	rootCmd.AddCommand(newBatchCmd())
	rootCmd.AddCommand(newDiscoverCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// outputResult writes the scan result in the requested format and exits non-zero if findings exist.
func outputResult(result *scanner.ScanResult, format, output string) error {
	var w *os.File
	var err error
	if output != "" {
		w, err = os.Create(output)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer w.Close()
	} else {
		w = os.Stdout
	}

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

func newRemoteCmd() *cobra.Command {
	var (
		format     string
		output     string
		severities string
		rules      string
		token      string
	)

	cmd := &cobra.Command{
		Use:   "remote [owner/repo]",
		Short: "Scan a remote GitHub repository",
		Long:  "Fetch and scan GitHub Actions workflows from a remote repository via the GitHub API.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			parts := strings.SplitN(args[0], "/", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid repo format: use owner/repo")
			}
			owner, repo := parts[0], parts[1]

			if token == "" {
				token = os.Getenv("GITHUB_TOKEN")
			}

			client := ghclient.NewClient(token)
			ctx := context.Background()

			opts := parseScanOpts(severities, rules)
			result, err := client.ScanRemote(ctx, owner, repo, opts)
			if err != nil {
				return fmt.Errorf("remote scan failed: %w", err)
			}

			return outputResult(result, format, output)
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table, json, sarif")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().StringVar(&severities, "severity", "", "Filter by severity (comma-separated: critical,high,medium,low)")
	cmd.Flags().StringVar(&rules, "rules", "", "Filter by rule ID (comma-separated: FG-001,FG-002)")
	cmd.Flags().StringVarP(&token, "token", "t", "", "GitHub token (default: $GITHUB_TOKEN)")

	return cmd
}

func newBatchCmd() *cobra.Command {
	var (
		top        int
		dbPath     string
		list       string
		resume     bool
		delay      time.Duration
		reportPath string
		token      string
		severities string
		rules      string
	)

	cmd := &cobra.Command{
		Use:   "batch",
		Short: "Batch scan top GitHub repos",
		Long:  "Scan the top N most-starred repos on GitHub, store findings in SQLite, and generate research reports.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dbPath == "" {
				dbPath = "findings.db"
			}

			db, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("opening database: %w", err)
			}
			defer db.Close()

			// Report-only mode
			if reportPath != "" && top == 0 && list == "" {
				return generateReport(db, reportPath)
			}

			if token == "" {
				token = os.Getenv("GITHUB_TOKEN")
			}

			client := ghclient.NewClient(token)
			ctx := context.Background()

			var repos []ghclient.RepoInfo
			if list != "" {
				repos, err = ghclient.LoadRepoList(list)
				if err != nil {
					return fmt.Errorf("loading repo list: %w", err)
				}
			} else if top > 0 {
				fmt.Printf("Fetching top %d repos by stars...\n", top)
				repos, err = client.FetchTopRepos(ctx, top)
				if err != nil {
					return fmt.Errorf("fetching top repos: %w", err)
				}
				fmt.Printf("Found %d repos\n\n", len(repos))
			} else {
				return fmt.Errorf("specify --top N or --list file")
			}

			batchOpts := ghclient.BatchOptions{
				Top:    top,
				List:   list,
				Resume: resume,
				Delay:  delay,
				DB:     db,
				Opts:   parseScanOpts(severities, rules),
			}

			if err := client.BatchScan(ctx, repos, batchOpts); err != nil {
				return fmt.Errorf("batch scan: %w", err)
			}

			// Auto-generate report if requested
			if reportPath != "" {
				return generateReport(db, reportPath)
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&top, "top", 0, "Scan top N repos by star count")
	cmd.Flags().StringVar(&dbPath, "db", "findings.db", "SQLite database path")
	cmd.Flags().StringVar(&list, "list", "", "File with repos to scan (one owner/repo per line)")
	cmd.Flags().BoolVar(&resume, "resume", false, "Skip repos already in the database")
	cmd.Flags().StringVar(&reportPath, "report", "", "Generate markdown report to this path")
	cmd.Flags().StringVarP(&token, "token", "t", "", "GitHub token (default: $GITHUB_TOKEN)")
	cmd.Flags().StringVar(&severities, "severity", "", "Filter by severity (comma-separated)")
	cmd.Flags().StringVar(&rules, "rules", "", "Filter by rule ID (comma-separated)")
	cmd.Flags().DurationVar(&delay, "delay", 0, "Delay between repos to avoid rate limits (e.g. 1s, 500ms)")

	return cmd
}

func newDiscoverCmd() *cobra.Command {
	var (
		trigger    string
		minStars   int
		maxPages   int
		dbPath     string
		delay      time.Duration
		resume     bool
		token      string
		severities string
		rules      string
		listOnly   bool
		output     string
	)

	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover and scan repos by workflow pattern",
		Long:  "Use GitHub code search to find repos with specific workflow triggers, then scan them.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if token == "" {
				token = os.Getenv("GITHUB_TOKEN")
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

			batchOpts := ghclient.BatchOptions{
				Resume: resume,
				Delay:  delay,
				DB:     db,
				Opts:   parseScanOpts(severities, rules),
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

	return cmd
}

// writeRepoList writes discovered repos to a file or stdout.
func writeRepoList(repos []ghclient.RepoInfo, output string) error {
	var w *os.File
	if output != "" {
		var err error
		w, err = os.Create(output)
		if err != nil {
			return err
		}
		defer w.Close()
	} else {
		w = os.Stdout
	}

	for _, r := range repos {
		fmt.Fprintf(w, "%s/%s\n", r.Owner, r.Name)
	}
	return nil
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
