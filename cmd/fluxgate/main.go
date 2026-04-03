package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	azureclient "github.com/north-echo/fluxgate/internal/azure"
	"github.com/north-echo/fluxgate/internal/dashboard"
	"github.com/north-echo/fluxgate/internal/diff"
	"github.com/north-echo/fluxgate/internal/export"
	ghclient "github.com/north-echo/fluxgate/internal/github"
	gitlabclient "github.com/north-echo/fluxgate/internal/gitlab"
	"github.com/north-echo/fluxgate/internal/merge"
	"github.com/north-echo/fluxgate/internal/report"
	"github.com/north-echo/fluxgate/internal/scanner"
	"github.com/north-echo/fluxgate/internal/store"
	"github.com/spf13/cobra"
)

var version = "0.6.0"

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
	rootCmd.AddCommand(newIngestCmd())
	rootCmd.AddCommand(newGatoxImportCmd())
	rootCmd.AddCommand(newDisclosureCmd())
	rootCmd.AddCommand(newDashboardCmd())
	rootCmd.AddCommand(newDiffCmd())
	rootCmd.AddCommand(newMergeCmd())
	rootCmd.AddCommand(newExportCmd())
	rootCmd.AddCommand(newCacheCmd())
	rootCmd.AddCommand(newSARIFPushCmd())

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
		platform   string
		baseURL    string
	)

	cmd := &cobra.Command{
		Use:   "remote [owner/repo]",
		Short: "Scan a remote repository",
		Long: `Fetch and scan CI/CD pipelines from a remote repository.

Platforms:
  github  (default) — GitHub Actions via GitHub API
  gitlab  — GitLab CI via GitLab API (use --url for self-hosted)
  azure   — Azure Pipelines via Azure DevOps API (use --url for org URL)`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if token == "" {
				token = os.Getenv("GITHUB_TOKEN")
			}

			opts := parseScanOpts(severities, rules)
			ctx := context.Background()

			switch platform {
			case "github", "":
				parts := strings.SplitN(args[0], "/", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid repo format: use owner/repo")
				}
				client := ghclient.NewClient(token)
				result, err := client.ScanRemote(ctx, parts[0], parts[1], opts)
				if err != nil {
					return fmt.Errorf("remote scan failed: %w", err)
				}
				return outputResult(result, format, output)

			case "gitlab":
				if token == "" {
					token = os.Getenv("GITLAB_TOKEN")
				}
				client := gitlabclient.NewClient(baseURL, token)
				result, err := client.ScanRemote(ctx, args[0], opts)
				if err != nil {
					return fmt.Errorf("gitlab scan failed: %w", err)
				}
				return outputResult(result, format, output)

			case "azure":
				if token == "" {
					token = os.Getenv("AZURE_DEVOPS_TOKEN")
				}
				parts := strings.SplitN(args[0], "/", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid format: use project/repo")
				}
				client := azureclient.NewClient(baseURL, token)
				result, err := client.ScanRemote(ctx, parts[0], parts[1], opts)
				if err != nil {
					return fmt.Errorf("azure scan failed: %w", err)
				}
				return outputResult(result, format, output)

			default:
				return fmt.Errorf("unknown platform %q (use github, gitlab, or azure)", platform)
			}
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table, json, sarif")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().StringVar(&severities, "severity", "", "Filter by severity (comma-separated)")
	cmd.Flags().StringVar(&rules, "rules", "", "Filter by rule ID (comma-separated)")
	cmd.Flags().StringVarP(&token, "token", "t", "", "API token (default: $GITHUB_TOKEN, $GITLAB_TOKEN, or $AZURE_DEVOPS_TOKEN)")
	cmd.Flags().StringVar(&platform, "platform", "github", "Platform: github, gitlab, azure")
	cmd.Flags().StringVar(&baseURL, "url", "", "Base URL for self-hosted instances (e.g., https://gitlab.example.com)")

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
		tokens     string
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

			// Build client with token rotation support
			var client *ghclient.Client
			if tokens != "" {
				tokenList := strings.Split(tokens, ",")
				for i := range tokenList {
					tokenList[i] = strings.TrimSpace(tokenList[i])
				}
				client = ghclient.NewClientWithTokens(tokenList)
				fmt.Printf("Using %d PATs with rotation\n", len(tokenList))
			} else {
				if token == "" {
					token = os.Getenv("GITHUB_TOKEN")
				}
				client = ghclient.NewClient(token)
			}
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
	cmd.Flags().StringVar(&tokens, "tokens", "", "Comma-separated GitHub tokens for PAT rotation")
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

// ingestRecord represents a single workflow file from BigQuery export.
type ingestRecord struct {
	Repo    string `json:"repo"`
	Path    string `json:"path"`
	Content string `json:"content"`
}

func newIngestCmd() *cobra.Command {
	var (
		dbPath     string
		severities string
		rules      string
		source     string
	)

	cmd := &cobra.Command{
		Use:   "ingest [file.jsonl]",
		Short: "Ingest pre-extracted workflow YAML from JSONL",
		Long: `Ingest workflow YAML from a JSONL file (e.g., BigQuery export).
Each line must be a JSON object: {"repo": "owner/repo", "path": ".github/workflows/ci.yml", "content": "..."}
Results are stored in SQLite for analysis.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("opening database: %w", err)
			}
			defer db.Close()

			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("opening input: %w", err)
			}
			defer f.Close()

			opts := parseScanOpts(severities, rules)
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0), 10*1024*1024) // 10MB max line

			var total, scanned, withFindings, errors int
			// Track workflows per repo for batch saving
			repoWorkflows := make(map[string][]ingestRecord)

			for sc.Scan() {
				total++
				var rec ingestRecord
				if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
					errors++
					continue
				}
				if rec.Repo == "" || rec.Content == "" {
					errors++
					continue
				}
				repoWorkflows[rec.Repo] = append(repoWorkflows[rec.Repo], rec)
			}
			if err := sc.Err(); err != nil {
				return fmt.Errorf("reading input: %w", err)
			}

			fmt.Printf("Loaded %d workflows from %d repos (%d errors)\n", total, len(repoWorkflows), errors)

			for repo, records := range repoWorkflows {
				parts := strings.SplitN(repo, "/", 2)
				if len(parts) != 2 {
					errors++
					continue
				}
				owner, name := parts[0], parts[1]

				result := &scanner.ScanResult{
					Path:      repo,
					Workflows: len(records),
				}

				for _, rec := range records {
					findings, err := scanner.ScanWorkflowBytes([]byte(rec.Content), rec.Path, opts)
					if err != nil {
						continue
					}
					result.Findings = append(result.Findings, findings...)
				}

				scanned++
				if len(result.Findings) > 0 {
					withFindings++
				}

				if err := db.SaveResultWithSource(owner, name, 0, "", result, source); err != nil {
					fmt.Fprintf(os.Stderr, "Error saving %s: %v\n", repo, err)
					errors++
				}

				if scanned%1000 == 0 {
					fmt.Printf("  Processed %d/%d repos...\n", scanned, len(repoWorkflows))
				}
			}

			fmt.Printf("\nIngest complete: %d repos scanned, %d with findings, %d errors\n",
				scanned, withFindings, errors)

			return nil
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "ingest.db", "SQLite database path")
	cmd.Flags().StringVar(&severities, "severity", "", "Filter by severity (comma-separated)")
	cmd.Flags().StringVar(&rules, "rules", "", "Filter by rule ID (comma-separated)")
	cmd.Flags().StringVar(&source, "source", "bigquery", "Source tag for these records")

	return cmd
}

func newGatoxImportCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "gatox-import [file.json]",
		Short: "Import Gato-X enumeration results as a repo list",
		Long: `Convert Gato-X JSON output to a Fluxgate repo list.
Reads Gato-X enumeration output and extracts unique repos for batch scanning.

Usage:
  gato-x enumerate -t <token> -o gatox-results.json
  fluxgate gatox-import gatox-results.json -o repos.txt
  fluxgate batch --list repos.txt --db gatox-scan.db --resume`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("reading input: %w", err)
			}

			// Gato-X outputs various JSON formats depending on the command.
			// Try to extract repo names from common patterns.
			repos := extractGatoxRepos(data)

			if len(repos) == 0 {
				return fmt.Errorf("no repos found in input file")
			}

			var w *os.File
			if output != "" {
				w, err = os.Create(output)
				if err != nil {
					return err
				}
				defer w.Close()
			} else {
				w = os.Stdout
			}

			for _, repo := range repos {
				fmt.Fprintln(w, repo)
			}

			fmt.Fprintf(os.Stderr, "Extracted %d unique repos\n", len(repos))
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output repo list file (default: stdout)")
	return cmd
}

// extractGatoxRepos parses various Gato-X output formats and extracts repo names.
func extractGatoxRepos(data []byte) []string {
	seen := make(map[string]bool)
	var repos []string

	// Try parsing as a JSON array of objects with "repo" or "full_name" fields
	var records []map[string]interface{}
	if err := json.Unmarshal(data, &records); err == nil {
		for _, rec := range records {
			for _, key := range []string{"repo", "full_name", "repository", "repo_name"} {
				if val, ok := rec[key]; ok {
					if s, ok := val.(string); ok && strings.Contains(s, "/") && !seen[s] {
						seen[s] = true
						repos = append(repos, s)
					}
				}
			}
		}
		return repos
	}

	// Try parsing as a JSON object with nested repo references
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err == nil {
		extractReposFromMap(obj, seen, &repos)
		return repos
	}

	// Try line-by-line JSON (JSONL)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec map[string]interface{}
		if err := json.Unmarshal([]byte(line), &rec); err == nil {
			for _, key := range []string{"repo", "full_name", "repository"} {
				if val, ok := rec[key]; ok {
					if s, ok := val.(string); ok && strings.Contains(s, "/") && !seen[s] {
						seen[s] = true
						repos = append(repos, s)
					}
				}
			}
		}
	}

	return repos
}

func extractReposFromMap(obj map[string]interface{}, seen map[string]bool, repos *[]string) {
	for _, key := range []string{"repo", "full_name", "repository"} {
		if val, ok := obj[key]; ok {
			if s, ok := val.(string); ok && strings.Contains(s, "/") && !seen[s] {
				seen[s] = true
				*repos = append(*repos, s)
			}
		}
	}
	// Recurse into nested objects and arrays
	for _, val := range obj {
		switch v := val.(type) {
		case map[string]interface{}:
			extractReposFromMap(v, seen, repos)
		case []interface{}:
			for _, item := range v {
				if m, ok := item.(map[string]interface{}); ok {
					extractReposFromMap(m, seen, repos)
				}
			}
		}
	}
}

func newDashboardCmd() *cobra.Command {
	var dbPaths []string
	var host string
	var port int

	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Launch interactive web dashboard for scan results",
		Long:  "Launch dashboard with one or more scan databases. Use multiple --db flags to enable the database switcher.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(dbPaths) == 0 {
				dbPaths = []string{"findings.db"}
			}

			var entries []dashboard.DBEntry
			for _, p := range dbPaths {
				db, err := store.Open(p)
				if err != nil {
					return fmt.Errorf("opening %s: %w", p, err)
				}
				defer db.Close()
				// Derive display name from filename
				name := strings.TrimSuffix(p, ".db")
				if idx := strings.LastIndex(name, "/"); idx >= 0 {
					name = name[idx+1:]
				}
				entries = append(entries, dashboard.DBEntry{Name: name, DB: db})
			}

			srv := dashboard.NewMulti(entries)
			addr := fmt.Sprintf("%s:%d", host, port)
			fmt.Printf("fluxgate dashboard listening on http://%s\n", addr)
			return srv.ListenAndServe(addr)
		},
	}
	cmd.Flags().StringSliceVar(&dbPaths, "db", nil, "Database path(s) — use multiple times for DB switcher")
	cmd.Flags().StringVar(&host, "host", "localhost", "Bind address")
	cmd.Flags().IntVar(&port, "port", 8080, "HTTP port")
	return cmd
}

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
			var w = os.Stdout
			if output != "" {
				f, err := os.Create(output)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
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

func newExportCmd() *cobra.Command {
	var dbPath, format, output string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export anonymized dataset for academic research",
		RunE: func(cmd *cobra.Command, args []string) error {
			var w = os.Stdout
			if output != "" {
				f, err := os.Create(output)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
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

func newDisclosureCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "disclosure",
		Short: "Track vulnerability disclosure lifecycle",
	}
	cmd.AddCommand(newDisclosureAddCmd())
	cmd.AddCommand(newDisclosureListCmd())
	cmd.AddCommand(newDisclosureUpdateCmd())
	cmd.AddCommand(newDisclosurePatchCmd())
	return cmd
}

func newDisclosureAddCmd() *cobra.Command {
	var findingID int64
	var channel, disclosureID, dbPath string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "File a new disclosure for a finding",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()

			disc, err := db.AddDisclosure(findingID, channel, disclosureID)
			if err != nil {
				return fmt.Errorf("adding disclosure: %w", err)
			}
			fmt.Printf("Disclosure #%d created (channel: %s, status: %s)\n", disc.ID, disc.Channel, disc.Status)
			return nil
		},
	}
	cmd.Flags().Int64Var(&findingID, "finding-id", 0, "Finding ID to disclose")
	cmd.Flags().StringVar(&channel, "channel", "", "Disclosure channel (GHSA, HackerOne, email, vendor-portal)")
	cmd.Flags().StringVar(&disclosureID, "id", "", "External disclosure ID")
	cmd.Flags().StringVar(&dbPath, "db", "findings.db", "Database path")
	cmd.MarkFlagRequired("finding-id")
	cmd.MarkFlagRequired("channel")
	return cmd
}

func newDisclosureListCmd() *cobra.Command {
	var status, dbPath string
	var findingID int64

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List disclosures",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()

			disclosures, err := db.ListDisclosures(status, findingID)
			if err != nil {
				return err
			}
			if len(disclosures) == 0 {
				fmt.Println("No disclosures found.")
				return nil
			}
			fmt.Printf("%-4s %-10s %-30s %-8s %-12s %-12s %s\n",
				"ID", "Channel", "Repo", "Rule", "Status", "Filed", "Disclosure ID")
			for _, d := range disclosures {
				filed := d.FiledAt.String
				if len(filed) > 10 {
					filed = filed[:10]
				}
				fmt.Printf("%-4d %-10s %-30s %-8s %-12s %-12s %s\n",
					d.ID, d.Channel, d.Owner+"/"+d.RepoName, d.RuleID, d.Status, filed, d.DisclosureID.String)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&status, "status", "", "Filter by status (filed/acknowledged/patched/wontfix/timeout)")
	cmd.Flags().Int64Var(&findingID, "finding-id", 0, "Filter by finding ID")
	cmd.Flags().StringVar(&dbPath, "db", "findings.db", "Database path")
	return cmd
}

func newDisclosureUpdateCmd() *cobra.Command {
	var id int64
	var status, dbPath string

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update disclosure status",
		RunE: func(cmd *cobra.Command, args []string) error {
			valid := map[string]bool{"filed": true, "acknowledged": true, "patched": true, "wontfix": true, "timeout": true}
			if !valid[status] {
				return fmt.Errorf("invalid status %q (must be filed/acknowledged/patched/wontfix/timeout)", status)
			}
			db, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()

			if err := db.UpdateDisclosureStatus(id, status); err != nil {
				return err
			}
			fmt.Printf("Disclosure #%d updated to status: %s\n", id, status)
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "Disclosure ID")
	cmd.Flags().StringVar(&status, "status", "", "New status")
	cmd.Flags().StringVar(&dbPath, "db", "findings.db", "Database path")
	cmd.MarkFlagRequired("id")
	cmd.MarkFlagRequired("status")
	return cmd
}

func newDisclosurePatchCmd() *cobra.Command {
	var disclosureID int64
	var commitURL, releaseTag, dbPath string

	cmd := &cobra.Command{
		Use:   "patch",
		Short: "Record a patch for a disclosure",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()

			p, err := db.AddPatch(disclosureID, commitURL, releaseTag)
			if err != nil {
				return err
			}
			fmt.Printf("Patch #%d recorded for disclosure #%d\n", p.ID, disclosureID)
			return nil
		},
	}
	cmd.Flags().Int64Var(&disclosureID, "disclosure-id", 0, "Disclosure ID")
	cmd.Flags().StringVar(&commitURL, "commit-url", "", "Fix commit URL")
	cmd.Flags().StringVar(&releaseTag, "release", "", "Release tag with fix")
	cmd.Flags().StringVar(&dbPath, "db", "findings.db", "Database path")
	cmd.MarkFlagRequired("disclosure-id")
	return cmd
}

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

func newSARIFPushCmd() *cobra.Command {
	var (
		dbPath string
		repo   string
		token  string
	)

	cmd := &cobra.Command{
		Use:   "sarif-push",
		Short: "Upload SARIF results to GitHub Code Scanning",
		Long:  "Query findings for a repo from the database, generate SARIF, and upload to GitHub Code Scanning API.",
		RunE: func(cmd *cobra.Command, args []string) error {
			parts := strings.SplitN(repo, "/", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid repo format: use owner/repo")
			}
			owner, name := parts[0], parts[1]

			if token == "" {
				token = os.Getenv("GITHUB_TOKEN")
			}
			if token == "" {
				return fmt.Errorf("GitHub token required (--token or $GITHUB_TOKEN)")
			}

			db, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("opening database: %w", err)
			}
			defer db.Close()

			// Query findings for this repo
			records, err := db.GetFindingsForRepo(owner, name)
			if err != nil {
				return fmt.Errorf("querying findings: %w", err)
			}
			if len(records) == 0 {
				fmt.Printf("No findings for %s/%s\n", owner, name)
				return nil
			}

			// Convert FindingRecords back to scanner.Finding
			var findings []scanner.Finding
			for _, r := range records {
				findings = append(findings, scanner.Finding{
					RuleID:   r.RuleID,
					Severity: r.Severity,
					File:     r.WorkflowPath,
					Line:     r.LineNumber,
					Message:  r.Description,
					Details:  r.Details,
				})
			}

			result := &scanner.ScanResult{
				Path:      fmt.Sprintf("%s/%s", owner, name),
				Workflows: len(records),
				Findings:  findings,
			}

			// Generate SARIF to buffer
			var sarifBuf bytes.Buffer
			if err := report.WriteSARIF(&sarifBuf, result); err != nil {
				return fmt.Errorf("generating SARIF: %w", err)
			}

			// Gzip + base64 encode (required by GitHub)
			var gzBuf bytes.Buffer
			gz := gzip.NewWriter(&gzBuf)
			if _, err := gz.Write(sarifBuf.Bytes()); err != nil {
				return fmt.Errorf("gzip compress: %w", err)
			}
			if err := gz.Close(); err != nil {
				return fmt.Errorf("gzip close: %w", err)
			}
			encoded := base64.StdEncoding.EncodeToString(gzBuf.Bytes())

			// Upload to GitHub Code Scanning API
			payload := map[string]string{
				"commit_sha": "HEAD",
				"ref":        "refs/heads/main",
				"sarif":      encoded,
			}
			payloadBytes, _ := json.Marshal(payload)

			url := fmt.Sprintf("https://api.github.com/repos/%s/%s/code-scanning/sarifs", owner, name)
			req, err := http.NewRequest("POST", url, bytes.NewReader(payloadBytes))
			if err != nil {
				return fmt.Errorf("creating request: %w", err)
			}
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("uploading SARIF: %w", err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode >= 300 {
				return fmt.Errorf("GitHub API error (%d): %s", resp.StatusCode, string(body))
			}

			fmt.Printf("SARIF uploaded for %s/%s (%d findings)\n", owner, name, len(findings))
			fmt.Printf("Response: %s\n", string(body))
			return nil
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "findings.db", "Database path")
	cmd.Flags().StringVar(&repo, "repo", "", "Repository (owner/repo)")
	cmd.Flags().StringVarP(&token, "token", "t", "", "GitHub token (default: $GITHUB_TOKEN)")
	cmd.MarkFlagRequired("repo")
	return cmd
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
