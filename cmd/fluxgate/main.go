package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	gitclone "github.com/north-echo/fluxgate/internal/git"
	ghclient "github.com/north-echo/fluxgate/internal/github"
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
		top         int
		dbPath      string
		list        string
		resume      bool
		delay       time.Duration
		reportPath  string
		token       string
		severities  string
		rules       string
		useClone    bool
		concurrency int
		keepDir     string
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

			if useClone {
				if err := gitclone.CheckGit(); err != nil {
					return err
				}
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
				cacheKey := fmt.Sprintf("top:%d", top)
				if resume {
					cached, _ := db.LoadRepoList(cacheKey)
					if cached != nil {
						fmt.Printf("Loaded %d repos from cache\n\n", len(cached))
						for _, c := range cached {
							repos = append(repos, ghclient.RepoInfo{Owner: c.Owner, Name: c.Name, Stars: c.Stars, Language: c.Language})
						}
					}
				}
				if len(repos) == 0 {
					fmt.Printf("Fetching top %d repos by stars...\n", top)
					repos, err = client.FetchTopRepos(ctx, top)
					if err != nil {
						return fmt.Errorf("fetching top repos: %w", err)
					}
					fmt.Printf("Found %d repos\n\n", len(repos))

					entries := make([]store.RepoListEntry, len(repos))
					for i, r := range repos {
						entries[i] = store.RepoListEntry{Owner: r.Owner, Name: r.Name, Stars: r.Stars, Language: r.Language}
					}
					if saveErr := db.SaveRepoList(cacheKey, entries); saveErr != nil {
						fmt.Fprintf(os.Stderr, "Warning: could not cache repo list: %v\n", saveErr)
					}
				}
			} else {
				return fmt.Errorf("specify --top N or --list file")
			}

			if useClone {
				return batchScanWithClone(ctx, repos, cloneScanOptions{
					DB:          db,
					Token:       token,
					ScanOpts:    parseScanOpts(severities, rules),
					Resume:      resume,
					Concurrency: concurrency,
					KeepDir:     keepDir,
				})
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
	cmd.Flags().BoolVar(&useClone, "clone", false, "Use git sparse checkout instead of API (avoids rate limits)")
	cmd.Flags().IntVar(&concurrency, "concurrency", 5, "Number of concurrent clone operations (used with --clone)")
	cmd.Flags().StringVar(&keepDir, "keep", "", "Keep cloned repos in this directory instead of cleaning up")

	return cmd
}

// cloneScanOptions groups parameters for clone-based batch scanning.
type cloneScanOptions struct {
	DB          *store.DB
	Token       string
	ScanOpts    scanner.ScanOptions
	Resume      bool
	Concurrency int
	KeepDir     string
}

// batchScanWithClone scans repos by sparse-cloning them locally instead of
// fetching workflows via the GitHub API. Each repo is cloned, scanned, and
// cleaned up within a goroutine, bounding disk usage to O(concurrency).
func batchScanWithClone(ctx context.Context, repos []ghclient.RepoInfo, copts cloneScanOptions) error {
	var toScan []ghclient.RepoInfo
	for _, repo := range repos {
		if copts.Resume {
			already, err := copts.DB.IsRepoScanned(repo.Owner, repo.Name)
			if err != nil {
				return fmt.Errorf("checking if %s/%s is scanned: %w", repo.Owner, repo.Name, err)
			}
			if already {
				continue
			}
		}
		toScan = append(toScan, repo)
	}

	if len(toScan) == 0 {
		fmt.Println("All repos already scanned.")
		return nil
	}

	if copts.KeepDir != "" {
		fmt.Fprintf(os.Stderr, "Keeping clones in: %s\n", copts.KeepDir)
		if err := os.MkdirAll(copts.KeepDir, 0o750); err != nil {
			return fmt.Errorf("creating keep dir: %w", err)
		}
	}

	repoInfo := make(map[string]ghclient.RepoInfo, len(toScan))
	cloneRepos := make([]gitclone.Repo, len(toScan))
	for i, r := range toScan {
		cloneRepos[i] = gitclone.Repo{Owner: r.Owner, Name: r.Name}
		repoInfo[r.Owner+"/"+r.Name] = r
	}

	fmt.Printf("Scanning %d repos via clone (concurrency: %d)...\n", len(toScan), copts.Concurrency)

	results := gitclone.CloneAndScan(ctx, cloneRepos, copts.Concurrency, copts.Token, copts.KeepDir,
		func(owner, name, dir string, cr *gitclone.CloneResult) error {
			key := owner + "/" + name
			info := repoInfo[key]

			scanResult, err := scanner.ScanDirectory(dir, copts.ScanOpts)
			if err != nil {
				emptyResult := &scanner.ScanResult{Path: key}
				if saveErr := copts.DB.SaveResult(owner, name, info.Stars, info.Language, emptyResult); saveErr != nil {
					fmt.Fprintf(os.Stderr, "  Warning: could not save error state: %v\n", saveErr)
				}
				return err
			}

			cr.SetFindings(len(scanResult.Findings), scanResult.Workflows)
			scanResult.Path = key
			return copts.DB.SaveResult(owner, name, info.Stars, info.Language, scanResult)
		})

	scanned, withFindings := 0, 0
	for i, cr := range results {
		key := cr.Owner + "/" + cr.Name
		info := repoInfo[key]

		fmt.Printf("[%d/%d] %s", i+1, len(results), key)
		if info.Stars > 0 {
			fmt.Printf(" (%d stars)", info.Stars)
		}

		if cr.Err != nil {
			fmt.Printf(" error: %v\n", cr.Err)
			continue
		}

		scanned++
		if cr.Findings > 0 {
			withFindings++
			fmt.Printf(" %d issues in %d workflows\n", cr.Findings, cr.Workflows)
		} else {
			fmt.Println(" clean")
		}
	}

	fmt.Printf("\nBatch complete: %d scanned, %d with findings, %d skipped\n",
		scanned, withFindings, len(repos)-len(toScan))
	return nil
}

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
			if token == "" {
				token = os.Getenv("GITHUB_TOKEN")
			}

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
				return batchScanWithClone(ctx, repos, cloneScanOptions{
					DB:          db,
					Token:       token,
					ScanOpts:    parseScanOpts(severities, rules),
					Resume:      resume,
					Concurrency: concurrency,
					KeepDir:     keepDir,
				})
			}

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
	cmd.Flags().BoolVar(&useClone, "clone", false, "Use git sparse checkout instead of API (avoids rate limits)")
	cmd.Flags().IntVar(&concurrency, "concurrency", 5, "Number of concurrent clone operations (used with --clone)")
	cmd.Flags().StringVar(&keepDir, "keep", "", "Keep cloned repos in this directory instead of cleaning up")

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
