package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	gitclone "github.com/north-echo/fluxgate/internal/git"
	ghclient "github.com/north-echo/fluxgate/internal/github"
	"github.com/north-echo/fluxgate/internal/scanner"
	"github.com/north-echo/fluxgate/internal/store"
	"github.com/spf13/cobra"
)

func newBatchCmd() *cobra.Command {
	var (
		top         int
		dbPath      string
		list        string
		resume      bool
		delay       time.Duration
		reportPath  string
		token       string
		tokens      string
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

			return withDB(dbPath, func(db *store.DB) error {
				// Report-only mode
				if reportPath != "" && top == 0 && list == "" {
					return generateReport(db, reportPath)
				}

				// Build the token pool: --tokens/$GITHUB_TOKENS for rotation,
				// falling back to --token/$GITHUB_TOKEN. Both the API client and
				// the clone path draw from the same pool.
				tokens = resolveToken(tokens, "GITHUB_TOKENS")
				var tokenList []string
				for _, t := range strings.Split(tokens, ",") {
					if t = strings.TrimSpace(t); t != "" {
						tokenList = append(tokenList, t)
					}
				}
				if len(tokenList) == 0 {
					token = resolveToken(token, "GITHUB_TOKEN")
					if token != "" {
						tokenList = []string{token}
					}
				}
				client := ghclient.NewClientWithTokens(tokenList)
				if len(tokenList) > 1 {
					fmt.Printf("Using %d PATs with rotation\n", len(tokenList))
				}

				if useClone {
					if err := gitclone.CheckGit(); err != nil {
						return err
					}
				}
				ctx := context.Background()

				var repos []ghclient.RepoInfo
				var err error
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
						Tokens:      tokenList,
						ScanOpts:    parseScanOpts(severities, rules),
						Resume:      resume,
						Concurrency: concurrency,
						KeepDir:     keepDir,
					})
				}

				batchOpts := ghclient.BatchOptions{
					Top:         top,
					List:        list,
					Resume:      resume,
					Delay:       delay,
					Concurrency: concurrency,
					DB:          db,
					Opts:        parseScanOpts(severities, rules),
				}

				if err := client.BatchScan(ctx, repos, batchOpts); err != nil {
					return fmt.Errorf("batch scan: %w", err)
				}

				// Auto-generate report if requested
				if reportPath != "" {
					return generateReport(db, reportPath)
				}

				return nil
			})
		},
	}

	cmd.Flags().IntVar(&top, "top", 0, "Scan top N repos by star count")
	cmd.Flags().StringVar(&dbPath, "db", "findings.db", "SQLite database path")
	cmd.Flags().StringVar(&list, "list", "", "File with repos to scan (one owner/repo per line)")
	cmd.Flags().BoolVar(&resume, "resume", false, "Skip repos already in the database")
	cmd.Flags().StringVar(&reportPath, "report", "", "Generate markdown report to this path")
	cmd.Flags().StringVarP(&token, "token", "t", "", "GitHub token (default: $GITHUB_TOKEN)")
	cmd.Flags().StringVar(&tokens, "tokens", "", "Comma-separated GitHub tokens for PAT rotation (default: $GITHUB_TOKENS)")
	cmd.Flags().StringVar(&severities, "severity", "", "Filter by severity (comma-separated)")
	cmd.Flags().StringVar(&rules, "rules", "", "Filter by rule ID (comma-separated)")
	cmd.Flags().DurationVar(&delay, "delay", 0, "Delay between repos when the rate budget runs low (e.g. 1s, 500ms)")
	cmd.Flags().BoolVar(&useClone, "clone", false, "Use git sparse checkout instead of API (avoids rate limits)")
	cmd.Flags().IntVar(&concurrency, "concurrency", 5, "Number of concurrent repo scans (API and --clone modes)")
	cmd.Flags().StringVar(&keepDir, "keep", "", "Keep cloned repos in this directory instead of cleaning up")

	return cmd
}

// cloneScanOptions groups parameters for clone-based batch scanning.
type cloneScanOptions struct {
	DB          *store.DB
	Tokens      []string
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
		// Skip repos known to have no workflows — no point spawning git for them.
		if copts.DB.HasNoWorkflows(repo.Owner, repo.Name, 7) {
			continue
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

	results := gitclone.CloneAndScan(ctx, cloneRepos, copts.Concurrency, copts.Tokens, copts.KeepDir,
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

			if scanResult.Workflows == 0 {
				copts.DB.MarkNoWorkflows(owner, name)
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
