package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/north-echo/fluxgate/internal/scanner"
	"github.com/north-echo/fluxgate/internal/store"
	"github.com/spf13/cobra"
)

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
			return withDB(dbPath, func(db *store.DB) error {
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
			})
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "ingest.db", "SQLite database path")
	cmd.Flags().StringVar(&severities, "severity", "", "Filter by severity (comma-separated)")
	cmd.Flags().StringVar(&rules, "rules", "", "Filter by rule ID (comma-separated)")
	cmd.Flags().StringVar(&source, "source", "bigquery", "Source tag for these records")

	return cmd
}
