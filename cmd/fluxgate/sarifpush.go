package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/north-echo/fluxgate/internal/report"
	"github.com/north-echo/fluxgate/internal/scanner"
	"github.com/north-echo/fluxgate/internal/store"
	"github.com/spf13/cobra"
)

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

			token = resolveToken(token, "GITHUB_TOKEN")
			if token == "" {
				return fmt.Errorf("GitHub token required (--token or $GITHUB_TOKEN)")
			}

			return withDB(dbPath, func(db *store.DB) error {
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
			})
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "findings.db", "Database path")
	cmd.Flags().StringVar(&repo, "repo", "", "Repository (owner/repo)")
	cmd.Flags().StringVarP(&token, "token", "t", "", "GitHub token (default: $GITHUB_TOKEN)")
	cmd.MarkFlagRequired("repo")
	return cmd
}
