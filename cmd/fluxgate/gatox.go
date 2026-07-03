package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

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

			w, closeFn, err := openOutput(output)
			if err != nil {
				return err
			}
			defer closeFn()

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
