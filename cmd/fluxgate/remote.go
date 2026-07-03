package main

import (
	"context"
	"fmt"
	"strings"

	azureclient "github.com/north-echo/fluxgate/internal/azure"
	ghclient "github.com/north-echo/fluxgate/internal/github"
	gitlabclient "github.com/north-echo/fluxgate/internal/gitlab"
	"github.com/spf13/cobra"
)

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
			token = resolveToken(token, "GITHUB_TOKEN")

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
				token = resolveToken(token, "GITLAB_TOKEN")
				client := gitlabclient.NewClient(baseURL, token)
				result, err := client.ScanRemote(ctx, args[0], opts)
				if err != nil {
					return fmt.Errorf("gitlab scan failed: %w", err)
				}
				return outputResult(result, format, output)

			case "azure":
				token = resolveToken(token, "AZURE_DEVOPS_TOKEN")
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
