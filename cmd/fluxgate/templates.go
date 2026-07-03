package main

import (
	"fmt"
	"strings"

	"github.com/north-echo/fluxgate/internal/store"
	"github.com/spf13/cobra"
)

func newTemplatesCmd() *cobra.Command {
	var (
		dbPath     string
		minRepos   int
		maxShown   int
		showHash   bool
		ruleFilter string
	)

	cmd := &cobra.Command{
		Use:   "templates",
		Short: "Find workflow files shared verbatim across multiple repos",
		Long: "Group findings by workflow file hash to discover template propagation — when the same workflow appears\n" +
			"in N repos, one upstream fix or one disclosure brief covers all of them. Requires scans run with v0.7.7+\n" +
			"(workflow_hash column populated).",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("opening database: %w", err)
			}
			defer db.Close()

			type cluster struct {
				Hash      string `db:"workflow_hash"`
				RepoCount int    `db:"repo_count"`
				RuleCount int    `db:"rule_count"`
				Samples   string `db:"samples"`
			}

			query := `
				SELECT
					f.workflow_hash AS workflow_hash,
					COUNT(DISTINCT f.repo_id) AS repo_count,
					COUNT(DISTINCT f.rule_id) AS rule_count,
					GROUP_CONCAT(DISTINCT r.owner || '/' || r.name || ':' || f.workflow_path) AS samples
				FROM findings f
				JOIN repos r ON r.id = f.repo_id
				WHERE f.workflow_hash != ''`
			args2 := []interface{}{}
			if ruleFilter != "" {
				query += " AND f.rule_id = ?"
				args2 = append(args2, ruleFilter)
			}
			query += `
				GROUP BY f.workflow_hash
				HAVING repo_count >= ?
				ORDER BY repo_count DESC, rule_count DESC`
			args2 = append(args2, minRepos)

			var clusters []cluster
			if err := db.SqlxDB().Select(&clusters, query, args2...); err != nil {
				return fmt.Errorf("querying templates: %w", err)
			}

			if len(clusters) == 0 {
				fmt.Printf("No template clusters found (min-repos=%d).\n", minRepos)
				fmt.Println("If results look empty on a pre-existing DB, the scan likely predates the workflow_hash column. Re-scan to populate.")
				return nil
			}

			fmt.Printf("Template clusters (workflows appearing in >= %d repos):\n\n", minRepos)
			for _, c := range clusters {
				hashLabel := c.Hash[:12]
				if showHash {
					hashLabel = c.Hash
				}
				fmt.Printf("  %s  %d repos, %d distinct rules\n", hashLabel, c.RepoCount, c.RuleCount)
				instances := strings.Split(c.Samples, ",")
				shown := maxShown
				if shown > len(instances) {
					shown = len(instances)
				}
				for i := 0; i < shown; i++ {
					fmt.Printf("      %s\n", instances[i])
				}
				if len(instances) > shown {
					fmt.Printf("      ... and %d more\n", len(instances)-shown)
				}
				fmt.Println()
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "findings.db", "Database path")
	cmd.Flags().IntVar(&minRepos, "min-repos", 2, "Minimum repos sharing a workflow to include the cluster")
	cmd.Flags().IntVar(&maxShown, "show", 5, "Maximum instances to display per cluster")
	cmd.Flags().BoolVar(&showHash, "full-hash", false, "Show full SHA-256 hash instead of 12-char prefix")
	cmd.Flags().StringVar(&ruleFilter, "rule", "", "Only include workflows with findings for this rule ID (e.g. FG-022)")
	return cmd
}
