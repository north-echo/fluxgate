package main

import (
	"fmt"
	"strings"

	"github.com/north-echo/fluxgate/internal/store"
	"github.com/spf13/cobra"
)

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
	var status, disclosureID, notes, dbPath string

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update disclosure status, external ID, or notes",
		RunE: func(cmd *cobra.Command, args []string) error {
			if status == "" && disclosureID == "" && notes == "" {
				return fmt.Errorf("at least one of --status, --disclosure-id, or --notes must be provided")
			}
			if status != "" {
				valid := map[string]bool{"filed": true, "acknowledged": true, "patched": true, "wontfix": true, "timeout": true}
				if !valid[status] {
					return fmt.Errorf("invalid status %q (must be filed/acknowledged/patched/wontfix/timeout)", status)
				}
			}
			db, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()

			updates := []string{}
			if status != "" {
				if err := db.UpdateDisclosureStatus(id, status); err != nil {
					return err
				}
				updates = append(updates, "status="+status)
			}
			if disclosureID != "" {
				if err := db.UpdateDisclosureID(id, disclosureID); err != nil {
					return err
				}
				updates = append(updates, "disclosure-id="+disclosureID)
			}
			if notes != "" {
				if err := db.UpdateDisclosureNotes(id, notes); err != nil {
					return err
				}
				updates = append(updates, "notes updated")
			}
			fmt.Printf("Disclosure #%d updated: %s\n", id, strings.Join(updates, ", "))
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "Disclosure ID")
	cmd.Flags().StringVar(&status, "status", "", "New status (filed/acknowledged/patched/wontfix/timeout)")
	cmd.Flags().StringVar(&disclosureID, "disclosure-id", "", "External disclosure ID")
	cmd.Flags().StringVar(&notes, "notes", "", "Free-form notes")
	cmd.Flags().StringVar(&dbPath, "db", "findings.db", "Database path")
	cmd.MarkFlagRequired("id")
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
