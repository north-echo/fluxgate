package main

import (
	"fmt"
	"strings"

	"github.com/north-echo/fluxgate/internal/dashboard"
	"github.com/north-echo/fluxgate/internal/store"
	"github.com/spf13/cobra"
)

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
				// Read-only pool: the dashboard never writes, and WAL
				// supports concurrent readers that the single-connection
				// writer pool would otherwise serialize.
				db, err := store.OpenReadOnly(p)
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
