package dashboard

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/north-echo/fluxgate/internal/store"
)

// overviewData holds template data for the overview page.
type overviewData struct {
	Stats           *store.ReportStats
	Heatmap         map[string]map[string]int // owner -> severity -> count
	HeatmapOrgs     []string
	Severities      []string
	DisclosureStats *store.DisclosureStats
	TopRepos        []store.Repo
	RuleDistribution []ruleBar
}

// ruleBar holds a rule's count and its percentage for the distribution bar.
type ruleBar struct {
	RuleID  string
	Count   int
	Percent int
}

// findingsData holds template data for the findings page.
type findingsData struct {
	Findings []store.FindingWithRepo
	Total    int
	Page     int
	PageSize int
	Severity string
	Rule     string
	Owner    string
	HasMore  bool
	NextPage int
}

// repoData holds template data for the repo detail page.
type repoData struct {
	Detail *store.RepoDetail
}

// disclosuresData holds template data for the disclosures page.
type disclosuresData struct {
	Disclosures []store.DisclosureWithContext
}

// overviewHandler renders the main dashboard overview with severity heatmap.
func (s *Server) overviewHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	db, _ := s.activeDB(r)

	stats, err := db.GetReportStats()
	if err != nil {
		http.Error(w, "failed to load stats: "+err.Error(), http.StatusInternalServerError)
		return
	}

	orgSev, err := db.GetSeverityByOrg()
	if err != nil {
		http.Error(w, "failed to load heatmap: "+err.Error(), http.StatusInternalServerError)
		return
	}

	heatmap := make(map[string]map[string]int)
	orgSet := make(map[string]bool)
	for _, os := range orgSev {
		if _, ok := heatmap[os.Owner]; !ok {
			heatmap[os.Owner] = make(map[string]int)
		}
		heatmap[os.Owner][os.Severity] = os.Count
		orgSet[os.Owner] = true
	}

	var orgs []string
	for org := range orgSet {
		orgs = append(orgs, org)
	}

	discStats, err := db.GetDisclosureStats()
	if err != nil {
		discStats = &store.DisclosureStats{}
	}

	topRepos, err := db.GetTopRepos(10)
	if err != nil {
		topRepos = nil
	}

	// Build rule distribution bars
	var ruleBars []ruleBar
	if stats.TotalFindings > 0 {
		for rule, count := range stats.ByRule {
			pct := count * 100 / stats.TotalFindings
			if pct < 1 {
				pct = 1
			}
			ruleBars = append(ruleBars, ruleBar{
				RuleID:  rule,
				Count:   count,
				Percent: pct,
			})
		}
	}

	data := overviewData{
		Stats:            stats,
		Heatmap:          heatmap,
		HeatmapOrgs:      orgs,
		Severities:       []string{"critical", "high", "medium", "low", "info"},
		DisclosureStats:  discStats,
		TopRepos:         topRepos,
		RuleDistribution: ruleBars,
	}

	s.renderPage(w, r, "overview", data)
}

// findingsHandler renders paginated, filterable findings.
func (s *Server) findingsHandler(w http.ResponseWriter, r *http.Request) {
	db, _ := s.activeDB(r)

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	const pageSize = 50

	severity := r.URL.Query().Get("severity")
	rule := r.URL.Query().Get("rule")
	owner := r.URL.Query().Get("owner")

	offset := (page - 1) * pageSize
	findings, total, err := db.ListFindings(offset, pageSize, severity, rule, owner)
	if err != nil {
		http.Error(w, "failed to load findings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := findingsData{
		Findings: findings,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
		Severity: severity,
		Rule:     rule,
		Owner:    owner,
		HasMore:  offset+pageSize < total,
		NextPage: page + 1,
	}

	if r.Header.Get("HX-Request") == "true" {
		s.renderPartial(w, "findings-table", data)
		return
	}

	s.renderPage(w, r, "findings", data)
}

// repoHandler renders the detail view for a single repository.
func (s *Server) repoHandler(w http.ResponseWriter, r *http.Request) {
	db, _ := s.activeDB(r)

	owner := r.PathValue("owner")
	name := r.PathValue("name")

	if owner == "" || name == "" {
		http.Error(w, "missing owner or name", http.StatusBadRequest)
		return
	}

	detail, err := db.GetRepoDetail(owner, name)
	if err != nil {
		http.Error(w, "repo not found: "+err.Error(), http.StatusNotFound)
		return
	}

	data := repoData{Detail: detail}
	s.renderPage(w, r, "repo", data)
}

// findingsExportHandler exports all findings (with current filters) as CSV.
func (s *Server) findingsExportHandler(w http.ResponseWriter, r *http.Request) {
	db, _ := s.activeDB(r)

	severity := r.URL.Query().Get("severity")
	rule := r.URL.Query().Get("rule")
	owner := r.URL.Query().Get("owner")

	// Fetch all matching findings (no pagination)
	findings, _, err := db.ListFindings(0, 1000000, severity, rule, owner)
	if err != nil {
		http.Error(w, "failed to export findings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Build descriptive filename
	filename := "fluxgate-findings"
	if severity != "" {
		filename += "-" + severity
	}
	if owner != "" {
		filename += "-" + owner
	}
	filename += ".csv"

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))

	cw := csv.NewWriter(w)
	cw.Write([]string{"Severity", "Rule", "Owner", "Repo", "Workflow", "Line", "Description", "Details"})
	for _, f := range findings {
		// Sanitize newlines in description/details for cleaner CSV
		desc := strings.ReplaceAll(f.Description, "\n", " ")
		details := strings.ReplaceAll(f.Details, "\n", " ")
		cw.Write([]string{
			f.Severity, f.RuleID, f.Owner, f.RepoName,
			f.WorkflowPath, fmt.Sprintf("%d", f.LineNumber),
			desc, details,
		})
	}
	cw.Flush()
}

// disclosuresHandler renders the disclosure tracking table.
func (s *Server) disclosuresHandler(w http.ResponseWriter, r *http.Request) {
	db, _ := s.activeDB(r)

	disclosures, err := db.ListDisclosures("", 0)
	if err != nil {
		http.Error(w, "failed to load disclosures: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := disclosuresData{Disclosures: disclosures}
	s.renderPage(w, r, "disclosures", data)
}
