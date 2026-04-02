package dashboard

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/north-echo/fluxgate/internal/store"
)

//go:embed templates/*.html templates/partials/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// DBEntry holds a named database connection.
type DBEntry struct {
	Name string
	DB   *store.DB
}

// Server serves the fluxgate dashboard web UI.
type Server struct {
	dbs       []DBEntry
	dbsByName map[string]*store.DB
	pages     map[string]*template.Template
	mux       http.ServeMux
}

var funcMap = template.FuncMap{
	"add": func(a, b int) int { return a + b },
	"sub": func(a, b int) int { return a - b },
	"seq": func(n int) []int {
		s := make([]int, n)
		for i := range s {
			s[i] = i
		}
		return s
	},
}

// New creates a new dashboard server backed by the given database.
// For single-DB mode; wraps NewMulti.
func New(db *store.DB) *Server {
	return NewMulti([]DBEntry{{Name: "default", DB: db}})
}

// NewMulti creates a dashboard server with multiple named databases.
func NewMulti(dbs []DBEntry) *Server {
	byName := make(map[string]*store.DB, len(dbs))
	for _, e := range dbs {
		byName[e.Name] = e.DB
	}
	s := &Server{
		dbs:       dbs,
		dbsByName: byName,
		pages:     make(map[string]*template.Template),
	}

	// Parse each page template independently with the layout so {{define "content"}} doesn't collide
	layout := "templates/layout.html"
	pages := map[string][]string{
		"overview":    {layout, "templates/overview.html"},
		"findings":    {layout, "templates/findings.html", "templates/partials/findings-table.html"},
		"repo":        {layout, "templates/repo.html"},
		"disclosures": {layout, "templates/disclosures.html"},
	}
	for name, files := range pages {
		s.pages[name] = template.Must(
			template.New("").Funcs(funcMap).ParseFS(templateFS, files...),
		)
	}

	// Standalone partial (no layout) for HTMX responses
	s.pages["findings-table"] = template.Must(
		template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/partials/findings-table.html"),
	)

	// Static file server from embedded FS
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(fmt.Sprintf("dashboard: embedded static fs: %v", err))
	}

	// Register routes
	s.mux.HandleFunc("GET /", s.overviewHandler)
	s.mux.HandleFunc("GET /findings", s.findingsHandler)
	s.mux.HandleFunc("GET /findings/export.csv", s.findingsExportHandler)
	s.mux.HandleFunc("GET /repos/{owner}/{name}", s.repoHandler)
	s.mux.HandleFunc("GET /disclosures", s.disclosuresHandler)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	return s
}

// ListenAndServe starts the dashboard HTTP server on the given address.
func (s *Server) ListenAndServe(addr string) error {
	fmt.Printf("fluxgate dashboard listening on %s\n", addr)
	return http.ListenAndServe(addr, &s.mux)
}

// Handler returns the underlying http.Handler for embedding in other servers.
func (s *Server) Handler() http.Handler {
	return &s.mux
}

// activeDB returns the database selected by the ?db= query param, or the first one.
func (s *Server) activeDB(r *http.Request) (*store.DB, string) {
	name := r.URL.Query().Get("db")
	if db, ok := s.dbsByName[name]; ok {
		return db, name
	}
	// Default to first
	return s.dbs[0].DB, s.dbs[0].Name
}

// pageContext wraps page-specific data with the DB selector context.
type pageContext struct {
	DBs      []DBEntry
	ActiveDB string
	Data     any
}

// renderPage executes a named page template (layout + content).
func (s *Server) renderPage(w http.ResponseWriter, r *http.Request, page string, data any) {
	tmpl, ok := s.pages[page]
	if !ok {
		http.Error(w, fmt.Sprintf("unknown page: %s", page), http.StatusInternalServerError)
		return
	}
	_, activeDB := s.activeDB(r)
	ctx := pageContext{
		DBs:      s.dbs,
		ActiveDB: activeDB,
		Data:     data,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout.html", ctx); err != nil {
		http.Error(w, fmt.Sprintf("template error: %v", err), http.StatusInternalServerError)
	}
}

// renderPartial executes a partial template without the layout.
func (s *Server) renderPartial(w http.ResponseWriter, name string, data any) {
	tmpl, ok := s.pages[name]
	if !ok {
		http.Error(w, fmt.Sprintf("unknown partial: %s", name), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, fmt.Sprintf("template error: %v", err), http.StatusInternalServerError)
	}
}
