package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// BenchmarkScanFixtures runs the full rule set over every GitHub Actions
// fixture, approximating the per-repo scan cost in a batch run.
func BenchmarkScanFixtures(b *testing.B) {
	dir := filepath.Join("..", "..", "test", "fixtures")
	entries, err := os.ReadDir(dir)
	if err != nil {
		b.Fatalf("reading fixtures: %v", err)
	}

	var workflows []*Workflow
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		wf, err := ParseWorkflow(data, name)
		if err != nil {
			continue // platform fixtures that aren't GH workflows
		}
		workflows = append(workflows, wf)
	}
	if len(workflows) == 0 {
		b.Fatal("no parseable workflow fixtures found")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, wf := range workflows {
			ScanWorkflow(wf, ScanOptions{})
		}
	}
}

// BenchmarkParseAndScanFixtures includes parsing, matching what ScanFile does.
func BenchmarkParseAndScanFixtures(b *testing.B) {
	dir := filepath.Join("..", "..", "test", "fixtures")
	entries, err := os.ReadDir(dir)
	if err != nil {
		b.Fatalf("reading fixtures: %v", err)
	}

	type raw struct {
		name string
		data []byte
	}
	var files []raw
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if _, err := ParseWorkflow(data, name); err != nil {
			continue
		}
		files = append(files, raw{name, data})
	}
	if len(files) == 0 {
		b.Fatal("no parseable workflow fixtures found")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, f := range files {
			_, _ = ScanWorkflowBytes(f.data, f.name, ScanOptions{})
		}
	}
}
