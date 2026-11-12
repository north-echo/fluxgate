package main

import (
	"path/filepath"
	"testing"

	"github.com/north-echo/fluxgate/internal/scanner"
)

func TestRelativizeFindingPaths(t *testing.T) {
	dir := filepath.Join("clones", "acme", "app")
	result := &scanner.ScanResult{Findings: []scanner.Finding{
		{File: filepath.Join(dir, ".github", "workflows", "ci.yml")},
		{File: filepath.Join(dir, ".gitlab-ci.yml")},
		{File: filepath.Join("elsewhere", "ci.yml")}, // outside dir: left alone
	}}
	relativizeFindingPaths(dir, result)
	want := []string{".github/workflows/ci.yml", ".gitlab-ci.yml", filepath.Join("elsewhere", "ci.yml")}
	for i, f := range result.Findings {
		if f.File != want[i] {
			t.Errorf("finding %d: got %q, want %q", i, f.File, want[i])
		}
	}
}
