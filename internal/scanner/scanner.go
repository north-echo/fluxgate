package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ScanOptions configures a scan run.
type ScanOptions struct {
	Severities []string // filter by severity (empty = all)
	Rules      []string // filter by rule ID (empty = all)
}

// ScanResult holds all findings from a scan.
type ScanResult struct {
	Path      string
	Workflows int
	Findings  []Finding
}

// ScanDirectory scans all workflow files in a directory's .github/workflows/ folder.
func ScanDirectory(dir string, opts ScanOptions) (*ScanResult, error) {
	workflowDir := filepath.Join(dir, ".github", "workflows")
	info, err := os.Stat(workflowDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, os.ErrNotExist
	}

	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		return nil, err
	}

	result := &ScanResult{Path: workflowDir}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		path := filepath.Join(workflowDir, name)
		findings, err := ScanFile(path, opts)
		if err != nil {
			continue // skip unparseable files
		}
		result.Workflows++
		result.Findings = append(result.Findings, findings...)
	}

	sortFindings(result.Findings)
	return result, nil
}

// ScanFile scans a single workflow file and returns findings.
func ScanFile(path string, opts ScanOptions) ([]Finding, error) {
	wf, err := ParseWorkflowFile(path)
	if err != nil {
		return nil, err
	}
	return ScanWorkflow(wf, opts), nil
}

// ScanWorkflow runs all enabled rules against a parsed workflow.
func ScanWorkflow(wf *Workflow, opts ScanOptions) []Finding {
	allRules := AllRules()
	enabledRules := make(map[string]Rule)

	if len(opts.Rules) > 0 {
		for _, id := range opts.Rules {
			if r, ok := allRules[id]; ok {
				enabledRules[id] = r
			}
		}
	} else {
		enabledRules = allRules
	}

	var findings []Finding
	for _, rule := range enabledRules {
		results := rule(wf)
		findings = append(findings, results...)
	}

	if len(opts.Severities) > 0 {
		sevSet := make(map[string]bool)
		for _, s := range opts.Severities {
			sevSet[strings.ToLower(s)] = true
		}
		var filtered []Finding
		for _, f := range findings {
			if sevSet[f.Severity] {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	sortFindings(findings)
	return findings
}

// ScanWorkflowBytes parses and scans workflow YAML content.
func ScanWorkflowBytes(data []byte, path string, opts ScanOptions) ([]Finding, error) {
	wf, err := ParseWorkflow(data, path)
	if err != nil {
		return nil, err
	}
	return ScanWorkflow(wf, opts), nil
}

func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		ri := SeverityRank(findings[i].Severity)
		rj := SeverityRank(findings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return findings[i].File < findings[j].File
	})
}
