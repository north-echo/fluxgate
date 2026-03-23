package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/north-echo/fluxgate/internal/cicd"
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

// ScanDirectory scans all workflow files in a directory's .github/workflows/ folder,
// and optionally .gitlab-ci.yml if present.
func ScanDirectory(dir string, opts ScanOptions) (*ScanResult, error) {
	result := &ScanResult{Path: dir}

	// Scan GitHub Actions workflows
	workflowDir := filepath.Join(dir, ".github", "workflows")
	if info, err := os.Stat(workflowDir); err == nil && info.IsDir() {
		entries, err := os.ReadDir(workflowDir)
		if err != nil {
			return nil, err
		}

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
	}

	// Scan GitLab CI if .gitlab-ci.yml exists
	gitlabPath := filepath.Join(dir, ".gitlab-ci.yml")
	if data, err := os.ReadFile(gitlabPath); err == nil {
		glFindings := ScanGitLabCI(data, gitlabPath, opts)
		result.Workflows++
		result.Findings = append(result.Findings, glFindings...)
	}

	// Scan Azure Pipelines if azure-pipelines.yml exists
	for _, azName := range []string{"azure-pipelines.yml", "azure-pipelines.yaml"} {
		azPath := filepath.Join(dir, azName)
		if data, err := os.ReadFile(azPath); err == nil {
			azFindings := ScanAzurePipelines(data, azPath, opts)
			result.Workflows++
			result.Findings = append(result.Findings, azFindings...)
			break
		}
	}

	if result.Workflows == 0 {
		return nil, os.ErrNotExist
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

// ScanGitLabCI parses and scans a .gitlab-ci.yml file, returning findings
// in the common Finding format.
func ScanGitLabCI(data []byte, path string, opts ScanOptions) []Finding {
	pipeline, err := cicd.ParseGitLabCI(data, path)
	if err != nil {
		return nil
	}

	glFindings := cicd.ScanGitLabPipeline(pipeline)

	// Convert GitLab findings to common Finding type
	var findings []Finding
	for _, glf := range glFindings {
		f := Finding{
			RuleID:   glf.RuleID,
			Severity: glf.Severity,
			File:     glf.File,
			Line:     glf.Line,
			Message:  glf.Message,
			Details:  glf.Details,
		}
		findings = append(findings, f)
	}

	// Apply severity filter
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

	// Apply rule filter
	if len(opts.Rules) > 0 {
		ruleSet := make(map[string]bool)
		for _, r := range opts.Rules {
			ruleSet[r] = true
		}
		var filtered []Finding
		for _, f := range findings {
			if ruleSet[f.RuleID] {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	return findings
}

// ScanAzurePipelines parses and scans an azure-pipelines.yml file, returning
// findings in the common Finding format.
func ScanAzurePipelines(data []byte, path string, opts ScanOptions) []Finding {
	pipeline, err := cicd.ParseAzurePipeline(data, path)
	if err != nil {
		return nil
	}

	azFindings := cicd.ScanAzurePipeline(pipeline)

	var findings []Finding
	for _, azf := range azFindings {
		f := Finding{
			RuleID:   azf.RuleID,
			Severity: azf.Severity,
			File:     azf.File,
			Line:     azf.Line,
			Message:  azf.Message,
			Details:  azf.Details,
		}
		findings = append(findings, f)
	}

	// Apply severity filter
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

	// Apply rule filter
	if len(opts.Rules) > 0 {
		ruleSet := make(map[string]bool)
		for _, r := range opts.Rules {
			ruleSet[r] = true
		}
		var filtered []Finding
		for _, f := range findings {
			if ruleSet[f.RuleID] {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	return findings
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
