package scanner

import (
	"fmt"
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

	// Scan Jenkinsfile if it exists
	jenkinsPath := filepath.Join(dir, "Jenkinsfile")
	if data, err := os.ReadFile(jenkinsPath); err == nil {
		jkFindings := ScanJenkinsfile(data, jenkinsPath, opts)
		result.Workflows++
		result.Findings = append(result.Findings, jkFindings...)
	}

	// Scan Tekton pipelines/tasks in .tekton/ directory
	tektonDir := filepath.Join(dir, ".tekton")
	if entries, err := os.ReadDir(tektonDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
				continue
			}
			tkPath := filepath.Join(tektonDir, name)
			if data, err := os.ReadFile(tkPath); err == nil {
				tkFindings := ScanTektonPipeline(data, tkPath, opts)
				result.Workflows++
				result.Findings = append(result.Findings, tkFindings...)
			}
		}
	}

	// Scan CircleCI if .circleci/config.yml exists
	circleciPath := filepath.Join(dir, ".circleci", "config.yml")
	if data, err := os.ReadFile(circleciPath); err == nil {
		ccFindings := ScanCircleCI(data, circleciPath, opts)
		result.Workflows++
		result.Findings = append(result.Findings, ccFindings...)
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

	// Post-scan correlation: merge FG-001+FG-002 co-occurrences
	findings = CorrelatePwnRequestInjection(findings)

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

// ScanJenkinsfile parses and scans a Jenkinsfile.
func ScanJenkinsfile(data []byte, path string, opts ScanOptions) []Finding {
	pipeline, err := cicd.ParseJenkinsfile(data, path)
	if err != nil {
		return nil
	}
	jkFindings := cicd.ScanJenkinsPipeline(pipeline)
	var findings []Finding
	for _, f := range jkFindings {
		findings = append(findings, Finding{
			RuleID: f.RuleID, Severity: f.Severity, File: f.File,
			Line: f.Line, Message: f.Message, Details: f.Details,
		})
	}
	return filterFindings(findings, opts)
}

// ScanTektonPipeline parses and scans a Tekton Pipeline/Task YAML.
func ScanTektonPipeline(data []byte, path string, opts ScanOptions) []Finding {
	pipeline, err := cicd.ParseTektonPipeline(data, path)
	if err != nil {
		return nil
	}
	tkFindings := cicd.ScanTektonPipeline(pipeline)
	var findings []Finding
	for _, f := range tkFindings {
		findings = append(findings, Finding{
			RuleID: f.RuleID, Severity: f.Severity, File: f.File,
			Line: f.Line, Message: f.Message, Details: f.Details,
		})
	}
	return filterFindings(findings, opts)
}

// ScanCircleCI parses and scans a .circleci/config.yml.
func ScanCircleCI(data []byte, path string, opts ScanOptions) []Finding {
	pipeline, err := cicd.ParseCircleCI(data, path)
	if err != nil {
		return nil
	}
	ccFindings := cicd.ScanCircleCIPipeline(pipeline)
	var findings []Finding
	for _, f := range ccFindings {
		findings = append(findings, Finding{
			RuleID: f.RuleID, Severity: f.Severity, File: f.File,
			Line: f.Line, Message: f.Message, Details: f.Details,
		})
	}
	return filterFindings(findings, opts)
}

// filterFindings applies severity and rule filters to a finding list.
func filterFindings(findings []Finding, opts ScanOptions) []Finding {
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

// CorrelatePwnRequestInjection runs after all rules complete and merges
// co-occurring FG-001 (confirmed) + FG-002 findings on the same file into a
// single enhanced finding with the Ultralytics attack pattern narrative.
// The original FG-001 and FG-002 findings are replaced by the merged finding.
func CorrelatePwnRequestInjection(findings []Finding) []Finding {
	// Index FG-001 findings by file — any confidence level qualifies because
	// the co-occurrence of FG-002 itself proves attacker-controlled execution
	fg001ByFile := make(map[string]int) // file -> index in findings
	for i, f := range findings {
		if f.RuleID == "FG-001" {
			fg001ByFile[f.File] = i
		}
	}

	if len(fg001ByFile) == 0 {
		return findings
	}

	// Find FG-002 findings on the same files
	mergedFiles := make(map[string]bool)
	var fg002Exprs []string
	for _, f := range findings {
		if f.RuleID == "FG-002" {
			if _, ok := fg001ByFile[f.File]; ok {
				mergedFiles[f.File] = true
				fg002Exprs = append(fg002Exprs, f.Message)
			}
		}
	}

	if len(mergedFiles) == 0 {
		return findings
	}

	// Build merged findings and filter out originals
	var result []Finding
	for _, f := range findings {
		if mergedFiles[f.File] && (f.RuleID == "FG-001" || f.RuleID == "FG-002") {
			// Skip — will be replaced by merged finding
			if f.RuleID == "FG-001" {
				// Emit the merged finding in place of FG-001
				merged := Finding{
					RuleID:     "FG-001",
					Severity:   SeverityCritical,
					Confidence: f.Confidence,
					File:       f.File,
					Line:       f.Line,
					Message: fmt.Sprintf(
						"Pwn Request + Script Injection: fork checkout with attacker-controlled expression in run block (Ultralytics pattern) [%s]",
						f.Confidence),
					Details: f.Details + " | Combined FG-001+FG-002: attacker controls both checked-out code AND " +
						"expressions interpolated into shell commands. This is the exact attack chain used in the " +
						"Ultralytics compromise (pull_request_target → shell injection via branch name → credential exfiltration).",
					Mitigations: f.Mitigations,
				}
				result = append(result, merged)
			}
			continue
		}
		result = append(result, f)
	}
	return result
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
