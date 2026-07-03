package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/north-echo/fluxgate/internal/cicd"
)

// MaxYAMLSize is the maximum allowed size (in bytes) for a workflow YAML file.
// Files larger than this are rejected before parsing to prevent YAML bomb DoS.
// 10 MB is generous — real workflow files rarely exceed 100 KB.
const MaxYAMLSize = 10 * 1024 * 1024

// ErrFileTooLarge is returned when a workflow file exceeds MaxYAMLSize.
var ErrFileTooLarge = fmt.Errorf("workflow file exceeds maximum size (%d bytes)", MaxYAMLSize)

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
			wf, err := ParseWorkflowFile(path)
			if err != nil {
				continue // skip unparseable files
			}
			// scanWorkflow, not ScanFile: the aggregate is sorted once below,
			// so per-file sorting would be wasted work.
			result.Workflows++
			result.Findings = append(result.Findings, scanWorkflow(wf, opts)...)
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
	findings := scanWorkflow(wf, opts)
	sortFindings(findings)
	return findings
}

// scanWorkflow runs the rules without sorting, for callers that sort the
// aggregate themselves (ScanDirectory).
func scanWorkflow(wf *Workflow, opts ScanOptions) []Finding {
	enabledRules := allRules
	if len(opts.Rules) > 0 {
		enabledRules = make(map[string]Rule, len(opts.Rules))
		for _, id := range opts.Rules {
			if r, ok := allRules[id]; ok {
				enabledRules[id] = r
			}
		}
	}

	var findings []Finding
	for _, rule := range enabledRules {
		results := rule(wf)
		findings = append(findings, results...)
	}

	// Post-scan correlation: merge FG-001+FG-002 co-occurrences
	findings = CorrelatePwnRequestInjection(findings)

	// Stamp the workflow hash on every finding so template-propagation queries
	// can group identical workflows across repos without re-reading source.
	if wf.Hash != "" {
		for i := range findings {
			if findings[i].WorkflowHash == "" {
				findings[i].WorkflowHash = wf.Hash
			}
		}
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
	if len(data) > MaxYAMLSize {
		return nil
	}
	pipeline, err := cicd.ParseGitLabCI(data, path)
	if err != nil {
		return nil
	}

	return filterFindings(platformFindings(cicd.ScanGitLabPipeline(pipeline)), opts)
}

// ScanAzurePipelines parses and scans an azure-pipelines.yml file, returning
// findings in the common Finding format.
func ScanAzurePipelines(data []byte, path string, opts ScanOptions) []Finding {
	if len(data) > MaxYAMLSize {
		return nil
	}
	pipeline, err := cicd.ParseAzurePipeline(data, path)
	if err != nil {
		return nil
	}

	return filterFindings(platformFindings(cicd.ScanAzurePipeline(pipeline)), opts)
}

// ScanJenkinsfile parses and scans a Jenkinsfile.
func ScanJenkinsfile(data []byte, path string, opts ScanOptions) []Finding {
	if len(data) > MaxYAMLSize {
		return nil
	}
	pipeline, err := cicd.ParseJenkinsfile(data, path)
	if err != nil {
		return nil
	}
	return filterFindings(platformFindings(cicd.ScanJenkinsPipeline(pipeline)), opts)
}

// ScanTektonPipeline parses and scans a Tekton Pipeline/Task YAML.
func ScanTektonPipeline(data []byte, path string, opts ScanOptions) []Finding {
	if len(data) > MaxYAMLSize {
		return nil
	}
	pipeline, err := cicd.ParseTektonPipeline(data, path)
	if err != nil {
		return nil
	}
	return filterFindings(platformFindings(cicd.ScanTektonPipeline(pipeline)), opts)
}

// ScanCircleCI parses and scans a .circleci/config.yml.
func ScanCircleCI(data []byte, path string, opts ScanOptions) []Finding {
	if len(data) > MaxYAMLSize {
		return nil
	}
	pipeline, err := cicd.ParseCircleCI(data, path)
	if err != nil {
		return nil
	}
	return filterFindings(platformFindings(cicd.ScanCircleCIPipeline(pipeline)), opts)
}

// platformFindings converts findings from the internal/cicd platform rule
// sets into the common Finding type.
func platformFindings(pfs []cicd.PlatformFinding) []Finding {
	var findings []Finding
	for _, pf := range pfs {
		findings = append(findings, Finding{
			RuleID:   pf.RuleID,
			Severity: pf.Severity,
			File:     pf.File,
			Line:     pf.Line,
			Message:  pf.Message,
			Details:  pf.Details,
		})
	}
	return findings
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
