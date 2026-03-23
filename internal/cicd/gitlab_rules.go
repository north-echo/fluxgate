package cicd

import (
	"fmt"
	"strings"
)

// GitLabFinding represents a security finding in a GitLab CI pipeline.
type GitLabFinding struct {
	RuleID   string
	Severity string
	File     string
	Line     int
	Message  string
	Details  string
}

// Severity constants (matching scanner package).
const (
	severityCritical = "critical"
	severityHigh     = "high"
	severityMedium   = "medium"
	severityLow      = "low"
	severityInfo     = "info"
)

// ScanGitLabPipeline runs all GitLab CI security rules against a parsed pipeline.
func ScanGitLabPipeline(pipeline *GitLabPipeline) []GitLabFinding {
	var findings []GitLabFinding
	findings = append(findings, checkGitLabMRSecrets(pipeline)...)
	findings = append(findings, checkGitLabScriptInjection(pipeline)...)
	findings = append(findings, checkGitLabUnsafeIncludes(pipeline)...)
	findings = append(findings, checkGitLabSelfHostedRunner(pipeline)...)
	return findings
}

// checkGitLabMRSecrets detects merge request pipelines that may expose
// parent project secrets to fork MR authors (GitLab equivalent of FG-001).
func checkGitLabMRSecrets(pipeline *GitLabPipeline) []GitLabFinding {
	var findings []GitLabFinding

	for _, job := range pipeline.Jobs() {
		// Check if job runs on MR pipelines
		runsOnMR := false
		for _, cond := range job.Conditions {
			lower := strings.ToLower(cond)
			if strings.Contains(lower, "ci_pipeline_source") &&
				strings.Contains(lower, "merge_request_event") {
				runsOnMR = true
				break
			}
		}

		if !runsOnMR {
			continue
		}

		// Check for secrets in variables or script
		hasSecrets := false
		for _, secret := range job.Secrets {
			if strings.Contains(secret, "CI_JOB_TOKEN") ||
				strings.HasPrefix(secret, "$") {
				hasSecrets = true
				break
			}
		}

		// Check for dangerous commands in scripts
		hasDangerousExec := false
		for _, step := range job.Steps {
			if step.Type != StepScript {
				continue
			}
			cmd := strings.ToLower(step.Command)
			dangerousCmds := []string{
				"pip install", "npm install", "npm ci", "yarn install",
				"make", "cargo build", "go build", "mvn", "gradle",
				"./", "bash ", "sh ", "python ", "node ",
			}
			for _, dc := range dangerousCmds {
				if strings.Contains(cmd, dc) {
					hasDangerousExec = true
					break
				}
			}
		}

		// Check for checkout of MR source branch
		checksOutMRCode := false
		for _, step := range job.Steps {
			cmd := strings.ToLower(step.Command)
			if strings.Contains(cmd, "git checkout") &&
				(strings.Contains(cmd, "ci_merge_request_source_branch") ||
					strings.Contains(cmd, "merge_request_source_branch_name")) {
				checksOutMRCode = true
				break
			}
		}

		if hasDangerousExec || checksOutMRCode {
			severity := severityMedium
			msg := fmt.Sprintf("GitLab MR Pipeline: job '%s' runs on merge_request_event", job.Name)

			if checksOutMRCode {
				severity = severityHigh
				msg += " with explicit checkout of MR source branch"
			}
			if hasSecrets {
				severity = severityHigh
				msg += " with secret access"
			}
			if hasDangerousExec {
				msg += " — executes build commands that may run fork code"
			}

			findings = append(findings, GitLabFinding{
				RuleID:   "GL-001",
				Severity: severity,
				File:     pipeline.FilePath(),
				Message:  msg,
				Details:  "GitLab CI pipelines triggered by merge_request_event may expose parent project CI/CD variables to fork MR authors if ci_allow_fork_pipelines_to_run_in_parent_project is enabled.",
			})
		}
	}
	return findings
}

// checkGitLabScriptInjection detects user-controllable CI variables used
// in script blocks (GitLab equivalent of FG-002).
func checkGitLabScriptInjection(pipeline *GitLabPipeline) []GitLabFinding {
	dangerousVars := []string{
		"$CI_MERGE_REQUEST_TITLE",
		"$CI_MERGE_REQUEST_DESCRIPTION",
		"$CI_COMMIT_MESSAGE",
		"$CI_COMMIT_TITLE",
		"$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
		"${CI_MERGE_REQUEST_TITLE}",
		"${CI_MERGE_REQUEST_DESCRIPTION}",
		"${CI_COMMIT_MESSAGE}",
	}

	var findings []GitLabFinding
	for _, job := range pipeline.Jobs() {
		for _, step := range job.Steps {
			if step.Type != StepScript {
				continue
			}
			for _, dv := range dangerousVars {
				if strings.Contains(step.Command, dv) {
					findings = append(findings, GitLabFinding{
						RuleID:   "GL-002",
						Severity: severityHigh,
						File:     pipeline.FilePath(),
						Line:     step.Line,
						Message: fmt.Sprintf(
							"GitLab Script Injection: %s used in script block of job '%s'",
							dv, job.Name),
						Details: "User-controllable CI variables in script blocks can be exploited for command injection via crafted branch names, commit messages, or MR titles.",
					})
					break
				}
			}
		}
	}
	return findings
}

// checkGitLabUnsafeIncludes detects external includes from unversioned or
// untrusted sources (GitLab equivalent of FG-003).
func checkGitLabUnsafeIncludes(pipeline *GitLabPipeline) []GitLabFinding {
	var findings []GitLabFinding

	for _, inc := range pipeline.Includes() {
		if inc.Remote != "" {
			severity := severityMedium
			msg := fmt.Sprintf("GitLab Unsafe Include: remote include from %s", inc.Remote)

			// HTTP (not HTTPS) is worse
			if strings.HasPrefix(inc.Remote, "http://") {
				severity = severityHigh
				msg += " (unencrypted HTTP)"
			}

			findings = append(findings, GitLabFinding{
				RuleID:   "GL-003",
				Severity: severity,
				File:     pipeline.FilePath(),
				Message:  msg,
				Details:  "Remote includes fetch pipeline configuration from external URLs. If the URL is compromised or intercepted, arbitrary pipeline code can be injected.",
			})
		}

		if inc.Project != "" && inc.Ref == "" {
			findings = append(findings, GitLabFinding{
				RuleID:   "GL-003",
				Severity: severityLow,
				File:     pipeline.FilePath(),
				Message: fmt.Sprintf(
					"GitLab Unpinned Include: project include from %s without ref pin",
					inc.Project),
				Details: "Project includes without a ref pin use the default branch, which can change. Pin to a specific tag or SHA.",
			})
		}
	}
	return findings
}

// checkGitLabSelfHostedRunner detects jobs using self-hosted runners
// (shell executor, custom tags) on MR pipelines (GitLab equivalent of FG-009).
func checkGitLabSelfHostedRunner(pipeline *GitLabPipeline) []GitLabFinding {
	var findings []GitLabFinding

	for _, job := range pipeline.Jobs() {
		if job.RunnerType == "" || job.RunnerType == "docker" {
			continue
		}

		isSelfHosted := job.RunnerType == "self-hosted" ||
			job.RunnerType == "shell" ||
			strings.Contains(job.RunnerType, "shell")

		if !isSelfHosted {
			continue
		}

		// Check if this job runs on MR events
		runsOnMR := false
		for _, cond := range job.Conditions {
			if strings.Contains(strings.ToLower(cond), "merge_request") {
				runsOnMR = true
				break
			}
		}

		if runsOnMR {
			findings = append(findings, GitLabFinding{
				RuleID:   "GL-009",
				Severity: severityHigh,
				File:     pipeline.FilePath(),
				Message: fmt.Sprintf(
					"GitLab Self-Hosted Runner: job '%s' uses shell executor on MR pipeline",
					job.Name),
				Details: "Shell executors on self-hosted runners execute commands directly on the host. Fork MR authors can execute arbitrary commands on the runner machine, risking credential theft and lateral movement.",
			})
		}
	}
	return findings
}
