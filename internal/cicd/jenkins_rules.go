package cicd

import (
	"fmt"
	"strings"
)

// JenkinsFinding represents a security finding in a Jenkins pipeline.
type JenkinsFinding struct {
	RuleID   string
	Severity string
	File     string
	Line     int
	Message  string
	Details  string
}

// ScanJenkinsPipeline runs all Jenkins security rules against a parsed pipeline.
func ScanJenkinsPipeline(pipeline *JenkinsPipeline) []JenkinsFinding {
	var findings []JenkinsFinding
	findings = append(findings, checkJenkinsPRSecrets(pipeline)...)
	findings = append(findings, checkJenkinsScriptInjection(pipeline)...)
	findings = append(findings, checkJenkinsUnpinnedLibrary(pipeline)...)
	findings = append(findings, checkJenkinsSelfHostedRunner(pipeline)...)
	return findings
}

// checkJenkinsPRSecrets detects changeRequest stages with credentials()
// environment variables — secret access on PR builds (JK-001).
func checkJenkinsPRSecrets(pipeline *JenkinsPipeline) []JenkinsFinding {
	var findings []JenkinsFinding

	for _, job := range pipeline.Jobs() {
		isChangeRequest := false
		for _, cond := range job.Conditions {
			if strings.Contains(cond, "changeRequest") {
				isChangeRequest = true
				break
			}
		}

		if !isChangeRequest {
			continue
		}

		if len(job.Secrets) == 0 {
			continue
		}

		findings = append(findings, JenkinsFinding{
			RuleID:   "JK-001",
			Severity: severityHigh,
			File:     pipeline.FilePath(),
			Message: fmt.Sprintf(
				"Jenkins PR Secrets: stage '%s' uses credentials() on changeRequest trigger (secrets: %s)",
				job.Name, strings.Join(job.Secrets, ", ")),
			Details: "Jenkins stages triggered by changeRequest() that use credentials() expose secrets to pull request authors. Fork PR authors can exfiltrate credential values via crafted build scripts.",
		})
	}

	return findings
}

// checkJenkinsScriptInjection detects user-controllable Jenkins environment
// variables (env.CHANGE_BRANCH, env.CHANGE_TITLE, env.CHANGE_AUTHOR) used
// in sh/bat blocks (JK-002).
func checkJenkinsScriptInjection(pipeline *JenkinsPipeline) []JenkinsFinding {
	dangerousVars := []string{
		"env.CHANGE_BRANCH",
		"env.CHANGE_TITLE",
		"env.CHANGE_AUTHOR",
		"env.CHANGE_AUTHOR_DISPLAY_NAME",
		"env.CHANGE_AUTHOR_EMAIL",
		"CHANGE_BRANCH",
		"CHANGE_TITLE",
		"CHANGE_AUTHOR",
	}

	var findings []JenkinsFinding
	for _, job := range pipeline.Jobs() {
		for _, step := range job.Steps {
			if step.Type != StepScript {
				continue
			}
			for _, dv := range dangerousVars {
				if strings.Contains(step.Command, dv) {
					findings = append(findings, JenkinsFinding{
						RuleID:   "JK-002",
						Severity: severityHigh,
						File:     pipeline.FilePath(),
						Line:     step.Line,
						Message: fmt.Sprintf(
							"Jenkins Script Injection: %s used in shell block of stage '%s'",
							dv, job.Name),
						Details: "User-controllable Jenkins change variables in shell blocks can be exploited for command injection via crafted branch names, PR titles, or author names.",
					})
					break
				}
			}
		}
	}
	return findings
}

// checkJenkinsUnpinnedLibrary detects @Library annotations without a version
// pin (JK-003).
func checkJenkinsUnpinnedLibrary(pipeline *JenkinsPipeline) []JenkinsFinding {
	var findings []JenkinsFinding

	for _, lib := range pipeline.Libraries() {
		if lib.Version == "" {
			findings = append(findings, JenkinsFinding{
				RuleID:   "JK-003",
				Severity: severityMedium,
				File:     pipeline.FilePath(),
				Message: fmt.Sprintf(
					"Jenkins Unpinned Library: @Library('%s') without version pin",
					lib.Name),
				Details: "Shared libraries without a version pin use the default branch, which can change. Pin to a specific tag or SHA to prevent supply chain attacks via library modification.",
			})
		}
	}

	return findings
}

// checkJenkinsSelfHostedRunner detects self-hosted or non-standard agent labels
// on changeRequest stages (JK-009).
func checkJenkinsSelfHostedRunner(pipeline *JenkinsPipeline) []JenkinsFinding {
	var findings []JenkinsFinding

	for _, job := range pipeline.Jobs() {
		isChangeRequest := false
		for _, cond := range job.Conditions {
			if strings.Contains(cond, "changeRequest") {
				isChangeRequest = true
				break
			}
		}

		if !isChangeRequest {
			continue
		}

		agent := job.RunnerType
		if agent == "" || agent == "any" || agent == "none" || agent == "docker" {
			continue
		}

		// Non-standard agent label on a PR stage
		findings = append(findings, JenkinsFinding{
			RuleID:   "JK-009",
			Severity: severityHigh,
			File:     pipeline.FilePath(),
			Message: fmt.Sprintf(
				"Jenkins Self-Hosted Agent: stage '%s' uses agent label '%s' on changeRequest trigger",
				job.Name, agent),
			Details: "Non-standard agent labels on changeRequest stages may route PR builds to self-hosted agents. Fork PR authors can execute arbitrary code on the agent machine, risking credential theft and lateral movement.",
		})
	}

	return findings
}
