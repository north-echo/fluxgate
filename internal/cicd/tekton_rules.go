package cicd

import (
	"fmt"
	"strings"
)

// TektonFinding represents a security finding in a Tekton pipeline.
type TektonFinding struct {
	RuleID   string
	Severity string
	File     string
	Line     int
	Message  string
	Details  string
}

// ScanTektonPipeline runs all Tekton security rules against a parsed pipeline.
func ScanTektonPipeline(pipeline *TektonPipeline) []TektonFinding {
	var findings []TektonFinding
	findings = append(findings, checkTektonParamInjection(pipeline)...)
	findings = append(findings, checkTektonUnpinnedTask(pipeline)...)
	findings = append(findings, checkTektonWorkspaceSecrets(pipeline)...)
	findings = append(findings, checkTektonPrivileged(pipeline)...)
	return findings
}

// checkTektonParamInjection detects $(params.*) references in script steps
// which are user-controllable and can lead to command injection (TK-001).
func checkTektonParamInjection(pipeline *TektonPipeline) []TektonFinding {
	var findings []TektonFinding

	for _, job := range pipeline.Jobs() {
		for _, step := range job.Steps {
			if step.Type != StepScript {
				continue
			}
			if strings.Contains(step.Command, "$(params.") {
				findings = append(findings, TektonFinding{
					RuleID:   "TK-001",
					Severity: severityHigh,
					File:     pipeline.FilePath(),
					Line:     step.Line,
					Message: fmt.Sprintf(
						"Tekton Parameter Injection: $(params.*) used in script of step '%s' in task '%s'",
						step.Name, job.Name),
					Details: "Tekton parameter references in script blocks are interpolated at runtime. If parameters originate from external input (webhooks, PR events), attackers can inject arbitrary commands.",
				})
			}
		}
	}
	return findings
}

// checkTektonUnpinnedTask detects taskRef with bundle references that use
// a tag instead of a @sha256: digest (TK-002).
func checkTektonUnpinnedTask(pipeline *TektonPipeline) []TektonFinding {
	var findings []TektonFinding

	for _, ref := range pipeline.TaskRefs() {
		if ref.Bundle == "" {
			continue
		}

		// Check if bundle is pinned by SHA256 digest
		if strings.Contains(ref.Bundle, "@sha256:") {
			continue
		}

		findings = append(findings, TektonFinding{
			RuleID:   "TK-002",
			Severity: severityMedium,
			File:     pipeline.FilePath(),
			Message: fmt.Sprintf(
				"Tekton Unpinned Task: taskRef '%s' uses bundle '%s' without @sha256: digest",
				ref.Name, ref.Bundle),
			Details: "Tekton task bundles referenced by tag can be modified upstream. Pin to a @sha256: digest to prevent supply chain attacks via task image replacement.",
		})
	}
	return findings
}

// checkTektonWorkspaceSecrets detects workspaces bound to Secrets on
// externally-triggered pipelines (TK-003).
func checkTektonWorkspaceSecrets(pipeline *TektonPipeline) []TektonFinding {
	if !pipeline.HasExternalTrigger() {
		return nil
	}

	var findings []TektonFinding
	for _, job := range pipeline.Jobs() {
		if len(job.Secrets) == 0 {
			continue
		}

		findings = append(findings, TektonFinding{
			RuleID:   "TK-003",
			Severity: severityHigh,
			File:     pipeline.FilePath(),
			Message: fmt.Sprintf(
				"Tekton Workspace Secret: task '%s' binds workspace to secret(s) [%s] on externally-triggered pipeline",
				job.Name, strings.Join(job.Secrets, ", ")),
			Details: "Tekton workspaces bound to Kubernetes Secrets on externally-triggered pipelines (EventListener/TriggerBinding) expose secrets to untrusted code execution.",
		})
	}
	return findings
}

// checkTektonPrivileged detects steps with privileged security context or
// running as root (TK-009).
func checkTektonPrivileged(pipeline *TektonPipeline) []TektonFinding {
	var findings []TektonFinding

	for _, job := range pipeline.Jobs() {
		for _, step := range job.Steps {
			isPrivileged := step.Env["__securityContext_privileged"] == "true"
			isRoot := step.Env["__securityContext_runAsUser"] == "0"

			if !isPrivileged && !isRoot {
				continue
			}

			msg := fmt.Sprintf("Tekton Privileged Step: step '%s' in task '%s'", step.Name, job.Name)
			if isPrivileged {
				msg += " runs with privileged: true"
			}
			if isRoot {
				msg += " runs as root (runAsUser: 0)"
			}

			findings = append(findings, TektonFinding{
				RuleID:   "TK-009",
				Severity: severityHigh,
				File:     pipeline.FilePath(),
				Line:     step.Line,
				Message:  msg,
				Details:  "Privileged containers or root execution in Tekton steps can escape container boundaries. If the pipeline processes untrusted input, this enables host-level compromise.",
			})
		}
	}
	return findings
}
