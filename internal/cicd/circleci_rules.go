package cicd

import (
	"fmt"
	"strings"
)

// CircleCIFinding represents a security finding in a CircleCI pipeline.
type CircleCIFinding struct {
	RuleID   string
	Severity string
	File     string
	Line     int
	Message  string
	Details  string
}

// ScanCircleCIPipeline runs all CircleCI security rules against a parsed pipeline.
func ScanCircleCIPipeline(pipeline *CircleCIPipeline) []CircleCIFinding {
	var findings []CircleCIFinding
	findings = append(findings, checkCircleCIForkExec(pipeline)...)
	findings = append(findings, checkCircleCIScriptInjection(pipeline)...)
	findings = append(findings, checkCircleCIUnpinnedOrb(pipeline)...)
	findings = append(findings, checkCircleCISelfHosted(pipeline)...)
	return findings
}

// checkCircleCIForkExec detects jobs with checkout + build commands that run
// on fork PRs (CC-001). CircleCI builds all PRs including forks by default.
func checkCircleCIForkExec(pipeline *CircleCIPipeline) []CircleCIFinding {
	if !pipeline.HasExternalTrigger() {
		return nil
	}

	var findings []CircleCIFinding

	for _, job := range pipeline.Jobs() {
		hasCheckout := false
		hasBuildCmd := false

		for _, step := range job.Steps {
			if step.Type == StepAction && step.Command == "checkout" {
				hasCheckout = true
			}
			if step.Type == StepScript {
				cmd := strings.ToLower(step.Command)
				buildCmds := []string{
					"pip install", "npm install", "npm ci", "yarn install",
					"make", "cargo build", "go build", "mvn", "gradle",
					"./", "bash ", "sh ", "python ", "node ",
					"pytest", "npm test", "npm run",
				}
				for _, bc := range buildCmds {
					if strings.Contains(cmd, bc) {
						hasBuildCmd = true
						break
					}
				}
			}
		}

		if hasCheckout && hasBuildCmd {
			findings = append(findings, CircleCIFinding{
				RuleID:   "CC-001",
				Severity: severityHigh,
				File:     pipeline.FilePath(),
				Message: fmt.Sprintf(
					"CircleCI Fork PR Execution: job '%s' checks out and executes fork code",
					job.Name),
				Details: "CircleCI builds all PRs including forks by default. Jobs that checkout and run build commands execute attacker-controlled code. Restrict fork PR builds or avoid running untrusted code with secrets.",
			})
		}
	}

	return findings
}

// checkCircleCIScriptInjection detects user-controllable CircleCI environment
// variables used in run.command blocks (CC-002).
func checkCircleCIScriptInjection(pipeline *CircleCIPipeline) []CircleCIFinding {
	dangerousVars := []string{
		"$CIRCLE_BRANCH",
		"$CIRCLE_PR_USERNAME",
		"$CIRCLE_PR_REPONAME",
		"$CIRCLE_PR_NUMBER",
		"$CIRCLE_USERNAME",
		"${CIRCLE_BRANCH}",
		"${CIRCLE_PR_USERNAME}",
		"${CIRCLE_PR_REPONAME}",
	}

	var findings []CircleCIFinding
	for _, job := range pipeline.Jobs() {
		for _, step := range job.Steps {
			if step.Type != StepScript {
				continue
			}
			for _, dv := range dangerousVars {
				if strings.Contains(step.Command, dv) {
					findings = append(findings, CircleCIFinding{
						RuleID:   "CC-002",
						Severity: severityHigh,
						File:     pipeline.FilePath(),
						Line:     step.Line,
						Message: fmt.Sprintf(
							"CircleCI Script Injection: %s used in run command of job '%s'",
							dv, job.Name),
						Details: "User-controllable CircleCI environment variables in run commands can be exploited for command injection via crafted branch names or PR metadata.",
					})
					break
				}
			}
		}
	}
	return findings
}

// checkCircleCIUnpinnedOrb detects orb references with a tag version instead
// of a SHA digest (CC-003).
func checkCircleCIUnpinnedOrb(pipeline *CircleCIPipeline) []CircleCIFinding {
	var findings []CircleCIFinding

	for _, orb := range pipeline.Orbs() {
		if orb.Version == "" {
			findings = append(findings, CircleCIFinding{
				RuleID:   "CC-003",
				Severity: severityMedium,
				File:     pipeline.FilePath(),
				Message: fmt.Sprintf(
					"CircleCI Unpinned Orb: %s/%s without version pin",
					orb.Namespace, orb.Name),
				Details: "Orbs without a version pin use the latest version, which can change. Pin to a specific version or SHA digest.",
			})
			continue
		}

		// Check if version is a SHA digest
		if strings.HasPrefix(orb.Version, "sha256:") {
			continue // Pinned by digest — safe
		}

		// Tag-based version — flag as unpinned
		findings = append(findings, CircleCIFinding{
			RuleID:   "CC-003",
			Severity: severityLow,
			File:     pipeline.FilePath(),
			Message: fmt.Sprintf(
				"CircleCI Tag-Pinned Orb: %s/%s@%s uses tag instead of SHA digest",
				orb.Namespace, orb.Name, orb.Version),
			Details: "Orb references pinned by tag can be modified upstream if the tag is mutable. Pin to a SHA digest (e.g., @sha256:...) for maximum supply chain security.",
		})
	}
	return findings
}

// checkCircleCISelfHosted detects jobs using machine executors or self-hosted
// resource classes (CC-009).
func checkCircleCISelfHosted(pipeline *CircleCIPipeline) []CircleCIFinding {
	var findings []CircleCIFinding

	for _, job := range pipeline.Jobs() {
		runner := job.RunnerType
		if runner == "" {
			continue
		}

		isSelfHosted := runner == "machine" ||
			strings.Contains(strings.ToLower(runner), "self-hosted")

		if !isSelfHosted {
			continue
		}

		severity := severityMedium
		msg := fmt.Sprintf(
			"CircleCI Self-Hosted Runner: job '%s' uses runner type '%s'",
			job.Name, runner)

		if pipeline.HasExternalTrigger() {
			severity = severityHigh
			msg += " on fork-accessible pipeline"
		}

		findings = append(findings, CircleCIFinding{
			RuleID:   "CC-009",
			Severity: severity,
			File:     pipeline.FilePath(),
			Message:  msg,
			Details:  "Machine executors and self-hosted runners execute code directly on the host. If the pipeline builds fork PRs, attackers can execute arbitrary commands on the runner, risking credential theft and lateral movement.",
		})
	}
	return findings
}
