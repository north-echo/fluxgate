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
	findings = append(findings, checkGitLabBroadPermissions(pipeline)...)
	findings = append(findings, checkGitLabSecretsInLogs(pipeline)...)
	findings = append(findings, checkGitLabForkMRExec(pipeline)...)
	findings = append(findings, checkGitLabOIDCMisconfig(pipeline)...)
	findings = append(findings, checkGitLabSelfHostedRunner(pipeline)...)
	findings = append(findings, checkGitLabCachePoisoning(pipeline)...)
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
					severity := severityHigh
					details := "User-controllable CI variables in script blocks can be exploited for command injection via crafted branch names, commit messages, or MR titles."

					// Downgrade: echo/printf is logging, not exploitable injection
					if isLoggingOnlyUsage(step.Command, dv) {
						severity = severityInfo
						details = "Variable used in echo/printf for logging. Not directly exploitable but may leak sensitive metadata to build logs."
					} else if isQuotedArgUsage(step.Command, dv) {
						// Quoted CLI argument — harder to exploit than unquoted interpolation
						severity = severityMedium
						details = "Variable used as a quoted CLI argument. Exploitation requires breaking out of the quoted context, which is significantly harder than unquoted shell interpolation."
					}

					findings = append(findings, GitLabFinding{
						RuleID:   "GL-002",
						Severity: severity,
						File:     pipeline.FilePath(),
						Line:     step.Line,
						Message: fmt.Sprintf(
							"GitLab Script Injection: %s used in script block of job '%s'",
							dv, job.Name),
						Details: details,
					})
					break
				}
			}
		}
	}
	return findings
}

// isLoggingOnlyUsage checks if a variable is only used in echo/printf statements.
func isLoggingOnlyUsage(cmd, varRef string) bool {
	for _, line := range strings.Split(cmd, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, varRef) {
			continue
		}
		// If this line uses the variable and is NOT an echo/printf, it's not logging-only
		lower := strings.ToLower(trimmed)
		isEcho := strings.HasPrefix(lower, "echo ") || strings.HasPrefix(lower, "echo\t") ||
			strings.HasPrefix(lower, "printf ") || strings.HasPrefix(lower, "printf\t") ||
			strings.Contains(lower, "| echo") || strings.HasPrefix(lower, "- echo ")
		if !isEcho {
			return false
		}
	}
	return true
}

// isQuotedArgUsage checks if a variable appears inside double quotes as a CLI argument.
func isQuotedArgUsage(cmd, varRef string) bool {
	for _, line := range strings.Split(cmd, "\n") {
		if !strings.Contains(line, varRef) {
			continue
		}
		// Check if the variable reference is inside double quotes
		idx := strings.Index(line, varRef)
		if idx < 0 {
			continue
		}
		// Look for surrounding double quotes
		before := line[:idx]
		after := line[idx+len(varRef):]
		quotesBefore := strings.Count(before, "\"") - strings.Count(before, "\\\"")
		if quotesBefore%2 == 1 && strings.Contains(after, "\"") {
			return true // Inside double quotes
		}
	}
	return false
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

// checkGitLabBroadPermissions detects overly permissive CI_JOB_TOKEN scope.
// Jobs that access CI_JOB_TOKEN without restricting token scope may grant
// broader access than intended (GL-004).
func checkGitLabBroadPermissions(pipeline *GitLabPipeline) []GitLabFinding {
	var findings []GitLabFinding

	for _, job := range pipeline.Jobs() {
		usesJobToken := false
		accessesSecrets := false

		// Check if job references CI_JOB_TOKEN in script steps
		for _, step := range job.Steps {
			if step.Type != StepScript {
				continue
			}
			if strings.Contains(step.Command, "CI_JOB_TOKEN") {
				usesJobToken = true
			}
		}

		// Check if job references CI_JOB_TOKEN in secrets/variables
		for _, secret := range job.Secrets {
			if strings.Contains(secret, "CI_JOB_TOKEN") {
				usesJobToken = true
			}
			if strings.HasPrefix(secret, "$") {
				accessesSecrets = true
			}
		}

		if !usesJobToken {
			continue
		}

		// Check if the job has any scoping (permissions restrictions)
		// GitLab scoped tokens use the `id_tokens` or `secrets` blocks
		// with restricted scope. A bare CI_JOB_TOKEN usage without
		// explicit permission scoping is overly broad.
		hasScoping := false
		if job.Permissions != nil {
			if _, ok := job.Permissions["ci_job_token"]; ok {
				hasScoping = true
			}
		}

		if !hasScoping {
			msg := fmt.Sprintf("GitLab Broad Permissions: job '%s' uses CI_JOB_TOKEN without scoped permissions", job.Name)
			if accessesSecrets {
				msg += " and accesses additional secrets"
			}
			findings = append(findings, GitLabFinding{
				RuleID:   "GL-004",
				Severity: severityMedium,
				File:     pipeline.FilePath(),
				Message:  msg,
				Details:  "CI_JOB_TOKEN provides API access scoped to the project. Without restricting token permissions via CI/CD settings, the token may have broader access than intended. Consider using id_tokens with restricted audience or limiting CI_JOB_TOKEN scope in project settings.",
			})
		}
	}
	return findings
}

// checkGitLabSecretsInLogs detects echo of secret-like CI variables in script
// steps. Patterns like `echo $CI_*` or `echo $SECRET_*` where the variable
// name suggests it holds sensitive data (GL-005).
func checkGitLabSecretsInLogs(pipeline *GitLabPipeline) []GitLabFinding {
	sensitivePatterns := []string{"SECRET", "TOKEN", "KEY", "PASSWORD", "CREDENTIALS"}

	var findings []GitLabFinding
	for _, job := range pipeline.Jobs() {
		for _, step := range job.Steps {
			if step.Type != StepScript {
				continue
			}
			cmd := step.Command
			// Look for echo/printf statements containing secret-like variables
			lower := strings.ToLower(cmd)
			if !strings.Contains(lower, "echo ") && !strings.Contains(lower, "echo\t") &&
				!strings.Contains(lower, "printf ") && !strings.Contains(lower, "printf\t") {
				continue
			}

			// Check for variable patterns that look sensitive
			for _, pattern := range sensitivePatterns {
				if containsSensitiveVar(cmd, pattern) {
					findings = append(findings, GitLabFinding{
						RuleID:   "GL-005",
						Severity: severityLow,
						File:     pipeline.FilePath(),
						Line:     step.Line,
						Message: fmt.Sprintf(
							"GitLab Secrets in Logs: job '%s' may echo a sensitive variable containing '%s'",
							job.Name, pattern),
						Details: "Echoing CI variables that contain secrets, tokens, or credentials to the build log can expose sensitive data. GitLab masks variables marked as 'protected' or 'masked', but custom variables or CI_JOB_TOKEN may still be leaked.",
					})
					break // One finding per step
				}
			}
		}
	}
	return findings
}

// containsSensitiveVar checks if a command string contains a variable reference
// (like $FOO_TOKEN or ${FOO_TOKEN}) where the variable name contains the given pattern.
func containsSensitiveVar(cmd string, pattern string) bool {
	upper := strings.ToUpper(cmd)
	patternUpper := strings.ToUpper(pattern)

	// Look for $VARNAME or ${VARNAME} patterns
	for i := 0; i < len(upper)-1; i++ {
		if upper[i] != '$' {
			continue
		}
		// Extract variable name
		start := i + 1
		if start < len(upper) && upper[start] == '{' {
			start++
			end := strings.Index(upper[start:], "}")
			if end > 0 {
				varName := upper[start : start+end]
				if strings.Contains(varName, patternUpper) {
					return true
				}
			}
		} else {
			// Bare $VARNAME - extract until non-alphanumeric/underscore
			end := start
			for end < len(upper) && (upper[end] == '_' || (upper[end] >= 'A' && upper[end] <= 'Z') || (upper[end] >= '0' && upper[end] <= '9')) {
				end++
			}
			if end > start {
				varName := upper[start:end]
				if strings.Contains(varName, patternUpper) {
					return true
				}
			}
		}
	}
	return false
}

// checkGitLabForkMRExec detects merge_request_event pipelines that check out
// the MR source branch and run build commands, enabling fork code execution (GL-006).
func checkGitLabForkMRExec(pipeline *GitLabPipeline) []GitLabFinding {
	var findings []GitLabFinding

	for _, job := range pipeline.Jobs() {
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

		// Check for explicit checkout of MR source branch
		checksOutMRSource := false
		for _, step := range job.Steps {
			if step.Type != StepScript {
				continue
			}
			cmd := strings.ToLower(step.Command)
			if (strings.Contains(cmd, "git checkout") || strings.Contains(cmd, "git fetch") || strings.Contains(cmd, "git merge")) &&
				(strings.Contains(cmd, "ci_merge_request_source_branch") ||
					strings.Contains(cmd, "merge_request_source_branch_name") ||
					strings.Contains(cmd, "$ci_merge_request_ref_path")) {
				checksOutMRSource = true
				break
			}
		}

		if !checksOutMRSource {
			continue
		}

		// Check for build commands after checkout
		hasBuildCmd := false
		for _, step := range job.Steps {
			if step.Type != StepScript {
				continue
			}
			cmd := strings.ToLower(step.Command)
			buildCmds := []string{
				"pip install", "npm install", "npm ci", "yarn install",
				"make", "cargo build", "go build", "mvn", "gradle",
				"./", "bash ", "sh ", "python ", "node ", "bundle install",
				"composer install",
			}
			for _, bc := range buildCmds {
				if strings.Contains(cmd, bc) {
					hasBuildCmd = true
					break
				}
			}
		}

		severity := severityMedium
		msg := fmt.Sprintf("GitLab Fork MR Execution: job '%s' checks out MR source on merge_request_event", job.Name)
		if hasBuildCmd {
			severity = severityHigh
			msg += " and runs build commands — fork code may be executed"
		}

		findings = append(findings, GitLabFinding{
			RuleID:   "GL-006",
			Severity: severity,
			File:     pipeline.FilePath(),
			Message:  msg,
			Details:  "Checking out the merge request source branch in a merge_request_event pipeline and running build commands allows fork authors to execute arbitrary code in the parent project context. This can lead to secret exfiltration and supply chain attacks.",
		})
	}
	return findings
}

// checkGitLabOIDCMisconfig detects id_tokens blocks in jobs on merge_request_event
// pipelines with broad audience values (GL-008).
func checkGitLabOIDCMisconfig(pipeline *GitLabPipeline) []GitLabFinding {
	var findings []GitLabFinding

	for _, job := range pipeline.Jobs() {
		if len(job.IdTokens) == 0 {
			continue
		}

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

		for tokenName, aud := range job.IdTokens {
			msg := fmt.Sprintf("GitLab OIDC Misconfiguration: job '%s' issues id_token '%s' on merge_request_event pipeline",
				job.Name, tokenName)

			severity := severityHigh
			if aud != "" {
				// Check for overly broad audience
				broadAuds := []string{"*", "https://gitlab.com", "https://gitlab.example.com"}
				isBroad := false
				for _, ba := range broadAuds {
					if strings.EqualFold(aud, ba) {
						isBroad = true
						break
					}
				}
				if isBroad {
					msg += fmt.Sprintf(" with broad audience '%s'", aud)
				} else {
					msg += fmt.Sprintf(" (audience: '%s')", aud)
				}
			} else {
				msg += " with no audience restriction"
			}

			findings = append(findings, GitLabFinding{
				RuleID:   "GL-008",
				Severity: severity,
				File:     pipeline.FilePath(),
				Message:  msg,
				Details:  "OIDC id_tokens on merge_request_event pipelines may be issued to fork MR authors. This can allow attackers to federate into cloud providers (AWS, GCP, Azure) using the project's identity. Restrict id_tokens to trusted pipeline sources only.",
			})
		}
	}
	return findings
}

// checkGitLabCachePoisoning detects shared cache keys on merge_request_event
// pipelines that could be poisoned by fork MR authors (GL-010).
func checkGitLabCachePoisoning(pipeline *GitLabPipeline) []GitLabFinding {
	var findings []GitLabFinding

	for _, job := range pipeline.Jobs() {
		if len(job.CacheKeys) == 0 {
			continue
		}

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

		for _, key := range job.CacheKeys {
			// CI_COMMIT_REF_SLUG keys are ref-scoped by default since GitLab 13.x
			// Each branch gets its own cache namespace, so MR pipelines can't poison
			// the default branch cache. Only flag truly shared keys.
			isRefScoped := strings.Contains(key, "CI_COMMIT_REF_SLUG") ||
				strings.Contains(key, "CI_COMMIT_REF_NAME") ||
				strings.Contains(key, "CI_MERGE_REQUEST_IID")

			if isRefScoped {
				// Ref-scoped keys are safe by default in modern GitLab — downgrade to info
				findings = append(findings, GitLabFinding{
					RuleID:   "GL-010",
					Severity: severityInfo,
					File:     pipeline.FilePath(),
					Message: fmt.Sprintf(
						"GitLab Cache: job '%s' uses ref-scoped cache key '%s' (mitigated by GitLab cache scoping)",
						job.Name, key),
					Details: "Cache key uses a ref-derived variable. Since GitLab 13.x, caches are scoped by ref by default, preventing cross-branch cache poisoning. This is informational only.",
				})
				continue
			}

			// Truly shared keys — static key or project-wide variable
			isShared := strings.Contains(key, "${CI_DEFAULT_BRANCH}") ||
				strings.Contains(key, "$CI_DEFAULT_BRANCH") ||
				strings.Contains(key, "${CI_PROJECT_ID}") ||
				strings.Contains(key, "$CI_PROJECT_ID") ||
				!strings.Contains(key, "$") // static key shared across branches

			if isShared {
				findings = append(findings, GitLabFinding{
					RuleID:   "GL-010",
					Severity: severityMedium,
					File:     pipeline.FilePath(),
					Message: fmt.Sprintf(
						"GitLab Cache Poisoning: job '%s' uses shared cache key '%s' on merge_request_event pipeline",
						job.Name, key),
					Details: "Static or project-wide cache keys on merge_request_event pipelines may allow fork MR authors to poison the cache if cache scoping is disabled or overridden.",
				})
			}
		}
	}
	return findings
}
