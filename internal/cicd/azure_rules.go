package cicd

import (
	"fmt"
	"strings"
)

// AzureFinding represents a security finding in an Azure Pipeline.
type AzureFinding struct {
	RuleID   string
	Severity string
	File     string
	Line     int
	Message  string
	Details  string
}

// ScanAzurePipeline runs all Azure Pipelines security rules.
func ScanAzurePipeline(pipeline *AzurePipeline) []AzureFinding {
	var findings []AzureFinding
	findings = append(findings, checkAzurePRSecrets(pipeline)...)
	findings = append(findings, checkAzureScriptInjection(pipeline)...)
	findings = append(findings, checkAzureUnpinnedTemplates(pipeline)...)
	findings = append(findings, checkAzureBroadPermissions(pipeline)...)
	findings = append(findings, checkAzureSecretsInLogs(pipeline)...)
	findings = append(findings, checkAzureForkSecrets(pipeline)...)
	findings = append(findings, checkAzureOIDCMisconfig(pipeline)...)
	findings = append(findings, checkAzureSelfHostedAgent(pipeline)...)
	findings = append(findings, checkAzureCachePoisoning(pipeline)...)
	return findings
}

// checkAzurePRSecrets detects PR-triggered pipelines that may expose secrets
// to fork authors. Azure DevOps has a setting "Make secrets available to builds
// of forks" — when enabled, fork PR builds access pipeline secrets.
func checkAzurePRSecrets(pipeline *AzurePipeline) []AzureFinding {
	if !pipeline.HasExternalTrigger() {
		return nil
	}

	var findings []AzureFinding

	for _, job := range pipeline.Jobs() {
		// Check for dangerous execution in PR-triggered jobs
		hasDangerousExec := false
		hasCheckout := false
		for _, step := range job.Steps {
			if step.Type == StepScript {
				cmd := strings.ToLower(step.Command)
				dangerousCmds := []string{
					"pip install", "npm install", "npm ci", "yarn install",
					"make", "cargo build", "go build", "mvn", "gradle",
					"dotnet build", "nuget restore", "msbuild",
					"./", "bash ", "sh ", "python ", "node ",
				}
				for _, dc := range dangerousCmds {
					if strings.Contains(cmd, dc) {
						hasDangerousExec = true
						break
					}
				}
			}
			if step.Type == StepAction && strings.Contains(strings.ToLower(step.Command), "checkout") {
				hasCheckout = true
			}
		}

		// Check for secret variable groups
		hasSecrets := len(job.Secrets) > 0
		for _, v := range pipeline.Variables() {
			if v.IsSecret || v.Group != "" {
				hasSecrets = true
				break
			}
		}

		if hasDangerousExec || hasCheckout {
			severity := severityMedium
			msg := fmt.Sprintf("Azure PR Build: job '%s' runs on PR trigger", job.Name)

			if hasDangerousExec {
				msg += " — executes build commands that may run fork code"
				severity = severityHigh
			}
			if hasSecrets {
				msg += " with secret/variable group access"
				severity = severityHigh
			}

			findings = append(findings, AzureFinding{
				RuleID:   "AZ-001",
				Severity: severity,
				File:     pipeline.FilePath(),
				Message:  msg,
				Details:  "Azure DevOps pipelines triggered by PRs from forks can expose secrets if 'Make secrets available to builds of forks' is enabled in pipeline settings. Review fork build settings and consider using environment approvals.",
			})
		}
	}

	return findings
}

// checkAzureScriptInjection detects user-controllable Azure DevOps predefined
// variables used directly in script blocks.
func checkAzureScriptInjection(pipeline *AzurePipeline) []AzureFinding {
	// Azure DevOps predefined variables that can be attacker-controlled
	dangerousVars := []string{
		"$(Build.SourceBranchName)",
		"$(Build.SourceVersionMessage)",
		"$(System.PullRequest.SourceBranch)",
		"$(System.PullRequest.TargetBranch)",
		"$(Build.RequestedFor)",
		"$(Build.RequestedForEmail)",
	}

	var findings []AzureFinding
	for _, job := range pipeline.Jobs() {
		for _, step := range job.Steps {
			if step.Type != StepScript {
				continue
			}
			for _, dv := range dangerousVars {
				if strings.Contains(step.Command, dv) {
					findings = append(findings, AzureFinding{
						RuleID:   "AZ-002",
						Severity: severityHigh,
						File:     pipeline.FilePath(),
						Line:     step.Line,
						Message: fmt.Sprintf(
							"Azure Script Injection: %s used in script of job '%s'",
							dv, job.Name),
						Details: "User-controllable predefined variables in script blocks can be exploited for command injection via crafted branch names or commit messages. Use environment variables or task inputs instead of inline variable expansion.",
					})
					break
				}
			}

			// Also check env mappings for dangerous variable references
			for envKey, envVal := range step.Env {
				for _, dv := range dangerousVars {
					if strings.Contains(envVal, dv) {
						// Using env var mapping is actually the SAFE pattern — skip
						_ = envKey
						break
					}
				}
			}
		}
	}
	return findings
}

// checkAzureUnpinnedTemplates detects template references without version
// pinning and external repository resources without ref pins.
func checkAzureUnpinnedTemplates(pipeline *AzurePipeline) []AzureFinding {
	var findings []AzureFinding

	// Check for extends template without pinning
	if ext := pipeline.Extends(); ext != "" {
		if !strings.Contains(ext, "@") {
			findings = append(findings, AzureFinding{
				RuleID:   "AZ-003",
				Severity: severityMedium,
				File:     pipeline.FilePath(),
				Message:  fmt.Sprintf("Azure Unpinned Extends: pipeline extends template '%s' without repository pin", ext),
				Details:  "Pipeline extends templates from external repositories should use @<repo> with a pinned ref to prevent supply chain attacks via template modification.",
			})
		}
	}

	// Check step-level template references
	for _, job := range pipeline.Jobs() {
		for _, step := range job.Steps {
			if step.Type == StepInclude && step.Command != "" {
				// Template references with @ are cross-repo — check for ref pin
				if strings.Contains(step.Command, "@") {
					// Has repo reference, which is good — the ref is pinned at the
					// resource level, not in the template reference itself
					continue
				}
				// Local template references are fine
			}
		}
	}

	// Check resource repository references
	for _, res := range pipeline.Resources() {
		if res.Type == "repositories" && res.Ref == "" && res.Repository != "" {
			findings = append(findings, AzureFinding{
				RuleID:   "AZ-003",
				Severity: severityLow,
				File:     pipeline.FilePath(),
				Message: fmt.Sprintf(
					"Azure Unpinned Resource: repository resource '%s' without ref pin",
					res.Repository),
				Details: "Repository resources without a ref pin use the default branch. Pin to a specific tag, branch, or commit SHA to prevent supply chain attacks.",
			})
		}
	}

	return findings
}

// checkAzureSelfHostedAgent detects PR-triggered pipelines running on
// self-hosted agent pools.
func checkAzureSelfHostedAgent(pipeline *AzurePipeline) []AzureFinding {
	if !pipeline.HasExternalTrigger() {
		return nil
	}

	var findings []AzureFinding

	for _, job := range pipeline.Jobs() {
		if !isAzureSelfHosted(job.RunnerType) {
			continue
		}

		severity := severityHigh
		msg := fmt.Sprintf(
			"Azure Self-Hosted Agent: job '%s' uses agent pool '%s' on PR trigger",
			job.Name, job.RunnerType)

		// Deployment jobs with environment protection are safer
		if job.Environment != "" {
			severity = severityMedium
			msg += fmt.Sprintf(" (protected by environment '%s')", job.Environment)
		}

		findings = append(findings, AzureFinding{
			RuleID:   "AZ-009",
			Severity: severity,
			File:     pipeline.FilePath(),
			Message:  msg,
			Details:  "Self-hosted agent pools on PR-triggered pipelines allow fork PR authors to execute arbitrary code on the agent machine. This risks credential theft, persistence, and lateral movement. Use Microsoft-hosted agents for PR validation or restrict fork builds.",
		})
	}

	return findings
}

// checkAzureBroadPermissions detects service connections or variable groups
// with overly broad access. Looks for azureSubscription in task inputs
// without explicit scope restrictions (AZ-004).
func checkAzureBroadPermissions(pipeline *AzurePipeline) []AzureFinding {
	var findings []AzureFinding

	for _, job := range pipeline.Jobs() {
		for _, step := range job.Steps {
			if step.Type != StepAction {
				continue
			}
			// Check for Azure tasks that use service connections
			if step.Env == nil {
				continue
			}
			azSub, hasAzSub := step.Env["azureSubscription"]
			if !hasAzSub {
				// Also check inputs (Azure tasks pass inputs via Env in our model)
				continue
			}

			// azureSubscription without scope is broad
			findings = append(findings, AzureFinding{
				RuleID:   "AZ-004",
				Severity: severityMedium,
				File:     pipeline.FilePath(),
				Line:     step.Line,
				Message: fmt.Sprintf(
					"Azure Broad Permissions: task '%s' uses service connection '%s' without explicit scope",
					step.Command, azSub),
				Details: "Azure service connections grant access to cloud resources. Using azureSubscription without restricting the scope of the service connection allows the pipeline to access all resources in the subscription. Use scoped service connections with specific resource group permissions.",
			})
		}
	}
	return findings
}

// checkAzureSecretsInLogs detects Write-Host or echo statements that reference
// secret variables or Build.* variables that may leak sensitive data (AZ-005).
func checkAzureSecretsInLogs(pipeline *AzurePipeline) []AzureFinding {
	sensitivePatterns := []string{"secret", "token", "key", "password", "credentials"}

	var findings []AzureFinding
	for _, job := range pipeline.Jobs() {
		for _, step := range job.Steps {
			if step.Type != StepScript {
				continue
			}
			cmd := step.Command
			lower := strings.ToLower(cmd)

			// Look for echo/Write-Host/Write-Output statements
			isOutput := strings.Contains(lower, "echo ") || strings.Contains(lower, "echo\t") ||
				strings.Contains(lower, "write-host ") || strings.Contains(lower, "write-output ") ||
				strings.Contains(lower, "printf ")
			if !isOutput {
				continue
			}

			// Check for $(variable) references containing sensitive names
			for _, pattern := range sensitivePatterns {
				if strings.Contains(lower, "$(") {
					// Extract variable references $(...)
					idx := 0
					for {
						start := strings.Index(lower[idx:], "$(")
						if start == -1 {
							break
						}
						start += idx
						end := strings.Index(lower[start:], ")")
						if end == -1 {
							break
						}
						varName := strings.ToLower(cmd[start+2 : start+end])
						if strings.Contains(varName, pattern) {
							findings = append(findings, AzureFinding{
								RuleID:   "AZ-005",
								Severity: severityLow,
								File:     pipeline.FilePath(),
								Line:     step.Line,
								Message: fmt.Sprintf(
									"Azure Secrets in Logs: job '%s' may echo sensitive variable containing '%s'",
									job.Name, pattern),
								Details: "Writing secret variables or sensitive build parameters to the log can expose credentials. Azure DevOps masks variables marked as secret, but variable group values or custom variables may not be masked automatically.",
							})
							goto nextStep
						}
						idx = start + end + 1
					}
				}
			}
		nextStep:
		}
	}
	return findings
}

// checkAzureForkSecrets detects PR-triggered pipelines where secrets from
// variable groups may be accessible to fork builds (AZ-006).
func checkAzureForkSecrets(pipeline *AzurePipeline) []AzureFinding {
	if !pipeline.HasExternalTrigger() {
		return nil
	}

	// Check for variable groups (which contain secrets)
	hasVariableGroup := false
	for _, v := range pipeline.Variables() {
		if v.Group != "" {
			hasVariableGroup = true
			break
		}
	}
	if !hasVariableGroup {
		return nil
	}

	var findings []AzureFinding
	for _, job := range pipeline.Jobs() {
		// Check if job references secrets or variable groups
		hasSecretRef := len(job.Secrets) > 0
		if !hasSecretRef {
			continue
		}

		findings = append(findings, AzureFinding{
			RuleID:   "AZ-006",
			Severity: severityHigh,
			File:     pipeline.FilePath(),
			Message: fmt.Sprintf(
				"Azure Fork Secrets: job '%s' accesses variable groups on PR-triggered pipeline",
				job.Name),
			Details: "PR-triggered pipelines with variable group references may expose secrets to fork builds if 'Make secrets available to builds of forks' is enabled. Variable groups often contain production credentials, service connection details, and API keys. Disable fork build secret access or use environment protections.",
		})
	}
	return findings
}

// checkAzureOIDCMisconfig detects workload identity federation references in
// PR-triggered pipelines. OIDC tokens issued to PR builds from forks can be
// used to authenticate to cloud providers (AZ-008).
func checkAzureOIDCMisconfig(pipeline *AzurePipeline) []AzureFinding {
	if !pipeline.HasExternalTrigger() {
		return nil
	}

	var findings []AzureFinding
	for _, job := range pipeline.Jobs() {
		for _, step := range job.Steps {
			if step.Type != StepAction {
				continue
			}

			// Check for Azure tasks that use OIDC/workload identity
			taskLower := strings.ToLower(step.Command)
			isOIDCTask := strings.Contains(taskLower, "azurecli@") ||
				strings.Contains(taskLower, "azurepowershell@") ||
				strings.Contains(taskLower, "azurermwebappdeployment@") ||
				strings.Contains(taskLower, "arm")

			if !isOIDCTask {
				continue
			}

			// Check if step has azureSubscription input (service connection that may use OIDC)
			hasAzSub := false
			if step.Env != nil {
				if _, ok := step.Env["azureSubscription"]; ok {
					hasAzSub = true
				}
			}

			if hasAzSub {
				severity := severityHigh
				msg := fmt.Sprintf(
					"Azure OIDC Misconfiguration: task '%s' uses service connection on PR-triggered pipeline",
					step.Command)

				// Deployment jobs with environment are somewhat protected
				if job.Environment != "" {
					severity = severityMedium
					msg += fmt.Sprintf(" (protected by environment '%s')", job.Environment)
				}

				findings = append(findings, AzureFinding{
					RuleID:   "AZ-008",
					Severity: severity,
					File:     pipeline.FilePath(),
					Line:     step.Line,
					Message:  msg,
					Details:  "Workload identity federation (OIDC) service connections on PR-triggered pipelines may issue tokens to fork PR builds. Attackers can use these tokens to authenticate to Azure, AWS, or GCP resources. Restrict OIDC service connections to protected environments with approval gates.",
				})
			}
		}
	}
	return findings
}

// checkAzureCachePoisoning detects Cache@2 or RestoreCache@1 tasks on PR
// pipelines with predictable cache keys (AZ-010).
func checkAzureCachePoisoning(pipeline *AzurePipeline) []AzureFinding {
	if !pipeline.HasExternalTrigger() {
		return nil
	}

	var findings []AzureFinding
	for _, job := range pipeline.Jobs() {
		for _, step := range job.Steps {
			if step.Type != StepAction {
				continue
			}

			taskLower := strings.ToLower(step.Command)
			isCacheTask := strings.Contains(taskLower, "cache@") ||
				strings.Contains(taskLower, "restorecache@")
			if !isCacheTask {
				continue
			}

			// Check for predictable cache key
			cacheKey := ""
			if step.Env != nil {
				if k, ok := step.Env["key"]; ok {
					cacheKey = k
				}
			}

			msg := fmt.Sprintf(
				"Azure Cache Poisoning: task '%s' in job '%s' on PR-triggered pipeline",
				step.Command, job.Name)

			if cacheKey != "" {
				msg += fmt.Sprintf(" with key '%s'", cacheKey)
			}

			findings = append(findings, AzureFinding{
				RuleID:   "AZ-010",
				Severity: severityMedium,
				File:     pipeline.FilePath(),
				Line:     step.Line,
				Message:  msg,
				Details:  "Cache tasks on PR-triggered pipelines allow fork authors to poison the build cache. Subsequent builds on protected branches may use poisoned cached artifacts, enabling supply chain attacks. Use isolated cache keys per PR or disable caching for fork builds.",
			})
		}
	}
	return findings
}

func isAzureSelfHosted(pool string) bool {
	if pool == "" {
		return false
	}
	if strings.HasPrefix(pool, "self-hosted:") {
		return true
	}
	// Microsoft-hosted pools use vmImage
	if strings.HasPrefix(pool, "hosted:") {
		return false
	}
	// Named pools without "hosted:" prefix are likely self-hosted
	// Common Microsoft-hosted pool names
	hostedPools := []string{
		"azure pipelines", "vs2022-preview", "windows-latest",
		"ubuntu-latest", "macos-latest",
	}
	lower := strings.ToLower(pool)
	for _, hp := range hostedPools {
		if strings.Contains(lower, hp) {
			return false
		}
	}
	// If it's a named pool and not recognized as hosted, assume self-hosted
	return strings.Contains(pool, ":")
}
