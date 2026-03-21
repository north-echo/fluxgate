package scanner

import (
	"fmt"
	"regexp"
	"strings"
)

// Rule is a function that checks a workflow and returns findings.
type Rule func(wf *Workflow) []Finding

// AllRules returns all enabled detection rules.
func AllRules() map[string]Rule {
	return map[string]Rule{
		"FG-001": CheckPwnRequest,
		"FG-002": CheckScriptInjection,
		"FG-003": CheckTagPinning,
		"FG-004": CheckBroadPermissions,
		"FG-005": CheckSecretsInLogs,
	}
}

// RuleDescriptions maps rule IDs to human-readable descriptions.
var RuleDescriptions = map[string]string{
	"FG-001": "Pwn Request",
	"FG-002": "Script Injection",
	"FG-003": "Tag-Based Pinning",
	"FG-004": "Broad Permissions",
	"FG-005": "Secrets in Logs",
}

// ExecutionAnalysis captures the result of post-checkout step analysis.
type ExecutionAnalysis struct {
	Confirmed bool
	Likely    bool
	Detail    string
}

// Build tools that definitely execute code from the working directory.
var confirmedBuildCommands = []string{
	"npm install", "npm ci", "npm run", "npm test", "npm start",
	"yarn install", "yarn run", "yarn test", "yarn build",
	"pnpm install", "pnpm run", "pnpm test",
	"pip install", "poetry install",
	"bundle install", "bundle exec",
	"cargo build", "cargo test", "cargo run",
	"go build", "go test", "go run",
	"make", "cmake",
	"mvn", "gradle", "ant",
	"dotnet build", "dotnet test", "dotnet run",
	"docker build",
}

// Tools that load and execute config files from the repo.
var configLoadingTools = []string{
	"eslint", "prettier", "jest", "vitest",
	"webpack", "rollup", "vite", "next", "nuxt",
	"pytest", "tox", "nox",
	"tsup", "esbuild",
}

// Actions known to execute code from the working directory.
var buildActions = []string{
	"docker/build-push-action",
	"gradle/gradle-build-action",
	"borales/actions-yarn",
	"bahmutov/npm-install",
}

// Read-only commands that don't execute checked-out code.
var readOnlyCommands = []string{
	"diff", "cmp", "cat", "grep", "head", "tail", "wc",
	"sha256sum", "md5sum", "jq", "yq",
	"gh pr comment", "gh pr review", "gh issue comment",
	"test -f", "[ -f", "stat", "file", "ls",
	"echo", "printf",
}

// CheckPwnRequest detects pull_request_target workflows that checkout PR head
// code with post-checkout execution analysis (FG-001).
func CheckPwnRequest(wf *Workflow) []Finding {
	if !wf.On.PullRequestTarget {
		return nil
	}

	var findings []Finding
	for _, job := range wf.Jobs {
		checkoutIdx := -1
		checkoutLine := 0
		checkoutRef := ""

		for i, step := range job.Steps {
			if isCheckoutAction(step.Uses) && refPointsToPRHead(step.With["ref"]) {
				checkoutIdx = i
				checkoutLine = step.Line
				checkoutRef = step.With["ref"]
				break
			}
		}

		if checkoutIdx == -1 {
			continue
		}

		// Analyze all steps after the checkout
		postCheckoutSteps := job.Steps[checkoutIdx+1:]
		execResult := analyzePostCheckoutExecution(postCheckoutSteps)

		severity := SeverityHigh
		confidence := ConfidencePatternOnly

		if execResult.Confirmed {
			severity = SeverityCritical
			confidence = ConfidenceConfirmed
		} else if execResult.Likely {
			severity = SeverityCritical
			confidence = ConfidenceLikely
		}

		msg := fmt.Sprintf("Pwn Request: pull_request_target with fork checkout [%s]", confidence)
		if execResult.Detail != "" {
			msg += " — " + execResult.Detail
		}

		permDesc := describePermissions(wf.Permissions, job.Permissions)
		details := fmt.Sprintf(
			"Trigger: pull_request_target, Checkout ref: %s, Permissions: %s, Execution: %s",
			checkoutRef, permDesc, confidence,
		)

		findings = append(findings, Finding{
			RuleID:     "FG-001",
			Severity:   severity,
			Confidence: confidence,
			File:       wf.Path,
			Line:       checkoutLine,
			Message:    msg,
			Details:    details,
		})
	}
	return findings
}

// analyzePostCheckoutExecution checks whether steps after a fork checkout
// execute code from the working directory.
func analyzePostCheckoutExecution(steps []Step) ExecutionAnalysis {
	hasSetupAction := false

	for _, step := range steps {
		// Check uses: for known build actions
		if step.Uses != "" {
			actionName := step.Uses
			if idx := strings.Index(actionName, "@"); idx != -1 {
				actionName = actionName[:idx]
			}

			for _, ba := range buildActions {
				if actionName == ba {
					return ExecutionAnalysis{
						Confirmed: true,
						Detail:    fmt.Sprintf("action '%s' executes repo code (line %d)", actionName, step.Line),
					}
				}
			}

			if strings.HasPrefix(actionName, "actions/setup-") {
				hasSetupAction = true
			}
		}

		// Check run: blocks
		if step.Run != "" {
			if cmd, found := matchesBuildCommand(step.Run); found {
				return ExecutionAnalysis{
					Confirmed: true,
					Detail:    fmt.Sprintf("run block executes '%s' on checked-out code (line %d)", cmd, step.Line),
				}
			}
			if cmd, found := matchesConfigLoadingTool(step.Run); found {
				return ExecutionAnalysis{
					Likely: true,
					Detail: fmt.Sprintf("run block invokes '%s' which loads config from repo (line %d)", cmd, step.Line),
				}
			}
			// If there's a setup action and a run block, it likely executes repo code
			if hasSetupAction && !isReadOnlyRun(step.Run) {
				return ExecutionAnalysis{
					Likely: true,
					Detail: fmt.Sprintf("run block after setup action may execute repo code (line %d)", step.Line),
				}
			}
		}
	}

	return ExecutionAnalysis{
		Confirmed: false,
		Likely:    false,
		Detail:    "no code execution detected in post-checkout steps",
	}
}

// splitShellCommands splits a shell line on &&, ||, ;, and |.
func splitShellCommands(line string) []string {
	var segments []string
	current := ""
	i := 0
	for i < len(line) {
		if i+1 < len(line) && (line[i:i+2] == "&&" || line[i:i+2] == "||") {
			segments = append(segments, current)
			current = ""
			i += 2
			continue
		}
		if line[i] == ';' || line[i] == '|' {
			segments = append(segments, current)
			current = ""
			i++
			continue
		}
		current += string(line[i])
		i++
	}
	if current != "" {
		segments = append(segments, current)
	}
	return segments
}

// matchesBuildCommand checks if a run block contains a known build command.
func matchesBuildCommand(run string) (string, bool) {
	lines := strings.Split(run, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		segments := splitShellCommands(line)
		for _, seg := range segments {
			seg = strings.TrimSpace(seg)
			for _, cmd := range confirmedBuildCommands {
				if strings.HasPrefix(seg, cmd+" ") || seg == cmd {
					return cmd, true
				}
			}
			// Check for relative path execution
			if strings.HasPrefix(seg, "./") {
				return seg, true
			}
		}
	}
	return "", false
}

// matchesConfigLoadingTool checks if a run block invokes a config-loading tool.
func matchesConfigLoadingTool(run string) (string, bool) {
	lines := strings.Split(run, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		segments := splitShellCommands(line)
		for _, seg := range segments {
			seg = strings.TrimSpace(seg)
			for _, tool := range configLoadingTools {
				if strings.HasPrefix(seg, tool+" ") || seg == tool {
					return tool, true
				}
			}
		}
	}
	return "", false
}

// isReadOnlyRun checks if a run block only contains read-only commands.
func isReadOnlyRun(run string) bool {
	lines := strings.Split(run, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		segments := splitShellCommands(line)
		for _, seg := range segments {
			seg = strings.TrimSpace(seg)
			if seg == "" {
				continue
			}
			isReadOnly := false
			for _, ro := range readOnlyCommands {
				if strings.HasPrefix(seg, ro+" ") || seg == ro {
					isReadOnly = true
					break
				}
			}
			if !isReadOnly {
				return false
			}
		}
	}
	return true
}

// CheckScriptInjection detects attacker-controllable expressions used in
// run blocks (FG-002).
func CheckScriptInjection(wf *Workflow) []Finding {
	dangerousExpressions := []string{
		"github.event.issue.title",
		"github.event.issue.body",
		"github.event.pull_request.title",
		"github.event.pull_request.body",
		"github.event.comment.body",
		"github.event.review.body",
		"github.event.pages.*.page_name",
		"github.event.commits.*.message",
		"github.event.head_commit.message",
		"github.head_ref",
		"github.event.workflow_run.head_branch",
	}

	var findings []Finding
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}
			for _, expr := range dangerousExpressions {
				if containsExpression(step.Run, expr) {
					findings = append(findings, Finding{
						RuleID:   "FG-002",
						Severity: SeverityHigh,
						File:     wf.Path,
						Line:     step.Line,
						Message:  fmt.Sprintf("Script Injection: %s in run block", expr),
					})
				}
			}
		}
	}
	return findings
}

var shaPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)

// CheckTagPinning detects third-party actions referenced by tag instead of
// commit SHA (FG-003).
func CheckTagPinning(wf *Workflow) []Finding {
	var findings []Finding
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" || !strings.Contains(step.Uses, "@") {
				continue
			}
			parts := strings.SplitN(step.Uses, "@", 2)
			action := parts[0]
			ref := parts[1]

			if shaPattern.MatchString(ref) {
				continue // SHA-pinned, safe
			}

			severity := SeverityMedium
			if ref == "main" || ref == "master" || ref == "dev" {
				severity = SeverityHigh
			}
			if strings.HasPrefix(action, "actions/") {
				severity = SeverityInfo
			}

			findings = append(findings, Finding{
				RuleID:   "FG-003",
				Severity: severity,
				File:     wf.Path,
				Line:     step.Line,
				Message:  fmt.Sprintf("Tag Pinning: %s@%s (use SHA instead)", action, ref),
			})
		}
	}
	return findings
}

// CheckBroadPermissions detects overly broad workflow permissions (FG-004).
func CheckBroadPermissions(wf *Workflow) []Finding {
	var findings []Finding
	isExternalTrigger := wf.On.PullRequestTarget || wf.On.IssueComment || wf.On.WorkflowRun

	// Check for write-all or missing permissions block
	if wf.Permissions.WriteAll {
		findings = append(findings, Finding{
			RuleID:   "FG-004",
			Severity: SeverityMedium,
			File:     wf.Path,
			Line:     1,
			Message:  "Broad Permissions: workflow has write-all permissions",
		})
	} else if !wf.Permissions.Set && isExternalTrigger {
		findings = append(findings, Finding{
			RuleID:   "FG-004",
			Severity: SeverityMedium,
			File:     wf.Path,
			Line:     1,
			Message:  "Broad Permissions: no permissions block on externally-triggered workflow (defaults may be write-all)",
		})
	}

	// Check for contents:write on external triggers
	if isExternalTrigger {
		for scope, perm := range wf.Permissions.Scopes {
			if scope == "contents" && perm == "write" {
				findings = append(findings, Finding{
					RuleID:   "FG-004",
					Severity: SeverityMedium,
					File:     wf.Path,
					Line:     1,
					Message:  "Broad Permissions: contents:write on externally-triggered workflow",
				})
				break
			}
		}
	}

	// Check for secrets:inherit on external triggers
	if isExternalTrigger {
		for _, job := range wf.Jobs {
			if job.Secrets == "inherit" {
				findings = append(findings, Finding{
					RuleID:   "FG-004",
					Severity: SeverityMedium,
					File:     wf.Path,
					Line:     1,
					Message:  "Broad Permissions: secrets:inherit on externally-triggered workflow",
				})
			}
		}
	}

	return findings
}

// CheckSecretsInLogs detects run blocks that may expose secrets in logs (FG-005).
func CheckSecretsInLogs(wf *Workflow) []Finding {
	secretPatterns := []string{
		"echo ${{ secrets.",
		"echo $GITHUB_TOKEN",
		"echo ${GITHUB_TOKEN",
		"printenv",
		"echo ${{ github.token",
	}

	var findings []Finding
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}
			for _, pattern := range secretPatterns {
				if strings.Contains(step.Run, pattern) {
					findings = append(findings, Finding{
						RuleID:   "FG-005",
						Severity: SeverityLow,
						File:     wf.Path,
						Line:     step.Line,
						Message:  fmt.Sprintf("Secrets in Logs: possible secret exposure via '%s'", pattern),
					})
					break // one finding per step is enough
				}
			}
		}
	}
	return findings
}

// --- helpers ---

func isCheckoutAction(uses string) bool {
	return strings.HasPrefix(uses, "actions/checkout@")
}

func refPointsToPRHead(ref string) bool {
	dangerous := []string{
		"github.event.pull_request.head.sha",
		"github.event.pull_request.head.ref",
		"github.head_ref",
	}
	for _, d := range dangerous {
		if strings.Contains(ref, d) {
			return true
		}
	}
	return false
}

func containsExpression(run, expr string) bool {
	// Match ${{ expr }} with optional whitespace
	return strings.Contains(run, "${{ "+expr) ||
		strings.Contains(run, "${{"+expr)
}

func describePermissions(wfPerms, jobPerms PermissionsConfig) string {
	if wfPerms.WriteAll || jobPerms.WriteAll {
		return "write-all"
	}
	if !wfPerms.Set && !jobPerms.Set {
		return "default (potentially write-all)"
	}

	var parts []string
	for k, v := range wfPerms.Scopes {
		parts = append(parts, fmt.Sprintf("%s:%s", k, v))
	}
	for k, v := range jobPerms.Scopes {
		parts = append(parts, fmt.Sprintf("job(%s:%s)", k, v))
	}
	if len(parts) == 0 {
		return "restricted"
	}
	return strings.Join(parts, ", ")
}
