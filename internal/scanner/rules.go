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
		"FG-006": CheckForkPRCodeExec,
		"FG-007": CheckTokenExposure,
	}
}

// RuleDescriptions maps rule IDs to human-readable descriptions.
var RuleDescriptions = map[string]string{
	"FG-001": "Pwn Request",
	"FG-002": "Script Injection",
	"FG-003": "Tag-Based Pinning",
	"FG-004": "Broad Permissions",
	"FG-005": "Secrets in Logs",
	"FG-006": "Fork PR Code Execution",
	"FG-007": "Token Exposure in Build Steps",
}

// ExecutionAnalysis captures the result of post-checkout step analysis.
type ExecutionAnalysis struct {
	Confirmed bool
	Likely    bool
	Detail    string
}

// MitigationAnalysis captures defensive controls detected on a workflow/job.
type MitigationAnalysis struct {
	LabelGated       bool
	EnvironmentGated bool
	MaintainerCheck  bool
	ForkGuard        bool
	ActorGuard       bool // Job if: restricts execution to specific bot actor(s)
	ActorGuardHuman  bool // Job if: restricts to specific human actor(s) (weaker)
	NeedsGate        bool // Job depends on upstream job with environment/fork gate
	TokenBlanked     bool
	PathIsolated     bool // Fork code checked out to subdirectory, no direct execution
	Details          []string
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
		checkoutPath := ""

		for i, step := range job.Steps {
			if isCheckoutAction(step.Uses) && refPointsToPRHead(step.With["ref"]) {
				checkoutIdx = i
				checkoutLine = step.Line
				checkoutRef = step.With["ref"]
				checkoutPath = step.With["path"]
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

		// Analyze mitigations and adjust severity
		mitigation := analyzeMitigations(wf, job, checkoutIdx, postCheckoutSteps, checkoutPath)
		mitigated := false

		if mitigation.ForkGuard || mitigation.ActorGuard {
			severity = SeverityInfo
			confidence = ConfidencePatternOnly
			mitigated = true
		} else if mitigation.LabelGated && mitigation.EnvironmentGated {
			severity = downgradeBy(severity, 2)
			mitigated = true
		} else if mitigation.LabelGated || mitigation.EnvironmentGated || mitigation.MaintainerCheck || mitigation.ActorGuardHuman {
			severity = downgradeBy(severity, 1)
			mitigated = true
		}

		// Path isolation adjusts confidence, not severity
		if mitigation.PathIsolated && confidence == ConfidenceConfirmed {
			confidence = ConfidencePatternOnly
			mitigated = true
		}

		msg := fmt.Sprintf("Pwn Request: pull_request_target with fork checkout [%s]", confidence)
		if execResult.Detail != "" {
			msg += " — " + execResult.Detail
		}
		if mitigated {
			msg += " (mitigated: " + strings.Join(mitigation.Details, "; ") + ")"
		}

		permDesc := describePermissions(wf.Permissions, job.Permissions)
		details := fmt.Sprintf(
			"Trigger: pull_request_target, Checkout ref: %s, Permissions: %s, Execution: %s",
			checkoutRef, permDesc, confidence,
		)

		findings = append(findings, Finding{
			RuleID:      "FG-001",
			Severity:    severity,
			Confidence:  confidence,
			File:        wf.Path,
			Line:        checkoutLine,
			Message:     msg,
			Details:     details,
			Mitigations: mitigation.Details,
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

// CheckForkPRCodeExec detects pull_request workflows that execute attacker-controlled
// build hooks from fork code (FG-006).
func CheckForkPRCodeExec(wf *Workflow) []Finding {
	if !wf.On.PullRequest {
		return nil
	}

	var findings []Finding
	for _, job := range wf.Jobs {
		// Skip if job has a fork guard
		if job.If != "" && containsForkGuard(job.If) {
			continue
		}

		checkoutIdx := -1
		checkoutLine := 0

		for i, step := range job.Steps {
			if isCheckoutAction(step.Uses) && checkoutsForkCode(step) {
				checkoutIdx = i
				checkoutLine = step.Line
				break
			}
		}

		if checkoutIdx == -1 {
			continue
		}

		postCheckoutSteps := job.Steps[checkoutIdx+1:]
		execResult := analyzePostCheckoutExecution(postCheckoutSteps)

		if !execResult.Confirmed && !execResult.Likely {
			continue
		}

		severity := SeverityMedium
		if postCheckoutAccessesSecrets(postCheckoutSteps) {
			severity = SeverityHigh
		}

		confidence := ConfidenceConfirmed
		if !execResult.Confirmed {
			confidence = ConfidenceLikely
		}

		msg := fmt.Sprintf("Fork PR Code Execution: pull_request checkout runs %s", execResult.Detail)

		findings = append(findings, Finding{
			RuleID:     "FG-006",
			Severity:   severity,
			Confidence: confidence,
			File:       wf.Path,
			Line:       checkoutLine,
			Message:    msg,
			Details:    "Trigger: pull_request (read-only token from forks, but arbitrary code execution on runner)",
		})
	}
	return findings
}

// CheckTokenExposure detects inconsistent GITHUB_TOKEN blanking where build steps
// have token access but other steps blank it (FG-007).
func CheckTokenExposure(wf *Workflow) []Finding {
	if !wf.On.PullRequestTarget && !wf.On.PullRequest {
		return nil
	}

	var findings []Finding
	for _, job := range wf.Jobs {
		checkoutIdx := -1
		for i, step := range job.Steps {
			if isCheckoutAction(step.Uses) && (refPointsToPRHead(step.With["ref"]) || checkoutsForkCode(step)) {
				checkoutIdx = i
				break
			}
		}
		if checkoutIdx == -1 {
			continue
		}

		postCheckoutSteps := job.Steps[checkoutIdx+1:]
		hasAnyBlanked := false
		var unblankedExecSteps []Step

		for _, step := range postCheckoutSteps {
			if step.Run == "" {
				continue
			}
			if isTokenBlanked(step) {
				hasAnyBlanked = true
			} else {
				if _, found := matchesBuildCommand(step.Run); found {
					unblankedExecSteps = append(unblankedExecSteps, step)
				} else if _, found := matchesConfigLoadingTool(step.Run); found {
					unblankedExecSteps = append(unblankedExecSteps, step)
				}
			}
		}

		// Only flag inconsistent blanking — some steps blank, build step doesn't
		if hasAnyBlanked && len(unblankedExecSteps) > 0 {
			severity := SeverityLow
			if wf.On.PullRequestTarget {
				severity = SeverityMedium
			}

			for _, step := range unblankedExecSteps {
				findings = append(findings, Finding{
					RuleID:   "FG-007",
					Severity: severity,
					File:     wf.Path,
					Line:     step.Line,
					Message: fmt.Sprintf(
						"Token Available During Code Execution: GITHUB_TOKEN not blanked on build step (line %d) despite being blanked on other steps",
						step.Line),
					Details: "Other steps in this job set GITHUB_TOKEN=\"\" but the step executing attacker-controlled code does not. The token is accessible to build hooks via the process environment.",
				})
			}
		}
	}
	return findings
}

// analyzeMitigations detects defensive controls on a workflow/job.
func analyzeMitigations(wf *Workflow, job Job, checkoutIdx int, postCheckoutSteps []Step, checkoutPath string) MitigationAnalysis {
	m := MitigationAnalysis{}

	// 1. Check pull_request_target types filter
	if containsOnly(wf.On.PullRequestTargetTypes, "labeled") {
		m.LabelGated = true
		m.Details = append(m.Details, "trigger requires 'labeled' event (maintainer action)")
	}

	// 2. Check job-level if: for label gates, fork guards, and actor guards
	if job.If != "" {
		if containsLabelCheck(job.If) {
			m.LabelGated = true
			m.Details = append(m.Details, fmt.Sprintf("job if: contains label gate (%s)", truncate(job.If, 80)))
		}
		if containsForkGuard(job.If) {
			m.ForkGuard = true
			m.Details = append(m.Details, "job if: contains fork guard")
		}
		isBot, isHuman := containsActorGuard(job.If)
		if isBot {
			m.ActorGuard = true
			m.Details = append(m.Details, fmt.Sprintf("job if: restricts to bot actor (%s)", truncate(job.If, 80)))
		} else if isHuman {
			m.ActorGuardHuman = true
			m.Details = append(m.Details, fmt.Sprintf("job if: restricts to specific actor(s) (%s)", truncate(job.If, 80)))
		}
	}

	// 3. Check environment protection
	if job.Environment != "" {
		m.EnvironmentGated = true
		m.Details = append(m.Details, fmt.Sprintf("job uses environment '%s' (may require approval)", job.Environment))
	}

	// 4. Check for maintainer permission verification in pre-checkout steps
	if checkoutIdx > 0 {
		preCheckoutSteps := job.Steps[:checkoutIdx]
		for _, step := range preCheckoutSteps {
			if containsMaintainerCheck(step) {
				m.MaintainerCheck = true
				m.Details = append(m.Details, fmt.Sprintf("pre-checkout step checks permissions (line %d)", step.Line))
			}
		}
	}

	// 5. Check if GITHUB_TOKEN is blanked on execution steps
	for _, step := range postCheckoutSteps {
		if step.Run != "" && !isReadOnlyRun(step.Run) {
			if isTokenBlanked(step) {
				m.TokenBlanked = true
			}
		}
	}
	if m.TokenBlanked {
		m.Details = append(m.Details, "GITHUB_TOKEN explicitly blanked on execution steps")
	}

	// 6. Check needs: chain for upstream environment/fork gates
	for _, depName := range job.Needs {
		if dep, ok := wf.Jobs[depName]; ok {
			if dep.Environment != "" {
				m.NeedsGate = true
				m.EnvironmentGated = true
				m.Details = append(m.Details, fmt.Sprintf(
					"depends on job '%s' with environment '%s' (requires approval)",
					depName, truncate(dep.Environment, 60)))
			}
			if dep.If != "" && containsForkGuard(dep.If) {
				m.NeedsGate = true
				m.ForkGuard = true
				m.Details = append(m.Details, fmt.Sprintf(
					"depends on job '%s' with fork guard", depName))
			}
			if dep.If != "" {
				isBot, _ := containsActorGuard(dep.If)
				if isBot {
					m.NeedsGate = true
					m.ActorGuard = true
					m.Details = append(m.Details, fmt.Sprintf(
						"depends on job '%s' with bot actor guard", depName))
				}
			}
		}
	}

	// 7. Check path isolation — fork code in subdirectory with no direct execution
	if checkoutPath != "" {
		hasForkExec := false
		for _, step := range postCheckoutSteps {
			if step.Run != "" && referencesForkPath(step.Run, checkoutPath) {
				hasForkExec = true
				break
			}
		}
		if !hasForkExec {
			m.PathIsolated = true
			m.Details = append(m.Details, fmt.Sprintf(
				"fork code checked out to '%s/' — no direct execution of fork path detected", checkoutPath))
		}
	}

	return m
}

// downgradeBy reduces severity by N levels on the severity ladder.
func downgradeBy(severity string, levels int) string {
	order := []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
	idx := 0
	for i, s := range order {
		if s == severity {
			idx = i
			break
		}
	}
	idx += levels
	if idx >= len(order) {
		idx = len(order) - 1
	}
	return order[idx]
}

// containsOnly checks if a slice contains only the specified allowed values.
func containsOnly(types []string, allowed ...string) bool {
	if len(types) == 0 {
		return false
	}
	allowSet := make(map[string]bool)
	for _, a := range allowed {
		allowSet[a] = true
	}
	for _, t := range types {
		if !allowSet[t] {
			return false
		}
	}
	return true
}

// containsLabelCheck detects label-based gating in if: conditionals.
func containsLabelCheck(ifExpr string) bool {
	labelPatterns := []string{
		"github.event.label.name",
		"github.event.action == 'labeled'",
		`github.event.action == "labeled"`,
		"contains(github.event.pull_request.labels",
	}
	lower := strings.ToLower(ifExpr)
	for _, p := range labelPatterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// containsForkGuard detects conditions that restrict to internal PRs only.
func containsForkGuard(ifExpr string) bool {
	forkGuardPatterns := []string{
		"github.event.pull_request.head.repo.full_name == github.repository",
		"github.event.pull_request.head.repo.fork == false",
		"github.event.pull_request.head.repo.fork != true",
	}
	for _, p := range forkGuardPatterns {
		if strings.Contains(ifExpr, p) {
			return true
		}
	}
	return false
}

// containsActorGuard detects actor-based gating in if: conditionals.
// Returns (isBot, isHuman): bot guards are strong (info), human guards are weaker (downgrade by 1).
func containsActorGuard(ifExpr string) (isBot bool, isHuman bool) {
	lower := strings.ToLower(ifExpr)
	actorPrefixes := []string{
		"github.actor ==",
		"github.triggering_actor ==",
	}
	hasActorCheck := false
	for _, p := range actorPrefixes {
		if strings.Contains(lower, p) {
			hasActorCheck = true
			break
		}
	}
	if !hasActorCheck {
		// Also detect contains(fromJSON(...), github.actor) pattern
		if strings.Contains(lower, "github.actor") && strings.Contains(lower, "contains(") {
			hasActorCheck = true
		}
	}
	if !hasActorCheck {
		return false, false
	}
	// Bot accounts have [bot] suffix
	if strings.Contains(lower, "[bot]") {
		return true, false
	}
	return false, true
}

// containsMaintainerCheck detects permission verification steps.
func containsMaintainerCheck(step Step) bool {
	// 1. Check for known permission-checking actions
	permissionActions := []string{
		"actions-cool/check-user-permission",
		"prince-chrismc/check-actor-permissions-action",
		"lannonbr/repo-permission-check-action",
		"themoddinginquisition/actions-team-membership",
	}
	if step.Uses != "" {
		actionName := step.Uses
		if idx := strings.Index(actionName, "@"); idx != -1 {
			actionName = actionName[:idx]
		}
		for _, action := range permissionActions {
			if strings.EqualFold(actionName, action) {
				return true
			}
		}
	}

	// 2. Check script content for API calls
	checkPatterns := []string{
		"getCollaboratorPermissionLevel",
		"repos.getCollaboratorPermission",
		"permission.permission",
	}
	searchText := step.Run
	if step.Uses != "" && strings.Contains(step.Uses, "actions/github-script") {
		if script, ok := step.With["script"]; ok {
			searchText = script
		}
	}
	for _, p := range checkPatterns {
		if strings.Contains(searchText, p) {
			return true
		}
	}
	return false
}

// referencesForkPath checks if a run block executes code from the fork checkout path.
func referencesForkPath(run string, checkoutPath string) bool {
	execPatterns := []string{
		"cd " + checkoutPath,
		"./" + checkoutPath + "/",
		checkoutPath + "/",
		"pip install " + checkoutPath,
		"pip install -e " + checkoutPath,
		"npm install --prefix " + checkoutPath,
	}
	for _, p := range execPatterns {
		if strings.Contains(run, p) {
			// Distinguish data-only operations from execution
			// cp, mv, rsync are data operations, not execution
			lines := strings.Split(run, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, checkoutPath) {
					if isDataOnlyCommand(line) {
						continue
					}
					return true
				}
			}
		}
	}
	return false
}

// isDataOnlyCommand checks if a shell line is a data-copy operation (not execution).
func isDataOnlyCommand(line string) bool {
	dataOps := []string{"cp ", "cp -r ", "mv ", "rsync ", "rm ", "rm -rf ", "ln ", "mkdir "}
	trimmed := strings.TrimSpace(line)
	for _, op := range dataOps {
		if strings.HasPrefix(trimmed, op) {
			return true
		}
	}
	return false
}

// isTokenBlanked checks if a step explicitly sets GITHUB_TOKEN to empty.
func isTokenBlanked(step Step) bool {
	if token, ok := step.Env["GITHUB_TOKEN"]; ok {
		return token == "" || token == "''" || token == `""`
	}
	return false
}

// checkoutsForkCode checks if a checkout step checks out fork code.
// For pull_request trigger, default checkout (no ref) checks out the merge commit
// which includes fork code.
func checkoutsForkCode(step Step) bool {
	ref := step.With["ref"]
	if refPointsToPRHead(ref) {
		return true
	}
	// Default checkout on pull_request includes fork code
	if ref == "" {
		return true
	}
	return false
}

// postCheckoutAccessesSecrets checks if any post-checkout step references secrets.
func postCheckoutAccessesSecrets(steps []Step) bool {
	for _, step := range steps {
		if step.Run == "" {
			continue
		}
		for _, v := range step.Env {
			if strings.Contains(v, "secrets.") && !isTokenBlanked(step) {
				return true
			}
		}
		for _, v := range step.With {
			if strings.Contains(v, "secrets.") {
				return true
			}
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
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
