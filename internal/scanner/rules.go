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
		"FG-008": CheckOIDCMisconfiguration,
		"FG-009": CheckSelfHostedRunner,
		"FG-010": CheckCachePoisoning,
		"FG-011": CheckBotActorTOCTOU,
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
	"FG-008": "OIDC Misconfiguration",
	"FG-009": "Self-Hosted Runner",
	"FG-010": "Cache Poisoning",
	"FG-011": "Bot Actor Guard TOCTOU",
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
	NeedsGate          bool // Job depends on upstream job with environment/fork gate
	TokenBlanked       bool
	PathIsolated       bool // Fork code checked out to subdirectory, no direct execution
	TrustedRefIsolated bool // Fork checkout to subdir, all executed code from trusted ref
	PermissionGateJob  bool // Upstream job verifies collaborator permissions via API
	Details            []string
}

// Build tools that definitely execute code from the working directory.
var confirmedBuildCommands = []string{
	"npm install", "npm ci", "npm run", "npm test", "npm start",
	"yarn install", "yarn run", "yarn test", "yarn build",
	"pnpm install", "pnpm run", "pnpm test",
	"poetry install",
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

// Formatting/linting tools with declarative-only config (no code execution surface).
// These process checked-out code but don't execute it.
var safeFormattingTools = []string{
	"black", "autopep8", "yapf", "isort", "pyink",
	"gofmt", "goimports", "gofumpt",
	"rustfmt",
	"clang-format",
	"shfmt",
	"prettier",   // config is JSON/YAML-only, no plugin execution
	"markdownlint",
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
		// Skip jobs scoped to pull_request only — they never run in
		// pull_request_target context, so no privileged secret access.
		if jobScopedToPullRequest(job.If) {
			continue
		}

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

		// Check for git-based PR checkout in run blocks
		if checkoutIdx == -1 {
			for i, step := range job.Steps {
				if step.Run != "" && runFetchesPRHead(step.Run) {
					checkoutIdx = i
					checkoutLine = step.Line
					checkoutRef = "git fetch (PR head)"
					break
				}
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

		if mitigation.ForkGuard {
			severity = SeverityInfo
			confidence = ConfidencePatternOnly
			mitigated = true
		} else if mitigation.ActorGuard {
			// Bot actor guards are bypassable via TOCTOU — cap at high, never suppress
			if severity == SeverityCritical {
				severity = SeverityHigh
			}
			mitigated = true
		} else if mitigation.LabelGated && mitigation.EnvironmentGated {
			severity = downgradeBy(severity, 2)
			mitigated = true
		} else if mitigation.LabelGated || mitigation.EnvironmentGated || mitigation.MaintainerCheck || mitigation.ActorGuardHuman {
			severity = downgradeBy(severity, 1)
			mitigated = true
		}

		// Trusted-ref isolation: fork code in subdir, all execution from trusted ref — suppress
		if mitigation.TrustedRefIsolated {
			severity = SeverityInfo
			confidence = ConfidencePatternOnly
			mitigated = true
		}

		// Permission gate job: upstream job verifies collaborator access — internal threat only
		if mitigation.PermissionGateJob && !mitigated {
			severity = downgradeBy(severity, 2)
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
			if hasSetupAction && !isReadOnlyRun(step.Run) && !isPipNamedPackageOnly(step.Run) && !isSafeFormattingRun(step.Run) {
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

// classifyPipInstall analyzes a pip install command and returns
// whether it installs attacker-controlled code from the checkout.
func classifyPipInstall(args string) (confirmed bool, detail string) {
	args = strings.TrimSpace(args)

	// No args = reads from pyproject.toml/setup.cfg in checkout
	if args == "" {
		return true, "pip install with no target (reads project config)"
	}

	// Requirements file install — attacker can modify in PR
	if strings.HasPrefix(args, "-r ") || strings.HasPrefix(args, "--requirement ") {
		return true, "pip install from requirements file (attacker can modify in PR)"
	}

	// Strip leading flags (--upgrade, --no-deps, etc.) to find the install target
	target := stripPipFlags(args)

	// Local path installs
	if target == "." || target == "./" ||
		strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") {
		return true, fmt.Sprintf("pip install from local path '%s'", target)
	}
	// Editable installs: -e . or -e ./path or -e ".[dev]"
	if strings.HasPrefix(args, "-e ") {
		eTarget := strings.TrimSpace(strings.TrimPrefix(args, "-e "))
		eTarget = stripPipFlags(eTarget)
		eUnquoted := strings.Trim(eTarget, "\"'")
		if eUnquoted == "." || eUnquoted == "./" ||
			strings.HasPrefix(eUnquoted, "./") || strings.HasPrefix(eUnquoted, "../") ||
			strings.HasPrefix(eUnquoted, ".[") {
			return true, fmt.Sprintf("pip install editable from local path '%s'", eUnquoted)
		}
		// -e with a non-local target (e.g., -e git+https://...)
		return false, fmt.Sprintf("pip install editable '%s'", eTarget)
	}

	// Extras on local path: ".[dev]", ".[dev,test]"
	if strings.HasPrefix(target, ".[") || strings.HasPrefix(target, "./[") {
		return true, fmt.Sprintf("pip install from local path with extras '%s'", target)
	}
	// Quoted variants: ".[dev]"
	unquoted := strings.Trim(target, "\"'")
	if strings.HasPrefix(unquoted, ".[") || unquoted == "." {
		return true, fmt.Sprintf("pip install from local path '%s'", unquoted)
	}

	// Named package from PyPI = not directly exploitable
	return false, fmt.Sprintf("pip install of named package '%s' (PyPI supply chain risk only)", target)
}

// stripPipFlags removes common pip install flags to find the actual target.
func stripPipFlags(args string) string {
	parts := strings.Fields(args)
	var result []string
	skip := false
	for _, p := range parts {
		if skip {
			skip = false
			continue
		}
		// Flags that take a value argument
		if p == "--target" || p == "--prefix" || p == "--root" ||
			p == "--index-url" || p == "-i" || p == "--extra-index-url" ||
			p == "--constraint" || p == "-c" || p == "--find-links" || p == "-f" {
			skip = true
			continue
		}
		// Boolean flags
		if strings.HasPrefix(p, "--") || (strings.HasPrefix(p, "-") && len(p) == 2 && p != "-e" && p != "-r") {
			continue
		}
		result = append(result, p)
	}
	return strings.Join(result, " ")
}

// isSafeFormattingRun checks if a run block only invokes safe formatting tools
// that process code but don't execute it.
func isSafeFormattingRun(run string) bool {
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
			isSafe := false
			for _, tool := range safeFormattingTools {
				if strings.HasPrefix(seg, tool+" ") || seg == tool {
					isSafe = true
					break
				}
			}
			if !isSafe {
				return false
			}
		}
	}
	return true
}

// isPipNamedPackageOnly checks if a run block only contains pip install
// of named packages (not local paths or requirements files).
func isPipNamedPackageOnly(run string) bool {
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
			isPipInstall := false
			for _, prefix := range []string{"pip install", "pip3 install"} {
				if strings.HasPrefix(seg, prefix+" ") || seg == prefix {
					pipArgs := strings.TrimPrefix(seg, prefix)
					confirmed, _ := classifyPipInstall(pipArgs)
					if confirmed {
						return false // local install = executing checkout code
					}
					isPipInstall = true
					break
				}
			}
			if !isPipInstall {
				return false // non-pip command present
			}
		}
	}
	return true
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

			// Special handling for pip install — classify by argument
			for _, prefix := range []string{"pip install", "pip3 install"} {
				if strings.HasPrefix(seg, prefix+" ") || seg == prefix {
					pipArgs := strings.TrimPrefix(seg, prefix)
					confirmed, _ := classifyPipInstall(pipArgs)
					if confirmed {
						return seg, true
					}
					goto nextSeg // named package install, skip
				}
			}

			for _, cmd := range confirmedBuildCommands {
				if strings.HasPrefix(seg, cmd+" ") || seg == cmd {
					return cmd, true
				}
			}
			// Check for relative path execution
			if strings.HasPrefix(seg, "./") {
				return seg, true
			}
		nextSeg:
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
		"github.event.inputs.",
		"inputs.",
	}

	var findings []Finding
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}
			for _, expr := range dangerousExpressions {
				if containsExpression(step.Run, expr) {
					severity := SeverityHigh
					detail := ""

					// Check if the expression is only used in echo/logging context
					exprRef := "${{ " + expr // approximate the expression reference
					if isGHALoggingOnly(step.Run, expr) {
						severity = SeverityInfo
						detail = " (logging only — echo/printf context, not directly exploitable)"
					}

					findings = append(findings, Finding{
						RuleID:   "FG-002",
						Severity: severity,
						File:     wf.Path,
						Line:     step.Line,
						Message:  fmt.Sprintf("Script Injection: %s in run block%s", expr, detail),
					})
					_ = exprRef
				}
			}
		}
	}
	return findings
}

// isGHALoggingOnly checks if a GitHub Actions expression is only used in echo/printf lines.
func isGHALoggingOnly(run string, expr string) bool {
	for _, line := range strings.Split(run, "\n") {
		trimmed := strings.TrimSpace(line)
		// Check if this line references the expression
		if !strings.Contains(trimmed, expr) && !strings.Contains(trimmed, "${{") {
			continue
		}
		// Approximate: check if the expression appears in this line
		if !containsExpression(trimmed, expr) {
			continue
		}
		// If this line is NOT an echo/printf, it's not logging-only
		lower := strings.ToLower(trimmed)
		isEcho := strings.HasPrefix(lower, "echo ") || strings.HasPrefix(lower, "echo\t") ||
			strings.HasPrefix(lower, "echo \"") || strings.HasPrefix(lower, "echo '") ||
			strings.HasPrefix(lower, "printf ") || strings.HasPrefix(lower, "cat <<")
		if !isEcho {
			return false
		}
	}
	return true
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
			// Compound guard: if the same if: expression has both an actor guard AND a fork guard,
			// the fork guard is the real gate — the actor check is just an optimization.
			// Classify as ForkGuard (suppresses to info) instead of ActorGuard (caps at high).
			if m.ForkGuard {
				m.Details = append(m.Details, fmt.Sprintf("compound guard: bot actor + fork origin check (%s)", truncate(job.If, 80)))
			} else {
				m.ActorGuard = true
				m.Details = append(m.Details, fmt.Sprintf("job if: restricts to bot actor (%s)", truncate(job.If, 80)))
			}
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

	// 8. Check trusted-ref isolation — fork checkout to subdir + separate trusted ref checkout
	// Pattern: one checkout uses a fixed ref (main/master), another uses head.sha to a different path,
	// and all run blocks reference scripts from the trusted checkout, not the fork directory.
	if checkoutPath != "" && m.PathIsolated {
		hasTrustedRef := false
		for _, step := range job.Steps {
			if isCheckoutAction(step.Uses) {
				ref := step.With["ref"]
				path := step.With["path"]
				// If this checkout uses a fixed trusted ref and a different path than the fork checkout
				if isTrustedRef(ref) && path != checkoutPath {
					hasTrustedRef = true
					break
				}
			}
		}
		if hasTrustedRef {
			m.TrustedRefIsolated = true
			m.Details = append(m.Details, "trusted-ref isolation: fork code in subdirectory, executed scripts from trusted ref checkout")
		}
	}

	// 9. Check permission gate job — upstream job verifies collaborator permission level
	// Pattern: needs: [check-permissions] where that job uses getCollaboratorPermissionLevel
	// or similar permission verification, and this job's if: references its output.
	for _, depName := range job.Needs {
		if dep, ok := wf.Jobs[depName]; ok {
			if hasPermissionCheck(dep) {
				m.PermissionGateJob = true
				m.NeedsGate = true
				m.Details = append(m.Details, fmt.Sprintf(
					"depends on job '%s' which verifies collaborator permissions (internal-only gate)", depName))
				break
			}
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
	// Also match head.repo.full_name compared to a literal string (e.g., 'kubernetes/minikube')
	// This is equivalent to comparing against github.repository but with a hardcoded value.
	// Must be == (same repo check), NOT != (fork-only check which is the opposite).
	if strings.Contains(ifExpr, "head.repo.full_name") {
		// Find the operator near head.repo.full_name
		idx := strings.Index(ifExpr, "head.repo.full_name")
		if idx >= 0 {
			surrounding := ifExpr[idx:]
			// Check for == but not != before it
			if strings.Contains(surrounding, "==") && !strings.Contains(surrounding, "!=") {
				return true
			}
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
	// Direct path patterns
	execPatterns := []string{
		"cd " + checkoutPath,
		"./" + checkoutPath + "/",
		checkoutPath + "/",
		"pip install " + checkoutPath,
		"pip install -e " + checkoutPath,
		"npm install --prefix " + checkoutPath,
		// $GITHUB_WORKSPACE-relative references
		"$GITHUB_WORKSPACE/" + checkoutPath,
		"${GITHUB_WORKSPACE}/" + checkoutPath,
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

	// Detect shell variable aliases for the fork path.
	// Pattern: VAR="$GITHUB_WORKSPACE/<path>" or VAR="./<path>" followed by
	// usage of $VAR in a non-data command (e.g., python script.py "$VAR").
	aliasPatterns := []string{
		"$GITHUB_WORKSPACE/" + checkoutPath,
		"${GITHUB_WORKSPACE}/" + checkoutPath,
		"./" + checkoutPath,
		"\"" + checkoutPath + "\"",
	}
	lines := strings.Split(run, "\n")
	var aliasVars []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		for _, ap := range aliasPatterns {
			if strings.Contains(line, ap) {
				// Check for variable assignment: VAR="..." or VAR=...
				if eqIdx := strings.Index(line, "="); eqIdx > 0 {
					varName := strings.TrimSpace(line[:eqIdx])
					// Must be a simple identifier (no spaces, starts with letter/underscore)
					if len(varName) > 0 && !strings.ContainsAny(varName, " \t$()") {
						aliasVars = append(aliasVars, "$"+varName, "${"+varName+"}")
					}
				}
			}
		}
	}

	// Check if any alias variable is used in a non-data command
	for _, line := range lines {
		line = strings.TrimSpace(line)
		for _, av := range aliasVars {
			if strings.Contains(line, av) {
				// Skip the assignment line itself and data-only commands
				if strings.Contains(line, "=") && strings.HasPrefix(line, strings.TrimPrefix(strings.TrimPrefix(av, "${"), "$")) {
					continue
				}
				if isDataOnlyCommand(line) {
					continue
				}
				return true
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

// isTrustedRef checks if a checkout ref is a fixed trusted branch (not PR head).
func isTrustedRef(ref string) bool {
	if ref == "" {
		return true // Default checkout (base ref) is trusted
	}
	trusted := []string{
		"refs/heads/main", "refs/heads/master", "main", "master",
		"${{ github.base_ref }}", "${{ github.event.repository.default_branch }}",
	}
	lower := strings.ToLower(ref)
	for _, t := range trusted {
		if lower == strings.ToLower(t) {
			return true
		}
	}
	// Environment variable references to trusted refs
	if strings.Contains(lower, "trusted") || strings.Contains(lower, "base_ref") {
		return true
	}
	return false
}

// hasPermissionCheck detects if a job verifies collaborator permissions via GitHub API.
// Pattern: uses actions/github-script with getCollaboratorPermissionLevel or similar.
func hasPermissionCheck(job Job) bool {
	permPatterns := []string{
		"getCollaboratorPermissionLevel",
		"collaborator-permission",
		"check-permissions",
		"permission-level",
		"has-access",
		"author_association",
	}
	for _, step := range job.Steps {
		target := step.Run
		if step.Uses != "" {
			// Check action inputs for permission verification patterns
			for _, v := range step.With {
				target += " " + v
			}
		}
		lower := strings.ToLower(target)
		for _, p := range permPatterns {
			if strings.Contains(lower, strings.ToLower(p)) {
				return true
			}
		}
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

// jobScopedToPullRequest checks if a job's if: condition restricts it
// to only run on pull_request events (not pull_request_target).
func jobScopedToPullRequest(ifCondition string) bool {
	if ifCondition == "" {
		return false
	}
	normalized := strings.ReplaceAll(ifCondition, " ", "")
	normalized = strings.ReplaceAll(normalized, "\u2018", "'")
	normalized = strings.ReplaceAll(normalized, "\u2019", "'")
	normalized = strings.ReplaceAll(normalized, "\"", "'")

	// Positive match: only runs on pull_request
	if strings.Contains(normalized, "github.event_name=='pull_request'") {
		// Make sure it's not checking for pull_request_target
		if !strings.Contains(normalized, "pull_request_target") {
			return true
		}
	}

	// Negative match: explicitly excludes pull_request_target
	if strings.Contains(normalized, "github.event_name!='pull_request_target'") {
		return true
	}

	return false
}

// runFetchesPRHead checks if a run block fetches PR content into the
// working directory via git commands (alternative to actions/checkout ref).
func runFetchesPRHead(run string) bool {
	lines := strings.Split(run, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// git fetch origin pull/<number>/head or git fetch origin <PR SHA>
		if strings.Contains(line, "git fetch") &&
			(strings.Contains(line, "pull/") && strings.Contains(line, "/head") ||
				strings.Contains(line, "github.event.number") ||
				strings.Contains(line, "github.event.pull_request.number") ||
				strings.Contains(line, "github.event.pull_request.head.sha")) {
			return true
		}
		// gh pr checkout
		if strings.Contains(line, "gh pr checkout") {
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

// githubHostedPrefixes lists runner labels that indicate GitHub-hosted runners.
var githubHostedPrefixes = []string{
	"ubuntu-", "windows-", "macos-",
}

// githubHostedExact lists exact runner labels that indicate GitHub-hosted runners.
var githubHostedExact = []string{
	"ubuntu-latest", "windows-latest", "macos-latest",
	"macos-13", "macos-14", "macos-15",
}

// isSelfHostedRunner checks if the runs-on labels indicate a self-hosted runner.
func isSelfHostedRunner(labels []string) bool {
	for _, label := range labels {
		lower := strings.ToLower(label)
		if lower == "self-hosted" {
			return true
		}
	}
	// If no labels match known GitHub-hosted patterns, it's likely self-hosted
	if len(labels) == 0 {
		return false
	}
	for _, label := range labels {
		lower := strings.ToLower(label)
		isGitHubHosted := false
		for _, exact := range githubHostedExact {
			if lower == exact {
				isGitHubHosted = true
				break
			}
		}
		if !isGitHubHosted {
			for _, prefix := range githubHostedPrefixes {
				if strings.HasPrefix(lower, prefix) {
					isGitHubHosted = true
					break
				}
			}
		}
		if isGitHubHosted {
			return false // At least one label matches a GitHub-hosted runner
		}
	}
	// All labels are non-standard — could be self-hosted or custom runner group
	// Only flag if "self-hosted" is explicitly present to avoid false positives
	return false
}

// CheckOIDCMisconfiguration detects id-token:write permissions on externally-triggered
// workflows where an attacker could mint cloud credentials (FG-008).
func CheckOIDCMisconfiguration(wf *Workflow) []Finding {
	var findings []Finding

	isExternalTrigger := wf.On.PullRequestTarget || wf.On.IssueComment

	for jobName, job := range wf.Jobs {
		hasIDTokenWrite := false

		// Check job-level permissions first, then workflow-level
		if job.Permissions.Scopes["id-token"] == "write" {
			hasIDTokenWrite = true
		} else if !job.Permissions.Set && wf.Permissions.Scopes["id-token"] == "write" {
			hasIDTokenWrite = true
		}

		if !hasIDTokenWrite {
			continue
		}

		// Check for cloud credential actions
		var cloudActions []string
		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}
			actionName := step.Uses
			if idx := strings.Index(actionName, "@"); idx != -1 {
				actionName = actionName[:idx]
			}
			switch actionName {
			case "aws-actions/configure-aws-credentials",
				"google-github-actions/auth",
				"azure/login",
				"hashicorp/vault-action":
				cloudActions = append(cloudActions, actionName)
			}
		}

		if wf.On.PullRequestTarget {
			// Check if this job also checks out fork code
			checkoutsFork := false
			for _, step := range job.Steps {
				if isCheckoutAction(step.Uses) && refPointsToPRHead(step.With["ref"]) {
					checkoutsFork = true
					break
				}
			}

			severity := SeverityHigh
			if checkoutsFork {
				severity = SeverityCritical
			}

			msg := fmt.Sprintf("OIDC Misconfiguration: id-token:write on pull_request_target workflow (job '%s')", jobName)
			if len(cloudActions) > 0 {
				msg += fmt.Sprintf(" with cloud auth (%s)", strings.Join(cloudActions, ", "))
			}
			if checkoutsFork {
				msg += " — attacker can mint cloud credentials via fork PR"
			}

			findings = append(findings, Finding{
				RuleID:   "FG-008",
				Severity: severity,
				File:     wf.Path,
				Line:     1,
				Message:  msg,
				Details:  "id-token:write on pull_request_target allows fork PR authors to request OIDC tokens. If cloud providers have overly broad sub claims, attacker can assume cloud roles.",
			})
		} else if isExternalTrigger {
			findings = append(findings, Finding{
				RuleID:   "FG-008",
				Severity: SeverityMedium,
				File:     wf.Path,
				Line:     1,
				Message:  fmt.Sprintf("OIDC Misconfiguration: id-token:write on externally-triggered workflow (job '%s')", jobName),
				Details:  "id-token:write on external triggers may allow token minting by untrusted actors depending on trigger type.",
			})
		} else if len(cloudActions) > 0 {
			// Informational: OIDC with cloud actions on non-external triggers
			findings = append(findings, Finding{
				RuleID:   "FG-008",
				Severity: SeverityInfo,
				File:     wf.Path,
				Line:     1,
				Message:  fmt.Sprintf("OIDC Configuration: id-token:write with cloud auth in job '%s' (%s)", jobName, strings.Join(cloudActions, ", ")),
			})
		}
	}
	return findings
}

// CheckSelfHostedRunner detects self-hosted runners on workflows that accept
// external input, which risks runner persistence and lateral movement (FG-009).
func CheckSelfHostedRunner(wf *Workflow) []Finding {
	var findings []Finding

	acceptsExternalPRs := wf.On.PullRequest || wf.On.PullRequestTarget

	for jobName, job := range wf.Jobs {
		if !isSelfHostedExplicit(job.RunsOn) {
			continue
		}

		// Self-hosted runner on a workflow that accepts external PRs
		if acceptsExternalPRs {
			severity := SeverityHigh
			msg := fmt.Sprintf(
				"Self-Hosted Runner: job '%s' runs on self-hosted runner with external PR trigger",
				jobName)

			if wf.On.PullRequestTarget {
				// Check if it also checks out fork code
				for _, step := range job.Steps {
					if isCheckoutAction(step.Uses) && refPointsToPRHead(step.With["ref"]) {
						severity = SeverityCritical
						msg += " — fork code executes on self-hosted runner (persistence risk)"
						break
					}
				}
			}

			// Check for fork guard mitigation
			if job.If != "" && containsForkGuard(job.If) {
				severity = SeverityInfo
				msg += " (mitigated: fork guard)"
			}

			findings = append(findings, Finding{
				RuleID:   "FG-009",
				Severity: severity,
				File:     wf.Path,
				Line:     1,
				Message:  msg,
				Details:  "Self-hosted runners on public repos accepting PRs allow fork authors to execute code on persistent infrastructure. Non-ephemeral runners risk credential theft, backdoor installation, and lateral movement.",
			})
		} else if wf.On.IssueComment || wf.On.WorkflowRun {
			findings = append(findings, Finding{
				RuleID:   "FG-009",
				Severity: SeverityMedium,
				File:     wf.Path,
				Line:     1,
				Message:  fmt.Sprintf("Self-Hosted Runner: job '%s' runs on self-hosted runner with external trigger", jobName),
				Details:  "Self-hosted runners on externally-triggered workflows may allow untrusted code execution on persistent infrastructure.",
			})
		}
	}
	return findings
}

// isSelfHostedExplicit checks if runs-on labels explicitly include "self-hosted".
func isSelfHostedExplicit(labels []string) bool {
	for _, label := range labels {
		if strings.ToLower(label) == "self-hosted" {
			return true
		}
	}
	return false
}

// CheckCachePoisoning detects shared cache usage across trust boundaries that
// could enable cache poisoning attacks (FG-010).
func CheckCachePoisoning(wf *Workflow) []Finding {
	var findings []Finding

	isExternalTrigger := wf.On.PullRequestTarget || wf.On.PullRequest

	if !isExternalTrigger {
		return nil
	}

	for jobName, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}
			actionName := step.Uses
			if idx := strings.Index(actionName, "@"); idx != -1 {
				actionName = actionName[:idx]
			}

			// Detect actions/cache with save on PR workflows
			if actionName == "actions/cache" || actionName == "actions/cache/save" {
				// Check if cache key uses attacker-controllable inputs
				cacheKey := step.With["key"]
				hasAttackerInput := false
				attackerInputs := []string{
					"github.head_ref",
					"github.event.pull_request",
					"hashFiles(",
				}
				for _, input := range attackerInputs {
					if strings.Contains(cacheKey, input) {
						hasAttackerInput = true
						break
					}
				}

				severity := SeverityMedium
				if wf.On.PullRequestTarget {
					severity = SeverityHigh
				}

				msg := fmt.Sprintf(
					"Cache Poisoning: actions/cache in job '%s' on %s workflow",
					jobName, describeTrigger(wf))
				if hasAttackerInput {
					msg += " with attacker-controllable cache key"
				}

				// Check if the job also checks out fork code and executes it
				hasExec := false
				if wf.On.PullRequestTarget {
					for _, s := range job.Steps {
						if isCheckoutAction(s.Uses) && refPointsToPRHead(s.With["ref"]) {
							postSteps := job.Steps[0:] // simplified — flag the pattern
							execResult := analyzePostCheckoutExecution(postSteps)
							if execResult.Confirmed || execResult.Likely {
								hasExec = true
							}
							break
						}
					}
				}

				if hasExec {
					severity = SeverityHigh
					msg += " — fork code execution can poison cache for subsequent runs"
				}

				findings = append(findings, Finding{
					RuleID:   "FG-010",
					Severity: severity,
					File:     wf.Path,
					Line:     step.Line,
					Message:  msg,
					Details:  "Shared caches on PR workflows allow fork authors to poison cache entries. Poisoned caches persist and affect subsequent builds on the default branch, enabling code execution via dependency or build artifact replacement.",
				})
			}

			// Detect setup-* actions with built-in caching
			if strings.HasPrefix(actionName, "actions/setup-") {
				if step.With["cache"] != "" && step.With["cache"] != "false" {
					findings = append(findings, Finding{
						RuleID:   "FG-010",
						Severity: SeverityLow,
						File:     wf.Path,
						Line:     step.Line,
						Message: fmt.Sprintf(
							"Cache Poisoning: %s with cache enabled in job '%s' on %s workflow",
							actionName, jobName, describeTrigger(wf)),
						Details: "Setup actions with built-in caching on PR workflows may share cache with default branch builds.",
					})
				}
			}
		}
	}
	return findings
}

// CheckBotActorTOCTOU detects workflows where a bot actor guard (e.g.,
// if: github.actor == 'dependabot[bot]') protects a fork checkout + execution
// path that may be bypassable via TOCTOU: an attacker updates their PR commit
// after the bot triggers the workflow but before the runner resolves the SHA (FG-011).
func CheckBotActorTOCTOU(wf *Workflow) []Finding {
	if !wf.On.PullRequestTarget && !wf.On.WorkflowRun {
		return nil
	}

	var findings []Finding
	for jobName, job := range wf.Jobs {
		// Must have a bot actor guard
		isBot := false
		if job.If != "" {
			isBot, _ = containsActorGuard(job.If)
		}
		// Also check needs chain for inherited actor guards
		if !isBot {
			for _, depName := range job.Needs {
				if dep, ok := wf.Jobs[depName]; ok {
					if dep.If != "" {
						isBot, _ = containsActorGuard(dep.If)
						if isBot {
							break
						}
					}
				}
			}
		}
		if !isBot {
			continue
		}

		// Must have fork checkout
		checkoutIdx := -1
		checkoutPath := ""
		for i, step := range job.Steps {
			if isCheckoutAction(step.Uses) && refPointsToPRHead(step.With["ref"]) {
				checkoutIdx = i
				checkoutPath = step.With["path"]
				break
			}
		}
		if checkoutIdx == -1 {
			continue
		}

		// Must have post-checkout execution
		postCheckoutSteps := job.Steps[checkoutIdx+1:]
		execResult := analyzePostCheckoutExecution(postCheckoutSteps)

		// Also check path isolation — if fork code is isolated and not executed, skip
		if checkoutPath != "" {
			hasForkExec := false
			for _, step := range postCheckoutSteps {
				if step.Run != "" && referencesForkPath(step.Run, checkoutPath) {
					hasForkExec = true
					break
				}
			}
			if !hasForkExec && !execResult.Confirmed && !execResult.Likely {
				continue
			}
		} else if !execResult.Confirmed && !execResult.Likely {
			continue
		}

		trigger := "pull_request_target"
		if !wf.On.PullRequestTarget && wf.On.WorkflowRun {
			trigger = "workflow_run"
		}

		msg := fmt.Sprintf(
			"Bot Actor Guard TOCTOU: job '%s' on %s has bot actor guard with fork checkout + execution — "+
				"attacker can update PR commit after bot triggers workflow but before runner resolves SHA",
			jobName, trigger)

		findings = append(findings, Finding{
			RuleID:   "FG-011",
			Severity: SeverityMedium,
			File:     wf.Path,
			Line:     1,
			Message:  msg,
			Details: "Bot-delegated TOCTOU: if: github.actor == 'dependabot[bot]' guards are " +
				"bypassable when an attacker pushes a new commit between the bot trigger event " +
				"and the runner's checkout. The workflow runs the attacker's code with the bot's privileges. " +
				"See BoostSecurity 'Weaponizing Dependabot' research.",
		})
	}
	return findings
}

// describeTrigger returns a human-readable description of the workflow trigger.
func describeTrigger(wf *Workflow) string {
	if wf.On.PullRequestTarget {
		return "pull_request_target"
	}
	if wf.On.PullRequest {
		return "pull_request"
	}
	return "external"
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
