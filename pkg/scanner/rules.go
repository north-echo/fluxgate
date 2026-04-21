package scanner

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

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
	BuildBeforeCheckout bool // Binary compiled from base branch BEFORE PR code checkout
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

		// Build-before-checkout: binary compiled from base branch before PR checkout — suppress
		// The executed binary is from trusted code, PR content is only data input.
		if mitigation.BuildBeforeCheckout {
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

// ClassifyPipInstall analyzes a pip install command and returns
// whether it installs attacker-controlled code from the checkout.
func ClassifyPipInstall(args string) (confirmed bool, detail string) {
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
					confirmed, _ := ClassifyPipInstall(pipArgs)
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
					confirmed, _ := ClassifyPipInstall(pipArgs)
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

	// 8. Check trusted-ref isolation
	if checkoutPath != "" {
		trustedRefPath := ""
		for _, step := range job.Steps {
			if isCheckoutAction(step.Uses) {
				ref := step.With["ref"]
				path := step.With["path"]
				if isTrustedRef(ref) && path != checkoutPath {
					trustedRefPath = path
					break
				}
			}
		}
		if trustedRefPath != "" {
			if m.PathIsolated {
				// No fork path references in execution at all — straightforward isolation
				m.TrustedRefIsolated = true
				m.Details = append(m.Details, "trusted-ref isolation: fork code in subdirectory, executed scripts from trusted ref checkout")
			} else if forkPathIsDataOnly(postCheckoutSteps, checkoutPath, trustedRefPath) {
				// Fork path IS referenced, but only as data arguments to trusted-ref scripts
				m.TrustedRefIsolated = true
				m.Details = append(m.Details, "trusted-ref isolation: fork path passed as data argument to scripts sourced from trusted ref")
			}
		}
	}

	// 9. Check permission gate job
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

	// 10. Check build-before-checkout pattern
	// Pattern: binary compiled from base branch BEFORE PR code is checked out,
	// then the pre-built binary runs against PR content as DATA (not code).
	// Sequence: checkout(base) → build step (go build / cargo build / etc.) → checkout(PR head) → execute binary
	if detectBuildBeforeCheckout(job.Steps, checkoutIdx) {
		m.BuildBeforeCheckout = true
		m.Details = append(m.Details, "build-before-checkout: binary compiled from base branch before PR checkout")
	}

	return m
}

// detectBuildBeforeCheckout detects the defense-in-depth pattern where a binary
// is compiled from the trusted base branch before the PR's code is checked out.
// The attacker cannot control the binary's code because it was built from base.
func detectBuildBeforeCheckout(steps []Step, prCheckoutIdx int) bool {
	if prCheckoutIdx <= 0 {
		return false
	}
	// Must have a PRIOR checkout (base branch) before the PR checkout
	hasBaseCheckout := false
	hasBuildStep := false
	for i := 0; i < prCheckoutIdx; i++ {
		step := steps[i]
		if isCheckoutAction(step.Uses) {
			// A prior checkout with no ref (or with refs/heads/main/master) = base checkout
			ref := step.With["ref"]
			if ref == "" || ref == "main" || ref == "master" ||
				strings.Contains(ref, "refs/heads/main") || strings.Contains(ref, "refs/heads/master") ||
				strings.Contains(ref, "base_ref") {
				hasBaseCheckout = true
			}
		}
		// Check for build commands in run blocks BEFORE PR checkout
		if step.Run != "" {
			for _, cmd := range []string{"go build", "cargo build", "mvn package", "mvn compile", "gradle build", "gradle assemble", "dotnet build", "make build"} {
				if strings.Contains(step.Run, cmd) {
					hasBuildStep = true
					break
				}
			}
		}
	}
	return hasBaseCheckout && hasBuildStep
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
	if strings.Contains(ifExpr, "head.repo.full_name") {
		idx := strings.Index(ifExpr, "head.repo.full_name")
		if idx >= 0 {
			surrounding := ifExpr[idx:]
			if strings.Contains(surrounding, "==") && !strings.Contains(surrounding, "!=") {
				return true
			}
		}
	}
	return false
}

// containsActorGuard detects actor-based gating in if: conditionals.
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
		if strings.Contains(lower, "github.actor") && strings.Contains(lower, "contains(") {
			hasActorCheck = true
		}
	}
	if !hasActorCheck {
		return false, false
	}
	if strings.Contains(lower, "[bot]") {
		return true, false
	}
	return false, true
}

// containsMaintainerCheck detects permission verification steps.
func containsMaintainerCheck(step Step) bool {
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
		"$GITHUB_WORKSPACE/" + checkoutPath,
		"${GITHUB_WORKSPACE}/" + checkoutPath,
	}
	for _, p := range execPatterns {
		if strings.Contains(run, p) {
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
				if eqIdx := strings.Index(line, "="); eqIdx > 0 {
					varName := strings.TrimSpace(line[:eqIdx])
					if len(varName) > 0 && !strings.ContainsAny(varName, " \t$()") {
						aliasVars = append(aliasVars, "$"+varName, "${"+varName+"}")
					}
				}
			}
		}
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		for _, av := range aliasVars {
			if strings.Contains(line, av) {
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

// forkPathIsDataOnly checks whether fork path references in post-checkout steps
// are only used as data arguments to scripts sourced from a trusted-ref checkout,
// not as the executable itself. This detects patterns like:
//
//	cp "$BASE/sz.py" .
//	python sz.py "$BASE" "$PR"   # $PR is data, sz.py is from trusted ref
func forkPathIsDataOnly(postCheckoutSteps []Step, forkPath string, trustedRefPath string) bool {
	for _, step := range postCheckoutSteps {
		if step.Run == "" || !referencesForkPath(step.Run, forkPath) {
			continue
		}
		// This step references the fork path — check if it's safe
		if !runBlockUsesForPathAsDataOnly(step.Run, forkPath, trustedRefPath) {
			return false
		}
	}
	return true
}

// runBlockUsesForPathAsDataOnly analyzes a run block to determine if all references
// to the fork path are as data arguments (not executables). It tracks variable aliases
// for both fork and trusted-ref paths, detects scripts copied from the trusted ref,
// and verifies that fork path references appear only in argument position.
func runBlockUsesForPathAsDataOnly(run string, forkPath string, trustedRefPath string) bool {
	lines := strings.Split(run, "\n")

	// Build alias patterns for both paths
	forkAliases := pathAliasPatterns(forkPath)
	trustedAliases := pathAliasPatterns(trustedRefPath)

	// Resolve shell variable assignments for both paths
	forkVars := resolvePathVars(lines, forkAliases)
	trustedVars := resolvePathVars(lines, trustedAliases)

	// Track scripts copied from the trusted ref
	trustedScripts := trackCopiedScripts(lines, trustedAliases, trustedVars)

	// Track pip/npm installs from the trusted ref (makes imports safe)
	hasTrustedInstall := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		for _, tv := range append(trustedVars, trustedAliases...) {
			if strings.Contains(trimmed, "pip install") && strings.Contains(trimmed, tv) {
				hasTrustedInstall = true
			}
			if strings.Contains(trimmed, "npm install") && strings.Contains(trimmed, tv) {
				hasTrustedInstall = true
			}
		}
	}

	// All fork-path + fork-var aliases to check
	allForkRefs := append(forkAliases, forkVars...)

	// Check each line that references the fork path
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		hasForkRef := false
		for _, fr := range allForkRefs {
			if strings.Contains(trimmed, fr) {
				hasForkRef = true
				break
			}
		}
		if !hasForkRef {
			continue
		}

		// Variable assignment — safe
		if isVariableAssignment(trimmed) {
			continue
		}

		// Data-only commands — safe
		if isDataOnlyCommand(trimmed) {
			continue
		}

		// Check if this is an interpreter command where the script is from trusted ref
		if isInterpreterWithTrustedScript(trimmed, trustedScripts, trustedAliases, trustedVars, allForkRefs, hasTrustedInstall) {
			continue
		}

		// Fork path in executable position — not safe
		return false
	}
	return true
}

// pathAliasPatterns returns patterns that reference a checkout path.
func pathAliasPatterns(path string) []string {
	if path == "" {
		return nil
	}
	return []string{
		"$GITHUB_WORKSPACE/" + path,
		"${GITHUB_WORKSPACE}/" + path,
		"./" + path,
		"\"" + path + "\"",
		"'" + path + "'",
	}
}

// resolvePathVars finds shell variable assignments that reference the given path aliases
// and returns the variable reference forms ($VAR, ${VAR}).
func resolvePathVars(lines []string, aliases []string) []string {
	var vars []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		eqIdx := strings.Index(line, "=")
		if eqIdx <= 0 {
			continue
		}
		varName := strings.TrimSpace(line[:eqIdx])
		if len(varName) == 0 || strings.ContainsAny(varName, " \t$()") {
			continue
		}
		for _, ap := range aliases {
			if strings.Contains(line, ap) {
				vars = append(vars, "$"+varName, "${"+varName+"}")
				break
			}
		}
	}
	return vars
}

// trackCopiedScripts finds scripts copied from the trusted ref (e.g., cp "$BASE/sz.py" .)
// and returns their local filenames.
func trackCopiedScripts(lines []string, trustedAliases []string, trustedVars []string) map[string]bool {
	scripts := map[string]bool{}
	allTrusted := append(trustedAliases, trustedVars...)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "cp ") {
			continue
		}
		hasTrustedSrc := false
		for _, t := range allTrusted {
			if strings.Contains(trimmed, t) {
				hasTrustedSrc = true
				break
			}
		}
		if !hasTrustedSrc {
			continue
		}
		// Extract the filename from the source path: cp "$BASE/sz.py" . → sz.py
		parts := splitShellArgs(trimmed)
		if len(parts) >= 3 {
			src := parts[1]
			src = strings.Trim(src, "\"'")
			if idx := strings.LastIndex(src, "/"); idx >= 0 {
				scripts[src[idx+1:]] = true
			}
		}
	}
	return scripts
}

// isVariableAssignment checks if a line is a shell variable assignment.
func isVariableAssignment(line string) bool {
	eqIdx := strings.Index(line, "=")
	if eqIdx <= 0 {
		return false
	}
	varName := line[:eqIdx]
	return !strings.ContainsAny(varName, " \t$()") && len(varName) > 0
}

// isInterpreterWithTrustedScript checks if a command line runs an interpreter
// (python, node, bash, etc.) where the script comes from the trusted ref
// and the fork path is only in argument position.
func isInterpreterWithTrustedScript(line string, trustedScripts map[string]bool, trustedAliases []string, trustedVars []string, forkRefs []string, hasTrustedInstall bool) bool {
	interpreters := []string{"python", "python3", "node", "ruby", "bash", "sh", "perl"}
	parts := splitShellArgs(line)
	if len(parts) < 2 {
		return false
	}

	cmd := parts[0]
	isInterpreter := false
	for _, interp := range interpreters {
		if cmd == interp {
			isInterpreter = true
			break
		}
	}
	if !isInterpreter {
		return false
	}

	// Find the script argument (first arg that's not a flag)
	scriptIdx := -1
	for i := 1; i < len(parts); i++ {
		if !strings.HasPrefix(parts[i], "-") {
			scriptIdx = i
			break
		}
	}
	if scriptIdx < 0 {
		return false
	}

	script := strings.Trim(parts[scriptIdx], "\"'")

	// Check if the script itself references the fork path — that's code execution
	for _, fr := range forkRefs {
		if strings.Contains(script, strings.Trim(fr, "\"'")) {
			return false
		}
	}

	// Check if the script is from the trusted ref (copied or direct path)
	allTrusted := append(trustedAliases, trustedVars...)
	if trustedScripts[script] {
		return true
	}
	for _, t := range allTrusted {
		if strings.Contains(script, strings.Trim(t, "\"'")) {
			return true
		}
	}

	// If there's a pip/npm install from trusted ref, interpreter scripts that
	// don't reference the fork path as executable are likely using trusted imports
	if hasTrustedInstall {
		return true
	}

	return false
}

// splitShellArgs does a basic split of a shell command line, respecting quoted strings.
func splitShellArgs(line string) []string {
	var args []string
	var current strings.Builder
	inSingle := false
	inDouble := false

	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			current.WriteByte(c)
		case c == '"' && !inSingle:
			inDouble = !inDouble
			current.WriteByte(c)
		case c == ' ' && !inSingle && !inDouble:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
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
		return true
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
	if strings.Contains(lower, "trusted") || strings.Contains(lower, "base_ref") {
		return true
	}
	return false
}

// hasPermissionCheck detects if a job verifies collaborator permissions via GitHub API.
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
func checkoutsForkCode(step Step) bool {
	ref := step.With["ref"]
	if refPointsToPRHead(ref) {
		return true
	}
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

func jobScopedToPullRequest(ifCondition string) bool {
	if ifCondition == "" {
		return false
	}
	normalized := strings.ReplaceAll(ifCondition, " ", "")
	normalized = strings.ReplaceAll(normalized, "\u2018", "'")
	normalized = strings.ReplaceAll(normalized, "\u2019", "'")
	normalized = strings.ReplaceAll(normalized, "\"", "'")

	if strings.Contains(normalized, "github.event_name=='pull_request'") {
		if !strings.Contains(normalized, "pull_request_target") {
			return true
		}
	}

	if strings.Contains(normalized, "github.event_name!='pull_request_target'") {
		return true
	}

	return false
}

func runFetchesPRHead(run string) bool {
	lines := strings.Split(run, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "git fetch") &&
			(strings.Contains(line, "pull/") && strings.Contains(line, "/head") ||
				strings.Contains(line, "github.event.number") ||
				strings.Contains(line, "github.event.pull_request.number") ||
				strings.Contains(line, "github.event.pull_request.head.sha")) {
			return true
		}
		if strings.Contains(line, "gh pr checkout") {
			return true
		}
	}
	return false
}

func containsExpression(run, expr string) bool {
	return strings.Contains(run, "${{ "+expr) ||
		strings.Contains(run, "${{"+expr)
}

var githubHostedPrefixes = []string{
	"ubuntu-", "windows-", "macos-",
}

var githubHostedExact = []string{
	"ubuntu-latest", "windows-latest", "macos-latest",
	"macos-13", "macos-14", "macos-15",
}

func isSelfHostedRunner(labels []string) bool {
	for _, label := range labels {
		lower := strings.ToLower(label)
		if lower == "self-hosted" {
			return true
		}
	}
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
			return false
		}
	}
	return false
}

// CheckOIDCMisconfiguration detects id-token:write permissions on externally-triggered
// workflows where an attacker could mint cloud credentials (FG-008).
func CheckOIDCMisconfiguration(wf *Workflow) []Finding {
	var findings []Finding

	isExternalTrigger := wf.On.PullRequestTarget || wf.On.IssueComment

	for jobName, job := range wf.Jobs {
		hasIDTokenWrite := false

		if job.Permissions.Scopes["id-token"] == "write" {
			hasIDTokenWrite = true
		} else if !job.Permissions.Set && wf.Permissions.Scopes["id-token"] == "write" {
			hasIDTokenWrite = true
		}

		if !hasIDTokenWrite {
			continue
		}

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
// external input (FG-009).
func CheckSelfHostedRunner(wf *Workflow) []Finding {
	var findings []Finding

	acceptsExternalPRs := wf.On.PullRequest || wf.On.PullRequestTarget

	for jobName, job := range wf.Jobs {
		if !isSelfHostedExplicit(job.RunsOn) {
			continue
		}

		if acceptsExternalPRs {
			severity := SeverityHigh
			msg := fmt.Sprintf(
				"Self-Hosted Runner: job '%s' runs on self-hosted runner with external PR trigger",
				jobName)

			if wf.On.PullRequestTarget {
				for _, step := range job.Steps {
					if isCheckoutAction(step.Uses) && refPointsToPRHead(step.With["ref"]) {
						severity = SeverityCritical
						msg += " — fork code executes on self-hosted runner (persistence risk)"
						break
					}
				}
			}

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

func isSelfHostedExplicit(labels []string) bool {
	for _, label := range labels {
		if strings.ToLower(label) == "self-hosted" {
			return true
		}
	}
	return false
}

// CheckCachePoisoning detects shared cache usage across trust boundaries (FG-010).
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

			if actionName == "actions/cache" || actionName == "actions/cache/save" {
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

				hasExec := false
				if wf.On.PullRequestTarget {
					for _, s := range job.Steps {
						if isCheckoutAction(s.Uses) && refPointsToPRHead(s.With["ref"]) {
							postSteps := job.Steps[0:]
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

// CheckBotActorTOCTOU detects bot actor guard TOCTOU vulnerabilities (FG-011).
func CheckBotActorTOCTOU(wf *Workflow) []Finding {
	if !wf.On.PullRequestTarget && !wf.On.WorkflowRun {
		return nil
	}

	var findings []Finding
	for jobName, job := range wf.Jobs {
		isBot := false
		if job.If != "" {
			isBot, _ = containsActorGuard(job.If)
		}
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

		postCheckoutSteps := job.Steps[checkoutIdx+1:]
		execResult := analyzePostCheckoutExecution(postCheckoutSteps)

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

var ifExprPattern = regexp.MustCompile(`\$\{\{.*?\}\}`)

// CheckIfAlwaysTrue detects malformed if: conditions (FG-012).
func CheckIfAlwaysTrue(wf *Workflow) []Finding {
	var findings []Finding

	checkIf := func(ifExpr string, context string, line int) {
		if ifExpr == "" {
			return
		}
		trimmed := strings.TrimSpace(ifExpr)

		if !strings.Contains(trimmed, "${{") {
			return
		}

		if strings.HasPrefix(trimmed, "${{") && strings.HasSuffix(trimmed, "}}") {
			matches := ifExprPattern.FindAllStringIndex(trimmed, -1)
			if len(matches) == 1 && matches[0][0] == 0 && matches[0][1] == len(trimmed) {
				return
			}
		}

		lower := strings.ToLower(trimmed)
		if lower == "always()" || lower == "${{ always() }}" ||
			lower == "failure()" || lower == "${{ failure() }}" ||
			lower == "cancelled()" || lower == "${{ cancelled() }}" ||
			lower == "success()" || lower == "${{ success() }}" {
			return
		}

		findings = append(findings, Finding{
			RuleID:   "FG-012",
			Severity: SeverityHigh,
			File:     wf.Path,
			Line:     line,
			Message: fmt.Sprintf(
				"If Always True: %s if: condition '%s' has ${{ }} that doesn't span the entire value — "+
					"GitHub evaluates it as a non-empty string (always truthy)",
				context, truncate(trimmed, 80)),
			Details: "When an if: value contains text outside ${{ }}, GitHub does not evaluate it " +
				"as an expression. Instead, it treats the entire string as a non-empty string " +
				"which is always truthy. Security guards using this pattern are silently no-ops.",
		})
	}

	for jobName, job := range wf.Jobs {
		checkIf(job.If, fmt.Sprintf("job '%s'", jobName), 1)
		for _, step := range job.Steps {
			stepDesc := fmt.Sprintf("step (line %d)", step.Line)
			if step.Name != "" {
				stepDesc = fmt.Sprintf("step '%s'", step.Name)
			}
			checkIf(step.If, stepDesc, step.Line)
		}
	}
	return findings
}

// CheckAllSecretsExposed detects toJSON(secrets) or secrets[ patterns (FG-013).
func CheckAllSecretsExposed(wf *Workflow) []Finding {
	var findings []Finding

	dangerousPatterns := []string{
		"toJSON(secrets)",
		"tojson(secrets)",
		"secrets[",
	}

	isRiskyTrigger := wf.On.PullRequestTarget || wf.On.IssueComment

	checkContent := func(content string, step Step) {
		lower := strings.ToLower(content)
		for _, pat := range dangerousPatterns {
			if strings.Contains(lower, strings.ToLower(pat)) {
				severity := SeverityHigh
				if isRiskyTrigger {
					severity = SeverityCritical
				}
				findings = append(findings, Finding{
					RuleID:   "FG-013",
					Severity: severity,
					File:     wf.Path,
					Line:     step.Line,
					Message: fmt.Sprintf(
						"All Secrets Exposed: '%s' in step (line %d) dumps all repository secrets",
						pat, step.Line),
					Details: "Using toJSON(secrets) or dynamic secrets[] access exposes every " +
						"repository secret in the job. If any attacker-controlled code runs in " +
						"the same job, all secrets can be exfiltrated.",
				})
				return
			}
		}
	}

	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run != "" {
				checkContent(step.Run, step)
			}
			for _, v := range step.Env {
				checkContent(v, step)
			}
			for _, v := range step.With {
				checkContent(v, step)
			}
		}
	}
	return findings
}

// CheckMissingPermsRisky detects missing permissions blocks on risky triggers (FG-014).
func CheckMissingPermsRisky(wf *Workflow) []Finding {
	isRisky := wf.On.PullRequestTarget || wf.On.IssueComment || wf.On.WorkflowRun
	if !isRisky {
		return nil
	}

	if wf.Permissions.Set {
		return nil
	}

	var findings []Finding
	for jobName, job := range wf.Jobs {
		if job.Permissions.Set {
			continue
		}
		trigger := ""
		if wf.On.PullRequestTarget {
			trigger = "pull_request_target"
		} else if wf.On.IssueComment {
			trigger = "issue_comment"
		} else if wf.On.WorkflowRun {
			trigger = "workflow_run"
		}

		findings = append(findings, Finding{
			RuleID:   "FG-014",
			Severity: SeverityMedium,
			File:     wf.Path,
			Line:     1,
			Message: fmt.Sprintf(
				"Missing Permissions: job '%s' on %s trigger has no permissions block — "+
					"inherits repository default (often write-all)",
				jobName, trigger),
			Details: "Without an explicit permissions block, the workflow inherits the " +
				"repository or organization default, which is often write-all. On risky " +
				"triggers like pull_request_target and issue_comment, this grants untrusted " +
				"code broad access to the repository and its secrets.",
		})
	}
	return findings
}

var curlPipeBashPattern = regexp.MustCompile(`(?i)(curl|wget)\s+[^|]*\|\s*(ba)?sh\b`)
var bashProcessSubPattern = regexp.MustCompile(`(?i)(ba)?sh\s+<\(\s*(curl|wget)\s`)
var invokeExprPattern = regexp.MustCompile(`(?i)Invoke-Expression.*DownloadString`)
var denoRunHTTPPattern = regexp.MustCompile(`(?i)deno\s+run\s+[^\n]*-A[^\n]*https://`)
var commitPinnedURLPattern = regexp.MustCompile(`[a-f0-9]{40}`)

// CheckCurlPipeBash detects unverified remote script execution (FG-015).
func CheckCurlPipeBash(wf *Workflow) []Finding {
	var findings []Finding

	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}
			lines := strings.Split(step.Run, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				matched := false
				detail := ""

				if curlPipeBashPattern.MatchString(line) {
					matched = true
					detail = "curl/wget piped to shell"
				} else if bashProcessSubPattern.MatchString(line) {
					matched = true
					detail = "bash process substitution with curl/wget"
				} else if invokeExprPattern.MatchString(line) {
					matched = true
					detail = "PowerShell Invoke-Expression with DownloadString"
				} else if denoRunHTTPPattern.MatchString(line) {
					matched = true
					detail = "deno run -A with remote HTTPS URL"
				}

				if !matched {
					continue
				}

				severity := SeverityMedium
				if commitPinnedURLPattern.MatchString(line) {
					severity = SeverityInfo
					detail += " (commit-pinned URL)"
				}

				findings = append(findings, Finding{
					RuleID:   "FG-015",
					Severity: severity,
					File:     wf.Path,
					Line:     step.Line,
					Message: fmt.Sprintf(
						"Unverified Script Execution: %s (line %d)",
						detail, step.Line),
					Details: "Fetching and executing remote scripts without integrity verification " +
						"allows man-in-the-middle or upstream compromise to inject arbitrary code. " +
						"Pin to a specific commit SHA or verify a checksum before execution.",
				})
			}
		}
	}
	return findings
}

// CheckLocalActionUntrustedCheckout detects local action usage after fork checkout (FG-016).
func CheckLocalActionUntrustedCheckout(wf *Workflow) []Finding {
	if !wf.On.PullRequestTarget && !wf.On.IssueComment && !wf.On.WorkflowRun {
		return nil
	}

	var findings []Finding
	for jobName, job := range wf.Jobs {
		checkoutIdx := -1
		for i, step := range job.Steps {
			if isCheckoutAction(step.Uses) && refPointsToPRHead(step.With["ref"]) {
				checkoutIdx = i
				break
			}
			if step.Run != "" && runFetchesPRHead(step.Run) {
				checkoutIdx = i
				break
			}
		}
		if checkoutIdx == -1 {
			continue
		}

		for _, step := range job.Steps[checkoutIdx+1:] {
			if strings.HasPrefix(step.Uses, "./") {
				findings = append(findings, Finding{
					RuleID:   "FG-016",
					Severity: SeverityCritical,
					File:     wf.Path,
					Line:     step.Line,
					Message: fmt.Sprintf(
						"Local Action After Untrusted Checkout: job '%s' uses local action '%s' "+
							"after checking out fork code — attacker controls action.yml",
						jobName, step.Uses),
					Details: "Local composite actions (uses: ./) are loaded from the checked-out " +
						"code. When preceded by a checkout of fork/PR head code, the attacker controls " +
						"the entire action definition including action.yml, scripts, and Dockerfiles. " +
						"This bypasses all step-level security controls.",
				})
			}
		}
	}
	return findings
}

// CheckGitHubScriptInjection detects expression injection in actions/github-script (FG-017).
func CheckGitHubScriptInjection(wf *Workflow) []Finding {
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
			if step.Uses == "" {
				continue
			}
			actionName := step.Uses
			if idx := strings.Index(actionName, "@"); idx != -1 {
				actionName = actionName[:idx]
			}
			if actionName != "actions/github-script" {
				continue
			}
			script, ok := step.With["script"]
			if !ok || script == "" {
				continue
			}

			for _, expr := range dangerousExpressions {
				if containsExpression(script, expr) {
					findings = append(findings, Finding{
						RuleID:   "FG-017",
						Severity: SeverityHigh,
						File:     wf.Path,
						Line:     step.Line,
						Message: fmt.Sprintf(
							"GitHub Script Injection: %s in actions/github-script (line %d) — "+
								"JavaScript injection via attacker-controlled expression",
							expr, step.Line),
						Details: "actions/github-script executes JavaScript. When attacker-controlled " +
							"expressions like PR titles or comment bodies are interpolated into the " +
							"script via ${{ }}, an attacker can inject arbitrary JavaScript that runs " +
							"with the workflow's GITHUB_TOKEN permissions.",
					})
				}
			}
		}
	}
	return findings
}

// knownSafeOrgPrefixes lists GitHub org prefixes whose SHA-pinned actions
// are trusted and do not need impostor commit verification.
var knownSafeOrgPrefixes = []string{
	"actions/",
	"github/",
	"hashicorp/",
	"google-github-actions/",
	"aws-actions/",
	"azure/",
	"docker/",
}

// CheckImpostorCommit flags actions pinned to SHAs from unknown orgs where
// impostor commit attacks are possible (FG-018).
func CheckImpostorCommit(wf *Workflow) []Finding {
	var findings []Finding
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" || !strings.Contains(step.Uses, "@") {
				continue
			}
			parts := strings.SplitN(step.Uses, "@", 2)
			action := parts[0]
			ref := parts[1]

			// Only flag SHA-pinned actions
			if !shaPattern.MatchString(ref) {
				continue
			}

			// Skip known-safe orgs
			safe := false
			for _, prefix := range knownSafeOrgPrefixes {
				if strings.HasPrefix(action, prefix) {
					safe = true
					break
				}
			}
			if safe {
				continue
			}

			findings = append(findings, Finding{
				RuleID:     "FG-018",
				Severity:   SeverityInfo,
				Confidence: ConfidencePatternOnly,
				File:       wf.Path,
				Line:       step.Line,
				Message: fmt.Sprintf(
					"Impostor Commit: %s pinned to SHA from unknown org — "+
						"verify commit belongs to claimed repo (not a fork-network hijack)",
					action),
				Details: "Actions pinned to full SHA are generally safe, but the SHA must actually " +
					"belong to the claimed repository. In GitHub's fork network, a commit SHA " +
					"from any fork can be referenced as if it belongs to the parent repo. " +
					"Use the GitHub API (GET /repos/OWNER/REPO/commits/SHA) to verify the " +
					"commit exists in the claimed repository.",
				Mitigations: []string{
					"Verify the SHA belongs to the claimed repo via GitHub API",
					"Use actions from well-known orgs (actions/*, github/*, etc.)",
				},
			})
		}
	}
	return findings
}

// secretsRefPattern matches ${{ secrets.* }} references.
var secretsRefPattern = regexp.MustCompile(`\$\{\{\s*secrets\.\w+\s*\}\}`)

// CheckHardcodedCredentials detects hardcoded credentials in container and
// services blocks (FG-019).
func CheckHardcodedCredentials(wf *Workflow) []Finding {
	var findings []Finding
	for jobName, job := range wf.Jobs {
		// Check job-level container
		findings = append(findings, checkContainerCreds(wf.Path, jobName, "container", job.Container)...)

		// Check services
		for svcName, svc := range job.Services {
			findings = append(findings, checkContainerCreds(wf.Path, jobName, "services."+svcName, svc)...)
		}
	}
	return findings
}

func checkContainerCreds(file, jobName, block string, cc ContainerConfig) []Finding {
	var findings []Finding

	// Check for user:pass@ in image URL
	if cc.Image != "" && strings.Contains(cc.Image, "@") {
		// Distinguish user:pass@host from registry.example.com/image@sha256:...
		atIdx := strings.Index(cc.Image, "@")
		before := cc.Image[:atIdx]
		if strings.Contains(before, ":") && !strings.HasPrefix(cc.Image[atIdx:], "@sha256:") {
			findings = append(findings, Finding{
				RuleID:   "FG-019",
				Severity: SeverityHigh,
				File:     file,
				Line:     1,
				Message: fmt.Sprintf(
					"Hardcoded Container Credentials: job '%s' %s image URL contains embedded credentials",
					jobName, block),
				Details: "Container image references should not contain inline credentials. " +
					"Use the credentials: block with secrets references instead.",
			})
		}
	}

	// Check credentials block
	if len(cc.Credentials) == 0 {
		return findings
	}

	username := cc.Credentials["username"]
	password := cc.Credentials["password"]

	if password == "" {
		return findings
	}

	// Check if password is a secrets reference (safe pattern)
	if secretsRefPattern.MatchString(password) {
		return findings
	}

	// Literal password found
	msg := fmt.Sprintf(
		"Hardcoded Container Credentials: job '%s' %s has literal password in credentials block",
		jobName, block)
	if username != "" && !secretsRefPattern.MatchString(username) {
		msg = fmt.Sprintf(
			"Hardcoded Container Credentials: job '%s' %s has literal username and password in credentials block",
			jobName, block)
	}

	findings = append(findings, Finding{
		RuleID:   "FG-019",
		Severity: SeverityHigh,
		File:     file,
		Line:     1,
		Message:  msg,
		Details: "Credentials in workflow files are visible to anyone with read access to the " +
			"repository. Use ${{ secrets.* }} references for all authentication values.",
		Mitigations: []string{
			"Move credentials to GitHub Secrets",
			"Use ${{ secrets.REGISTRY_USERNAME }} and ${{ secrets.REGISTRY_PASSWORD }}",
		},
	})
	return findings
}

// semverRefPattern matches version-like refs: v1, v1.2, v1.2.3
var semverRefPattern = regexp.MustCompile(`^v?\d+(\.\d+){0,2}$`)

// knownBranchRefs are refs already flagged by FG-003 as branch pinning.
var knownBranchRefs = map[string]bool{
	"main": true, "master": true, "dev": true, "develop": true,
}

// CheckRefConfusion detects action references with ambiguous refs that could
// be either tags or branches (FG-020).
func CheckRefConfusion(wf *Workflow) []Finding {
	var findings []Finding
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" || !strings.Contains(step.Uses, "@") {
				continue
			}
			parts := strings.SplitN(step.Uses, "@", 2)
			action := parts[0]
			ref := parts[1]

			// Skip SHA-pinned
			if shaPattern.MatchString(ref) {
				continue
			}
			// Skip semver-like refs (standard tag pattern)
			if semverRefPattern.MatchString(ref) {
				continue
			}
			// Skip known branch names (already flagged by FG-003)
			if knownBranchRefs[ref] {
				continue
			}
			// Skip first-party actions (lower risk)
			if strings.HasPrefix(action, "actions/") {
				continue
			}

			findings = append(findings, Finding{
				RuleID:   "FG-020",
				Severity: SeverityMedium,
				File:     wf.Path,
				Line:     step.Line,
				Message: fmt.Sprintf(
					"Ref Confusion: %s@%s uses ambiguous ref (could be tag or branch)",
					action, ref),
				Details: "Refs like 'release/v1', 'stable', or other non-semver strings are " +
					"ambiguous between tags and branches. An attacker who creates a branch " +
					"with the same name as a tag (or vice versa) can hijack the resolution. " +
					"Pin to a full SHA or use a semver tag (v1, v1.2.3).",
				Mitigations: []string{
					"Pin to a full 40-character commit SHA",
					"Use a semver tag (e.g., v1, v1.2.3)",
				},
			})
		}
	}
	return findings
}

// taintDangerousExpressions is the list of attacker-controlled expressions
// used by FG-021 for cross-step taint tracking (same as FG-002).
var taintDangerousExpressions = []string{
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

// outputSetPattern matches lines like: echo "name=value" >> $GITHUB_OUTPUT
// and captures the output name.
var outputSetPattern = regexp.MustCompile(
	`echo\s+['"]?(\w+)=.*>>\s*"?\$GITHUB_OUTPUT"?`)

// CheckCrossStepOutputTaint detects attacker-controlled expressions captured
// into step outputs and later consumed in run blocks (FG-021).
func CheckCrossStepOutputTaint(wf *Workflow) []Finding {
	var findings []Finding
	for _, job := range wf.Jobs {
		// Phase 1: find steps that write dangerous expressions to GITHUB_OUTPUT
		// Map: stepID -> outputName -> dangerous expression
		type taintedOutput struct {
			stepID   string
			name     string
			expr     string
			stepLine int
		}
		var tainted []taintedOutput

		for _, step := range job.Steps {
			if step.Run == "" || step.ID == "" {
				continue
			}
			// Check if run block writes to GITHUB_OUTPUT
			if !strings.Contains(step.Run, "GITHUB_OUTPUT") {
				continue
			}
			for _, line := range strings.Split(step.Run, "\n") {
				line = strings.TrimSpace(line)
				// Check if this line contains a dangerous expression
				hasDangerous := false
				var matchedExpr string
				for _, expr := range taintDangerousExpressions {
					if containsExpression(line, expr) {
						hasDangerous = true
						matchedExpr = expr
						break
					}
				}
				if !hasDangerous {
					continue
				}
				// Extract the output name
				matches := outputSetPattern.FindStringSubmatch(line)
				if len(matches) < 2 {
					continue
				}
				outputName := matches[1]
				tainted = append(tainted, taintedOutput{
					stepID:   step.ID,
					name:     outputName,
					expr:     matchedExpr,
					stepLine: step.Line,
				})
			}
		}

		if len(tainted) == 0 {
			continue
		}

		// Phase 2: check if any later step uses the tainted output in a run block
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}
			for _, t := range tainted {
				ref := fmt.Sprintf("steps.%s.outputs.%s", t.stepID, t.name)
				if containsExpression(step.Run, ref) {
					findings = append(findings, Finding{
						RuleID:   "FG-021",
						Severity: SeverityHigh,
						File:     wf.Path,
						Line:     step.Line,
						Message: fmt.Sprintf(
							"Cross-Step Output Taint: step '%s' captures %s into output '%s', "+
								"consumed in run block at line %d",
							t.stepID, t.expr, t.name, step.Line),
						Details: fmt.Sprintf(
							"Step '%s' writes attacker-controlled expression %s to GITHUB_OUTPUT "+
								"as '%s'. This tainted value is later interpolated into a run block "+
								"via ${{ steps.%s.outputs.%s }}, enabling indirect script injection.",
							t.stepID, t.expr, t.name, t.stepID, t.name),
						Mitigations: []string{
							"Pass the value through an environment variable instead of inline interpolation",
							"Sanitize the output value before writing to GITHUB_OUTPUT",
						},
					})
				}
			}
		}
	}
	return findings
}

// advisoryEntry describes a known security advisory for an action version.
type advisoryEntry struct {
	FixedVersion string
	Advisory     string
	Description  string
	HighSeverity bool // true for supply chain compromises
}

// knownVulnerableActions maps action names to their known advisories.
var knownVulnerableActions = map[string][]advisoryEntry{
	"actions/checkout": {
		{FixedVersion: "4.2.0", Advisory: "actions-checkout-credential-persistence", Description: "credential persistence", HighSeverity: false},
	},
	"hashicorp/vault-action": {
		{FixedVersion: "2.2.0", Advisory: "CVE-2021-32074", Description: "secret exposure", HighSeverity: false},
	},
	"tj-actions/changed-files": {
		{FixedVersion: "45.0.0", Advisory: "CVE-2025-30066", Description: "supply chain compromise", HighSeverity: true},
	},
	"docker/build-push-action": {
		{FixedVersion: "4.2.0", Advisory: "credential leak", Description: "credential leak", HighSeverity: false},
	},
}

// parseVersion extracts major, minor, patch from a version string like "v1.2.3", "v1.2", "v1", "1.2.3".
func parseVersion(v string) (major, minor, patch int, ok bool) {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) == 0 {
		return 0, 0, 0, false
	}
	var err error
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, false
	}
	if len(parts) >= 2 {
		minor, err = strconv.Atoi(parts[1])
		if err != nil {
			return major, 0, 0, true // ignore unparseable minor
		}
	}
	if len(parts) >= 3 {
		patch, err = strconv.Atoi(parts[2])
		if err != nil {
			return major, minor, 0, true
		}
	}
	return major, minor, patch, true
}

// versionLessThan returns true if version a < version b using semver comparison.
func versionLessThan(a, b string) bool {
	aMaj, aMin, aPat, aOK := parseVersion(a)
	bMaj, bMin, bPat, bOK := parseVersion(b)
	if !aOK || !bOK {
		return false
	}
	if aMaj != bMaj {
		return aMaj < bMaj
	}
	if aMin != bMin {
		return aMin < bMin
	}
	return aPat < bPat
}

// CheckKnownVulnerableActions detects actions pinned to versions with known
// security advisories (FG-022).
func CheckKnownVulnerableActions(wf *Workflow) []Finding {
	var findings []Finding
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" || !strings.Contains(step.Uses, "@") {
				continue
			}
			parts := strings.SplitN(step.Uses, "@", 2)
			action := parts[0]
			ref := parts[1]

			advisories, ok := knownVulnerableActions[action]
			if !ok {
				continue
			}

			// Skip SHA-pinned (can't determine version from SHA alone)
			if shaPattern.MatchString(ref) {
				continue
			}

			for _, adv := range advisories {
				if versionLessThan(ref, adv.FixedVersion) {
					severity := SeverityMedium
					if adv.HighSeverity {
						severity = SeverityHigh
					}

					desc := adv.Description
					if desc == "" {
						desc = "known vulnerability"
					}

					findings = append(findings, Finding{
						RuleID:   "FG-022",
						Severity: severity,
						File:     wf.Path,
						Line:     step.Line,
						Message: fmt.Sprintf(
							"Known Vulnerable Action: %s@%s has %s (%s, fixed in %s)",
							action, ref, desc, adv.Advisory, adv.FixedVersion),
						Details: fmt.Sprintf(
							"Action %s at version %s is affected by %s (%s). "+
								"Upgrade to version %s or later.",
							action, ref, adv.Advisory, desc, adv.FixedVersion),
						Mitigations: []string{
							fmt.Sprintf("Upgrade to %s@v%s or later", action, adv.FixedVersion),
							"Pin to the SHA of a fixed release",
						},
					})
				}
			}
		}
	}
	return findings
}

// CheckArtifactCredentialLeak detects upload-artifact uploading paths that
// may contain persisted credentials from checkout (FG-023).
func CheckArtifactCredentialLeak(wf *Workflow) []Finding {
	var findings []Finding
	for _, job := range wf.Jobs {
		// Determine if any checkout step has persist-credentials enabled (default is true)
		persistCreds := false
		persistExplicitlyFalse := false

		for _, step := range job.Steps {
			if !isCheckoutAction(step.Uses) {
				continue
			}
			pc, set := step.With["persist-credentials"]
			if !set {
				persistCreds = true // default is true
			} else if strings.EqualFold(pc, "true") {
				persistCreds = true
			} else if strings.EqualFold(pc, "false") {
				persistExplicitlyFalse = true
			}
		}

		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}
			actionName := step.Uses
			if idx := strings.Index(actionName, "@"); idx != -1 {
				actionName = actionName[:idx]
			}
			if actionName != "actions/upload-artifact" {
				continue
			}

			uploadPath := step.With["path"]
			if uploadPath == "" {
				continue
			}

			// Check for dangerous upload paths
			isDangerous := false
			reason := ""
			if strings.Contains(uploadPath, ".git") {
				isDangerous = true
				reason = "uploads .git directory (may contain persisted credentials)"
			} else if uploadPath == "." || uploadPath == "./" ||
				uploadPath == "${{ github.workspace }}" ||
				uploadPath == "${{github.workspace}}" {
				isDangerous = true
				reason = "uploads entire workspace (includes .git with persisted credentials)"
			}

			if !isDangerous {
				continue
			}

			severity := SeverityMedium
			details := fmt.Sprintf(
				"actions/upload-artifact uploads '%s' which %s. ",
				uploadPath, reason)

			if persistExplicitlyFalse {
				severity = SeverityInfo
				details += "persist-credentials is set to false on checkout, reducing risk."
			} else if persistCreds {
				details += "actions/checkout has persist-credentials: true (the default), " +
					"so the .git/config contains the GITHUB_TOKEN."
			} else {
				details += "No checkout step detected, but the .git directory may still " +
					"contain credentials from a prior workflow step."
			}

			findings = append(findings, Finding{
				RuleID:   "FG-023",
				Severity: severity,
				File:     wf.Path,
				Line:     step.Line,
				Message: fmt.Sprintf(
					"Artifact Credential Leak: upload-artifact uploads '%s' — %s",
					uploadPath, reason),
				Details: details,
				Mitigations: []string{
					"Set persist-credentials: false on actions/checkout",
					"Upload specific files/directories instead of the entire workspace",
					"Exclude .git from upload paths",
				},
			})
		}
	}
	return findings
}
