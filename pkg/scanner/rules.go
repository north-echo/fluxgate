package scanner

import (
	"fmt"
	"regexp"
	"sort"
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
	LabelGated            bool
	EnvironmentGated      bool
	MaintainerCheck       bool
	ForkGuard             bool
	ActorGuard            bool // Job if: restricts execution to specific bot actor(s)
	ActorGuardHuman       bool // Job if: restricts to specific human actor(s) (weaker)
	NeedsGate             bool // Job depends on upstream job with environment/fork gate
	TokenBlanked          bool
	PathIsolated          bool // Fork code checked out to subdirectory, no direct execution
	TrustedRefIsolated    bool // Fork checkout to subdir, all executed code from trusted ref
	PermissionGateJob     bool // Upstream job verifies collaborator permissions via API
	BuildBeforeCheckout   bool // Binary compiled from base branch BEFORE PR code checkout
	NoCredentialExec      bool // Executing job has empty permissions (no token) AND references no secrets
	AuthorAssociationGate bool // Job if: restricts execution by author_association (trusted commenters/contributors)
	Details               []string
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
	"prettier", // config is JSON/YAML-only, no plugin execution
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

// CheckPwnRequest detects pull_request_target and issue_comment workflows that
// checkout PR head code with post-checkout execution analysis (FG-001). Both are
// privileged triggers: issue_comment ChatOps bots (e.g. `gh pr checkout
// ${{ github.event.issue.number }}` on a `/command`) run fork code in the base
// context just like pull_request_target.
func CheckPwnRequest(wf *Workflow) []Finding {
	if !wf.On.PullRequestTarget && !wf.On.IssueComment && !wf.On.WorkflowRun {
		return nil
	}

	// All three are privileged triggers that run in the base-repo context with
	// secrets; workflow_run additionally can check out the triggering PR's head
	// (github.event.workflow_run.head_sha).
	var trigs []string
	if wf.On.PullRequestTarget {
		trigs = append(trigs, "pull_request_target")
	}
	if wf.On.IssueComment {
		trigs = append(trigs, "issue_comment")
	}
	if wf.On.WorkflowRun {
		trigs = append(trigs, "workflow_run")
	}
	triggerLabel := strings.Join(trigs, "/")

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

		// Check for git-based PR checkout in run blocks. A bare `git fetch` of
		// the PR head does not put fork code in the tree — require an actual
		// checkout/merge/reset of it (detectRunForkCheckout enforces this).
		runPathspec := ""
		runCheckout := false
		if checkoutIdx == -1 {
			if rc := detectRunForkCheckout(job); rc.found {
				checkoutIdx = rc.index
				checkoutLine = job.Steps[rc.index].Line
				checkoutRef = "git fetch + checkout (PR head)"
				checkoutPath = rc.pathspec
				runPathspec = rc.pathspec
				runCheckout = true
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

		// Pathspec-limited checkout isolation: fork code entered the tree only via
		// `git checkout <pr-head> -- <subpath>`, a trusted ref populated the root,
		// and nothing executes from the fork subpath — executed scripts are trusted.
		if runCheckout && pathspecForkCheckoutIsolated(job, checkoutIdx, runPathspec, postCheckoutSteps) {
			severity = SeverityInfo
			confidence = ConfidencePatternOnly
			mitigated = true
			mitigation.Details = append(mitigation.Details, fmt.Sprintf(
				"pathspec-checkout isolation: fork content limited to '%s/', executed scripts from trusted ref", runPathspec))
		}

		// No-credential execution: the executing job has empty permissions (no
		// GITHUB_TOKEN) and references no secrets — fork code runs but there is
		// nothing to exfiltrate, so it isn't a secret-stealing pwn request.
		if mitigation.NoCredentialExec {
			severity = SeverityInfo
			confidence = ConfidencePatternOnly
			mitigated = true
		}

		// Permission gate job: upstream job verifies collaborator access — internal threat only
		if mitigation.PermissionGateJob && !mitigated {
			severity = downgradeBy(severity, 2)
			mitigated = true
		}

		// Author-association gate: only trusted commenters/contributors can
		// trigger — an arbitrary external commenter can't reach the checkout.
		if mitigation.AuthorAssociationGate && !mitigated {
			severity = downgradeBy(severity, 2)
			mitigated = true
		}

		// Path isolation adjusts confidence, not severity
		if mitigation.PathIsolated && confidence == ConfidenceConfirmed {
			confidence = ConfidencePatternOnly
			mitigated = true
		}

		msg := fmt.Sprintf("Pwn Request: %s with fork checkout [%s]", triggerLabel, confidence)
		if execResult.Detail != "" {
			msg += " — " + execResult.Detail
		}
		if mitigated {
			msg += " (mitigated: " + strings.Join(mitigation.Details, "; ") + ")"
		}

		permDesc := describePermissions(wf.Permissions, job.Permissions)
		details := fmt.Sprintf(
			"Trigger: %s, Checkout ref: %s, Permissions: %s, Execution: %s",
			triggerLabel, checkoutRef, permDesc, confidence,
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
			segs := runShellSegments(step)
			if cmd, found := matchesBuildCommand(segs); found {
				return ExecutionAnalysis{
					Confirmed: true,
					Detail:    fmt.Sprintf("run block executes '%s' on checked-out code (line %d)", cmd, step.Line),
				}
			}
			if cmd, found := matchesConfigLoadingTool(segs); found {
				return ExecutionAnalysis{
					Likely: true,
					Detail: fmt.Sprintf("run block invokes '%s' which loads config from repo (line %d)", cmd, step.Line),
				}
			}
			// If there's a setup action and a run block, it likely executes repo code
			if hasSetupAction && !isReadOnlyRun(segs) && !isPipNamedPackageOnly(segs) && !isSafeFormattingRun(segs) {
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

// buildRunSegments splits a run block into trimmed shell command segments:
// newline-separated lines with blanks and comments removed, each split on
// shell separators. This is the shared pre-computation for the run-analysis
// helpers below; it runs once per step at parse time (see Step.runSegs).
func buildRunSegments(run string) []string {
	if run == "" {
		return nil
	}
	var segs []string
	for _, line := range strings.Split(run, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, seg := range splitShellCommands(line) {
			seg = strings.TrimSpace(seg)
			if seg == "" {
				continue
			}
			segs = append(segs, seg)
		}
	}
	return segs
}

// runShellSegments returns the cached shell segments for a step, computing
// them on the fly for hand-built Steps that never went through ParseWorkflow.
func runShellSegments(step Step) []string {
	if step.runSegs != nil || step.Run == "" {
		return step.runSegs
	}
	return buildRunSegments(step.Run)
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
func isSafeFormattingRun(segs []string) bool {
	for _, seg := range segs {
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
	return true
}

// isPipNamedPackageOnly checks if a run block only contains pip install
// of named packages (not local paths or requirements files).
func isPipNamedPackageOnly(segs []string) bool {
	for _, seg := range segs {
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
	return true
}

// matchesBuildCommand checks if a run block contains a known build command.
func matchesBuildCommand(segs []string) (string, bool) {
	for _, seg := range segs {
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
	return "", false
}

// matchesConfigLoadingTool checks if a run block invokes a config-loading tool.
func matchesConfigLoadingTool(segs []string) (string, bool) {
	for _, seg := range segs {
		for _, tool := range configLoadingTools {
			if strings.HasPrefix(seg, tool+" ") || seg == tool {
				return tool, true
			}
		}
	}
	return "", false
}

// isReadOnlyRun checks if a run block only contains read-only commands.
func isReadOnlyRun(segs []string) bool {
	for _, seg := range segs {
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
					} else if isDispatchInputExpr(expr) {
						// workflow_dispatch/workflow_call inputs are populated only via
						// a write-gated manual dispatch or an internal caller — never
						// directly from an untrusted trigger. Real injection, but low
						// external reach; drop a tier from high.
						severity = SeverityMedium
						detail = " (workflow_dispatch/workflow_call input — requires trigger access; verify reusable-workflow callers don't forward untrusted data)"
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

// isDispatchInputExpr reports whether a dangerous expression is a
// workflow_dispatch / workflow_call input. These contexts are only populated by
// a manual dispatch (which requires write access) or an internal caller, so the
// injection is not reachable from an untrusted trigger.
func isDispatchInputExpr(expr string) bool {
	return expr == "inputs." || expr == "github.event.inputs."
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

			// Supply-chain hygiene, not an acute exploit: a moving ref lets the
			// action change under you, but nothing is directly exploitable today.
			// Cap at medium. Branch refs (main/master/dev) move on every push and
			// are worse than a version tag, so they keep the ceiling and a note;
			// first-party actions/* are GitHub-controlled and stay info.
			severity := SeverityMedium
			note := ""
			if ref == "main" || ref == "master" || ref == "dev" {
				note = " — mutable branch ref"
			}
			if strings.HasPrefix(action, "actions/") {
				severity = SeverityInfo
			}

			findings = append(findings, Finding{
				RuleID:   "FG-003",
				Severity: severity,
				File:     wf.Path,
				Line:     step.Line,
				Message:  fmt.Sprintf("Tag Pinning: %s@%s (use SHA instead)%s", action, ref, note),
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

		// On `pull_request` (not `_target`), fork PRs run with a read-only token
		// and NO repository secrets — secret references resolve to empty. So this
		// is arbitrary code execution on an ephemeral runner with nothing to
		// steal: low severity. (Self-hosted-runner host risk is FG-009; cache
		// poisoning is FG-010; secret-bearing pwns are FG-001 on _target.)
		severity := SeverityLow

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
			Details:    "Trigger: pull_request — fork PRs get a read-only token and no secrets, so this is code execution on an ephemeral runner with nothing to exfiltrate (cache-poisoning aside).",
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
				segs := runShellSegments(step)
				if _, found := matchesBuildCommand(segs); found {
					unblankedExecSteps = append(unblankedExecSteps, step)
				} else if _, found := matchesConfigLoadingTool(segs); found {
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
		// author_association gate — common on issue_comment ChatOps: only
		// trusted commenters (MEMBER/OWNER/COLLABORATOR) or known contributors
		// can trigger. Strong for issue_comment (author is checked at fire time,
		// no re-run TOCTOU).
		if hasAuthorAssociationGuard(job) {
			m.AuthorAssociationGate = true
			m.Details = append(m.Details, "job if: restricts execution by author_association")
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
		if step.Run != "" && !isReadOnlyRun(runShellSegments(step)) {
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

	// 11. No-credential execution: the job running fork code has empty permissions
	// (no GITHUB_TOKEN) AND references no secrets. Fork code still executes, but
	// there is no token or secret to steal — so this is not a secret-exfil pwn
	// request. (Self-hosted-runner host risk, if any, is covered by FG-009.)
	if jobHasNoToken(wf, job) && !postCheckoutAccessesSecrets(postCheckoutSteps) {
		m.NoCredentialExec = true
		m.Details = append(m.Details, "executing job has empty permissions (no GITHUB_TOKEN) and references no secrets")
	}

	return m
}

// jobHasNoToken reports whether the effective permissions of the job (its own
// block, or the workflow-level block if the job doesn't set one) explicitly
// grant no token access — i.e. `permissions: {}`. This removes the GITHUB_TOKEN
// entirely, so fork code cannot abuse it.
func jobHasNoToken(wf *Workflow, job Job) bool {
	perm := job.Permissions
	if !perm.Set {
		perm = wf.Permissions
	}
	return perm.Set && !perm.WriteAll && !perm.ReadAll && len(perm.Scopes) == 0
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
		if strings.Contains(lower, p) { // patterns are already lowercase
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
		if lower == t { // trusted entries are already lowercase
			return true
		}
	}
	if strings.Contains(lower, "trusted") || strings.Contains(lower, "base_ref") {
		return true
	}
	// pull_request(_target) base ref/sha resolve to the base branch (trusted).
	// The expression form uses dots (`pull_request.base.ref`), distinct from the
	// `github.base_ref` context handled above. head.ref/head.sha are NOT trusted.
	if strings.Contains(lower, "pull_request.base.") {
		return true
	}
	// github.workflow_sha = the commit of the workflow file (the base/trusted ref
	// on pull_request_target), and github.sha = the base commit on
	// pull_request_target. Both check out trusted code, unlike ...head.sha (fork).
	// "github.sha" does not appear as a substring of "...head.sha", so this is safe.
	if strings.Contains(lower, "workflow_sha") || strings.Contains(lower, "github.sha") {
		return true
	}
	return false
}

// hasPermissionCheck detects if a job verifies collaborator permissions via GitHub API.
func hasPermissionCheck(job Job) bool {
	// Lowercased up front; compared against a lowercased haystack.
	permPatterns := []string{
		"getcollaboratorpermissionlevel",
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
			if strings.Contains(lower, p) {
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
		// issue_comment context: a checkout ref built from the PR number, e.g.
		// `refs/pull/${{ github.event.issue.number }}/head`.
		"github.event.issue.number",
		// workflow_run context: the triggering (fork) PR's head.
		"github.event.workflow_run.head_sha",
		"github.event.workflow_run.head_branch",
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
		if _, ok := lineFetchesPRHead(line); ok {
			return true
		}
		if strings.Contains(line, "gh pr checkout") {
			return true
		}
	}
	return false
}

// runForkCheckout describes how PR-head content enters the working tree via
// git commands inside run blocks. A bare `git fetch <pr-head>` populates a ref
// or FETCH_HEAD but leaves the working tree on trusted code; only a subsequent
// checkout/switch/merge/reset of that ref (or `gh pr checkout`) actually places
// fork code on disk. pathspec is set when the checkout is limited to a subpath
// (`git checkout <ref> -- <path>`), meaning only that subtree is attacker-controlled.
type runForkCheckout struct {
	index    int    // step index where fork code first lands in the tree
	pathspec string // "" = whole tree; else limited to this subpath (normalized, no trailing slash)
	found    bool
}

// detectRunForkCheckout scans a job's run steps in order and reports whether a
// PR-head checkout actually reaches the working tree, and if so at which step
// and limited to which pathspec. Fetch state is carried across steps because the
// fetch and the checkout are often in separate steps.
func detectRunForkCheckout(job Job) runForkCheckout {
	prHeadFetched := false
	dstRefs := map[string]bool{}
	for i, step := range job.Steps {
		if step.Run == "" {
			continue
		}
		for _, raw := range strings.Split(step.Run, "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// `gh pr checkout` both fetches and checks out the PR head into the tree.
			if strings.Contains(line, "gh pr checkout") {
				return runForkCheckout{index: i, pathspec: "", found: true}
			}
			if dst, ok := lineFetchesPRHead(line); ok {
				prHeadFetched = true
				if dst != "" {
					dstRefs[dst] = true
				}
			}
			if pathspec, ok := lineChecksOutPRHead(line, prHeadFetched, dstRefs); ok {
				return runForkCheckout{index: i, pathspec: pathspec, found: true}
			}
		}
	}
	return runForkCheckout{found: false}
}

// fetchDstRefPattern captures the local destination ref of a PR refspec. Both
// `pull/N/head:<dst>` (PR head) and `pull/N/merge:<dst>` (GitHub's auto-merge of
// head into base) carry attacker-influenced content, so both are captured.
var fetchDstRefPattern = regexp.MustCompile(`(?:head|merge)\s*:\s*([A-Za-z0-9][\w./-]*)`)

// lineFetchesPRHead reports whether a single line is a `git fetch` of the PR
// head or merge ref, and returns the local destination ref if the refspec names
// one (`pull/N/head:pr-head` -> "pr-head"). Empty dst means the fetch lands in
// FETCH_HEAD.
func lineFetchesPRHead(line string) (dst string, ok bool) {
	if !strings.Contains(line, "git fetch") {
		return "", false
	}
	prHead := (strings.Contains(line, "pull/") && (strings.Contains(line, "/head") || strings.Contains(line, "/merge"))) ||
		strings.Contains(line, "github.event.number") ||
		strings.Contains(line, "github.event.pull_request.number") ||
		strings.Contains(line, "github.event.pull_request.head.sha") ||
		strings.Contains(line, "github.event.pull_request.head.ref") ||
		strings.Contains(line, "github.head_ref")
	if !prHead {
		return "", false
	}
	if m := fetchDstRefPattern.FindStringSubmatch(line); m != nil {
		return m[1], true
	}
	return "", true
}

// lineChecksOutPRHead reports whether a single line moves the working tree to
// PR-head content, and the pathspec it is limited to (empty = whole tree). A
// checkout targets PR head when it references a PR-head expression, FETCH_HEAD
// (after a PR-head fetch), or a local ref created by such a fetch.
func lineChecksOutPRHead(line string, prHeadFetched bool, dstRefs map[string]bool) (pathspec string, ok bool) {
	treeMutators := []string{"git checkout", "git switch", "git merge", "git rebase", "git cherry-pick", "git reset --hard", "git reset --merge"}
	isMutator := false
	for _, m := range treeMutators {
		if strings.Contains(line, m) {
			isMutator = true
			break
		}
	}
	if !isMutator {
		return "", false
	}

	targetsPRHead := strings.Contains(line, "github.event.pull_request.head.sha") ||
		strings.Contains(line, "github.event.pull_request.head.ref") ||
		strings.Contains(line, "github.head_ref")
	if !targetsPRHead && prHeadFetched && strings.Contains(line, "FETCH_HEAD") {
		targetsPRHead = true
	}
	if !targetsPRHead {
		for ref := range dstRefs {
			if containsWord(line, ref) {
				targetsPRHead = true
				break
			}
		}
	}
	if !targetsPRHead {
		return "", false
	}

	// Pathspec-limited checkout: `git checkout <ref> -- <path> [<path>...]`.
	if idx := strings.Index(line, " -- "); idx != -1 {
		rest := strings.TrimSpace(line[idx+4:])
		if first := strings.Fields(rest); len(first) > 0 {
			return normalizePathspec(first[0]), true
		}
	}
	return "", true
}

// containsWord reports whether word appears in s delimited by non-word chars,
// so ref "pr" matches `git merge pr` but not `git merge preview`.
func containsWord(s, word string) bool {
	for {
		i := strings.Index(s, word)
		if i == -1 {
			return false
		}
		before := i == 0 || !isRefWordChar(rune(s[i-1]))
		after := i+len(word) >= len(s) || !isRefWordChar(rune(s[i+len(word)]))
		if before && after {
			return true
		}
		s = s[i+len(word):]
	}
}

func isRefWordChar(r rune) bool {
	return r == '_' || r == '-' || r == '/' || r == '.' ||
		(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// normalizePathspec strips quotes, a leading ./, and a trailing / so a pathspec
// like `"Lib/"` compares equal to the `Lib` form used for checkout paths.
func normalizePathspec(p string) string {
	p = strings.Trim(p, `"'`)
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimSuffix(p, "/")
	return p
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

	// Sorted scope order keeps the details string deterministic run to run.
	var parts []string
	for _, k := range sortedKeys(wfPerms.Scopes) {
		parts = append(parts, k+":"+wfPerms.Scopes[k])
	}
	for _, k := range sortedKeys(jobPerms.Scopes) {
		parts = append(parts, "job("+k+":"+jobPerms.Scopes[k]+")")
	}
	if len(parts) == 0 {
		return "restricted"
	}
	return strings.Join(parts, ", ")
}

// sortedKeys returns the map's keys in sorted order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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

	isRiskyTrigger := wf.On.PullRequestTarget || wf.On.IssueComment

	checkContent := func(content string, step Step) {
		pat := matchedDangerousSecretsPattern(content)
		if pat == "" {
			return
		}
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

// matchedDangerousSecretsPattern returns the matched pattern name if the content
// dumps all secrets (toJSON(secrets)) or accesses secrets with a dynamic key
// (secrets[<expr>] where <expr> is not a static string literal). Returns "" if
// none match. secrets['LITERAL'] and secrets["LITERAL"] are equivalent to dot
// notation (secrets.LITERAL) and are NOT flagged.
func matchedDangerousSecretsPattern(content string) string {
	lower := strings.ToLower(content)
	if strings.Contains(lower, "tojson(secrets)") {
		return "toJSON(secrets)"
	}
	idx := 0
	for {
		hit := strings.Index(lower[idx:], "secrets[")
		if hit == -1 {
			return ""
		}
		absStart := idx + hit + len("secrets[")
		if absStart >= len(content) {
			return ""
		}
		c := content[absStart]
		// Static literal key — semantically equivalent to secrets.KEY, safe.
		if c == '\'' || c == '"' {
			quote := c
			rest := content[absStart+1:]
			end := strings.IndexByte(rest, quote)
			if end >= 0 && end+1 < len(rest) && rest[end+1] == ']' {
				idx = absStart + 1 + end + 2
				continue
			}
		}
		return "secrets["
	}
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

// localActionUnderTrustedCheckout reports whether a `uses: ./<dir>/...` local
// action resolves to a directory that a checkout of a trusted ref populated
// (e.g. `actions/checkout` at `github.workflow_sha` into `path: <dir>`), so the
// action definition comes from trusted code, not the fork.
func localActionUnderTrustedCheckout(job Job, uses string) bool {
	p := strings.TrimPrefix(uses, "./")
	seg := p
	if i := strings.Index(p, "/"); i != -1 {
		seg = p[:i]
	}
	if seg == "" || seg == "." {
		return false
	}
	for _, step := range job.Steps {
		if !isCheckoutAction(step.Uses) {
			continue
		}
		if normalizePathspec(step.With["path"]) == seg && isTrustedRef(step.With["ref"]) {
			return true
		}
	}
	return false
}

// CheckLocalActionUntrustedCheckout detects local action usage after fork checkout (FG-016).
func CheckLocalActionUntrustedCheckout(wf *Workflow) []Finding {
	if !wf.On.PullRequestTarget && !wf.On.IssueComment && !wf.On.WorkflowRun {
		return nil
	}

	var findings []Finding
	for jobName, job := range wf.Jobs {
		checkoutIdx := -1
		forkCheckoutPath := ""
		for i, step := range job.Steps {
			if isCheckoutAction(step.Uses) && refPointsToPRHead(step.With["ref"]) {
				checkoutIdx = i
				forkCheckoutPath = step.With["path"]
				break
			}
		}
		// Run-based checkout: a bare `git fetch` of the PR head leaves fork code
		// off the working tree (it only populates a ref/FETCH_HEAD). Require an
		// actual checkout/merge/reset before treating the tree as attacker-owned.
		if rc := detectRunForkCheckout(job); rc.found && (checkoutIdx == -1 || rc.index < checkoutIdx) {
			checkoutIdx = rc.index
			forkCheckoutPath = rc.pathspec
		}
		if checkoutIdx == -1 {
			continue
		}

		// Trusted-ref isolation: if the fork checkout lands in a subdir and a
		// prior checkout in the same job used a trusted ref to the workspace
		// root, local action references at './' load from the trusted ref, not
		// the fork. Suppress the finding in that case.
		if localActionsTrustedRefIsolated(job, checkoutIdx, forkCheckoutPath) {
			continue
		}

		// Author-association / fork guard: if the job restricts execution to
		// trusted authors (MEMBER/OWNER/COLLABORATOR) or excludes forks, an
		// arbitrary fork PR cannot reach the local action. Downgrade to info
		// (residual: a maintainer-applied label plus a synchronize TOCTOU could
		// still run, but not an unauthenticated external fork).
		severity := SeverityCritical
		guardNote := ""
		if hasAuthorAssociationGuard(job) || containsForkGuard(job.If) {
			severity = SeverityInfo
			guardNote = " (mitigated: job restricts execution to trusted authors / non-forks)"
		}

		for _, step := range job.Steps[checkoutIdx+1:] {
			if strings.HasPrefix(step.Uses, "./") {
				// The local action lives under a subdir populated by a checkout of
				// a trusted ref (e.g. actions checked out at github.workflow_sha
				// into path/), so its definition is not attacker-controlled.
				if localActionUnderTrustedCheckout(job, step.Uses) {
					continue
				}
				findings = append(findings, Finding{
					RuleID:   "FG-016",
					Severity: severity,
					File:     wf.Path,
					Line:     step.Line,
					Message: fmt.Sprintf(
						"Local Action After Untrusted Checkout: job '%s' uses local action '%s' "+
							"after checking out fork code — attacker controls action.yml%s",
						jobName, step.Uses, guardNote),
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

// localActionsTrustedRefIsolated returns true when the job's fork checkout
// goes into a subdirectory AND an earlier checkout in the same job pulled a
// trusted ref into the workspace root. In that case, references like
// './.github/actions/foo' resolve to the trusted-ref checkout, not the fork.
//
// The defensive pattern: first `actions/checkout` uses a trusted ref env var
// (resolving to refs/heads/main or refs/heads/<base_ref>), then a second
// checkout puts the PR head in `path: "pr-branch"`.
func localActionsTrustedRefIsolated(job Job, forkCheckoutIdx int, forkPath string) bool {
	if forkPath == "" || forkPath == "." {
		return false
	}
	for i := 0; i < forkCheckoutIdx; i++ {
		step := job.Steps[i]
		if !isCheckoutAction(step.Uses) {
			continue
		}
		path := step.With["path"]
		if path != "" && path != "." {
			continue
		}
		if isTrustedRef(step.With["ref"]) {
			return true
		}
	}
	return false
}

// pathspecForkCheckoutIsolated recognizes the hardened pattern where PR-head
// content enters the tree only via a pathspec-limited checkout
// (`git checkout <pr-head> -- <subpath>`), a prior checkout populated the root
// from a trusted ref, and no post-checkout step executes code located under the
// fork subpath. Fork content is confined to data files; executed scripts live
// outside the subpath and come from trusted code.
func pathspecForkCheckoutIsolated(job Job, checkoutIdx int, pathspec string, postCheckoutSteps []Step) bool {
	if pathspec == "" || pathspec == "." {
		return false
	}
	if !hasTrustedRootCheckoutBefore(job, checkoutIdx, pathspec) {
		return false
	}
	for _, step := range postCheckoutSteps {
		if step.Run != "" && runExecutesFromPath(step.Run, pathspec) {
			return false
		}
	}
	return true
}

// hasTrustedRootCheckoutBefore reports whether a step before idx checks out a
// trusted ref into a location other than the fork pathspec (typically the
// workspace root), so scripts outside the pathspec are trusted.
func hasTrustedRootCheckoutBefore(job Job, idx int, pathspec string) bool {
	if idx > len(job.Steps) {
		idx = len(job.Steps)
	}
	for i := 0; i < idx; i++ {
		step := job.Steps[i]
		if !isCheckoutAction(step.Uses) {
			continue
		}
		if normalizePathspec(step.With["path"]) == pathspec {
			continue
		}
		if isTrustedRef(step.With["ref"]) {
			return true
		}
	}
	return false
}

var interpreterCmds = map[string]bool{
	"python": true, "python3": true, "bash": true, "sh": true, "zsh": true,
	"node": true, "ruby": true, "perl": true, "deno": true, "bun": true,
	"pwsh": true, "php": true, "source": true, ".": true,
}

// runExecutesFromPath reports whether a run block executes an interpreter or
// script whose target lives under path/ (or cd's into it). Data-only references
// to path (e.g. `git diff -- 'Lib/*.py'`, string literals in an inline script)
// do not count — only command-position execution does.
func runExecutesFromPath(run, path string) bool {
	prefix := path + "/"
	for _, raw := range strings.Split(run, "\n") {
		for _, cmd := range splitShellSegments(raw) {
			fields := strings.Fields(cmd)
			if len(fields) == 0 {
				continue
			}
			head := strings.Trim(fields[0], `"'`)
			args := fields[1:]
			switch {
			case head == "cd":
				if len(args) > 0 && underPath(args[0], path, prefix) {
					return true
				}
			case head == "pip" || head == "pip3":
				for _, a := range args {
					if underPath(a, path, prefix) {
						return true
					}
				}
			case head == "go":
				if len(args) >= 2 && args[0] == "run" && underPath(args[1], path, prefix) {
					return true
				}
			case head == "make":
				for j, a := range args {
					if a == "-C" && j+1 < len(args) && underPath(args[j+1], path, prefix) {
						return true
					}
				}
			case interpreterCmds[head]:
				for _, a := range args {
					if strings.HasPrefix(a, "-") {
						continue
					}
					return underPath(a, path, prefix)
				}
			default:
				// Direct execution of a script located under the fork path.
				if underPath(head, path, prefix) {
					return true
				}
			}
		}
	}
	return false
}

// underPath reports whether a shell token refers to a file under path.
func underPath(tok, path, prefix string) bool {
	tok = strings.Trim(tok, `"'`)
	tok = strings.TrimPrefix(tok, "./")
	tok = strings.TrimPrefix(tok, "$GITHUB_WORKSPACE/")
	tok = strings.TrimPrefix(tok, "${GITHUB_WORKSPACE}/")
	return tok == path || strings.HasPrefix(tok, prefix)
}

// splitShellSegments splits a line on shell command separators (&&, ||, ;, |)
// so each segment can be inspected for a command in head position.
func splitShellSegments(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	fields := strings.FieldsFunc(line, func(r rune) bool {
		return r == ';' || r == '|' || r == '&'
	})
	var segs []string
	for _, f := range fields {
		if s := strings.TrimSpace(f); s != "" {
			segs = append(segs, s)
		}
	}
	return segs
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
	FixedVersion     string
	Advisory         string
	Description      string
	HighSeverity     bool // true for supply chain compromises
	AllVersions      bool // true when every tag/SHA is compromised (no fixed version exists)
	CriticalSeverity bool // true for credential-stealing supply chain takeovers
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
	"actions-cool/issues-helper": {
		{AllVersions: true, CriticalSeverity: true, Advisory: "actions-cool-impostor-commit-2026",
			Description: "all tags retargeted to impostor commits stealing runner credentials (exfil: t.m-kosche[.]com); repo disabled by GitHub"},
	},
	"actions-cool/maintain-one-comment": {
		{AllVersions: true, CriticalSeverity: true, Advisory: "actions-cool-impostor-commit-2026",
			Description: "15 tags retargeted to impostor commits stealing runner credentials (exfil: t.m-kosche[.]com); repo disabled by GitHub"},
	},
}

var floatingMajorPattern = regexp.MustCompile(`^v?\d+$`)

// isFloatingMajor reports whether a ref is a bare major-version tag like
// "v4" or "3" — tags that float to the latest release in that major series.
func isFloatingMajor(ref string) bool {
	return floatingMajorPattern.MatchString(ref)
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

			isSHA := shaPattern.MatchString(ref)

			for _, adv := range advisories {
				severity := SeverityMedium
				switch {
				case adv.CriticalSeverity:
					severity = SeverityCritical
				case adv.HighSeverity:
					severity = SeverityHigh
				}

				desc := adv.Description
				if desc == "" {
					desc = "known vulnerability"
				}

				if adv.AllVersions {
					findings = append(findings, Finding{
						RuleID:   "FG-022",
						Severity: severity,
						File:     wf.Path,
						Line:     step.Line,
						Message: fmt.Sprintf(
							"Compromised Action: %s@%s — %s (%s); remove this action",
							action, ref, desc, adv.Advisory),
						Details: fmt.Sprintf(
							"Action %s is fully compromised — every tag and the underlying commits "+
								"are attacker-controlled (%s). No fixed version exists. "+
								"Remove all references to this action and rotate any secrets that "+
								"may have been exposed to its runs.",
							action, adv.Advisory),
						Mitigations: []string{
							fmt.Sprintf("Remove all uses of %s", action),
							"Rotate any secrets exposed to workflows that ran this action",
							"Audit runner credentials and OIDC token usage during the compromise window",
						},
					})
					continue
				}

				// Version-bounded advisory: SHA pins can't be version-compared.
				if isSHA {
					continue
				}
				// Floating major-version tag (e.g. @v4) resolves to the latest
				// release in that major series. If the fix landed in the same
				// or older major, the floating tag picks it up automatically —
				// flagging would be a false positive.
				if isFloatingMajor(ref) {
					refMaj, _, _, _ := parseVersion(ref)
					fixMaj, _, _, _ := parseVersion(adv.FixedVersion)
					if refMaj >= fixMaj {
						continue
					}
				}
				if versionLessThan(ref, adv.FixedVersion) {
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

// envFileWritePattern matches redirections to $GITHUB_ENV or $GITHUB_PATH.
// Covers > and >>, optional double-quotes, and ${} brace form.
var envFileWritePattern = regexp.MustCompile(`>>?\s*"?\$\{?GITHUB_(ENV|PATH)\}?"?`)

// CheckGitHubEnvInjection detects tainted writes to $GITHUB_ENV or $GITHUB_PATH
// that smuggle attacker-controlled content into env vars or PATH for later steps
// in the same job (FG-024). Per-step bash quoting protects the immediate write
// but the persisted value is unquoted at the consumption site, defeating the
// quoted-arg downgrade applied by FG-002.
func CheckGitHubEnvInjection(wf *Workflow) []Finding {
	// Scope to fork-eligible / external-content triggers. push/schedule/
	// workflow_dispatch are authenticated-actor contexts (different threat model).
	if !wf.On.PullRequest && !wf.On.PullRequestTarget &&
		!wf.On.IssueComment && !wf.On.WorkflowRun {
		return nil
	}

	highTaint := []string{
		"github.event.issue.title",
		"github.event.issue.body",
		"github.event.pull_request.title",
		"github.event.pull_request.body",
		"github.event.comment.body",
		"github.event.review.body",
		"github.event.pages.*.page_name",
		"github.event.commits.*.message",
		"github.event.head_commit.message",
	}
	medTaint := []string{
		"github.head_ref",
		"github.event.workflow_run.head_branch",
		"github.event.inputs.",
		"inputs.",
	}

	var findings []Finding
	for _, job := range wf.Jobs {
		checkoutIdx := -1
		for i, s := range job.Steps {
			if isCheckoutAction(s.Uses) {
				checkoutIdx = i
				break
			}
		}
		var postCheckout []Step
		if checkoutIdx >= 0 && checkoutIdx+1 < len(job.Steps) {
			postCheckout = job.Steps[checkoutIdx+1:]
		}
		mit := analyzeMitigations(wf, job, checkoutIdx, postCheckout, "")

		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}
			if !envFileWritePattern.MatchString(step.Run) {
				continue
			}

			target := "GITHUB_ENV"
			if strings.Contains(step.Run, "GITHUB_PATH") {
				target = "GITHUB_PATH"
			}

			matchedExpr := ""
			taintTier := ""
			for _, expr := range highTaint {
				if containsExpression(step.Run, expr) {
					matchedExpr = expr
					taintTier = "high"
					break
				}
			}
			if taintTier == "" {
				for _, expr := range medTaint {
					if containsExpression(step.Run, expr) {
						matchedExpr = expr
						taintTier = "med"
						break
					}
				}
			}
			if taintTier == "" {
				continue
			}

			// Base severity by trigger + taint tier.
			//   pull_request_target / issue_comment / workflow_run + high → critical
			//   same triggers + med → high
			//   pull_request → cap at high (no secrets, but injection is real)
			severity := SeverityHigh
			if wf.On.PullRequestTarget || wf.On.IssueComment || wf.On.WorkflowRun {
				if taintTier == "high" {
					severity = SeverityCritical
				} else {
					severity = SeverityHigh
				}
			} else if wf.On.PullRequest {
				severity = SeverityHigh
			}

			// Mitigation downgrades — fork/label/env gates protect the workflow
			// run as a whole, so they apply to env-file injection too. Fork guard
			// reduces this to internal-collaborator threat (matches FG-001 pattern).
			mitNote := ""
			switch {
			case mit.ForkGuard:
				severity = SeverityInfo
				mitNote = " (fork guard — internal-collaborator threat only)"
			case mit.LabelGated, mit.EnvironmentGated, mit.MaintainerCheck:
				severity = downgradeBy(severity, 1)
				mitNote = " (gate detected — downgraded)"
			}

			findings = append(findings, Finding{
				RuleID:   "FG-024",
				Severity: severity,
				File:     wf.Path,
				Line:     step.Line,
				Message: fmt.Sprintf(
					"GitHub Env Injection: %s written to $%s — persists as env var/PATH for later steps%s",
					matchedExpr, target, mitNote),
				Details: "Bash quoting protects the immediate write, but the persisted value is " +
					"interpolated unquoted by later steps. The injection is laundered through " +
					"the env file and bypasses per-step quoted-arg analysis (FG-002).",
				Mitigations: []string{
					"Sanitize attacker-controlled values before writing to $GITHUB_ENV / $GITHUB_PATH",
					"Use the action's `env:` block with the expression as the value, not shell redirection",
					"For pull_request_target: gate the job with a maintainer label or environment approval",
				},
			})
		}
	}
	return findings
}

// iocEntry is a known threat-actor indicator that, if observed in workflow
// content, is high-confidence evidence of compromise (not a heuristic).
type iocEntry struct {
	Needle   string // substring to match (case-insensitive)
	Campaign string // short campaign tag for the finding message
	Note     string // one-line explanation of what the indicator means

	needleLower string // precomputed in init; matching runs per step scanned
}

func init() {
	for i := range knownIOCs {
		knownIOCs[i].needleLower = strings.ToLower(knownIOCs[i].Needle)
	}
}

// knownIOCs is the catalog of substrings to flag in workflow Run blocks, env
// values, and With inputs. Keep entries narrow enough to avoid false positives
// — these emit critical findings.
var knownIOCs = []iocEntry{
	{
		Needle:   "m-kosche.com",
		Campaign: "Mini Shai-Hulud / TeamPCP (May 2026)",
		Note:     "C2/exfil domain for the actions-cool + atool/prop npm maintainer compromise; payload reads Runner.Worker memory and posts masked secrets to t.m-kosche.com",
	},
	{
		Needle:   "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner",
		Campaign: "Mini Shai-Hulud / TeamPCP (May 2026)",
		Note:     "Threat-actor commit fingerprint string used across attacker-controlled repos",
	},
	{
		Needle:   "niagA oG eW ereH :duluH-iahS",
		Campaign: "Mini Shai-Hulud / TeamPCP (May 2026)",
		Note:     "Reversed 'Shai-Hulud: Here We Go Again' marker used in 2,500+ attacker-created repos",
	},
}

// CheckKnownIOCs flags exact threat-actor indicators in workflow run blocks,
// env values, and with: inputs (FG-025). Hits are critical and high-confidence
// — only catalog needles tightly tied to a known campaign.
func CheckKnownIOCs(wf *Workflow) []Finding {
	type haystack struct {
		where string
		text  string
	}
	var findings []Finding
	var haystacks []haystack // reused across steps to avoid per-step allocation
	for jobName, job := range wf.Jobs {
		for _, step := range job.Steps {
			haystacks = append(haystacks[:0],
				haystack{"run block", strings.ToLower(step.Run)},
				haystack{"uses ref", strings.ToLower(step.Uses)},
			)
			for k, v := range step.Env {
				haystacks = append(haystacks, haystack{"env." + k, strings.ToLower(v)})
			}
			for k, v := range step.With {
				haystacks = append(haystacks, haystack{"with." + k, strings.ToLower(v)})
			}

			// Haystacks are lowercased once above; re-lowercasing inside the
			// IOC loop would repeat the work once per catalog entry.
			for _, ioc := range knownIOCs {
				for _, h := range haystacks {
					if h.text == "" {
						continue
					}
					if !strings.Contains(h.text, ioc.needleLower) {
						continue
					}
					findings = append(findings, Finding{
						RuleID:   "FG-025",
						Severity: SeverityCritical,
						File:     wf.Path,
						Line:     step.Line,
						Message: fmt.Sprintf(
							"Known IOC: %q matched in job %s %s — %s",
							ioc.Needle, jobName, h.where, ioc.Campaign),
						Details: ioc.Note + ". Treat the repo as compromised: assume any secrets " +
							"exposed to this workflow are exfiltrated, rotate credentials, audit " +
							"runner activity, and revert the offending change.",
						Mitigations: []string{
							"Rotate all secrets exposed to this workflow",
							"Audit recent commits and CI run history for the campaign window",
							"Remove the offending content and re-scan",
						},
					})
				}
			}
		}
	}
	return findings
}

type lifecycleInstall struct {
	step      Step
	index     int
	ecosystem string
	command   string
}

type credentialedOperation struct {
	step      Step
	index     int
	kind      string
	ecosystem string
	command   string
	class     string // "registry", "cloud", "github-token" — see feedback-credential-classes memory
}

// Credential-class priority for picking the highest-risk op after an install.
// registry > cloud > github-token (rationale: registry tokens are long-lived
// and supply-chain-pivotable; cloud OIDC is ephemeral but cross-system;
// github-token is repo-scoped and revoked at job end).
const (
	credClassRegistry    = "registry"
	credClassCloud       = "cloud"
	credClassGithubToken = "github-token"
)

func credClassPriority(c string) int {
	switch c {
	case credClassRegistry:
		return 3
	case credClassCloud:
		return 2
	case credClassGithubToken:
		return 1
	}
	return 0
}

var npmInstallPattern = regexp.MustCompile(`(?i)(^|[\s;&|()])npm\s+(install|i|ci)\b`)
var yarnInstallPattern = regexp.MustCompile(`(?i)(^|[\s;&|()])yarn(\s+install\b|\s+--|\s*$)`)
var pnpmInstallPattern = regexp.MustCompile(`(?i)(^|[\s;&|()])pnpm\s+(install|i)\b`)
var pipInstallPattern = regexp.MustCompile(`(?i)(^|[\s;&|()])(python[0-9.]*\s+-m\s+)?pip\s+install\b`)
var gemInstallPattern = regexp.MustCompile(`(?i)(^|[\s;&|()])(gem\s+install|bundle\s+install)\b`)

var npmPublishPattern = regexp.MustCompile(`(?i)(^|[\s;&|()])(npm\s+publish|pnpm\s+publish|yarn\s+npm\s+publish)\b`)
var pypiPublishPattern = regexp.MustCompile(`(?i)(^|[\s;&|()])((python[0-9.]*\s+-m\s+)?twine\s+upload|uv\s+publish|poetry\s+publish|pdm\s+publish|hatch\s+publish)\b`)
var gemPublishPattern = regexp.MustCompile(`(?i)(^|[\s;&|()])((bundle\s+exec\s+)?gem\s+push|rake\s+release)\b`)
var ghReleasePattern = regexp.MustCompile(`(?i)(^|[\s;&|()])gh\s+release\s+(create|upload)\b`)

// CheckLifecycleInstallBeforeCredentialedOperation detects package manager
// install steps that can execute dependency lifecycle/build scripts before a
// later publish, cloud-auth, or release operation in the same credential
// context (FG-026).
func CheckLifecycleInstallBeforeCredentialedOperation(wf *Workflow) []Finding {
	var findings []Finding

	for jobName, job := range wf.Jobs {
		installs := lifecycleInstalls(wf, job)
		if len(installs) == 0 {
			continue
		}

		ops := credentialedOperations(wf, job)
		if len(ops) == 0 {
			continue
		}

		for _, install := range installs {
			op, ok := firstOperationAfter(install, ops)
			if !ok {
				continue
			}

			severity, reason := lifecycleCredentialSeverity(wf, job, install.step, op.step)

			// Credential-class downgrade: when the highest-class op after the
			// install is github-token (gh release / softprops-action-gh-release
			// / actions/upload-release-asset / ncipollo with default token),
			// the credential at risk is the ephemeral repo-scoped GITHUB_TOKEN
			// — revoked at job end, can't pivot to an external registry. Drop
			// to info regardless of trigger surface. See feedback-credential-
			// classes memory for the full taxonomy.
			//
			// Guard: only downgrade when there's no *other* registry/cloud
			// credential reachable on the same chain. Workflows that combine
			// `gh release` with `ansible-galaxy publish` or container-registry
			// push (like redhat-cop/infra.leapp and rhdh-plugin-export-utils)
			// would otherwise be falsely silenced — the github-token op is the
			// highest-class one we *detect*, but the un-detected GALAXY_*/
			// container-registry secrets are the real exposure.
			if op.class == credClassGithubToken && !hasNonGithubTokenSecret(wf, job, install.index) {
				severity = SeverityInfo
				reason += " + github-token-only credential (no external registry exposure)"
			}

			msg := fmt.Sprintf(
				"Lifecycle Install Before Credentialed Operation: %s install runs before %s in job '%s'",
				install.ecosystem, op.kind, jobName)
			if reason != "" {
				msg += " (" + reason + ")"
			}

			findings = append(findings, Finding{
				RuleID:   "FG-026",
				Severity: severity,
				File:     wf.Path,
				Line:     install.step.Line,
				Message:  msg,
				Details: fmt.Sprintf(
					"The %s command %q can execute package lifecycle/build scripts before later %s %q at line %d in the same job. "+
						"Compromised dependencies can harvest publish tokens, OIDC-minted cloud credentials, release credentials, or repository tokens from that job context.",
					install.ecosystem, install.command, op.kind, op.command, op.step.Line),
				Mitigations: lifecycleInstallMitigations(install.ecosystem),
			})
		}
	}

	return findings
}

// packageManagerTools are first-party CLIs that projects self-update globally.
// A global install of only these runs no project dependency lifecycle scripts,
// so it can't harvest a publish token — distinct from installing project deps.
var packageManagerTools = map[string]bool{
	"npm": true, "pnpm": true, "yarn": true, "corepack": true,
}

// isToolingSelfUpdate reports whether every node install command in the run is a
// global self-update of the package-manager tooling (e.g. `npm install -g
// npm@11`), with no project-dependency install present. Such a step installs no
// untrusted dependencies and runs no project lifecycle scripts.
func isToolingSelfUpdate(run string) bool {
	sawInstall := false
	for _, raw := range strings.Split(run, "\n") {
		for _, seg := range splitShellSegments(raw) {
			fields := strings.Fields(seg)
			if len(fields) < 2 {
				continue
			}
			mgr := fields[0]
			if mgr != "npm" && mgr != "pnpm" && mgr != "yarn" {
				continue
			}
			verb := fields[1]
			isInstall := verb == "install" || verb == "i" || verb == "ci" || verb == "add" ||
				(mgr == "yarn" && verb == "global")
			if !isInstall {
				continue
			}
			sawInstall = true
			global := false
			var pkgs []string
			for _, a := range fields[2:] {
				switch {
				case a == "-g" || a == "--global" || a == "global":
					global = true
				case strings.HasPrefix(a, "-"):
					// other flag, ignore
				default:
					pkgs = append(pkgs, a)
				}
			}
			if !global || len(pkgs) == 0 {
				return false
			}
			for _, p := range pkgs {
				base := p
				if at := strings.Index(base, "@"); at > 0 {
					base = base[:at]
				}
				if !packageManagerTools[base] {
					return false
				}
			}
		}
	}
	return sawInstall
}

func lifecycleInstalls(wf *Workflow, job Job) []lifecycleInstall {
	var installs []lifecycleInstall
	for i, step := range job.Steps {
		if step.Uses != "" {
			action := strings.ToLower(actionName(step.Uses))
			if action == "bahmutov/npm-install" {
				if !actionInstallSuppressed(step, "bahmutov/npm-install") &&
					!installScriptsSuppressed(wf, step, job, "npm") {
					cmd := step.With["install-command"]
					if cmd == "" {
						cmd = "bahmutov/npm-install"
					}
					installs = append(installs, lifecycleInstall{step: step, index: i, ecosystem: "npm", command: cmd})
				}
				continue
			}
		}
		if step.Run == "" {
			continue
		}
		if npmInstallPattern.MatchString(step.Run) {
			if installScriptsSuppressed(wf, step, job, "npm") || isToolingSelfUpdate(step.Run) {
				continue
			}
			installs = append(installs, lifecycleInstall{step: step, index: i, ecosystem: "npm", command: matchedCommand(step.Run, npmInstallPattern)})
			continue
		}
		if yarnInstallPattern.MatchString(step.Run) && !strings.Contains(strings.ToLower(step.Run), "yarn npm publish") {
			if installScriptsSuppressed(wf, step, job, "yarn") || isToolingSelfUpdate(step.Run) {
				continue
			}
			installs = append(installs, lifecycleInstall{step: step, index: i, ecosystem: "yarn", command: matchedCommand(step.Run, yarnInstallPattern)})
			continue
		}
		if pnpmInstallPattern.MatchString(step.Run) {
			if installScriptsSuppressed(wf, step, job, "pnpm") || isToolingSelfUpdate(step.Run) {
				continue
			}
			installs = append(installs, lifecycleInstall{step: step, index: i, ecosystem: "pnpm", command: matchedCommand(step.Run, pnpmInstallPattern)})
			continue
		}
		if pipInstallPattern.MatchString(step.Run) {
			installs = append(installs, lifecycleInstall{step: step, index: i, ecosystem: "pip", command: matchedCommand(step.Run, pipInstallPattern)})
			continue
		}
		if gemInstallPattern.MatchString(step.Run) {
			installs = append(installs, lifecycleInstall{step: step, index: i, ecosystem: "gem", command: matchedCommand(step.Run, gemInstallPattern)})
			continue
		}
	}
	return installs
}

// actionInstallSuppressed returns true when a known install action carries an
// inline mitigation in its with: inputs (e.g. install-command: "npm ci --ignore-scripts").
func actionInstallSuppressed(step Step, action string) bool {
	if action == "bahmutov/npm-install" {
		cmd := strings.ToLower(step.With["install-command"])
		if strings.Contains(cmd, "--ignore-scripts") || strings.Contains(cmd, "ignore-scripts=true") {
			return true
		}
	}
	return false
}

func installScriptsSuppressed(wf *Workflow, step Step, job Job, ecosystem string) bool {
	if wf.NPMIgnoreScripts && (ecosystem == "npm" || ecosystem == "pnpm") {
		return true
	}
	runLower := strings.ToLower(step.Run)
	if strings.Contains(runLower, "--ignore-scripts=false") ||
		strings.Contains(runLower, "ignore-scripts=false") {
		return false
	}
	if strings.Contains(runLower, "--ignore-scripts") ||
		strings.Contains(runLower, "ignore-scripts=true") ||
		strings.Contains(runLower, "npm config set ignore-scripts true") ||
		strings.Contains(runLower, "pnpm config set ignore-scripts true") {
		return true
	}
	for k, v := range mergeEnv(job.Env, step.Env) {
		key := strings.ToUpper(k)
		val := strings.ToLower(strings.TrimSpace(v))
		if (key == "NPM_CONFIG_IGNORE_SCRIPTS" || key == "PNPM_CONFIG_IGNORE_SCRIPTS") &&
			(val == "true" || val == "1") {
			return true
		}
		if key == "YARN_ENABLE_SCRIPTS" && (val == "false" || val == "0") {
			return true
		}
	}
	return false
}

func credentialedOperations(wf *Workflow, job Job) []credentialedOperation {
	var ops []credentialedOperation
	for i, step := range job.Steps {
		if step.Run != "" {
			switch {
			case npmPublishPattern.MatchString(step.Run):
				ops = append(ops, credentialedOperation{step: step, index: i, kind: "npm publish", ecosystem: "npm", command: matchedCommand(step.Run, npmPublishPattern), class: credClassRegistry})
			case pypiPublishPattern.MatchString(step.Run):
				ops = append(ops, credentialedOperation{step: step, index: i, kind: "PyPI publish", ecosystem: "pip", command: matchedCommand(step.Run, pypiPublishPattern), class: credClassRegistry})
			case gemPublishPattern.MatchString(step.Run):
				ops = append(ops, credentialedOperation{step: step, index: i, kind: "RubyGems publish", ecosystem: "gem", command: matchedCommand(step.Run, gemPublishPattern), class: credClassRegistry})
			case ghReleasePattern.MatchString(step.Run):
				if effectivePermission(wf, job, "contents") == "write" || hasCredentialEnv(wf, job, step) || HasElevatedPermissions(wf.Permissions, job.Permissions) {
					ops = append(ops, credentialedOperation{step: step, index: i, kind: "GitHub release", command: matchedCommand(step.Run, ghReleasePattern), class: credClassGithubToken})
				}
			}
		}

		if step.Uses != "" {
			action := strings.ToLower(actionName(step.Uses))
			switch action {
			case "aws-actions/configure-aws-credentials",
				"google-github-actions/auth",
				"azure/login",
				"hashicorp/vault-action":
				if effectivePermission(wf, job, "id-token") == "write" || hasCredentialEnv(wf, job, step) {
					ops = append(ops, credentialedOperation{step: step, index: i, kind: "cloud auth", command: action, class: credClassCloud})
				}
			case "softprops/action-gh-release",
				"actions/upload-release-asset",
				"ncipollo/release-action":
				if effectivePermission(wf, job, "contents") == "write" || hasCredentialEnv(wf, job, step) || HasElevatedPermissions(wf.Permissions, job.Permissions) {
					ops = append(ops, credentialedOperation{step: step, index: i, kind: "GitHub release", command: action, class: credClassGithubToken})
				}
			case "js-devtools/npm-publish":
				ops = append(ops, credentialedOperation{step: step, index: i, kind: "npm publish", ecosystem: "npm", command: action, class: credClassRegistry})
			case "pypa/gh-action-pypi-publish":
				ops = append(ops, credentialedOperation{step: step, index: i, kind: "PyPI publish", ecosystem: "pip", command: action, class: credClassRegistry})
			case "rubygems/release-gem":
				ops = append(ops, credentialedOperation{step: step, index: i, kind: "RubyGems publish", ecosystem: "gem", command: action, class: credClassRegistry})
			}
		}
	}
	return ops
}

// firstOperationAfter returns the highest-class credentialed operation ordered
// after the install. Class priority: registry > cloud > github-token. Picking
// the highest-class op (rather than the chronologically first one) lets us
// surface the worst-case exposure when multiple credentialed steps follow an
// install — e.g. `softprops/action-gh-release` (github-token) immediately
// after install followed by `npm publish` (registry) two steps later. The
// registry op is what matters for blast radius even though the github-token
// op came first.
func firstOperationAfter(install lifecycleInstall, ops []credentialedOperation) (credentialedOperation, bool) {
	var best credentialedOperation
	found := false
	for _, op := range ops {
		if op.index <= install.index {
			continue
		}
		if !found || credClassPriority(op.class) > credClassPriority(best.class) {
			best = op
			found = true
		}
	}
	return best, found
}

// lifecycleCredentialSeverity tiers the FG-026 finding by trigger + defense-
// in-depth signals. Environment gate, tag-ref guard, author-association guard,
// and user-login allowlist each reduce severity by one step; absent all, the
// trigger's base severity applies. When the install step's own if: excludes
// the fork-PR branch (claude-code-action / Backstage-style workflows),
// pull_request_target is removed from the external-trigger tier consideration.
// Tag-only push (`on: push: tags:`) and release events (`on: release:`)
// restrict the credentialed path to repo-writer actions and use the internal-
// trigger tier instead of external. Tag-ref guard at the job level folds the
// FG-027 weakly-constrained trusted publishing case into FG-026; author
// guards restrict triggers like issue_comment to known contributors only.
func lifecycleCredentialSeverity(wf *Workflow, job Job, install Step, op Step) (string, string) {
	hasEnvGate := job.Environment != ""
	hasTag := hasTagGuard(job, op)
	hasAuthor := hasAuthorAssociationGuard(job) || hasUserLoginAllowlist(job)
	forkExcluded := installStepExcludesForks(install) && wf.On.PullRequestTarget
	// Step-level publish guard: when the credentialed op's own if: restricts
	// the trigger surface (e.g. yaml-language-server CI.yaml publishes only on
	// push to main while the install runs on PRs too), the credential isn't
	// reachable on the broader trigger set even though the install is.
	publishGuarded := opStepRestrictsToInternal(op)

	// Drop pull_request_target from the external set when the install step
	// itself excludes forks. WorkflowRun and IssueComment are not affected.
	externalTrigger := wf.On.WorkflowRun || wf.On.IssueComment
	if !forkExcluded && wf.On.PullRequestTarget {
		externalTrigger = true
	}
	// Step-level publish guard wins over the trigger surface: if the credentialed
	// op's `if:` restricts execution to push-to-main / non-external triggers, the
	// install can still run on PRs but no credential is reachable. Drop all
	// external triggers from consideration.
	if publishGuarded {
		externalTrigger = false
	}

	// Repo-writer-gated paths: only contributors with tag-create, release-
	// create, or workflow_dispatch permission can trigger. All three require
	// the same `actions: write` / repo-write permission level. When the only
	// trigger paths are these, treat as repo-writer-trigger tier (not
	// external). workflow_dispatch alone counts only when paired with no
	// auto-firing trigger (push/PR/PRT/WR/IC) — otherwise a co-existing push
	// is the dominant surface and the dispatch flag adds no safety.
	dispatchOnly := wf.On.WorkflowDispatch &&
		!wf.On.Push &&
		!wf.On.PullRequest &&
		!wf.On.PullRequestTarget &&
		!wf.On.WorkflowRun &&
		!wf.On.IssueComment
	hasGatedTrigger := (wf.On.Push && wf.On.PushTagsOnly) || wf.On.Release || dispatchOnly

	var sev, triggerLabel string
	switch {
	case externalTrigger:
		triggerLabel = "external trigger"
		if hasEnvGate {
			sev = SeverityHigh
		} else {
			sev = SeverityCritical
		}
	case hasGatedTrigger:
		// Tag-only push, release event, or dispatch-only = repo-writer-only
		// path. Equivalent in effect to a permission-gate job (FG-001
		// PermissionGateJob pattern).
		triggerLabel = "repo-writer trigger"
		if hasEnvGate {
			sev = SeverityLow
		} else {
			sev = SeverityMedium
		}
	default:
		triggerLabel = "internal trigger"
		if hasEnvGate {
			sev = SeverityMedium
		} else {
			sev = SeverityHigh
		}
	}

	if hasTag {
		sev = downgradeBy(sev, 1)
	}
	if hasAuthor {
		sev = downgradeBy(sev, 1)
	}

	gates := []string{}
	if hasEnvGate {
		gates = append(gates, "environment gate")
	}
	if hasTag {
		gates = append(gates, "tag-ref guard")
	}
	if hasAuthor {
		gates = append(gates, "author/login allowlist")
	}
	if forkExcluded {
		gates = append(gates, "step-level fork exclusion")
	}
	if publishGuarded {
		gates = append(gates, "step-level publish guard")
	}
	if wf.On.Push && wf.On.PushTagsOnly {
		gates = append(gates, "tag-only push")
	}
	if wf.On.Release {
		gates = append(gates, "release event")
	}
	if dispatchOnly {
		gates = append(gates, "dispatch-only")
	}
	reason := triggerLabel
	if len(gates) > 0 {
		reason += " with " + strings.Join(gates, " + ")
	} else {
		reason += " without environment or tag guard"
	}
	return sev, reason
}

// hasUserLoginAllowlist returns true when the job's if: restricts the actor by
// explicit login allowlist — e.g. `github.event.pull_request.user.login ==
// 'rhdh-bot'` or `github.actor == 'backstage-service'`. Common in
// changesets-driven release workflows (community-plugins, rhdh-plugins) where
// the publish flow only runs on a PR merged by a specific bot account.
// Treated equivalently to hasAuthorAssociationGuard — one-step downgrade.
func hasUserLoginAllowlist(job Job) bool {
	g := strings.ToLower(strings.ReplaceAll(job.If, " ", ""))
	if g == "" {
		return false
	}
	patterns := []string{
		"user.login=='",
		`user.login=="`,
		"github.actor=='",
		`github.actor=="`,
		"sender.login=='",
		`sender.login=="`,
	}
	for _, p := range patterns {
		if strings.Contains(g, p) {
			return true
		}
	}
	return false
}

// hasNonGithubTokenSecret returns true when any step at or after installIdx
// references a secret other than the ambient GITHUB_TOKEN, or has an env var
// with a credential-shaped name not bound to secrets.GITHUB_TOKEN. Catches
// registry/cloud tokens that aren't tied to a credentialed op the rule
// explicitly detects (ansible-galaxy publish, container-registry push,
// arbitrary `secrets.X` inline in run/with blocks).
func hasNonGithubTokenSecret(wf *Workflow, job Job, installIdx int) bool {
	// Workflow- and job-level env are reachable from all steps.
	for k, v := range mergeEnv(wf.Env, job.Env) {
		if envIsNonGithubCredential(k, v) {
			return true
		}
	}
	// Steps ordered after the install.
	for i, step := range job.Steps {
		if i <= installIdx {
			continue
		}
		for k, v := range step.Env {
			if envIsNonGithubCredential(k, v) {
				return true
			}
		}
		for _, v := range step.With {
			if containsNonGithubSecretRef(v) {
				return true
			}
		}
		if containsNonGithubSecretRef(step.Run) {
			return true
		}
	}
	return false
}

func envIsNonGithubCredential(k, v string) bool {
	keyU := strings.ToUpper(k)
	// GH_TOKEN/GITHUB_TOKEN set to secrets.GITHUB_TOKEN is the ambient path; skip.
	if keyU == "GITHUB_TOKEN" || keyU == "GH_TOKEN" {
		if strings.Contains(strings.ToLower(v), "secrets.github_token") {
			return false
		}
	}
	if containsNonGithubSecretRef(v) {
		return true
	}
	// Suspicious key names imply external credential even if value isn't a
	// secrets.* reference (could be a raw env injection in CI config).
	if (strings.Contains(keyU, "TOKEN") || strings.Contains(keyU, "PASSWORD") ||
		strings.Contains(keyU, "API_KEY") || strings.HasSuffix(keyU, "_KEY") ||
		strings.Contains(keyU, "SECRET")) && keyU != "GITHUB_TOKEN" && keyU != "GH_TOKEN" {
		return true
	}
	return false
}

var nonGithubSecretRefPattern = regexp.MustCompile(`(?i)secrets\.([a-z0-9_-]+)`)

func containsNonGithubSecretRef(s string) bool {
	if s == "" {
		return false
	}
	for _, m := range nonGithubSecretRefPattern.FindAllStringSubmatch(s, -1) {
		name := strings.ToLower(m[1])
		if name == "github_token" {
			continue
		}
		return true
	}
	return false
}

// opStepRestrictsToInternal returns true when a credentialed op step's if:
// restricts execution to push-to-main / internal triggers — i.e. the publish
// won't run on PRs or external triggers even though the install does. Mirror
// of installStepExcludesForks but applied to the publish op, so we recognize
// patterns like yaml-language-server CI.yaml where:
//
//	on: [push, pull_request]
//	...
//	  - name: Install   # runs on both
//	    run: npm ci
//	  - name: Publish   # runs only on push to main
//	    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
//	    run: npm publish
//
// When the publish step's if: gates to internal-only, no credential is
// reachable on PR-triggered runs, so external triggers should drop out.
func opStepRestrictsToInternal(step Step) bool {
	g := strings.ToLower(strings.ReplaceAll(step.If, " ", ""))
	if g == "" {
		return false
	}
	// Restrict to push event (excludes PR/PRT/IC/WR).
	if strings.Contains(g, "github.event_name=='push'") ||
		strings.Contains(g, `github.event_name=="push"`) {
		return true
	}
	// Restrict to a default-branch ref (only push to main/master fires).
	if strings.Contains(g, "github.ref=='refs/heads/main'") ||
		strings.Contains(g, `github.ref=="refs/heads/main"`) ||
		strings.Contains(g, "github.ref=='refs/heads/master'") ||
		strings.Contains(g, `github.ref=="refs/heads/master"`) ||
		strings.Contains(g, "ref=='refs/heads/main'") ||
		strings.Contains(g, `ref=="refs/heads/main"`) {
		return true
	}
	// Negation of external event names.
	if strings.Contains(g, "github.event_name!='pull_request'") ||
		strings.Contains(g, `github.event_name!="pull_request"`) ||
		strings.Contains(g, "github.event_name!='pull_request_target'") ||
		strings.Contains(g, `github.event_name!="pull_request_target"`) {
		return true
	}
	return false
}

// installStepExcludesForks returns true when an install step's if: evaluates
// to false on pull_request_target / fork-PR triggers. Recognizes the common
// idioms: step output flags set by an upstream "determine context" step
// (is_fork-style), direct same-repo guards comparing head.repo.full_name to
// github.repository, and explicit event_name comparisons.
func installStepExcludesForks(step Step) bool {
	g := strings.ToLower(strings.ReplaceAll(step.If, " ", ""))
	if g == "" {
		return false
	}
	// Step-output fork flag set by an upstream "determine context" step.
	if strings.Contains(g, "is_fork!='true'") ||
		strings.Contains(g, `is_fork!="true"`) ||
		strings.Contains(g, "is_fork=='false'") ||
		strings.Contains(g, `is_fork=="false"`) ||
		strings.Contains(g, "fork_pr!='true'") ||
		strings.Contains(g, `fork_pr!="true"`) {
		return true
	}
	// Direct same-repo guard.
	if strings.Contains(g, "head.repo.full_name==github.repository") ||
		strings.Contains(g, "github.repository==github.event.pull_request.head.repo.full_name") {
		return true
	}
	// Direct trigger exclusion.
	if strings.Contains(g, "github.event_name!='pull_request_target'") ||
		strings.Contains(g, `github.event_name!="pull_request_target"`) {
		return true
	}
	return false
}

// hasAuthorAssociationGuard returns true when the job's if: restricts execution
// to known contributors. Matches both exclusion idioms (`!= 'NONE'`,
// `!= 'FIRST_TIME_CONTRIBUTOR'`) and inclusion idioms (`== 'MEMBER'`,
// `== 'COLLABORATOR'`, etc.). One-step downgrade — soft signal because the
// guard often applies to a subset of triggers (e.g. issue_comment only), so we
// don't claim full mitigation.
func hasAuthorAssociationGuard(job Job) bool {
	g := strings.ToLower(strings.ReplaceAll(job.If, " ", ""))
	if !strings.Contains(g, "author_association") {
		return false
	}
	if strings.Contains(g, "author_association!='none'") ||
		strings.Contains(g, `author_association!="none"`) ||
		strings.Contains(g, "author_association!='first_timer'") ||
		strings.Contains(g, `author_association!="first_timer"`) ||
		strings.Contains(g, "author_association!='first_time_contributor'") ||
		strings.Contains(g, `author_association!="first_time_contributor"`) {
		return true
	}
	for _, role := range []string{"member", "owner", "collaborator", "contributor"} {
		if strings.Contains(g, "author_association=='"+role+"'") ||
			strings.Contains(g, `author_association=="`+role+`"`) {
			return true
		}
	}
	// Allowlist idiom: contains(fromJSON('["MEMBER","OWNER","COLLABORATOR"]'), author_association)
	if strings.Contains(g, "fromjson") {
		for _, role := range []string{"'member'", "'owner'", "'collaborator'", `"member"`, `"owner"`, `"collaborator"`} {
			if strings.Contains(g, role) {
				return true
			}
		}
	}
	return false
}

func hasTagGuard(job Job, op Step) bool {
	guards := []string{job.If, op.If}
	for _, guard := range guards {
		g := strings.ToLower(strings.ReplaceAll(guard, " ", ""))
		if strings.Contains(g, "refs/tags/") ||
			strings.Contains(g, "github.ref_type=='tag'") ||
			strings.Contains(g, `github.ref_type=="tag"`) ||
			strings.Contains(g, "github.ref.startswith('refs/tags/')") ||
			strings.Contains(g, `github.ref.startswith("refs/tags/")`) ||
			strings.Contains(g, "startswith(github.ref,'refs/tags/')") ||
			strings.Contains(g, `startswith(github.ref,"refs/tags/")`) {
			return true
		}
	}
	return false
}

func hasCredentialEnv(wf *Workflow, job Job, step Step) bool {
	for k, v := range mergeEnv(wf.Env, mergeEnv(job.Env, step.Env)) {
		key := strings.ToUpper(k)
		val := strings.ToLower(v)
		if strings.Contains(key, "TOKEN") ||
			strings.Contains(key, "PASSWORD") ||
			strings.Contains(key, "SECRET") ||
			key == "GEM_HOST_API_KEY" ||
			key == "RUBYGEMS_API_KEY" ||
			key == "TWINE_USERNAME" ||
			key == "TWINE_PASSWORD" {
			return true
		}
		if strings.Contains(val, "secrets.") {
			return true
		}
	}
	return false
}

func effectivePermission(wf *Workflow, job Job, scope string) string {
	if job.Permissions.Scopes != nil {
		if v, ok := job.Permissions.Scopes[scope]; ok {
			return v
		}
	}
	if wf.Permissions.Scopes != nil {
		if v, ok := wf.Permissions.Scopes[scope]; ok {
			return v
		}
	}
	if job.Permissions.WriteAll || wf.Permissions.WriteAll {
		return "write"
	}
	return ""
}

func mergeEnv(a, b map[string]string) map[string]string {
	merged := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		merged[k] = v
	}
	for k, v := range b {
		merged[k] = v
	}
	return merged
}

func actionName(uses string) string {
	if idx := strings.Index(uses, "@"); idx != -1 {
		return uses[:idx]
	}
	return uses
}

func matchedCommand(run string, re *regexp.Regexp) string {
	match := strings.TrimSpace(re.FindString(run))
	if match == "" {
		return "install"
	}
	return strings.TrimLeft(match, " \t\n\r;&|()")
}

func lifecycleInstallMitigations(ecosystem string) []string {
	common := []string{
		"Run dependency installation in a separate job that has no publish, release, cloud, or repository-write credentials",
		"Move publish/cloud/release operations behind an environment protection gate",
		"Restrict publishing to tag-protected releases",
	}
	switch ecosystem {
	case "npm", "yarn", "pnpm":
		return append([]string{
			"Use --ignore-scripts or ignore-scripts=true for install steps in credentialed jobs",
		}, common...)
	case "pip":
		return append([]string{
			"Install build/publish tooling in an isolated job or prebuilt image instead of the publish job",
			"Prefer wheel-only installs for dependencies where practical",
		}, common...)
	case "gem":
		return append([]string{
			"Install RubyGems/Bundler dependencies in an isolated job or prebuilt image instead of the publish job",
		}, common...)
	default:
		return common
	}
}

// CheckLabelGateTOCTOU detects pull_request_target workflows that gate fork
// code execution on a PR label but don't strip the label on synchronize.
// After a maintainer applies the label, every subsequent commit on the PR
// re-triggers the workflow with the label still attached — the gate authorizes
// the initial SHA but trusts every later SHA implicitly (FG-027).
//
// Pattern observed in multiple workflows during corpus scanning.
func CheckLabelGateTOCTOU(wf *Workflow) []Finding {
	if !wf.On.PullRequestTarget {
		return nil
	}
	if !prtTypesIncludeSynchronize(wf.On.PullRequestTargetTypes) {
		return nil
	}
	if workflowStripsLabelOnSync(wf) {
		return nil
	}
	if !workflowHasForkCheckout(wf) {
		return nil
	}

	var findings []Finding
	for jobName, job := range wf.Jobs {
		labelName, gateLine, ok := jobLabelGate(job)
		if !ok {
			continue
		}
		findings = append(findings, Finding{
			RuleID:   "FG-027",
			Severity: SeverityHigh,
			File:     wf.Path,
			Line:     gateLine,
			Message: fmt.Sprintf(
				"TOCTOU label gate: job '%s' is gated on label '%s' but workflow does not strip "+
					"the label on synchronize — attacker can re-push malicious code after approval",
				jobName, labelName),
			Details: "The 'synchronize' event re-runs the workflow when a PR's head is updated. " +
				"If the gate label persists across pushes, a maintainer who applies the label to " +
				"approve one commit implicitly approves every future commit on the same PR. " +
				"Mitigations: (1) strip the label on synchronize and require re-labeling, " +
				"(2) pin the gated SHA at label-application time and reject other SHAs, " +
				"(3) use trusted-ref isolation (checkout base ref to root, PR head to subdir).",
		})
	}
	return findings
}

// prtTypesIncludeSynchronize reports whether the pull_request_target trigger's
// types list includes 'synchronize' (the default set when types is unspecified
// also includes synchronize, so an empty list returns true).
func prtTypesIncludeSynchronize(types []string) bool {
	if len(types) == 0 {
		return true
	}
	for _, t := range types {
		if strings.EqualFold(t, "synchronize") {
			return true
		}
	}
	return false
}

// workflowStripsLabelOnSync detects steps that remove the gating label, which
// neutralizes the TOCTOU window. Matches `gh pr edit --remove-label`,
// actions-ecosystem/action-remove-labels, and similar.
func workflowStripsLabelOnSync(wf *Workflow) bool {
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if strings.HasPrefix(step.Uses, "actions-ecosystem/action-remove-labels") {
				return true
			}
			if step.Run != "" && strings.Contains(step.Run, "gh pr edit") &&
				strings.Contains(step.Run, "--remove-label") {
				return true
			}
			if step.Run != "" && strings.Contains(step.Run, "/issues/") &&
				strings.Contains(step.Run, "DELETE") &&
				strings.Contains(step.Run, "/labels/") {
				return true
			}
		}
	}
	return false
}

// workflowHasForkCheckout reports whether any job in the workflow checks out
// fork code (PR head ref).
func workflowHasForkCheckout(wf *Workflow) bool {
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if isCheckoutAction(step.Uses) && refPointsToPRHead(step.With["ref"]) {
				return true
			}
		}
	}
	return false
}

// jobLabelGate returns the label name, the gating step's line, and true if the
// job is gated on a PR label — either via an `if:` condition referencing
// pull_request labels, or via the mheap/github-action-required-labels action.
func jobLabelGate(job Job) (string, int, bool) {
	if name := extractLabelFromCondition(job.If); name != "" {
		line := 0
		if len(job.Steps) > 0 {
			line = job.Steps[0].Line
		}
		return name, line, true
	}
	for _, step := range job.Steps {
		if strings.HasPrefix(step.Uses, "mheap/github-action-required-labels") {
			label := step.With["labels"]
			if label == "" {
				label = step.With["label"]
			}
			if label == "" {
				label = "<required>"
			}
			return label, step.Line, true
		}
		if name := extractLabelFromCondition(step.If); name != "" {
			return name, step.Line, true
		}
	}
	return "", 0, false
}

var labelContainsPattern = regexp.MustCompile(
	`(?i)contains\s*\(\s*github\.event\.pull_request\.labels\.\*\.name\s*,\s*['"]([^'"]+)['"]`)
var labelEqualsPattern = regexp.MustCompile(
	`(?i)github\.event\.label\.name\s*==\s*['"]([^'"]+)['"]`)

// extractLabelFromCondition returns the label name referenced in a GitHub
// Actions condition expression, or "" if the condition isn't a label gate.
func extractLabelFromCondition(cond string) string {
	if cond == "" {
		return ""
	}
	if m := labelContainsPattern.FindStringSubmatch(cond); m != nil {
		return m[1]
	}
	if m := labelEqualsPattern.FindStringSubmatch(cond); m != nil {
		return m[1]
	}
	return ""
}
