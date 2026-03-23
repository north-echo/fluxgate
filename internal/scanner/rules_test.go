package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixturesDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "test", "fixtures")
}

func loadFixture(t *testing.T, name string) *Workflow {
	t.Helper()
	path := filepath.Join(fixturesDir(), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	wf, err := ParseWorkflow(data, name)
	if err != nil {
		t.Fatalf("parsing fixture %s: %v", name, err)
	}
	return wf
}

func TestCheckPwnRequest_Confirmed(t *testing.T) {
	wf := loadFixture(t, "pwn-request.yaml")
	findings := CheckPwnRequest(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "FG-001" {
		t.Errorf("expected rule FG-001, got %s", f.RuleID)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("expected critical severity, got %s", f.Severity)
	}
	if f.Confidence != ConfidenceConfirmed {
		t.Errorf("expected confirmed confidence, got %s", f.Confidence)
	}
}

func TestCheckPwnRequest_NpmInstall(t *testing.T) {
	wf := loadFixture(t, "pwn-request-npm-install.yaml")
	findings := CheckPwnRequest(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityCritical {
		t.Errorf("expected critical severity, got %s", f.Severity)
	}
	if f.Confidence != ConfidenceConfirmed {
		t.Errorf("expected confirmed confidence, got %s", f.Confidence)
	}
}

func TestCheckPwnRequest_ConfigTool(t *testing.T) {
	wf := loadFixture(t, "pwn-request-config-tool.yaml")
	findings := CheckPwnRequest(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityCritical {
		t.Errorf("expected critical severity, got %s", f.Severity)
	}
	if f.Confidence != ConfidenceLikely {
		t.Errorf("expected likely confidence, got %s", f.Confidence)
	}
}

func TestCheckPwnRequest_NoExec(t *testing.T) {
	wf := loadFixture(t, "pwn-request-no-exec.yaml")
	findings := CheckPwnRequest(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("expected high severity for pattern-only, got %s", f.Severity)
	}
	if f.Confidence != ConfidencePatternOnly {
		t.Errorf("expected pattern-only confidence, got %s", f.Confidence)
	}
}

func TestCheckPwnRequest_WriteAll(t *testing.T) {
	wf := loadFixture(t, "pwn-request-write-all.yaml")
	findings := CheckPwnRequest(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("expected high severity for pattern-only, got %s", f.Severity)
	}
	if f.Confidence != ConfidencePatternOnly {
		t.Errorf("expected pattern-only confidence, got %s", f.Confidence)
	}
}

func TestCheckPwnRequest_Safe(t *testing.T) {
	wf := loadFixture(t, "safe-workflow.yaml")
	findings := CheckPwnRequest(wf)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for safe workflow, got %d", len(findings))
	}
}

func TestCheckScriptInjection(t *testing.T) {
	wf := loadFixture(t, "script-injection.yaml")
	findings := CheckScriptInjection(wf)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (title + body), got %d", len(findings))
	}
	for _, f := range findings {
		if f.RuleID != "FG-002" {
			t.Errorf("expected rule FG-002, got %s", f.RuleID)
		}
		if f.Severity != SeverityHigh {
			t.Errorf("expected high severity, got %s", f.Severity)
		}
	}
}

func TestCheckScriptInjection_Safe(t *testing.T) {
	wf := loadFixture(t, "safe-workflow.yaml")
	findings := CheckScriptInjection(wf)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for safe workflow, got %d", len(findings))
	}
}

func TestCheckTagPinning(t *testing.T) {
	wf := loadFixture(t, "tag-pinned.yaml")
	findings := CheckTagPinning(wf)

	// actions/checkout@v4 = info, trivy-action@v0.35.0 = medium, semgrep by SHA = no finding
	var mediumCount, infoCount int
	for _, f := range findings {
		if f.RuleID != "FG-003" {
			t.Errorf("expected rule FG-003, got %s", f.RuleID)
		}
		switch f.Severity {
		case SeverityMedium:
			mediumCount++
		case SeverityInfo:
			infoCount++
		}
	}

	if mediumCount != 1 {
		t.Errorf("expected 1 medium finding (trivy-action by tag), got %d", mediumCount)
	}
	if infoCount != 1 {
		t.Errorf("expected 1 info finding (actions/checkout by tag), got %d", infoCount)
	}
}

func TestCheckBroadPermissions(t *testing.T) {
	wf := loadFixture(t, "broad-perms.yaml")
	findings := CheckBroadPermissions(wf)

	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding for write-all permissions")
	}
	for _, f := range findings {
		if f.RuleID != "FG-004" {
			t.Errorf("expected rule FG-004, got %s", f.RuleID)
		}
	}
}

func TestCheckSecretsInLogs(t *testing.T) {
	wf := loadFixture(t, "secret-echo.yaml")
	findings := CheckSecretsInLogs(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "FG-005" {
		t.Errorf("expected rule FG-005, got %s", findings[0].RuleID)
	}
	if findings[0].Severity != SeverityLow {
		t.Errorf("expected low severity, got %s", findings[0].Severity)
	}
}

func TestSafeWorkflow_NoFindings(t *testing.T) {
	wf := loadFixture(t, "safe-workflow.yaml")
	opts := ScanOptions{}
	findings := ScanWorkflow(wf, opts)

	// The safe workflow uses pull_request + go test, which triggers FG-006
	// (fork PR code execution). This is by design — FG-006 flags all
	// pull_request workflows that execute build commands on fork code.
	for _, f := range findings {
		if f.RuleID != "FG-006" {
			t.Errorf("expected only FG-006 findings for safe workflow, got %s: %s", f.RuleID, f.Message)
		}
	}
}

func TestMixedWorkflow_MultipleFindings(t *testing.T) {
	wf := loadFixture(t, "mixed-workflow.yaml")
	opts := ScanOptions{}
	findings := ScanWorkflow(wf, opts)

	if len(findings) < 3 {
		t.Fatalf("expected at least 3 findings for mixed workflow, got %d", len(findings))
	}

	rulesSeen := map[string]bool{}
	for _, f := range findings {
		rulesSeen[f.RuleID] = true
	}
	// Should trigger FG-001 (pwn request), FG-002 (script injection),
	// FG-003 (tag pinning), FG-004 (broad permissions)
	for _, expected := range []string{"FG-001", "FG-002", "FG-003"} {
		if !rulesSeen[expected] {
			t.Errorf("expected rule %s to fire on mixed workflow", expected)
		}
	}
}

// --- FG-001 mitigation tests ---

func TestCheckPwnRequest_LabelGated(t *testing.T) {
	wf := loadFixture(t, "pwn-request-label-gated.yaml")
	findings := CheckPwnRequest(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityMedium {
		t.Errorf("expected medium severity (downgraded from critical by 2: label+env), got %s", f.Severity)
	}
	if len(f.Mitigations) == 0 {
		t.Error("expected mitigations to be populated")
	}
}

func TestCheckPwnRequest_ForkGuard(t *testing.T) {
	wf := loadFixture(t, "pwn-request-fork-guard.yaml")
	findings := CheckPwnRequest(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityInfo {
		t.Errorf("expected info severity for fork-guarded workflow, got %s", f.Severity)
	}
}

func TestCheckPwnRequest_EnvOnly(t *testing.T) {
	wf := loadFixture(t, "pwn-request-env-only.yaml")
	findings := CheckPwnRequest(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("expected high severity (downgraded from critical by 1: env only), got %s", f.Severity)
	}
}

// --- FG-006 tests ---

func TestCheckForkPRCodeExec(t *testing.T) {
	wf := loadFixture(t, "fork-pr-code-exec.yaml")
	findings := CheckForkPRCodeExec(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "FG-006" {
		t.Errorf("expected rule FG-006, got %s", f.RuleID)
	}
	if f.Severity != SeverityMedium {
		t.Errorf("expected medium severity (no secrets), got %s", f.Severity)
	}
}

func TestCheckForkPRCodeExec_WithSecrets(t *testing.T) {
	wf := loadFixture(t, "fork-pr-code-exec-with-secrets.yaml")
	findings := CheckForkPRCodeExec(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("expected high severity (secrets on build step), got %s", f.Severity)
	}
}

func TestCheckForkPRCodeExec_Safe(t *testing.T) {
	wf := loadFixture(t, "fork-pr-safe.yaml")
	findings := CheckForkPRCodeExec(wf)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for fork-guarded workflow, got %d", len(findings))
	}
}

// --- FG-007 tests ---

func TestCheckTokenExposure_PartialBlank(t *testing.T) {
	wf := loadFixture(t, "token-partial-blank.yaml")
	findings := CheckTokenExposure(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (pip install without blank), got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "FG-007" {
		t.Errorf("expected rule FG-007, got %s", f.RuleID)
	}
	if f.Severity != SeverityLow {
		t.Errorf("expected low severity (pull_request trigger), got %s", f.Severity)
	}
}

func TestCheckTokenExposure_SafeWorkflow(t *testing.T) {
	wf := loadFixture(t, "safe-workflow.yaml")
	findings := CheckTokenExposure(wf)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for safe workflow, got %d", len(findings))
	}
}

// --- Gap 1: Actor guard tests ---

func TestCheckPwnRequest_ActorGuardBot(t *testing.T) {
	wf := loadFixture(t, "pwn-request-actor-guard-bot.yaml")
	findings := CheckPwnRequest(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityInfo {
		t.Errorf("expected info severity for bot actor guard, got %s", f.Severity)
	}
	if len(f.Mitigations) == 0 {
		t.Error("expected mitigations to be populated")
	}
}

func TestCheckPwnRequest_ActorGuardHuman(t *testing.T) {
	wf := loadFixture(t, "pwn-request-actor-guard-human.yaml")
	findings := CheckPwnRequest(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("expected high severity (downgraded from critical by 1 for human actor guard), got %s", f.Severity)
	}
}

// --- Gap 2: Action permission gate tests ---

func TestCheckPwnRequest_ActionPermGate(t *testing.T) {
	wf := loadFixture(t, "pwn-request-action-perm-gate.yaml")
	findings := CheckPwnRequest(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("expected high severity (downgraded from critical by 1 for maintainer check via action), got %s", f.Severity)
	}
	if len(f.Mitigations) == 0 {
		t.Error("expected mitigations to be populated")
	}
}

// --- Gap 3: Cross-job needs gate tests ---

func TestCheckPwnRequest_NeedsGate(t *testing.T) {
	wf := loadFixture(t, "pwn-request-needs-gate.yaml")
	findings := CheckPwnRequest(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("expected high severity (downgraded from critical by 1 for environment gate via needs), got %s", f.Severity)
	}
	if len(f.Mitigations) == 0 {
		t.Error("expected mitigations to be populated")
	}
	// Verify the mitigation mentions the authorize job
	found := false
	for _, m := range f.Mitigations {
		if strings.Contains(m, "authorize") {
			found = true
		}
	}
	if !found {
		t.Error("expected mitigations to reference 'authorize' job")
	}
}

// --- Gap 4: Path isolation tests ---

func TestCheckPwnRequest_PathIsolated(t *testing.T) {
	wf := loadFixture(t, "pwn-request-path-isolated.yaml")
	findings := CheckPwnRequest(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	// Path isolation downgrades confidence to pattern-only, not severity
	if f.Confidence != ConfidencePatternOnly {
		t.Errorf("expected pattern-only confidence for path-isolated checkout, got %s", f.Confidence)
	}
	if len(f.Mitigations) == 0 {
		t.Error("expected mitigations to mention path isolation")
	}
}

func TestCheckPwnRequest_PathExec(t *testing.T) {
	wf := loadFixture(t, "pwn-request-path-exec.yaml")
	findings := CheckPwnRequest(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	// Path with direct execution should still be confirmed/critical
	if f.Severity != SeverityCritical {
		t.Errorf("expected critical severity for path with direct execution, got %s", f.Severity)
	}
	if f.Confidence != ConfidenceConfirmed {
		t.Errorf("expected confirmed confidence for path with direct execution, got %s", f.Confidence)
	}
}

// --- FG-008 OIDC tests ---

func TestCheckOIDC_PRTWithForkCheckout(t *testing.T) {
	wf := loadFixture(t, "oidc-prt-fork-checkout.yaml")
	findings := CheckOIDCMisconfiguration(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "FG-008" {
		t.Errorf("expected FG-008, got %s", f.RuleID)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("expected critical (PRT + fork checkout + cloud auth), got %s", f.Severity)
	}
	if !strings.Contains(f.Message, "aws-actions/configure-aws-credentials") {
		t.Error("expected message to mention AWS auth action")
	}
}

func TestCheckOIDC_PRTNoFork(t *testing.T) {
	wf := loadFixture(t, "oidc-prt-no-fork.yaml")
	findings := CheckOIDCMisconfiguration(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("expected high (PRT but no fork checkout), got %s", f.Severity)
	}
}

func TestCheckOIDC_PushOnly(t *testing.T) {
	wf := loadFixture(t, "oidc-push-only.yaml")
	findings := CheckOIDCMisconfiguration(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 info finding for push-only OIDC, got %d", len(findings))
	}
	if findings[0].Severity != SeverityInfo {
		t.Errorf("expected info for push-only OIDC, got %s", findings[0].Severity)
	}
}

// --- FG-009 Self-Hosted Runner tests ---

func TestCheckSelfHosted_PR(t *testing.T) {
	wf := loadFixture(t, "self-hosted-pr.yaml")
	findings := CheckSelfHostedRunner(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "FG-009" {
		t.Errorf("expected FG-009, got %s", f.RuleID)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("expected high severity for self-hosted on PR, got %s", f.Severity)
	}
}

func TestCheckSelfHosted_PRTFork(t *testing.T) {
	wf := loadFixture(t, "self-hosted-prt-fork.yaml")
	findings := CheckSelfHostedRunner(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityCritical {
		t.Errorf("expected critical (PRT + fork checkout on self-hosted), got %s", f.Severity)
	}
}

func TestCheckSelfHosted_PushOnly(t *testing.T) {
	wf := loadFixture(t, "self-hosted-push-only.yaml")
	findings := CheckSelfHostedRunner(wf)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for push-only self-hosted, got %d", len(findings))
	}
}

// --- FG-010 Cache Poisoning tests ---

func TestCheckCachePoisoning_PRT(t *testing.T) {
	wf := loadFixture(t, "cache-poisoning-prt.yaml")
	findings := CheckCachePoisoning(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "FG-010" {
		t.Errorf("expected FG-010, got %s", f.RuleID)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("expected high for cache on PRT with fork exec, got %s", f.Severity)
	}
}

func TestCheckCachePoisoning_PR(t *testing.T) {
	wf := loadFixture(t, "cache-poisoning-pr.yaml")
	findings := CheckCachePoisoning(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityMedium {
		t.Errorf("expected medium for cache on PR, got %s", f.Severity)
	}
}

func TestCheckCachePoisoning_SetupAction(t *testing.T) {
	wf := loadFixture(t, "cache-setup-action.yaml")
	findings := CheckCachePoisoning(wf)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for setup-node with cache, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityLow {
		t.Errorf("expected low for setup-action caching, got %s", f.Severity)
	}
}

// --- Filter tests ---

func TestSeverityFilter(t *testing.T) {
	wf := loadFixture(t, "mixed-workflow.yaml")
	opts := ScanOptions{Severities: []string{"critical"}}
	findings := ScanWorkflow(wf, opts)

	for _, f := range findings {
		if f.Severity != SeverityCritical {
			t.Errorf("expected only critical findings, got %s", f.Severity)
		}
	}
}

// TestCheckPwnRequest_PathAliasExec verifies that fork path detection works
// when the checkout path is referenced via a shell variable alias (e.g.,
// PR="$GITHUB_WORKSPACE/pr" followed by python script.py "$PR").
// This is the tinygrad/szdiff.yml pattern.
func TestCheckPwnRequest_PathAliasExec(t *testing.T) {
	wf := loadFixture(t, "path-alias-exec.yaml")
	findings := CheckPwnRequest(wf)

	if len(findings) == 0 {
		t.Fatal("expected at least 1 FG-001 finding")
	}

	// The szdiff job should NOT have PathIsolated mitigation because
	// $PR (aliasing $GITHUB_WORKSPACE/pr) is used in python sz.py "$PR"
	for _, f := range findings {
		if f.RuleID == "FG-001" {
			for _, m := range f.Mitigations {
				if strings.Contains(m, "no direct execution of fork path") {
					t.Errorf("PathIsolated mitigation should not apply when fork path is aliased via shell variable: %s", m)
				}
			}
		}
	}
}

func TestRuleFilter(t *testing.T) {
	wf := loadFixture(t, "mixed-workflow.yaml")
	opts := ScanOptions{Rules: []string{"FG-002"}}
	findings := ScanWorkflow(wf, opts)

	for _, f := range findings {
		if f.RuleID != "FG-002" {
			t.Errorf("expected only FG-002 findings, got %s", f.RuleID)
		}
	}
}
