package scanner

import (
	"os"
	"path/filepath"
	"runtime"
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

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for safe workflow, got %d:", len(findings))
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
