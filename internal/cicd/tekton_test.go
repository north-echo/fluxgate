package cicd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadTektonFixture(t *testing.T, name string) *TektonPipeline {
	t.Helper()
	path := filepath.Join(fixturesDir(), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	pipeline, err := ParseTektonPipeline(data, name)
	if err != nil {
		t.Fatalf("parsing fixture %s: %v", name, err)
	}
	return pipeline
}

func TestParseTektonTask_Basic(t *testing.T) {
	pipeline := loadTektonFixture(t, "tekton-safe.yaml")

	if pipeline.Platform() != "tekton" {
		t.Errorf("expected platform 'tekton', got %s", pipeline.Platform())
	}

	jobs := pipeline.Jobs()
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobs))
	}
	if jobs[0].Name != "safe-build" {
		t.Errorf("expected job name 'safe-build', got %s", jobs[0].Name)
	}
}

func TestTektonSafe_NoFindings(t *testing.T) {
	pipeline := loadTektonFixture(t, "tekton-safe.yaml")
	findings := ScanTektonPipeline(pipeline)

	for _, f := range findings {
		if f.Severity == severityCritical || f.Severity == severityHigh {
			t.Errorf("expected no critical/high findings for safe task, got %s: %s", f.Severity, f.Message)
		}
	}
}

func TestTektonParamInjection(t *testing.T) {
	pipeline := loadTektonFixture(t, "tekton-param-injection.yaml")
	findings := ScanTektonPipeline(pipeline)

	var tk001 []TektonFinding
	for _, f := range findings {
		if f.RuleID == "TK-001" {
			tk001 = append(tk001, f)
		}
	}

	if len(tk001) == 0 {
		t.Fatal("expected at least 1 TK-001 finding for $(params.*) in script")
	}
	for _, f := range tk001 {
		if f.Severity != severityHigh {
			t.Errorf("expected high severity, got %s", f.Severity)
		}
	}
}

func TestTektonUnpinnedTask(t *testing.T) {
	pipeline := loadTektonFixture(t, "tekton-unpinned-task.yaml")
	findings := ScanTektonPipeline(pipeline)

	var tk002 []TektonFinding
	for _, f := range findings {
		if f.RuleID == "TK-002" {
			tk002 = append(tk002, f)
		}
	}

	if len(tk002) != 1 {
		t.Fatalf("expected 1 TK-002 finding (unpinned lint task), got %d", len(tk002))
	}
	if !strings.Contains(tk002[0].Message, "golangci-lint") {
		t.Error("expected message to reference unpinned task name")
	}
	// The sha256-pinned task should NOT trigger a finding
	for _, f := range tk002 {
		if strings.Contains(f.Message, "golang-build") {
			t.Error("sha256-pinned task should not trigger TK-002")
		}
	}
}

func TestTektonPrivileged(t *testing.T) {
	pipeline := loadTektonFixture(t, "tekton-privileged.yaml")
	findings := ScanTektonPipeline(pipeline)

	var tk009 []TektonFinding
	for _, f := range findings {
		if f.RuleID == "TK-009" {
			tk009 = append(tk009, f)
		}
	}

	if len(tk009) != 2 {
		t.Fatalf("expected 2 TK-009 findings (privileged + runAsUser:0), got %d", len(tk009))
	}

	hasPrivileged := false
	hasRoot := false
	for _, f := range tk009 {
		if strings.Contains(f.Message, "privileged: true") {
			hasPrivileged = true
		}
		if strings.Contains(f.Message, "runAsUser: 0") {
			hasRoot = true
		}
	}
	if !hasPrivileged {
		t.Error("expected finding for privileged: true")
	}
	if !hasRoot {
		t.Error("expected finding for runAsUser: 0")
	}
}
