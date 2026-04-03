package cicd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadCircleCIFixture(t *testing.T, name string) *CircleCIPipeline {
	t.Helper()
	path := filepath.Join(fixturesDir(), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	pipeline, err := ParseCircleCI(data, name)
	if err != nil {
		t.Fatalf("parsing fixture %s: %v", name, err)
	}
	return pipeline
}

func TestParseCircleCI_Basic(t *testing.T) {
	pipeline := loadCircleCIFixture(t, "circleci-safe.yml")

	if pipeline.Platform() != "circleci" {
		t.Errorf("expected platform 'circleci', got %s", pipeline.Platform())
	}

	jobs := pipeline.Jobs()
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobs))
	}
	if jobs[0].Name != "build" {
		t.Errorf("expected job name 'build', got %s", jobs[0].Name)
	}
}

func TestCircleCISafe_NoHighFindings(t *testing.T) {
	pipeline := loadCircleCIFixture(t, "circleci-safe.yml")
	findings := ScanCircleCIPipeline(pipeline)

	for _, f := range findings {
		if f.Severity == severityCritical || f.Severity == severityHigh {
			t.Errorf("expected no critical/high findings for safe config, got %s: %s", f.Severity, f.Message)
		}
	}
}

func TestCircleCIForkExec(t *testing.T) {
	pipeline := loadCircleCIFixture(t, "circleci-fork-exec.yml")
	findings := ScanCircleCIPipeline(pipeline)

	var cc001 []CircleCIFinding
	for _, f := range findings {
		if f.RuleID == "CC-001" {
			cc001 = append(cc001, f)
		}
	}

	if len(cc001) == 0 {
		t.Fatal("expected at least 1 CC-001 finding for fork PR code execution")
	}
	if cc001[0].Severity != severityHigh {
		t.Errorf("expected high severity, got %s", cc001[0].Severity)
	}
}

func TestCircleCIScriptInjection(t *testing.T) {
	pipeline := loadCircleCIFixture(t, "circleci-script-injection.yml")
	findings := ScanCircleCIPipeline(pipeline)

	var cc002 []CircleCIFinding
	for _, f := range findings {
		if f.RuleID == "CC-002" {
			cc002 = append(cc002, f)
		}
	}

	if len(cc002) == 0 {
		t.Fatal("expected at least 1 CC-002 finding for $CIRCLE_BRANCH in run command")
	}
	for _, f := range cc002 {
		if f.Severity != severityHigh {
			t.Errorf("expected high severity, got %s", f.Severity)
		}
	}
}

func TestCircleCIUnpinnedOrb(t *testing.T) {
	pipeline := loadCircleCIFixture(t, "circleci-unpinned-orb.yml")
	findings := ScanCircleCIPipeline(pipeline)

	var cc003 []CircleCIFinding
	for _, f := range findings {
		if f.RuleID == "CC-003" {
			cc003 = append(cc003, f)
		}
	}

	if len(cc003) == 0 {
		t.Fatal("expected at least 1 CC-003 finding for tag-pinned orb")
	}

	// Both orbs use tags, not SHA digests
	hasNode := false
	hasSlack := false
	for _, f := range cc003 {
		if strings.Contains(f.Message, "node") {
			hasNode = true
		}
		if strings.Contains(f.Message, "slack") {
			hasSlack = true
		}
	}
	if !hasNode {
		t.Error("expected finding for unpinned node orb")
	}
	if !hasSlack {
		t.Error("expected finding for unpinned slack orb")
	}
}
