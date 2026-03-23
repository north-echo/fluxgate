package cicd

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

func loadGitLabFixture(t *testing.T, name string) *GitLabPipeline {
	t.Helper()
	path := filepath.Join(fixturesDir(), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	pipeline, err := ParseGitLabCI(data, name)
	if err != nil {
		t.Fatalf("parsing fixture %s: %v", name, err)
	}
	return pipeline
}

func TestParseGitLabCI_Basic(t *testing.T) {
	pipeline := loadGitLabFixture(t, "gitlab-safe.yml")

	if pipeline.Platform() != "gitlab" {
		t.Errorf("expected platform 'gitlab', got %s", pipeline.Platform())
	}

	jobs := pipeline.Jobs()
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobs))
	}
	if jobs[0].Name != "test" {
		t.Errorf("expected job name 'test', got %s", jobs[0].Name)
	}
}

func TestGitLabMRSecrets(t *testing.T) {
	pipeline := loadGitLabFixture(t, "gitlab-mr-secrets.yml")
	findings := ScanGitLabPipeline(pipeline)

	var mrFindings []GitLabFinding
	for _, f := range findings {
		if f.RuleID == "GL-001" {
			mrFindings = append(mrFindings, f)
		}
	}

	if len(mrFindings) != 1 {
		t.Fatalf("expected 1 GL-001 finding, got %d", len(mrFindings))
	}
	f := mrFindings[0]
	if f.Severity != severityMedium {
		t.Errorf("expected medium severity (MR pipeline with pip install), got %s", f.Severity)
	}
	if !strings.Contains(f.Message, "test") {
		t.Error("expected message to reference job name 'test'")
	}
}

func TestGitLabScriptInjection(t *testing.T) {
	pipeline := loadGitLabFixture(t, "gitlab-script-injection.yml")
	findings := ScanGitLabPipeline(pipeline)

	var injectionFindings []GitLabFinding
	for _, f := range findings {
		if f.RuleID == "GL-002" {
			injectionFindings = append(injectionFindings, f)
		}
	}

	if len(injectionFindings) == 0 {
		t.Fatal("expected at least 1 GL-002 finding for $CI_MERGE_REQUEST_TITLE in script")
	}
	for _, f := range injectionFindings {
		if f.Severity != severityHigh {
			t.Errorf("expected high severity, got %s", f.Severity)
		}
	}
}

func TestGitLabUnsafeIncludes(t *testing.T) {
	pipeline := loadGitLabFixture(t, "gitlab-unsafe-include.yml")
	findings := ScanGitLabPipeline(pipeline)

	var includeFindings []GitLabFinding
	for _, f := range findings {
		if f.RuleID == "GL-003" {
			includeFindings = append(includeFindings, f)
		}
	}

	if len(includeFindings) < 2 {
		t.Fatalf("expected at least 2 GL-003 findings (remote + unpinned project), got %d", len(includeFindings))
	}

	hasRemote := false
	hasUnpinned := false
	for _, f := range includeFindings {
		if strings.Contains(f.Message, "remote include") {
			hasRemote = true
		}
		if strings.Contains(f.Message, "Unpinned Include") {
			hasUnpinned = true
		}
	}
	if !hasRemote {
		t.Error("expected a finding for remote include")
	}
	if !hasUnpinned {
		t.Error("expected a finding for unpinned project include")
	}
}

func TestGitLabSafe_NoFindings(t *testing.T) {
	pipeline := loadGitLabFixture(t, "gitlab-safe.yml")
	findings := ScanGitLabPipeline(pipeline)

	// Safe pipeline should have no critical/high findings
	for _, f := range findings {
		if f.Severity == severityCritical || f.Severity == severityHigh {
			t.Errorf("expected no critical/high findings for safe pipeline, got %s: %s", f.Severity, f.Message)
		}
	}
}

func TestGitLabIncludes_Parsed(t *testing.T) {
	pipeline := loadGitLabFixture(t, "gitlab-unsafe-include.yml")

	includes := pipeline.Includes()
	if len(includes) != 2 {
		t.Fatalf("expected 2 includes, got %d", len(includes))
	}
	if includes[0].Remote != "https://example.com/ci-templates/lint.yml" {
		t.Errorf("expected remote include URL, got %s", includes[0].Remote)
	}
	if includes[1].Project != "my-group/ci-templates" {
		t.Errorf("expected project include, got %s", includes[1].Project)
	}
}
