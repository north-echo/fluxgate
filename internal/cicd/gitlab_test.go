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

func TestGitLabBroadPermissions(t *testing.T) {
	pipeline := loadGitLabFixture(t, "gitlab-broad-permissions.yml")
	findings := ScanGitLabPipeline(pipeline)

	var gl004 []GitLabFinding
	for _, f := range findings {
		if f.RuleID == "GL-004" {
			gl004 = append(gl004, f)
		}
	}

	if len(gl004) == 0 {
		t.Fatal("expected GL-004 finding for CI_JOB_TOKEN without scoped permissions")
	}
	if gl004[0].Severity != severityMedium {
		t.Errorf("expected medium severity, got %s", gl004[0].Severity)
	}
	if !strings.Contains(gl004[0].Message, "deploy") {
		t.Error("expected message to reference job name 'deploy'")
	}
}

func TestGitLabSecretsInLogs(t *testing.T) {
	pipeline := loadGitLabFixture(t, "gitlab-secrets-in-logs.yml")
	findings := ScanGitLabPipeline(pipeline)

	var gl005 []GitLabFinding
	for _, f := range findings {
		if f.RuleID == "GL-005" {
			gl005 = append(gl005, f)
		}
	}

	if len(gl005) == 0 {
		t.Fatal("expected GL-005 finding for echo of $SECRET_TOKEN")
	}
	if gl005[0].Severity != severityLow {
		t.Errorf("expected low severity, got %s", gl005[0].Severity)
	}
}

func TestGitLabSecretsInLogs_SafeEcho(t *testing.T) {
	yamlContent := `
stages:
  - test

test:
  stage: test
  script:
    - echo "Running tests"
    - echo "$CI_PROJECT_NAME"
`
	pipeline, err := ParseGitLabCI([]byte(yamlContent), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	findings := ScanGitLabPipeline(pipeline)

	for _, f := range findings {
		if f.RuleID == "GL-005" {
			t.Errorf("unexpected GL-005 finding for safe echo: %s", f.Message)
		}
	}
}

func TestGitLabForkMRExec(t *testing.T) {
	pipeline := loadGitLabFixture(t, "gitlab-fork-mr-exec.yml")
	findings := ScanGitLabPipeline(pipeline)

	var gl006 []GitLabFinding
	for _, f := range findings {
		if f.RuleID == "GL-006" {
			gl006 = append(gl006, f)
		}
	}

	if len(gl006) == 0 {
		t.Fatal("expected GL-006 finding for fork MR execution")
	}
	if gl006[0].Severity != severityHigh {
		t.Errorf("expected high severity (checkout + build commands), got %s", gl006[0].Severity)
	}
	if !strings.Contains(gl006[0].Message, "build commands") {
		t.Error("expected message to mention build commands")
	}
}

func TestGitLabOIDCMisconfig(t *testing.T) {
	pipeline := loadGitLabFixture(t, "gitlab-oidc-misconfig.yml")
	findings := ScanGitLabPipeline(pipeline)

	var gl008 []GitLabFinding
	for _, f := range findings {
		if f.RuleID == "GL-008" {
			gl008 = append(gl008, f)
		}
	}

	if len(gl008) == 0 {
		t.Fatal("expected GL-008 finding for id_tokens on MR pipeline")
	}
	if gl008[0].Severity != severityHigh {
		t.Errorf("expected high severity, got %s", gl008[0].Severity)
	}
	if !strings.Contains(gl008[0].Message, "AWS_TOKEN") {
		t.Error("expected message to reference token name 'AWS_TOKEN'")
	}
}

func TestGitLabCachePoisoning(t *testing.T) {
	pipeline := loadGitLabFixture(t, "gitlab-cache-poisoning.yml")
	findings := ScanGitLabPipeline(pipeline)

	var gl010 []GitLabFinding
	for _, f := range findings {
		if f.RuleID == "GL-010" {
			gl010 = append(gl010, f)
		}
	}

	if len(gl010) == 0 {
		t.Fatal("expected GL-010 finding for shared cache key on MR pipeline")
	}
	if gl010[0].Severity != severityMedium {
		t.Errorf("expected medium severity, got %s", gl010[0].Severity)
	}
	if !strings.Contains(gl010[0].Message, "CI_COMMIT_REF_SLUG") {
		t.Error("expected message to reference cache key pattern")
	}
}

// TestGitLabScriptInjection_MappingNode verifies GL-002 detects script injection
// even when YAML parses unquoted script lines as mapping nodes (due to ": " in
// the command, e.g. `echo "MR: $CI_MERGE_REQUEST_TITLE"`).
func TestGitLabScriptInjection_MappingNode(t *testing.T) {
	yamlContent := `
stages:
  - test

check:
  stage: test
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
  script:
    - echo "Testing MR: $CI_MERGE_REQUEST_TITLE"
    - pytest
`
	pipeline, err := ParseGitLabCI([]byte(yamlContent), "test.yml")
	if err != nil {
		t.Fatal(err)
	}

	findings := ScanGitLabPipeline(pipeline)
	var gl002 []GitLabFinding
	for _, f := range findings {
		if f.RuleID == "GL-002" {
			gl002 = append(gl002, f)
		}
	}
	if len(gl002) == 0 {
		t.Fatal("expected GL-002 finding for $CI_MERGE_REQUEST_TITLE in script with mapping node")
	}
	if gl002[0].Severity != severityHigh {
		t.Errorf("expected high severity, got %s", gl002[0].Severity)
	}
}
