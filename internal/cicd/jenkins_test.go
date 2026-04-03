package cicd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadJenkinsFixture(t *testing.T, name string) *JenkinsPipeline {
	t.Helper()
	path := filepath.Join(fixturesDir(), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	pipeline, err := ParseJenkinsfile(data, name)
	if err != nil {
		t.Fatalf("parsing fixture %s: %v", name, err)
	}
	return pipeline
}

func TestParseJenkinsfile_Basic(t *testing.T) {
	pipeline := loadJenkinsFixture(t, "jenkins-safe.groovy")

	if pipeline.Platform() != "jenkins" {
		t.Errorf("expected platform 'jenkins', got %s", pipeline.Platform())
	}

	jobs := pipeline.Jobs()
	if len(jobs) != 2 {
		t.Fatalf("expected 2 jobs (Build, Test), got %d", len(jobs))
	}
	if jobs[0].Name != "Build" {
		t.Errorf("expected first job name 'Build', got %s", jobs[0].Name)
	}
}

func TestJenkinsSafe_NoFindings(t *testing.T) {
	pipeline := loadJenkinsFixture(t, "jenkins-safe.groovy")
	findings := ScanJenkinsPipeline(pipeline)

	for _, f := range findings {
		if f.Severity == severityCritical || f.Severity == severityHigh {
			t.Errorf("expected no critical/high findings for safe pipeline, got %s: %s", f.Severity, f.Message)
		}
	}
}

func TestJenkinsPRSecrets(t *testing.T) {
	pipeline := loadJenkinsFixture(t, "jenkins-pr-secrets.groovy")
	findings := ScanJenkinsPipeline(pipeline)

	var jk001 []JenkinsFinding
	for _, f := range findings {
		if f.RuleID == "JK-001" {
			jk001 = append(jk001, f)
		}
	}

	if len(jk001) != 1 {
		t.Fatalf("expected 1 JK-001 finding, got %d", len(jk001))
	}
	if jk001[0].Severity != severityHigh {
		t.Errorf("expected high severity, got %s", jk001[0].Severity)
	}
	if !strings.Contains(jk001[0].Message, "Validate PR") {
		t.Error("expected message to reference stage name 'Validate PR'")
	}
}

func TestJenkinsScriptInjection(t *testing.T) {
	pipeline := loadJenkinsFixture(t, "jenkins-script-injection.groovy")
	findings := ScanJenkinsPipeline(pipeline)

	var jk002 []JenkinsFinding
	for _, f := range findings {
		if f.RuleID == "JK-002" {
			jk002 = append(jk002, f)
		}
	}

	if len(jk002) == 0 {
		t.Fatal("expected at least 1 JK-002 finding for env.CHANGE_BRANCH in sh block")
	}
	for _, f := range jk002 {
		if f.Severity != severityHigh {
			t.Errorf("expected high severity, got %s", f.Severity)
		}
	}
}

func TestJenkinsUnpinnedLibrary(t *testing.T) {
	pipeline := loadJenkinsFixture(t, "jenkins-unpinned-lib.groovy")
	findings := ScanJenkinsPipeline(pipeline)

	var jk003 []JenkinsFinding
	for _, f := range findings {
		if f.RuleID == "JK-003" {
			jk003 = append(jk003, f)
		}
	}

	if len(jk003) != 1 {
		t.Fatalf("expected 1 JK-003 finding, got %d", len(jk003))
	}
	if jk003[0].Severity != severityMedium {
		t.Errorf("expected medium severity, got %s", jk003[0].Severity)
	}
	if !strings.Contains(jk003[0].Message, "shared-pipeline-lib") {
		t.Error("expected message to reference library name")
	}
}
