package scanner

import (
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

	// Should flag: tj-actions@v44, actions/checkout@v4.1.0, docker/build-push-action@v4.1.0
	// Should NOT flag: actions/checkout@v4.2.0, tj-actions@v45.0.1, SHA-pinned
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d: %v", len(findings), findings)
	}

	hasHigh := false
	hasMedium := false
	for _, f := range findings {
		if f.RuleID != "FG-022" {
			t.Errorf("expected FG-022, got %s", f.RuleID)
		}
		if f.Severity == SeverityHigh {
			hasHigh = true
		}
		if f.Severity == SeverityMedium {
			hasMedium = true
		}
	}
	if !hasHigh {
		t.Error("expected at least one high severity finding (tj-actions)")
	}
	if !hasMedium {
		t.Error("expected at least one medium severity finding")
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

// --- AllRules completeness ---

func TestAllRules_IncludesNewRules(t *testing.T) {
	rules := AllRules()
	expectedIDs := []string{"FG-018", "FG-019", "FG-020", "FG-021", "FG-022", "FG-023"}
	for _, id := range expectedIDs {
		if _, ok := rules[id]; !ok {
			t.Errorf("AllRules() missing %s", id)
		}
		if _, ok := RuleDescriptions[id]; !ok {
			t.Errorf("RuleDescriptions missing %s", id)
		}
	}
}
