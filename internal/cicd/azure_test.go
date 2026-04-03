package cicd

import (
	"testing"
)

func TestParseAzurePipeline_Basic(t *testing.T) {
	yaml := `
trigger:
  - main
pr:
  - main
pool:
  vmImage: 'ubuntu-latest'
steps:
  - script: echo hello
    displayName: Say hello
  - task: NodeTool@0
    inputs:
      versionSpec: '18.x'
`
	p, err := ParseAzurePipeline([]byte(yaml), "azure-pipelines.yml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Platform() != "azure" {
		t.Errorf("expected platform 'azure', got %s", p.Platform())
	}
	if len(p.Jobs()) != 1 {
		t.Fatalf("expected 1 job (root), got %d", len(p.Jobs()))
	}
	job := p.Jobs()[0]
	if len(job.Steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(job.Steps))
	}
	if job.Steps[0].Type != StepScript {
		t.Errorf("expected step 0 type 'script', got %s", job.Steps[0].Type)
	}
	if job.Steps[1].Type != StepAction {
		t.Errorf("expected step 1 type 'action', got %s", job.Steps[1].Type)
	}
}

func TestParseAzurePipeline_Stages(t *testing.T) {
	yaml := `
trigger:
  - main
stages:
  - stage: Build
    jobs:
      - job: BuildJob
        pool:
          vmImage: 'ubuntu-latest'
        steps:
          - script: make build
  - stage: Deploy
    dependsOn: Build
    jobs:
      - job: DeployJob
        pool:
          name: production-pool
        environment: production
        steps:
          - script: make deploy
`
	p, err := ParseAzurePipeline([]byte(yaml), "azure-pipelines.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Jobs()) != 2 {
		t.Fatalf("expected 2 jobs, got %d", len(p.Jobs()))
	}
	if p.Jobs()[0].Name != "BuildJob" {
		t.Errorf("expected first job 'BuildJob', got %s", p.Jobs()[0].Name)
	}
	if p.Jobs()[1].Environment != "production" {
		t.Errorf("expected second job environment 'production', got %s", p.Jobs()[1].Environment)
	}
}

func TestAzurePRSecrets(t *testing.T) {
	yaml := `
trigger:
  - main
pr:
  - main
pool:
  vmImage: 'ubuntu-latest'
variables:
  - group: production-secrets
steps:
  - script: npm ci
    displayName: Install
`
	p, err := ParseAzurePipeline([]byte(yaml), "azure-pipelines.yml")
	if err != nil {
		t.Fatal(err)
	}
	findings := ScanAzurePipeline(p)

	var az001 []AzureFinding
	for _, f := range findings {
		if f.RuleID == "AZ-001" {
			az001 = append(az001, f)
		}
	}
	if len(az001) == 0 {
		t.Fatal("expected AZ-001 finding for PR build with secrets")
	}
	if az001[0].Severity != severityHigh {
		t.Errorf("expected severity high, got %s", az001[0].Severity)
	}
}

func TestAzureScriptInjection(t *testing.T) {
	yaml := `
trigger:
  - main
pr:
  - main
pool:
  vmImage: 'ubuntu-latest'
jobs:
  - job: Build
    steps:
      - script: echo "Branch $(Build.SourceBranchName)"
        displayName: Echo branch
`
	p, err := ParseAzurePipeline([]byte(yaml), "azure-pipelines.yml")
	if err != nil {
		t.Fatal(err)
	}
	findings := ScanAzurePipeline(p)

	var az002 []AzureFinding
	for _, f := range findings {
		if f.RuleID == "AZ-002" {
			az002 = append(az002, f)
		}
	}
	if len(az002) == 0 {
		t.Fatal("expected AZ-002 finding for script injection")
	}
	if az002[0].Severity != severityHigh {
		t.Errorf("expected severity high, got %s", az002[0].Severity)
	}
}

func TestAzureSelfHostedAgent(t *testing.T) {
	yaml := `
trigger:
  - main
pr:
  - main
jobs:
  - job: Build
    pool:
      name: my-private-pool
    steps:
      - script: make build
`
	p, err := ParseAzurePipeline([]byte(yaml), "azure-pipelines.yml")
	if err != nil {
		t.Fatal(err)
	}
	findings := ScanAzurePipeline(p)

	var az009 []AzureFinding
	for _, f := range findings {
		if f.RuleID == "AZ-009" {
			az009 = append(az009, f)
		}
	}
	if len(az009) == 0 {
		t.Fatal("expected AZ-009 finding for self-hosted agent on PR")
	}
	if az009[0].Severity != severityHigh {
		t.Errorf("expected severity high, got %s", az009[0].Severity)
	}
}

func TestAzureUnpinnedResource(t *testing.T) {
	yaml := `
trigger:
  - main
resources:
  repositories:
    - repository: templates
      type: github
      endpoint: my-connection
extends:
  template: build.yml
pool:
  vmImage: 'ubuntu-latest'
steps:
  - script: echo hello
`
	p, err := ParseAzurePipeline([]byte(yaml), "azure-pipelines.yml")
	if err != nil {
		t.Fatal(err)
	}
	findings := ScanAzurePipeline(p)

	var az003 []AzureFinding
	for _, f := range findings {
		if f.RuleID == "AZ-003" {
			az003 = append(az003, f)
		}
	}
	if len(az003) < 2 {
		t.Fatalf("expected at least 2 AZ-003 findings (extends + resource), got %d", len(az003))
	}
}

func TestAzurePushOnly_NoFindings(t *testing.T) {
	yaml := `
trigger:
  - main
pr: none
pool:
  vmImage: 'ubuntu-latest'
steps:
  - script: npm ci
  - script: npm test
`
	p, err := ParseAzurePipeline([]byte(yaml), "azure-pipelines.yml")
	if err != nil {
		t.Fatal(err)
	}
	findings := ScanAzurePipeline(p)

	// AZ-001 and AZ-009 should not fire (no PR trigger)
	for _, f := range findings {
		if f.RuleID == "AZ-001" || f.RuleID == "AZ-009" {
			t.Errorf("unexpected finding %s on push-only pipeline", f.RuleID)
		}
	}
}

func TestAzureBroadPermissions(t *testing.T) {
	yaml := `
trigger:
  - main
pr:
  - main
pool:
  vmImage: 'ubuntu-latest'
steps:
  - task: AzureCLI@2
    displayName: Deploy
    inputs:
      azureSubscription: my-subscription
      scriptType: bash
      scriptLocation: inlineScript
      inlineScript: az webapp deploy
`
	p, err := ParseAzurePipeline([]byte(yaml), "azure-pipelines.yml")
	if err != nil {
		t.Fatal(err)
	}
	findings := ScanAzurePipeline(p)

	var az004 []AzureFinding
	for _, f := range findings {
		if f.RuleID == "AZ-004" {
			az004 = append(az004, f)
		}
	}
	if len(az004) == 0 {
		t.Fatal("expected AZ-004 finding for broad azureSubscription")
	}
	if az004[0].Severity != severityMedium {
		t.Errorf("expected medium severity, got %s", az004[0].Severity)
	}
}

func TestAzureSecretsInLogs(t *testing.T) {
	yaml := `
trigger:
  - main
pool:
  vmImage: 'ubuntu-latest'
steps:
  - script: echo "Token is $(secret_token)"
    displayName: Debug
`
	p, err := ParseAzurePipeline([]byte(yaml), "azure-pipelines.yml")
	if err != nil {
		t.Fatal(err)
	}
	findings := ScanAzurePipeline(p)

	var az005 []AzureFinding
	for _, f := range findings {
		if f.RuleID == "AZ-005" {
			az005 = append(az005, f)
		}
	}
	if len(az005) == 0 {
		t.Fatal("expected AZ-005 finding for echo of $(secret_token)")
	}
	if az005[0].Severity != severityLow {
		t.Errorf("expected low severity, got %s", az005[0].Severity)
	}
}

func TestAzureSecretsInLogs_Safe(t *testing.T) {
	yaml := `
trigger:
  - main
pool:
  vmImage: 'ubuntu-latest'
steps:
  - script: echo "Build number $(Build.BuildNumber)"
    displayName: Show build
`
	p, err := ParseAzurePipeline([]byte(yaml), "azure-pipelines.yml")
	if err != nil {
		t.Fatal(err)
	}
	findings := ScanAzurePipeline(p)

	for _, f := range findings {
		if f.RuleID == "AZ-005" {
			t.Errorf("unexpected AZ-005 finding for safe echo: %s", f.Message)
		}
	}
}

func TestAzureForkSecrets(t *testing.T) {
	yaml := `
trigger:
  - main
pr:
  - main
pool:
  vmImage: 'ubuntu-latest'
variables:
  - group: production-secrets
jobs:
  - job: Build
    variables:
      - group: build-secrets
    steps:
      - script: make build
`
	p, err := ParseAzurePipeline([]byte(yaml), "azure-pipelines.yml")
	if err != nil {
		t.Fatal(err)
	}
	findings := ScanAzurePipeline(p)

	var az006 []AzureFinding
	for _, f := range findings {
		if f.RuleID == "AZ-006" {
			az006 = append(az006, f)
		}
	}
	if len(az006) == 0 {
		t.Fatal("expected AZ-006 finding for fork secrets")
	}
	if az006[0].Severity != severityHigh {
		t.Errorf("expected high severity, got %s", az006[0].Severity)
	}
}

func TestAzureOIDCMisconfig(t *testing.T) {
	yaml := `
trigger:
  - main
pr:
  - main
pool:
  vmImage: 'ubuntu-latest'
steps:
  - task: AzureCLI@2
    displayName: Deploy with OIDC
    inputs:
      azureSubscription: my-oidc-connection
      scriptType: bash
      scriptLocation: inlineScript
      inlineScript: az account show
`
	p, err := ParseAzurePipeline([]byte(yaml), "azure-pipelines.yml")
	if err != nil {
		t.Fatal(err)
	}
	findings := ScanAzurePipeline(p)

	var az008 []AzureFinding
	for _, f := range findings {
		if f.RuleID == "AZ-008" {
			az008 = append(az008, f)
		}
	}
	if len(az008) == 0 {
		t.Fatal("expected AZ-008 finding for OIDC on PR pipeline")
	}
	if az008[0].Severity != severityHigh {
		t.Errorf("expected high severity, got %s", az008[0].Severity)
	}
}

func TestAzureCachePoisoning(t *testing.T) {
	yaml := `
trigger:
  - main
pr:
  - main
pool:
  vmImage: 'ubuntu-latest'
steps:
  - task: Cache@2
    displayName: Cache npm
    inputs:
      key: npm | $(Agent.OS) | package-lock.json
      path: $(npm_config_cache)
  - script: npm ci
`
	p, err := ParseAzurePipeline([]byte(yaml), "azure-pipelines.yml")
	if err != nil {
		t.Fatal(err)
	}
	findings := ScanAzurePipeline(p)

	var az010 []AzureFinding
	for _, f := range findings {
		if f.RuleID == "AZ-010" {
			az010 = append(az010, f)
		}
	}
	if len(az010) == 0 {
		t.Fatal("expected AZ-010 finding for Cache@2 on PR pipeline")
	}
	if az010[0].Severity != severityMedium {
		t.Errorf("expected medium severity, got %s", az010[0].Severity)
	}
}

func TestAzureSelfHosted_DeploymentProtection(t *testing.T) {
	yaml := `
trigger:
  - main
pr:
  - main
stages:
  - stage: Deploy
    jobs:
      - deployment: DeployProd
        pool:
          name: production-agents
        environment: production
        steps:
          - script: deploy.sh
`
	p, err := ParseAzurePipeline([]byte(yaml), "azure-pipelines.yml")
	if err != nil {
		t.Fatal(err)
	}
	findings := ScanAzurePipeline(p)

	var az009 []AzureFinding
	for _, f := range findings {
		if f.RuleID == "AZ-009" {
			az009 = append(az009, f)
		}
	}
	if len(az009) == 0 {
		t.Fatal("expected AZ-009 finding even with environment protection")
	}
	// Should be medium (mitigated by environment)
	if az009[0].Severity != severityMedium {
		t.Errorf("expected medium severity (environment protected), got %s", az009[0].Severity)
	}
}
