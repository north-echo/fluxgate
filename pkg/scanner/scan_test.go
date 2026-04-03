package scanner

import (
	"testing"
)

func TestScanWorkflowBytes_RoundTrip(t *testing.T) {
	yaml := `
name: Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "hello"
`
	findings, err := ScanWorkflowBytes([]byte(yaml), "test.yaml", ScanOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should find at least FG-003 (tag pinning on actions/checkout@v4)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for unpinned action")
	}
	found := false
	for _, f := range findings {
		if f.RuleID == "FG-003" {
			found = true
		}
	}
	if !found {
		t.Error("expected FG-003 finding for actions/checkout@v4")
	}
}

func TestScanWorkflowBytes_InvalidYAML(t *testing.T) {
	_, err := ScanWorkflowBytes([]byte("{{invalid yaml"), "bad.yaml", ScanOptions{})
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestScanWorkflowBytes_SelectiveRules(t *testing.T) {
	yaml := `
name: Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.event.pull_request.title }}"
`
	// Only run FG-002
	findings, err := ScanWorkflowBytes([]byte(yaml), "test.yaml", ScanOptions{
		Rules: []string{"FG-002"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.RuleID != "FG-002" {
			t.Errorf("expected only FG-002, got %s", f.RuleID)
		}
	}
}

func TestAllRules_Completeness(t *testing.T) {
	rules := AllRules()
	if len(rules) < 23 {
		t.Errorf("expected at least 23 rules (FG-001 through FG-023), got %d", len(rules))
	}
	// Every rule should have a description
	for id := range rules {
		if _, ok := RuleDescriptions[id]; !ok {
			t.Errorf("rule %s missing from RuleDescriptions", id)
		}
	}
}

// TestLibraryConsumerPattern simulates the integration pattern from fullsend-ai/fullsend#159
func TestLibraryConsumerPattern(t *testing.T) {
	workflowYAML := `
name: Deploy Agent
on:
  workflow_dispatch:
    inputs:
      event_payload:
        required: true
        type: string
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./deploy.sh "${{ inputs.event_payload }}"
`
	findings, err := ScanWorkflowBytes(
		[]byte(workflowYAML),
		"agent.yaml",
		ScanOptions{},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundFG002 bool
	for _, f := range findings {
		if f.RuleID == "FG-002" {
			foundFG002 = true
		}
	}
	if !foundFG002 {
		t.Error("expected FG-002 for dispatch input injection")
	}
}
