package scanner

import (
	"testing"
)

func TestParseRunsOn_Scalar(t *testing.T) {
	yaml := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	wf, err := ParseWorkflow([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	job := wf.Jobs["build"]
	if len(job.RunsOn) != 1 || job.RunsOn[0] != "ubuntu-latest" {
		t.Errorf("expected [ubuntu-latest], got %v", job.RunsOn)
	}
}

func TestParseRunsOn_Sequence(t *testing.T) {
	yaml := `
name: CI
on: push
jobs:
  build:
    runs-on: [self-hosted, linux, gpu]
    steps:
      - uses: actions/checkout@v4
`
	wf, err := ParseWorkflow([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	job := wf.Jobs["build"]
	if len(job.RunsOn) != 3 {
		t.Fatalf("expected 3 labels, got %d: %v", len(job.RunsOn), job.RunsOn)
	}
	if job.RunsOn[0] != "self-hosted" {
		t.Errorf("expected first label 'self-hosted', got %s", job.RunsOn[0])
	}
}

func TestParseRunsOn_Group(t *testing.T) {
	yaml := `
name: CI
on: push
jobs:
  build:
    runs-on:
      group: large-runners
      labels: [linux, x64]
    steps:
      - uses: actions/checkout@v4
`
	wf, err := ParseWorkflow([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	job := wf.Jobs["build"]
	if len(job.RunsOn) != 2 {
		t.Fatalf("expected 2 labels from group, got %d: %v", len(job.RunsOn), job.RunsOn)
	}
}

func TestParseNeeds_String(t *testing.T) {
	yaml := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
  test:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - run: echo test
`
	wf, err := ParseWorkflow([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	job := wf.Jobs["test"]
	if len(job.Needs) != 1 || job.Needs[0] != "build" {
		t.Errorf("expected [build], got %v", job.Needs)
	}
}

func TestParseNeeds_Sequence(t *testing.T) {
	yaml := `
name: CI
on: push
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo lint
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
  test:
    needs: [lint, build]
    runs-on: ubuntu-latest
    steps:
      - run: echo test
`
	wf, err := ParseWorkflow([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	job := wf.Jobs["test"]
	if len(job.Needs) != 2 {
		t.Fatalf("expected 2 needs, got %d: %v", len(job.Needs), job.Needs)
	}
}
