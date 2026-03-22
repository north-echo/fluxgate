package scanner

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Workflow represents a parsed GitHub Actions workflow file.
type Workflow struct {
	Name        string
	Path        string
	On          TriggerConfig
	Permissions PermissionsConfig
	Jobs        map[string]Job
}

// TriggerConfig captures which events trigger the workflow.
type TriggerConfig struct {
	PullRequestTarget      bool
	PullRequestTargetTypes []string // e.g., ["labeled"], ["opened", "synchronize"]
	PullRequest            bool
	IssueComment           bool
	WorkflowRun            bool
	Push                   bool
	Issues                 bool
}

// PermissionsConfig represents workflow or job-level permissions.
type PermissionsConfig struct {
	WriteAll bool
	ReadAll  bool
	Set      bool // whether a permissions block was explicitly set
	Scopes   map[string]string
}

// Job represents a single job in a workflow.
type Job struct {
	Name        string
	If          string // raw if: conditional string
	Environment string // environment protection name, if set
	Permissions PermissionsConfig
	Steps       []Step
	Secrets     string // "inherit" or empty
}

// Step represents a single step in a job.
type Step struct {
	Name string
	If   string // raw if: conditional
	Uses string
	With map[string]string
	Run  string
	Env  map[string]string
	Line int
}

// rawWorkflow is the intermediate representation for YAML unmarshalling.
type rawWorkflow struct {
	Name        string                       `yaml:"name"`
	On          yaml.Node                    `yaml:"on"`
	Permissions yaml.Node                    `yaml:"permissions"`
	Jobs        map[string]rawJob            `yaml:"jobs"`
}

type rawJob struct {
	Name        string            `yaml:"name"`
	If          string            `yaml:"if"`
	Environment yaml.Node         `yaml:"environment"`
	Permissions yaml.Node         `yaml:"permissions"`
	Steps       []rawStep         `yaml:"steps"`
	Secrets     string            `yaml:"secrets"`
}

type rawStep struct {
	Name string            `yaml:"name"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	With map[string]string `yaml:"with"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
}

// ParseWorkflowFile reads and parses a workflow YAML file.
func ParseWorkflowFile(path string) (*Workflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return ParseWorkflow(data, path)
}

// ParseWorkflow parses workflow YAML content.
func ParseWorkflow(data []byte, path string) (*Workflow, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("parsing %s: empty document", path)
	}

	var raw rawWorkflow
	if err := doc.Content[0].Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}

	wf := &Workflow{
		Name:        raw.Name,
		Path:        path,
		On:          parseTriggers(&raw.On),
		Permissions: parsePermissions(&raw.Permissions),
		Jobs:        make(map[string]Job),
	}

	// Build line number map from the raw YAML node tree
	stepLines := extractStepLines(&doc)

	for jobName, rawJ := range raw.Jobs {
		job := Job{
			Name:        rawJ.Name,
			If:          rawJ.If,
			Environment: parseEnvironment(&rawJ.Environment),
			Permissions: parsePermissions(&rawJ.Permissions),
			Secrets:     rawJ.Secrets,
		}
		for i, rawS := range rawJ.Steps {
			step := Step{
				Name: rawS.Name,
				If:   rawS.If,
				Uses: rawS.Uses,
				With: rawS.With,
				Run:  rawS.Run,
				Env:  rawS.Env,
			}
			// Try to get line number from our extracted map
			key := fmt.Sprintf("%s.%d", jobName, i)
			if line, ok := stepLines[key]; ok {
				step.Line = line
			}
			job.Steps = append(job.Steps, step)
		}
		wf.Jobs[jobName] = job
	}

	return wf, nil
}

// extractStepLines walks the YAML node tree to find line numbers for each step.
func extractStepLines(doc *yaml.Node) map[string]int {
	lines := make(map[string]int)
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return lines
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return lines
	}

	for i := 0; i < len(root.Content)-1; i += 2 {
		if root.Content[i].Value == "jobs" {
			jobsNode := root.Content[i+1]
			if jobsNode.Kind != yaml.MappingNode {
				break
			}
			for j := 0; j < len(jobsNode.Content)-1; j += 2 {
				jobName := jobsNode.Content[j].Value
				jobNode := jobsNode.Content[j+1]
				if jobNode.Kind != yaml.MappingNode {
					continue
				}
				for k := 0; k < len(jobNode.Content)-1; k += 2 {
					if jobNode.Content[k].Value == "steps" {
						stepsNode := jobNode.Content[k+1]
						if stepsNode.Kind != yaml.SequenceNode {
							continue
						}
						for idx, stepNode := range stepsNode.Content {
							key := fmt.Sprintf("%s.%d", jobName, idx)
							lines[key] = stepNode.Line
						}
					}
				}
			}
		}
	}
	return lines
}

// parseTriggers parses the "on" field into a TriggerConfig.
func parseTriggers(node *yaml.Node) TriggerConfig {
	tc := TriggerConfig{}
	if node == nil || node.Kind == 0 {
		return tc
	}

	switch node.Kind {
	case yaml.ScalarNode:
		applyTrigger(&tc, node.Value)
	case yaml.SequenceNode:
		for _, item := range node.Content {
			applyTrigger(&tc, item.Value)
		}
	case yaml.MappingNode:
		for i := 0; i < len(node.Content)-1; i += 2 {
			key := node.Content[i].Value
			applyTrigger(&tc, key)
			// Extract types for pull_request_target
			if key == "pull_request_target" {
				valNode := node.Content[i+1]
				if valNode.Kind == yaml.MappingNode {
					for j := 0; j < len(valNode.Content)-1; j += 2 {
						if valNode.Content[j].Value == "types" {
							typesNode := valNode.Content[j+1]
							if typesNode.Kind == yaml.SequenceNode {
								for _, t := range typesNode.Content {
									tc.PullRequestTargetTypes = append(
										tc.PullRequestTargetTypes, t.Value)
								}
							}
						}
					}
				}
			}
		}
	}
	return tc
}

func applyTrigger(tc *TriggerConfig, trigger string) {
	switch trigger {
	case "pull_request_target":
		tc.PullRequestTarget = true
	case "pull_request":
		tc.PullRequest = true
	case "issue_comment":
		tc.IssueComment = true
	case "workflow_run":
		tc.WorkflowRun = true
	case "push":
		tc.Push = true
	case "issues":
		tc.Issues = true
	}
}

// parsePermissions parses the permissions field.
func parsePermissions(node *yaml.Node) PermissionsConfig {
	pc := PermissionsConfig{
		Scopes: make(map[string]string),
	}
	if node == nil || node.Kind == 0 {
		return pc
	}

	switch node.Kind {
	case yaml.ScalarNode:
		pc.Set = true
		switch node.Value {
		case "write-all":
			pc.WriteAll = true
		case "read-all":
			pc.ReadAll = true
		}
	case yaml.MappingNode:
		pc.Set = true
		for i := 0; i < len(node.Content)-1; i += 2 {
			key := node.Content[i].Value
			val := node.Content[i+1].Value
			pc.Scopes[key] = val
		}
	}
	return pc
}

// parseEnvironment extracts the environment name from a job's environment field.
// Handles both string form ("production") and mapping form ({name: "production", url: "..."}).
func parseEnvironment(node *yaml.Node) string {
	if node == nil || node.Kind == 0 {
		return ""
	}
	switch node.Kind {
	case yaml.ScalarNode:
		return node.Value
	case yaml.MappingNode:
		for i := 0; i < len(node.Content)-1; i += 2 {
			if node.Content[i].Value == "name" {
				return node.Content[i+1].Value
			}
		}
	}
	return ""
}

// HasElevatedPermissions checks if the workflow/job has write permissions.
func HasElevatedPermissions(wfPerms, jobPerms PermissionsConfig) bool {
	if wfPerms.WriteAll || jobPerms.WriteAll {
		return true
	}
	// No permissions block defaults to write-all in many configurations
	if !wfPerms.Set && !jobPerms.Set {
		return true
	}
	for _, v := range jobPerms.Scopes {
		if v == "write" {
			return true
		}
	}
	for _, v := range wfPerms.Scopes {
		if v == "write" {
			return true
		}
	}
	return false
}

// AccessesSecrets checks if any step in the job references secrets.
func AccessesSecrets(job Job) bool {
	for _, step := range job.Steps {
		if strings.Contains(step.Run, "secrets.") {
			return true
		}
		for _, v := range step.Env {
			if strings.Contains(v, "secrets.") {
				return true
			}
		}
		for _, v := range step.With {
			if strings.Contains(v, "secrets.") {
				return true
			}
		}
	}
	return false
}
