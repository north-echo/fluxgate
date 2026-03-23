package cicd

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// GitLabPipeline represents a parsed .gitlab-ci.yml file.
type GitLabPipeline struct {
	path       string
	triggers   []TriggerType
	jobs       []PipelineJob
	includes   []GitLabInclude
	variables  map[string]string
}

// GitLabInclude represents an include directive in .gitlab-ci.yml.
type GitLabInclude struct {
	Local   string
	Remote  string
	Project string
	File    string
	Ref     string
}

// rawGitLabCI is the intermediate representation for YAML unmarshalling.
type rawGitLabCI struct {
	Stages    []string               `yaml:"stages"`
	Variables map[string]interface{} `yaml:"variables"`
	Include   yaml.Node              `yaml:"include"`
	Workflow  *rawGitLabWorkflow     `yaml:"workflow"`
	// Jobs are top-level keys that aren't reserved keywords
}

type rawGitLabWorkflow struct {
	Rules []rawGitLabRule `yaml:"rules"`
}

type rawGitLabRule struct {
	If        string `yaml:"if"`
	When      string `yaml:"when"`
	Exists    string `yaml:"exists"`
	Changes   string `yaml:"changes"`
	Variables map[string]string `yaml:"variables"`
}

type rawGitLabJob struct {
	Stage       string            `yaml:"stage"`
	Image       string            `yaml:"image"`
	Tags        []string          `yaml:"tags"`
	Script      yaml.Node         `yaml:"script"`
	BeforeScript yaml.Node        `yaml:"before_script"`
	AfterScript yaml.Node         `yaml:"after_script"`
	Rules       []rawGitLabRule   `yaml:"rules"`
	Only        yaml.Node         `yaml:"only"`
	Except      yaml.Node         `yaml:"except"`
	Environment yaml.Node         `yaml:"environment"`
	Secrets     yaml.Node         `yaml:"secrets"`
	Variables   map[string]string `yaml:"variables"`
	Needs       []string          `yaml:"needs"`
	Services    yaml.Node         `yaml:"services"`
}

// Reserved GitLab CI keywords that are NOT job names.
var gitlabReservedKeys = map[string]bool{
	"stages": true, "variables": true, "include": true, "workflow": true,
	"default": true, "image": true, "services": true, "cache": true,
	"before_script": true, "after_script": true, "pages": true,
}

// ParseGitLabCI parses a .gitlab-ci.yml file.
func ParseGitLabCI(data []byte, path string) (*GitLabPipeline, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("parsing %s: empty document", path)
	}

	// First pass: parse reserved keys
	var raw rawGitLabCI
	if err := doc.Content[0].Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}

	pipeline := &GitLabPipeline{
		path:      path,
		variables: make(map[string]string),
	}

	// Parse variables
	for k, v := range raw.Variables {
		switch val := v.(type) {
		case string:
			pipeline.variables[k] = val
		case map[string]interface{}:
			if value, ok := val["value"]; ok {
				pipeline.variables[k] = fmt.Sprintf("%v", value)
			}
		}
	}

	// Parse includes
	pipeline.includes = parseGitLabIncludes(&raw.Include)

	// Determine triggers from workflow rules
	pipeline.triggers = inferGitLabTriggers(raw.Workflow)

	// Second pass: extract jobs (top-level keys that aren't reserved)
	root := doc.Content[0]
	if root.Kind == yaml.MappingNode {
		for i := 0; i < len(root.Content)-1; i += 2 {
			key := root.Content[i].Value
			if gitlabReservedKeys[key] || strings.HasPrefix(key, ".") {
				continue // Skip reserved keys and hidden jobs (templates)
			}

			var rawJob rawGitLabJob
			if err := root.Content[i+1].Decode(&rawJob); err != nil {
				continue
			}

			job := convertGitLabJob(key, &rawJob, root.Content[i+1])
			pipeline.jobs = append(pipeline.jobs, job)
		}
	}

	return pipeline, nil
}

// Platform implements Pipeline.
func (p *GitLabPipeline) Platform() string { return "gitlab" }

// FilePath implements Pipeline.
func (p *GitLabPipeline) FilePath() string { return p.path }

// Triggers implements Pipeline.
func (p *GitLabPipeline) Triggers() []TriggerType { return p.triggers }

// HasExternalTrigger implements Pipeline.
func (p *GitLabPipeline) HasExternalTrigger() bool {
	for _, t := range p.triggers {
		if t == TriggerExternalPR || t == TriggerComment {
			return true
		}
	}
	return false
}

// Jobs implements Pipeline.
func (p *GitLabPipeline) Jobs() []PipelineJob { return p.jobs }

// Includes returns external includes (potential supply chain risk).
func (p *GitLabPipeline) Includes() []GitLabInclude { return p.includes }

// Variables returns pipeline-level variables.
func (p *GitLabPipeline) Variables() map[string]string { return p.variables }

func inferGitLabTriggers(workflow *rawGitLabWorkflow) []TriggerType {
	triggers := []TriggerType{TriggerPush} // GitLab pipelines run on push by default

	if workflow == nil {
		// Default: pipelines run on push, MR, and merge result
		triggers = append(triggers, TriggerInternalPR)
		return triggers
	}

	for _, rule := range workflow.Rules {
		lower := strings.ToLower(rule.If)
		if strings.Contains(lower, "ci_pipeline_source") {
			if strings.Contains(lower, "merge_request_event") {
				triggers = append(triggers, TriggerInternalPR)
			}
			if strings.Contains(lower, "schedule") {
				triggers = append(triggers, TriggerSchedule)
			}
			if strings.Contains(lower, "web") || strings.Contains(lower, "api") {
				triggers = append(triggers, TriggerAPI)
			}
			if strings.Contains(lower, "trigger") {
				triggers = append(triggers, TriggerAPI)
			}
		}
	}

	return triggers
}

func convertGitLabJob(name string, raw *rawGitLabJob, node *yaml.Node) PipelineJob {
	job := PipelineJob{
		Name:      name,
		DependsOn: raw.Needs,
	}

	// Runner type from tags
	for _, tag := range raw.Tags {
		if strings.ToLower(tag) == "self-hosted" || strings.ToLower(tag) == "shell" {
			job.RunnerType = "self-hosted"
			break
		}
	}
	if job.RunnerType == "" && len(raw.Tags) > 0 {
		job.RunnerType = strings.Join(raw.Tags, ",")
	}

	// Environment
	job.Environment = parseGitLabEnvironment(&raw.Environment)

	// Rules as conditions
	for _, rule := range raw.Rules {
		if rule.If != "" {
			job.Conditions = append(job.Conditions, rule.If)
		}
	}

	// Extract script steps
	job.Steps = append(job.Steps, extractScriptSteps("before_script", &raw.BeforeScript, node)...)
	job.Steps = append(job.Steps, extractScriptSteps("script", &raw.Script, node)...)
	job.Steps = append(job.Steps, extractScriptSteps("after_script", &raw.AfterScript, node)...)

	// Extract secret references from variables
	for _, v := range raw.Variables {
		if strings.HasPrefix(v, "$") || strings.Contains(v, "CI_JOB_TOKEN") {
			job.Secrets = append(job.Secrets, v)
		}
	}

	return job
}

func extractScriptSteps(name string, node *yaml.Node, jobNode *yaml.Node) []PipelineStep {
	if node == nil || node.Kind == 0 {
		return nil
	}

	var steps []PipelineStep
	switch node.Kind {
	case yaml.ScalarNode:
		steps = append(steps, PipelineStep{
			Name:    name,
			Type:    StepScript,
			Command: node.Value,
			Line:    node.Line,
		})
	case yaml.SequenceNode:
		for _, item := range node.Content {
			cmd := item.Value
			line := item.Line
			// When YAML parses an unquoted script line containing ": " (e.g.
			// echo "foo: $BAR"), it interprets it as a mapping node instead
			// of a scalar. Reconstruct the original string from the key-value.
			if item.Kind == yaml.MappingNode && len(item.Content) >= 2 {
				key := item.Content[0].Value
				val := item.Content[1].Value
				if val != "" {
					cmd = key + ": " + val
				} else {
					cmd = key
				}
				line = item.Content[0].Line
			}
			steps = append(steps, PipelineStep{
				Name:    name,
				Type:    StepScript,
				Command: cmd,
				Line:    line,
			})
		}
	}
	return steps
}

func parseGitLabEnvironment(node *yaml.Node) string {
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

func parseGitLabIncludes(node *yaml.Node) []GitLabInclude {
	if node == nil || node.Kind == 0 {
		return nil
	}

	var includes []GitLabInclude

	switch node.Kind {
	case yaml.ScalarNode:
		includes = append(includes, GitLabInclude{Local: node.Value})
	case yaml.SequenceNode:
		for _, item := range node.Content {
			inc := parseGitLabIncludeItem(item)
			includes = append(includes, inc)
		}
	case yaml.MappingNode:
		inc := parseGitLabIncludeItem(node)
		includes = append(includes, inc)
	}

	return includes
}

func parseGitLabIncludeItem(node *yaml.Node) GitLabInclude {
	inc := GitLabInclude{}
	if node.Kind == yaml.ScalarNode {
		if strings.HasPrefix(node.Value, "http") {
			inc.Remote = node.Value
		} else {
			inc.Local = node.Value
		}
		return inc
	}

	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content)-1; i += 2 {
			key := node.Content[i].Value
			val := node.Content[i+1].Value
			switch key {
			case "local":
				inc.Local = val
			case "remote":
				inc.Remote = val
			case "project":
				inc.Project = val
			case "file":
				inc.File = val
			case "ref":
				inc.Ref = val
			}
		}
	}
	return inc
}
