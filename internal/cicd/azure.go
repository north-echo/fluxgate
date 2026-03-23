package cicd

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// AzurePipeline represents a parsed azure-pipelines.yml file.
type AzurePipeline struct {
	path      string
	triggers  []TriggerType
	jobs      []PipelineJob
	resources []AzureResource
	variables []AzureVariable
	extends   string
}

// AzureResource represents a pipeline resource reference.
type AzureResource struct {
	Type       string // "repositories", "pipelines", "containers"
	Repository string
	Ref        string
	Endpoint   string
}

// AzureVariable represents a pipeline variable.
type AzureVariable struct {
	Name     string
	Value    string
	IsSecret bool
	Group    string
}

// rawAzurePipeline is the intermediate representation for YAML unmarshalling.
type rawAzurePipeline struct {
	Trigger   yaml.Node              `yaml:"trigger"`
	PR        yaml.Node              `yaml:"pr"`
	Schedules []rawAzureSchedule     `yaml:"schedules"`
	Pool      yaml.Node              `yaml:"pool"`
	Variables yaml.Node              `yaml:"variables"`
	Resources yaml.Node              `yaml:"resources"`
	Extends   *rawAzureExtends       `yaml:"extends"`
	Stages    []rawAzureStage        `yaml:"stages"`
	Jobs      []rawAzureJob          `yaml:"jobs"`
	Steps     []rawAzureStep         `yaml:"steps"`
}

type rawAzureSchedule struct {
	Cron string `yaml:"cron"`
}

type rawAzureExtends struct {
	Template string `yaml:"template"`
}

type rawAzureStage struct {
	Stage        string         `yaml:"stage"`
	DisplayName  string         `yaml:"displayName"`
	DependsOn    yaml.Node      `yaml:"dependsOn"`
	Condition    string         `yaml:"condition"`
	Pool         yaml.Node      `yaml:"pool"`
	Variables    yaml.Node      `yaml:"variables"`
	Jobs         []rawAzureJob  `yaml:"jobs"`
}

type rawAzureJob struct {
	Job         string         `yaml:"job"`
	Deployment  string         `yaml:"deployment"`
	DisplayName string         `yaml:"displayName"`
	DependsOn   yaml.Node      `yaml:"dependsOn"`
	Condition   string         `yaml:"condition"`
	Pool        yaml.Node      `yaml:"pool"`
	Variables   yaml.Node      `yaml:"variables"`
	Environment yaml.Node      `yaml:"environment"`
	Steps       []rawAzureStep `yaml:"steps"`
	Template    string         `yaml:"template"`
}

type rawAzureStep struct {
	Script      string            `yaml:"script"`
	Bash        string            `yaml:"bash"`
	Powershell  string            `yaml:"powershell"`
	Pwsh        string            `yaml:"pwsh"`
	Task        string            `yaml:"task"`
	Template    string            `yaml:"template"`
	Checkout    string            `yaml:"checkout"`
	DisplayName string            `yaml:"displayName"`
	Env         map[string]string `yaml:"env"`
	Inputs      map[string]string `yaml:"inputs"`
}

// ParseAzurePipeline parses an azure-pipelines.yml file.
func ParseAzurePipeline(data []byte, path string) (*AzurePipeline, error) {
	var raw rawAzurePipeline
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	pipeline := &AzurePipeline{
		path: path,
	}

	// Parse triggers
	pipeline.triggers = inferAzureTriggers(&raw)

	// Parse variables
	pipeline.variables = parseAzureVariables(&raw.Variables)

	// Parse resources
	pipeline.resources = parseAzureResources(&raw.Resources)

	// Parse extends
	if raw.Extends != nil {
		pipeline.extends = raw.Extends.Template
	}

	// Parse jobs from stages, jobs, or steps
	defaultPool := parseAzurePool(&raw.Pool)

	if len(raw.Stages) > 0 {
		for _, stage := range raw.Stages {
			stagePool := parseAzurePool(&stage.Pool)
			if stagePool == "" {
				stagePool = defaultPool
			}
			for _, rawJob := range stage.Jobs {
				job := convertAzureJob(&rawJob, stagePool)
				if stage.Condition != "" {
					job.Conditions = append(job.Conditions, stage.Condition)
				}
				pipeline.jobs = append(pipeline.jobs, job)
			}
		}
	} else if len(raw.Jobs) > 0 {
		for _, rawJob := range raw.Jobs {
			pipeline.jobs = append(pipeline.jobs, convertAzureJob(&rawJob, defaultPool))
		}
	} else if len(raw.Steps) > 0 {
		// Single-job pipeline (steps at root level)
		job := PipelineJob{
			Name:       "__root__",
			RunnerType: defaultPool,
		}
		for _, step := range raw.Steps {
			job.Steps = append(job.Steps, convertAzureStep(&step)...)
		}
		pipeline.jobs = append(pipeline.jobs, job)
	}

	return pipeline, nil
}

// Platform implements Pipeline.
func (p *AzurePipeline) Platform() string { return "azure" }

// FilePath implements Pipeline.
func (p *AzurePipeline) FilePath() string { return p.path }

// Triggers implements Pipeline.
func (p *AzurePipeline) Triggers() []TriggerType { return p.triggers }

// HasExternalTrigger implements Pipeline.
func (p *AzurePipeline) HasExternalTrigger() bool {
	for _, t := range p.triggers {
		if t == TriggerExternalPR || t == TriggerInternalPR || t == TriggerComment {
			return true
		}
	}
	return false
}

// Jobs implements Pipeline.
func (p *AzurePipeline) Jobs() []PipelineJob { return p.jobs }

// Variables returns pipeline variables.
func (p *AzurePipeline) Variables() []AzureVariable { return p.variables }

// Resources returns pipeline resource references.
func (p *AzurePipeline) Resources() []AzureResource { return p.resources }

// Extends returns the template this pipeline extends.
func (p *AzurePipeline) Extends() string { return p.extends }

func inferAzureTriggers(raw *rawAzurePipeline) []TriggerType {
	var triggers []TriggerType

	// Check trigger (CI trigger = push)
	hasTrigger := raw.Trigger.Kind != 0
	hasPR := raw.PR.Kind != 0

	if !hasTrigger && !hasPR {
		// Default: trigger on push and PR
		triggers = append(triggers, TriggerPush, TriggerInternalPR)
	} else {
		if hasTrigger {
			// Check if trigger is "none"
			if raw.Trigger.Kind == yaml.ScalarNode && raw.Trigger.Value == "none" {
				// Explicitly disabled
			} else {
				triggers = append(triggers, TriggerPush)
			}
		}
		if hasPR {
			if raw.PR.Kind == yaml.ScalarNode && raw.PR.Value == "none" {
				// Explicitly disabled
			} else {
				// Azure DevOps: PR triggers for forks are treated as external.
				// Fork PRs get limited access by default, but pipelines can
				// opt into "make secrets available to builds of forks".
				triggers = append(triggers, TriggerInternalPR)
			}
		}
	}

	if len(raw.Schedules) > 0 {
		triggers = append(triggers, TriggerSchedule)
	}

	return triggers
}

func parseAzurePool(node *yaml.Node) string {
	if node == nil || node.Kind == 0 {
		return ""
	}

	switch node.Kind {
	case yaml.ScalarNode:
		return node.Value
	case yaml.MappingNode:
		var vmImage, poolName string
		for i := 0; i < len(node.Content)-1; i += 2 {
			key := node.Content[i].Value
			val := node.Content[i+1].Value
			switch key {
			case "vmImage":
				vmImage = val
			case "name":
				poolName = val
			}
		}
		if vmImage != "" {
			return "hosted:" + vmImage
		}
		if poolName != "" {
			return "self-hosted:" + poolName
		}
	}
	return ""
}

func parseAzureVariables(node *yaml.Node) []AzureVariable {
	if node == nil || node.Kind == 0 {
		return nil
	}

	var vars []AzureVariable

	switch node.Kind {
	case yaml.MappingNode:
		// Simple key-value pairs
		for i := 0; i < len(node.Content)-1; i += 2 {
			vars = append(vars, AzureVariable{
				Name:  node.Content[i].Value,
				Value: node.Content[i+1].Value,
			})
		}
	case yaml.SequenceNode:
		// Extended form: [{name: ..., value: ...}, {group: ...}]
		for _, item := range node.Content {
			if item.Kind != yaml.MappingNode {
				continue
			}
			v := AzureVariable{}
			for i := 0; i < len(item.Content)-1; i += 2 {
				key := item.Content[i].Value
				val := item.Content[i+1].Value
				switch key {
				case "name":
					v.Name = val
				case "value":
					v.Value = val
				case "group":
					v.Group = val
					v.Name = val // use group name as identifier
				}
			}
			vars = append(vars, v)
		}
	}

	return vars
}

func parseAzureResources(node *yaml.Node) []AzureResource {
	if node == nil || node.Kind == 0 {
		return nil
	}

	// resources is a mapping: {repositories: [...], pipelines: [...], containers: [...]}
	if node.Kind != yaml.MappingNode {
		return nil
	}

	var resources []AzureResource
	for i := 0; i < len(node.Content)-1; i += 2 {
		resType := node.Content[i].Value // "repositories", "pipelines", etc.
		listNode := node.Content[i+1]
		if listNode.Kind != yaml.SequenceNode {
			continue
		}
		for _, item := range listNode.Content {
			if item.Kind != yaml.MappingNode {
				continue
			}
			r := AzureResource{Type: resType}
			for j := 0; j < len(item.Content)-1; j += 2 {
				key := item.Content[j].Value
				val := item.Content[j+1].Value
				switch key {
				case "repository":
					r.Repository = val
				case "ref":
					r.Ref = val
				case "endpoint":
					r.Endpoint = val
				}
			}
			resources = append(resources, r)
		}
	}

	return resources
}

func convertAzureJob(raw *rawAzureJob, parentPool string) PipelineJob {
	name := raw.Job
	if name == "" {
		name = raw.Deployment
	}
	if name == "" {
		name = raw.DisplayName
	}

	job := PipelineJob{
		Name:      name,
		DependsOn: parseAzureDependsOn(&raw.DependsOn),
	}

	// Pool / runner type
	pool := parseAzurePool(&raw.Pool)
	if pool == "" {
		pool = parentPool
	}
	job.RunnerType = pool

	// Condition
	if raw.Condition != "" {
		job.Conditions = append(job.Conditions, raw.Condition)
	}

	// Environment (deployment jobs)
	job.Environment = parseAzureEnvironment(&raw.Environment)

	// Template reference as a step
	if raw.Template != "" {
		job.Steps = append(job.Steps, PipelineStep{
			Name:    "template",
			Type:    StepInclude,
			Command: raw.Template,
		})
	}

	// Steps
	for _, step := range raw.Steps {
		job.Steps = append(job.Steps, convertAzureStep(&step)...)
	}

	// Extract variable-based secrets
	job.Secrets = extractAzureSecretRefs(&raw.Variables)

	return job
}

func convertAzureStep(raw *rawAzureStep) []PipelineStep {
	var steps []PipelineStep

	if raw.Script != "" {
		steps = append(steps, PipelineStep{
			Name:    raw.DisplayName,
			Type:    StepScript,
			Command: raw.Script,
			Env:     raw.Env,
		})
	}
	if raw.Bash != "" {
		steps = append(steps, PipelineStep{
			Name:    raw.DisplayName,
			Type:    StepScript,
			Command: raw.Bash,
			Env:     raw.Env,
		})
	}
	if raw.Powershell != "" {
		steps = append(steps, PipelineStep{
			Name:    raw.DisplayName,
			Type:    StepScript,
			Command: raw.Powershell,
			Env:     raw.Env,
		})
	}
	if raw.Pwsh != "" {
		steps = append(steps, PipelineStep{
			Name:    raw.DisplayName,
			Type:    StepScript,
			Command: raw.Pwsh,
			Env:     raw.Env,
		})
	}
	if raw.Task != "" {
		steps = append(steps, PipelineStep{
			Name:    raw.DisplayName,
			Type:    StepAction,
			Command: raw.Task,
			Env:     raw.Env,
		})
	}
	if raw.Template != "" {
		steps = append(steps, PipelineStep{
			Name:    raw.DisplayName,
			Type:    StepInclude,
			Command: raw.Template,
		})
	}

	return steps
}

func parseAzureDependsOn(node *yaml.Node) []string {
	if node == nil || node.Kind == 0 {
		return nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Value != "" {
			return []string{node.Value}
		}
	case yaml.SequenceNode:
		var deps []string
		for _, n := range node.Content {
			if n.Value != "" {
				deps = append(deps, n.Value)
			}
		}
		return deps
	}
	return nil
}

func parseAzureEnvironment(node *yaml.Node) string {
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

func extractAzureSecretRefs(node *yaml.Node) []string {
	if node == nil || node.Kind == 0 {
		return nil
	}
	// Look for variable group references or secret-marked variables
	var secrets []string
	if node.Kind == yaml.SequenceNode {
		for _, item := range node.Content {
			if item.Kind != yaml.MappingNode {
				continue
			}
			for i := 0; i < len(item.Content)-1; i += 2 {
				if item.Content[i].Value == "group" {
					secrets = append(secrets, "group:"+item.Content[i+1].Value)
				}
			}
		}
	}
	return secrets
}
