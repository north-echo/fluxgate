package cicd

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// TektonPipeline represents a parsed Tekton Pipeline or Task manifest.
type TektonPipeline struct {
	path      string
	kind      string // "Pipeline", "Task", "EventListener", "TriggerBinding"
	triggers  []TriggerType
	jobs      []PipelineJob
	params    []TektonParam
	taskRefs  []TektonTaskRef
}

// TektonParam represents a parameter definition in a Tekton resource.
type TektonParam struct {
	Name    string
	Default string
}

// TektonTaskRef represents a task reference in a Tekton pipeline.
type TektonTaskRef struct {
	Name   string
	Bundle string
}

// rawTektonResource is the intermediate representation for YAML unmarshalling.
type rawTektonResource struct {
	APIVersion string          `yaml:"apiVersion"`
	Kind       string          `yaml:"kind"`
	Metadata   rawTektonMeta   `yaml:"metadata"`
	Spec       rawTektonSpec   `yaml:"spec"`
}

type rawTektonMeta struct {
	Name string `yaml:"name"`
}

type rawTektonSpec struct {
	Params     []rawTektonParam     `yaml:"params"`
	Tasks      []rawTektonTask      `yaml:"tasks"`
	Steps      []rawTektonStep      `yaml:"steps"`
	Workspaces []rawTektonWorkspace `yaml:"workspaces"`
}

type rawTektonParam struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	Default string `yaml:"default"`
}

type rawTektonTask struct {
	Name     string           `yaml:"name"`
	TaskRef  *rawTektonRef    `yaml:"taskRef"`
	TaskSpec *rawTektonSpec   `yaml:"taskSpec"`
	Params   []rawTektonKV    `yaml:"params"`
}

type rawTektonRef struct {
	Name   string `yaml:"name"`
	Bundle string `yaml:"bundle"`
}

type rawTektonKV struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type rawTektonStep struct {
	Name            string                `yaml:"name"`
	Image           string                `yaml:"image"`
	Script          string                `yaml:"script"`
	Command         []string              `yaml:"command"`
	Env             []rawTektonEnv        `yaml:"env"`
	SecurityContext *rawTektonSecCtx      `yaml:"securityContext"`
}

type rawTektonEnv struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type rawTektonSecCtx struct {
	Privileged *bool  `yaml:"privileged"`
	RunAsUser  *int64 `yaml:"runAsUser"`
}

type rawTektonWorkspace struct {
	Name   string           `yaml:"name"`
	Secret *rawTektonSecret `yaml:"secret"`
}

type rawTektonSecret struct {
	SecretName string `yaml:"secretName"`
}

// ParseTektonPipeline parses a Tekton Pipeline or Task YAML manifest.
func ParseTektonPipeline(data []byte, path string) (*TektonPipeline, error) {
	var raw rawTektonResource
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	if raw.Kind == "" {
		return nil, fmt.Errorf("parsing %s: missing kind field", path)
	}

	pipeline := &TektonPipeline{
		path: path,
		kind: raw.Kind,
	}

	// Parse params
	for _, p := range raw.Spec.Params {
		pipeline.params = append(pipeline.params, TektonParam{
			Name:    p.Name,
			Default: p.Default,
		})
	}

	// Determine triggers based on kind
	pipeline.triggers = inferTektonTriggers(raw.Kind)

	switch raw.Kind {
	case "Pipeline":
		// Parse pipeline tasks
		for _, task := range raw.Spec.Tasks {
			job := convertTektonTask(&task)
			pipeline.jobs = append(pipeline.jobs, job)

			if task.TaskRef != nil {
				pipeline.taskRefs = append(pipeline.taskRefs, TektonTaskRef{
					Name:   task.TaskRef.Name,
					Bundle: task.TaskRef.Bundle,
				})
			}
		}
	case "Task":
		// Parse task steps into a single job
		job := PipelineJob{
			Name: raw.Metadata.Name,
		}
		for _, step := range raw.Spec.Steps {
			job.Steps = append(job.Steps, convertTektonStep(&step))
		}
		// Track workspace-bound secrets
		for _, ws := range raw.Spec.Workspaces {
			if ws.Secret != nil && ws.Secret.SecretName != "" {
				job.Secrets = append(job.Secrets, ws.Secret.SecretName)
			}
		}
		pipeline.jobs = append(pipeline.jobs, job)
	case "EventListener", "TriggerBinding":
		// Trigger resources — no jobs, but influence trigger type
	}

	return pipeline, nil
}

// Platform implements Pipeline.
func (p *TektonPipeline) Platform() string { return "tekton" }

// FilePath implements Pipeline.
func (p *TektonPipeline) FilePath() string { return p.path }

// Triggers implements Pipeline.
func (p *TektonPipeline) Triggers() []TriggerType { return p.triggers }

// HasExternalTrigger implements Pipeline.
func (p *TektonPipeline) HasExternalTrigger() bool {
	for _, t := range p.triggers {
		if t == TriggerExternalPR || t == TriggerComment || t == TriggerAPI {
			return true
		}
	}
	return false
}

// Jobs implements Pipeline.
func (p *TektonPipeline) Jobs() []PipelineJob { return p.jobs }

// Params returns pipeline/task parameter definitions.
func (p *TektonPipeline) Params() []TektonParam { return p.params }

// TaskRefs returns task references from pipeline tasks.
func (p *TektonPipeline) TaskRefs() []TektonTaskRef { return p.taskRefs }

func inferTektonTriggers(kind string) []TriggerType {
	switch kind {
	case "EventListener", "TriggerBinding":
		return []TriggerType{TriggerAPI}
	default:
		return []TriggerType{TriggerPush}
	}
}

func convertTektonTask(raw *rawTektonTask) PipelineJob {
	job := PipelineJob{
		Name: raw.Name,
	}

	// If taskSpec is inlined, extract steps
	if raw.TaskSpec != nil {
		for _, step := range raw.TaskSpec.Steps {
			job.Steps = append(job.Steps, convertTektonStep(&step))
		}
	}

	return job
}

func convertTektonStep(raw *rawTektonStep) PipelineStep {
	step := PipelineStep{
		Name: raw.Name,
		Type: StepScript,
		Env:  make(map[string]string),
	}

	if raw.Script != "" {
		step.Command = raw.Script
	} else if len(raw.Command) > 0 {
		step.Command = joinCommand(raw.Command)
	}

	for _, e := range raw.Env {
		step.Env[e.Name] = e.Value
	}

	// Store security context info in env for rule inspection
	if raw.SecurityContext != nil {
		if raw.SecurityContext.Privileged != nil && *raw.SecurityContext.Privileged {
			step.Env["__securityContext_privileged"] = "true"
		}
		if raw.SecurityContext.RunAsUser != nil && *raw.SecurityContext.RunAsUser == 0 {
			step.Env["__securityContext_runAsUser"] = "0"
		}
	}

	return step
}

func joinCommand(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += " "
		}
		result += p
	}
	return result
}
