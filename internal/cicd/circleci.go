package cicd

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// CircleCIPipeline represents a parsed .circleci/config.yml file.
type CircleCIPipeline struct {
	path      string
	triggers  []TriggerType
	jobs      []PipelineJob
	orbs      []CircleCIOrb
}

// CircleCIOrb represents an orb reference in a CircleCI config.
type CircleCIOrb struct {
	Alias     string // local alias (e.g., "node")
	Namespace string // org namespace (e.g., "circleci")
	Name      string // orb name (e.g., "node")
	Version   string // version or digest (e.g., "5.0", "sha256:...")
}

// rawCircleCIConfig is the intermediate representation for YAML unmarshalling.
type rawCircleCIConfig struct {
	Version   string                        `yaml:"version"`
	Orbs      map[string]string             `yaml:"orbs"`
	Jobs      map[string]rawCircleCIJob     `yaml:"jobs"`
	Workflows map[string]rawCircleCIWorkflow `yaml:"workflows"`
}

type rawCircleCIJob struct {
	Docker        []rawCircleCIDocker `yaml:"docker"`
	Machine       yaml.Node           `yaml:"machine"`
	ResourceClass string              `yaml:"resource_class"`
	Steps         []yaml.Node         `yaml:"steps"`
	Environment   map[string]string   `yaml:"environment"`
}

type rawCircleCIDocker struct {
	Image string `yaml:"image"`
}

type rawCircleCIWorkflow struct {
	Jobs     []yaml.Node            `yaml:"jobs"`
	Triggers []rawCircleCITrigger   `yaml:"triggers"`
}

type rawCircleCITrigger struct {
	Schedule *rawCircleCISchedule `yaml:"schedule"`
}

type rawCircleCISchedule struct {
	Cron string `yaml:"cron"`
}

// ParseCircleCI parses a .circleci/config.yml file.
func ParseCircleCI(data []byte, path string) (*CircleCIPipeline, error) {
	var raw rawCircleCIConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	pipeline := &CircleCIPipeline{
		path: path,
	}

	// Parse orbs
	pipeline.orbs = parseCircleCIOrbs(raw.Orbs)

	// Parse jobs
	for name, rawJob := range raw.Jobs {
		job := convertCircleCIJob(name, &rawJob)
		pipeline.jobs = append(pipeline.jobs, job)
	}

	// Determine triggers
	pipeline.triggers = inferCircleCITriggers(&raw)

	return pipeline, nil
}

// Platform implements Pipeline.
func (p *CircleCIPipeline) Platform() string { return "circleci" }

// FilePath implements Pipeline.
func (p *CircleCIPipeline) FilePath() string { return p.path }

// Triggers implements Pipeline.
func (p *CircleCIPipeline) Triggers() []TriggerType { return p.triggers }

// HasExternalTrigger implements Pipeline.
func (p *CircleCIPipeline) HasExternalTrigger() bool {
	for _, t := range p.triggers {
		if t == TriggerExternalPR || t == TriggerComment {
			return true
		}
	}
	return false
}

// Jobs implements Pipeline.
func (p *CircleCIPipeline) Jobs() []PipelineJob { return p.jobs }

// Orbs returns parsed orb references.
func (p *CircleCIPipeline) Orbs() []CircleCIOrb { return p.orbs }

func parseCircleCIOrbs(orbs map[string]string) []CircleCIOrb {
	var result []CircleCIOrb
	for alias, ref := range orbs {
		orb := CircleCIOrb{Alias: alias}

		// Parse "circleci/node@5.0" or "circleci/node@sha256:..."
		atIdx := strings.Index(ref, "@")
		var namepart string
		if atIdx >= 0 {
			namepart = ref[:atIdx]
			orb.Version = ref[atIdx+1:]
		} else {
			namepart = ref
		}

		slashIdx := strings.Index(namepart, "/")
		if slashIdx >= 0 {
			orb.Namespace = namepart[:slashIdx]
			orb.Name = namepart[slashIdx+1:]
		} else {
			orb.Name = namepart
		}

		result = append(result, orb)
	}
	return result
}

func inferCircleCITriggers(raw *rawCircleCIConfig) []TriggerType {
	// CircleCI builds all PRs including forks by default
	triggers := []TriggerType{TriggerPush, TriggerExternalPR}

	for _, wf := range raw.Workflows {
		for _, tr := range wf.Triggers {
			if tr.Schedule != nil {
				triggers = append(triggers, TriggerSchedule)
				return triggers
			}
		}

		// Check if workflow has branch filters restricting to specific branches
		// (which would exclude fork PRs)
		for _, jobNode := range wf.Jobs {
			if jobNode.Kind == yaml.MappingNode {
				for i := 0; i < len(jobNode.Content)-1; i += 2 {
					valNode := jobNode.Content[i+1]
					if valNode.Kind == yaml.MappingNode {
						for j := 0; j < len(valNode.Content)-1; j += 2 {
							if valNode.Content[j].Value == "filters" {
								// Has filters — check for branch restrictions
								filterNode := valNode.Content[j+1]
								if hasBranchOnly(filterNode) {
									// Restricted to specific branches, remove external PR trigger
									filtered := []TriggerType{}
									for _, t := range triggers {
										if t != TriggerExternalPR {
											filtered = append(filtered, t)
										}
									}
									triggers = filtered
								}
							}
						}
					}
				}
			}
		}
	}

	return triggers
}

func hasBranchOnly(filterNode *yaml.Node) bool {
	if filterNode == nil || filterNode.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i < len(filterNode.Content)-1; i += 2 {
		if filterNode.Content[i].Value == "branches" {
			branchNode := filterNode.Content[i+1]
			if branchNode.Kind == yaml.MappingNode {
				for j := 0; j < len(branchNode.Content)-1; j += 2 {
					if branchNode.Content[j].Value == "only" {
						return true
					}
				}
			}
		}
	}
	return false
}

func convertCircleCIJob(name string, raw *rawCircleCIJob) PipelineJob {
	job := PipelineJob{
		Name: name,
	}

	// Determine runner type
	if len(raw.Docker) > 0 {
		job.RunnerType = "docker:" + raw.Docker[0].Image
	}
	if raw.Machine.Kind != 0 {
		if raw.Machine.Kind == yaml.ScalarNode && raw.Machine.Value == "true" {
			job.RunnerType = "machine"
		} else {
			job.RunnerType = "machine"
		}
	}
	if raw.ResourceClass != "" {
		job.RunnerType = raw.ResourceClass
	}

	// Parse steps
	for _, stepNode := range raw.Steps {
		steps := convertCircleCIStep(&stepNode)
		job.Steps = append(job.Steps, steps...)
	}

	return job
}

func convertCircleCIStep(node *yaml.Node) []PipelineStep {
	var steps []PipelineStep

	switch node.Kind {
	case yaml.ScalarNode:
		// Simple step like "checkout"
		stepType := StepAction
		if node.Value == "checkout" {
			stepType = StepAction
		}
		steps = append(steps, PipelineStep{
			Name:    node.Value,
			Type:    stepType,
			Command: node.Value,
			Line:    node.Line,
		})
	case yaml.MappingNode:
		// Step with config like run: { command: ... }
		for i := 0; i < len(node.Content)-1; i += 2 {
			key := node.Content[i].Value
			val := node.Content[i+1]

			switch key {
			case "run":
				step := parseCircleCIRunStep(val)
				step.Line = node.Content[i].Line
				steps = append(steps, step)
			case "checkout":
				steps = append(steps, PipelineStep{
					Name:    "checkout",
					Type:    StepAction,
					Command: "checkout",
					Line:    node.Content[i].Line,
				})
			default:
				// Orb command or other step type
				steps = append(steps, PipelineStep{
					Name:    key,
					Type:    StepAction,
					Command: key,
					Line:    node.Content[i].Line,
				})
			}
		}
	}

	return steps
}

func parseCircleCIRunStep(node *yaml.Node) PipelineStep {
	step := PipelineStep{
		Name: "run",
		Type: StepScript,
	}

	switch node.Kind {
	case yaml.ScalarNode:
		// run: "command string"
		step.Command = node.Value
	case yaml.MappingNode:
		// run: { name: ..., command: ... }
		for i := 0; i < len(node.Content)-1; i += 2 {
			key := node.Content[i].Value
			val := node.Content[i+1].Value
			switch key {
			case "name":
				step.Name = val
			case "command":
				step.Command = val
			}
		}
	}

	return step
}
