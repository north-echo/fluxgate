package cicd

import (
	"fmt"
	"regexp"
	"strings"
)

// JenkinsPipeline represents a parsed Jenkinsfile (declarative syntax).
type JenkinsPipeline struct {
	path       string
	triggers   []TriggerType
	jobs       []PipelineJob
	libraries  []JenkinsLibrary
	agentLabel string
}

// JenkinsLibrary represents a @Library annotation in a Jenkinsfile.
type JenkinsLibrary struct {
	Name    string
	Version string // empty if unpinned
}

// ParseJenkinsfile parses a declarative Jenkinsfile using regex/string parsing.
func ParseJenkinsfile(data []byte, path string) (*JenkinsPipeline, error) {
	content := string(data)

	pipeline := &JenkinsPipeline{
		path: path,
	}

	// Extract @Library annotations from file header
	pipeline.libraries = parseJenkinsLibraries(content)

	// Extract pipeline { ... } block
	pipelineBlock := extractBlock(content, "pipeline")
	if pipelineBlock == "" {
		return nil, fmt.Errorf("parsing %s: no pipeline block found", path)
	}

	// Parse top-level agent
	pipeline.agentLabel = parseJenkinsAgent(pipelineBlock)

	// Parse triggers block
	triggersBlock := extractBlock(pipelineBlock, "triggers")

	// Parse stages
	stagesBlock := extractBlock(pipelineBlock, "stages")
	if stagesBlock != "" {
		pipeline.jobs = parseJenkinsStages(stagesBlock, pipelineBlock, pipeline.agentLabel)
	}

	// Infer trigger types
	pipeline.triggers = inferJenkinsTriggers(triggersBlock, pipeline.jobs)

	return pipeline, nil
}

// Platform implements Pipeline.
func (p *JenkinsPipeline) Platform() string { return "jenkins" }

// FilePath implements Pipeline.
func (p *JenkinsPipeline) FilePath() string { return p.path }

// Triggers implements Pipeline.
func (p *JenkinsPipeline) Triggers() []TriggerType { return p.triggers }

// HasExternalTrigger implements Pipeline.
func (p *JenkinsPipeline) HasExternalTrigger() bool {
	for _, t := range p.triggers {
		if t == TriggerExternalPR || t == TriggerComment {
			return true
		}
	}
	return false
}

// Jobs implements Pipeline.
func (p *JenkinsPipeline) Jobs() []PipelineJob { return p.jobs }

// Libraries returns parsed @Library annotations.
func (p *JenkinsPipeline) Libraries() []JenkinsLibrary { return p.libraries }

var libraryPattern = regexp.MustCompile(`@Library\(['"]([^'"]+)['"]\)`)

func parseJenkinsLibraries(content string) []JenkinsLibrary {
	var libs []JenkinsLibrary
	matches := libraryPattern.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		ref := m[1]
		lib := JenkinsLibrary{}
		if idx := strings.Index(ref, "@"); idx >= 0 {
			lib.Name = ref[:idx]
			lib.Version = ref[idx+1:]
		} else {
			lib.Name = ref
		}
		libs = append(libs, lib)
	}
	return libs
}

func parseJenkinsAgent(block string) string {
	agentBlock := extractBlock(block, "agent")
	if agentBlock == "" {
		// Try inline: agent any, agent none
		re := regexp.MustCompile(`agent\s+(any|none)\b`)
		m := re.FindStringSubmatch(block)
		if m != nil {
			return m[1]
		}
		return ""
	}

	// Check for label
	labelRe := regexp.MustCompile(`label\s+['"]([^'"]+)['"]`)
	if m := labelRe.FindStringSubmatch(agentBlock); m != nil {
		return m[1]
	}

	// Check for docker
	if strings.Contains(agentBlock, "docker") {
		return "docker"
	}

	return ""
}

func inferJenkinsTriggers(triggersBlock string, jobs []PipelineJob) []TriggerType {
	triggers := []TriggerType{TriggerPush} // Default

	if strings.Contains(triggersBlock, "cron") {
		triggers = append(triggers, TriggerSchedule)
	}

	// Check stages for changeRequest() when blocks
	for _, job := range jobs {
		for _, cond := range job.Conditions {
			if strings.Contains(cond, "changeRequest") {
				triggers = append(triggers, TriggerExternalPR)
				return triggers
			}
		}
	}

	return triggers
}

func parseJenkinsStages(stagesBlock string, pipelineBlock string, defaultAgent string) []PipelineJob {
	var jobs []PipelineJob

	// Find each stage('name') { ... } block
	stageNameRe := regexp.MustCompile(`stage\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	matches := stageNameRe.FindAllStringSubmatchIndex(stagesBlock, -1)

	for i, m := range matches {
		stageName := stagesBlock[m[2]:m[3]]

		// Find the block content for this stage
		blockStart := strings.Index(stagesBlock[m[0]:], "{")
		if blockStart < 0 {
			continue
		}
		blockStart += m[0]

		var blockEnd int
		if i+1 < len(matches) {
			blockEnd = matches[i+1][0]
		} else {
			blockEnd = len(stagesBlock)
		}

		stageContent := stagesBlock[blockStart:blockEnd]
		// Find matching brace
		stageContent = extractBraceContent(stageContent)

		job := PipelineJob{
			Name:       stageName,
			RunnerType: defaultAgent,
		}

		// Check for when { changeRequest() }
		whenBlock := extractBlock(stageContent, "when")
		if strings.Contains(whenBlock, "changeRequest") {
			job.Conditions = append(job.Conditions, "changeRequest()")
		}

		// Check for agent override within stage
		stageAgent := parseJenkinsAgent(stageContent)
		if stageAgent != "" {
			job.RunnerType = stageAgent
		}

		// Parse environment block for credentials
		envBlock := extractBlock(stageContent, "environment")
		if envBlock != "" {
			credRe := regexp.MustCompile(`(\w+)\s*=\s*credentials\s*\(\s*['"]([^'"]+)['"]\s*\)`)
			credMatches := credRe.FindAllStringSubmatch(envBlock, -1)
			for _, cm := range credMatches {
				job.Secrets = append(job.Secrets, cm[2])
				if job.Steps == nil {
					// Env vars will be set but track them
				}
			}
		}

		// Parse steps block
		stepsBlock := extractBlock(stageContent, "steps")
		if stepsBlock != "" {
			job.Steps = parseJenkinsSteps(stepsBlock)
		}

		jobs = append(jobs, job)
	}

	return jobs
}

func parseJenkinsSteps(stepsBlock string) []PipelineStep {
	var steps []PipelineStep

	// Match sh 'command' or sh "command" or sh '''multiline''' or sh """multiline"""
	// Also match bat variants
	patterns := []struct {
		re   *regexp.Regexp
		name string
	}{
		{regexp.MustCompile(`(?:sh|bat)\s+'''((?s:.*?))'''`), "sh"},
		{regexp.MustCompile(`(?:sh|bat)\s+"""((?s:.*?))"""`), "sh"},
		{regexp.MustCompile(`(?:sh|bat)\s+"([^"]+)"`), "sh"},
		{regexp.MustCompile(`(?:sh|bat)\s+'([^']+)'`), "sh"},
	}

	for _, p := range patterns {
		matches := p.re.FindAllStringSubmatch(stepsBlock, -1)
		for _, m := range matches {
			steps = append(steps, PipelineStep{
				Name:    p.name,
				Type:    StepScript,
				Command: m[1],
			})
		}
	}

	return steps
}

// extractBlock finds a named block `name { ... }` and returns the content
// between the braces (exclusive).
func extractBlock(content string, name string) string {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*\{`)
	loc := re.FindStringIndex(content)
	if loc == nil {
		return ""
	}

	braceStart := strings.Index(content[loc[0]:], "{") + loc[0]
	return extractBraceContent(content[braceStart:])
}

// extractBraceContent takes a string starting with '{' and returns the content
// between the outer braces.
func extractBraceContent(s string) string {
	if len(s) == 0 || s[0] != '{' {
		return ""
	}
	depth := 0
	for i, ch := range s {
		if ch == '{' {
			depth++
		} else if ch == '}' {
			depth--
			if depth == 0 {
				return s[1:i]
			}
		}
	}
	// Unmatched braces — return everything after the opening brace
	return s[1:]
}
