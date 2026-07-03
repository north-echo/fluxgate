package cicd

import (
	"fmt"
	"regexp"
	"sort"
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
	pipelineBlock, pipelineOff := extractBlockAt(content, "pipeline")
	if pipelineBlock == "" {
		return nil, fmt.Errorf("parsing %s: no pipeline block found", path)
	}

	// Parse top-level agent
	pipeline.agentLabel = parseJenkinsAgent(pipelineBlock)

	// Parse triggers block
	triggersBlock := extractBlock(pipelineBlock, "triggers")

	// Parse stages. Offsets are threaded through so steps can report real
	// line numbers instead of 0.
	li := newLineIndex(content)
	stagesBlock, stagesOff := extractBlockAt(pipelineBlock, "stages")
	if stagesBlock != "" {
		pipeline.jobs = parseJenkinsStages(stagesBlock, pipelineOff+stagesOff, pipeline.agentLabel, li)
	}

	// Infer trigger types
	pipeline.triggers = inferJenkinsTriggers(triggersBlock, pipeline.jobs)

	return pipeline, nil
}

// lineIndex maps byte offsets in a file to 1-based line numbers.
type lineIndex []int

func newLineIndex(content string) lineIndex {
	starts := lineIndex{0}
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// line returns the 1-based line number containing the byte offset.
func (li lineIndex) line(offset int) int {
	lo, hi := 0, len(li)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if li[mid] <= offset {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo + 1
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

var (
	agentInlineRe = regexp.MustCompile(`agent\s+(any|none)\b`)
	agentLabelRe  = regexp.MustCompile(`label\s+['"]([^'"]+)['"]`)
)

func parseJenkinsAgent(block string) string {
	agentBlock := extractBlock(block, "agent")
	if agentBlock == "" {
		// Try inline: agent any, agent none
		if m := agentInlineRe.FindStringSubmatch(block); m != nil {
			return m[1]
		}
		return ""
	}

	// Check for label
	if m := agentLabelRe.FindStringSubmatch(agentBlock); m != nil {
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

var (
	stageNameRe = regexp.MustCompile(`stage\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	credRe      = regexp.MustCompile(`(\w+)\s*=\s*credentials\s*\(\s*['"]([^'"]+)['"]\s*\)`)
)

// parseJenkinsStages parses stage blocks. stagesOff is the byte offset of
// stagesBlock in the original file, used with li to compute step lines.
func parseJenkinsStages(stagesBlock string, stagesOff int, defaultAgent string, li lineIndex) []PipelineJob {
	var jobs []PipelineJob

	// Find each stage('name') { ... } block
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
			credMatches := credRe.FindAllStringSubmatch(envBlock, -1)
			for _, cm := range credMatches {
				job.Secrets = append(job.Secrets, cm[2])
			}
		}

		// Parse steps block
		stepsBlock, stepsOff := extractBlockAt(stageContent, "steps")
		if stepsBlock != "" {
			// Offset of stageContent within stagesBlock: blockStart is where
			// the stage's brace starts; extractBraceContent strips that brace.
			stageContentOff := blockStart + 1
			job.Steps = parseJenkinsSteps(stepsBlock, stagesOff+stageContentOff+stepsOff, li)
		}

		jobs = append(jobs, job)
	}

	return jobs
}

// Match sh 'command' or sh "command" or sh ”'multiline”' or sh """multiline"""
// Also match bat variants
var jenkinsStepPatterns = []struct {
	re   *regexp.Regexp
	name string
}{
	{regexp.MustCompile(`(?:sh|bat)\s+'''((?s:.*?))'''`), "sh"},
	{regexp.MustCompile(`(?:sh|bat)\s+"""((?s:.*?))"""`), "sh"},
	{regexp.MustCompile(`(?:sh|bat)\s+"([^"]+)"`), "sh"},
	{regexp.MustCompile(`(?:sh|bat)\s+'([^']+)'`), "sh"},
}

// parseJenkinsSteps extracts sh/bat script steps with source line numbers.
// stepsOff is the byte offset of stepsBlock in the original file.
func parseJenkinsSteps(stepsBlock string, stepsOff int, li lineIndex) []PipelineStep {
	var steps []PipelineStep

	for _, p := range jenkinsStepPatterns {
		matches := p.re.FindAllStringSubmatchIndex(stepsBlock, -1)
		for _, m := range matches {
			line := 0
			if li != nil {
				line = li.line(stepsOff + m[0])
			}
			steps = append(steps, PipelineStep{
				Name:    p.name,
				Type:    StepScript,
				Command: stepsBlock[m[2]:m[3]],
				Line:    line,
			})
		}
	}

	// The four patterns each append in their own pass; order steps by
	// source position so downstream rules see them in file order.
	sort.Slice(steps, func(i, j int) bool { return steps[i].Line < steps[j].Line })

	return steps
}

// blockRes pre-compiles the block-start patterns for the fixed set of block
// names the parser looks up. extractBlock is called ~5x per stage, so
// compiling the pattern per call dominated Jenkinsfile parsing.
var blockRes = map[string]*regexp.Regexp{}

func init() {
	for _, name := range []string{"pipeline", "triggers", "stages", "when", "environment", "steps", "agent"} {
		blockRes[name] = regexp.MustCompile(`\b` + name + `\s*\{`)
	}
}

func blockRe(name string) *regexp.Regexp {
	if re, ok := blockRes[name]; ok {
		return re
	}
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*\{`)
}

// extractBlock finds a named block `name { ... }` and returns the content
// between the braces (exclusive).
func extractBlock(content string, name string) string {
	block, _ := extractBlockAt(content, name)
	return block
}

// extractBlockAt is extractBlock plus the byte offset of the returned
// content within the input string.
func extractBlockAt(content string, name string) (string, int) {
	loc := blockRe(name).FindStringIndex(content)
	if loc == nil {
		return "", 0
	}

	braceStart := strings.Index(content[loc[0]:], "{") + loc[0]
	return extractBraceContent(content[braceStart:]), braceStart + 1
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
