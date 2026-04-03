// Package cicd provides a platform-agnostic interface for CI/CD pipeline
// security analysis. Each CI/CD platform (GitHub Actions, GitLab CI, etc.)
// implements the Pipeline interface, enabling cross-platform vulnerability
// detection with shared rule logic.
package cicd

// TriggerType categorizes CI/CD pipeline triggers by trust level.
type TriggerType string

const (
	// TriggerExternalPR is an external/fork PR that runs in privileged context.
	// GitHub: pull_request_target, GitLab: merge_request_event (parent context)
	TriggerExternalPR TriggerType = "external_pr"

	// TriggerInternalPR is an internal PR with limited privileges.
	// GitHub: pull_request, GitLab: merge_request_event (fork context)
	TriggerInternalPR TriggerType = "internal_pr"

	// TriggerPush is a push to a branch (trusted).
	TriggerPush TriggerType = "push"

	// TriggerSchedule is a scheduled/cron trigger (trusted).
	TriggerSchedule TriggerType = "schedule"

	// TriggerManual is a manual trigger (trusted).
	TriggerManual TriggerType = "manual"

	// TriggerComment is triggered by a comment (partially trusted).
	TriggerComment TriggerType = "comment"

	// TriggerAPI is triggered by API/webhook (trust depends on config).
	TriggerAPI TriggerType = "api"
)

// Pipeline is the platform-agnostic representation of a CI/CD pipeline config.
type Pipeline interface {
	// Platform returns the CI/CD platform name (e.g., "github", "gitlab").
	Platform() string

	// FilePath returns the path to the pipeline config file.
	FilePath() string

	// Triggers returns all trigger types that activate this pipeline.
	Triggers() []TriggerType

	// HasExternalTrigger returns true if the pipeline can be triggered by
	// untrusted external input (fork PRs, comments, etc.).
	HasExternalTrigger() bool

	// Jobs returns all jobs/stages in the pipeline.
	Jobs() []PipelineJob
}

// PipelineJob represents a single job/stage in a CI/CD pipeline.
type PipelineJob struct {
	Name        string
	Conditions  []string  // Conditional execution rules
	Environment string    // Environment/deployment protection
	RunnerType  string    // Runner type (e.g., "hosted", "self-hosted", tag)
	Steps       []PipelineStep
	DependsOn   []string  // Job dependencies
	Secrets     []string  // Secret references
	Permissions map[string]string
	IdTokens    map[string]string // OIDC id_tokens (audience -> token name)
	CacheKeys   []string          // Cache key patterns
}

// PipelineStep represents a single step/script block in a job.
type PipelineStep struct {
	Name    string
	Type    StepType
	Command string   // Script content or action reference
	Line    int
	Env     map[string]string
}

// StepType categorizes pipeline steps.
type StepType string

const (
	StepScript StepType = "script"  // Shell script execution
	StepAction StepType = "action"  // Reusable action/template
	StepInclude StepType = "include" // External config include
)
