package cicd

import (
	"fmt"
	"strings"
)

// scanScriptInjection flags user-controllable variables interpolated into
// script blocks. It applies the mitigation-aware severity model to every
// platform (previously only GitLab had it): echo/printf-only usage downgrades
// to info, quoted-argument usage to medium.
//
// msgFmt receives the matched variable and the job/stage name.
func scanScriptInjection(pipeline Pipeline, dangerousVars []string, ruleID, msgFmt, baseDetails string) []PlatformFinding {
	var findings []PlatformFinding
	for _, job := range pipeline.Jobs() {
		for _, step := range job.Steps {
			if step.Type != StepScript {
				continue
			}
			for _, dv := range dangerousVars {
				if !strings.Contains(step.Command, dv) {
					continue
				}

				severity := severityHigh
				details := baseDetails

				// Downgrade: echo/printf is logging, not exploitable injection
				if isLoggingOnlyUsage(step.Command, dv) {
					severity = severityInfo
					details = "Variable used in echo/printf for logging. Not directly exploitable but may leak sensitive metadata to build logs."
				} else if isQuotedArgUsage(step.Command, dv) {
					// Quoted CLI argument — harder to exploit than unquoted interpolation
					severity = severityMedium
					details = "Variable used as a quoted CLI argument. Exploitation requires breaking out of the quoted context, which is significantly harder than unquoted shell interpolation."
				}

				findings = append(findings, PlatformFinding{
					RuleID:   ruleID,
					Severity: severity,
					File:     pipeline.FilePath(),
					Line:     step.Line,
					Message:  fmt.Sprintf(msgFmt, dv, job.Name),
					Details:  details,
				})
				break
			}
		}
	}
	return findings
}
