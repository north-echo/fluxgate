package scanner

// Rule is a function that checks a workflow and returns findings.
type Rule func(wf *Workflow) []Finding

// allRules is the immutable rule registry, built once. ScanWorkflow ranges
// over it directly instead of allocating a fresh map per file scanned.
var allRules = map[string]Rule{
	"FG-001": CheckPwnRequest,
	"FG-002": CheckScriptInjection,
	"FG-003": CheckTagPinning,
	"FG-004": CheckBroadPermissions,
	"FG-005": CheckSecretsInLogs,
	"FG-006": CheckForkPRCodeExec,
	"FG-007": CheckTokenExposure,
	"FG-008": CheckOIDCMisconfiguration,
	"FG-009": CheckSelfHostedRunner,
	"FG-010": CheckCachePoisoning,
	"FG-011": CheckBotActorTOCTOU,
	"FG-012": CheckIfAlwaysTrue,
	"FG-013": CheckAllSecretsExposed,
	"FG-014": CheckMissingPermsRisky,
	"FG-015": CheckCurlPipeBash,
	"FG-016": CheckLocalActionUntrustedCheckout,
	"FG-017": CheckGitHubScriptInjection,
	"FG-018": CheckImpostorCommit,
	"FG-019": CheckHardcodedCredentials,
	"FG-020": CheckRefConfusion,
	"FG-021": CheckCrossStepOutputTaint,
	"FG-022": CheckKnownVulnerableActions,
	"FG-023": CheckArtifactCredentialLeak,
	"FG-024": CheckGitHubEnvInjection,
	"FG-025": CheckKnownIOCs,
	"FG-026": CheckLifecycleInstallBeforeCredentialedOperation,
	"FG-027": CheckLabelGateTOCTOU,
}

// AllRules returns all enabled detection rules. The returned map is a copy;
// callers may mutate it without affecting scanning.
func AllRules() map[string]Rule {
	out := make(map[string]Rule, len(allRules))
	for id, r := range allRules {
		out[id] = r
	}
	return out
}

// RuleDescriptions maps rule IDs to human-readable descriptions.
var RuleDescriptions = map[string]string{
	"FG-001": "Pwn Request",
	"FG-002": "Script Injection",
	"FG-003": "Tag-Based Pinning",
	"FG-004": "Broad Permissions",
	"FG-005": "Secrets in Logs",
	"FG-006": "Fork PR Code Execution",
	"FG-007": "Token Exposure in Build Steps",
	"FG-008": "OIDC Misconfiguration",
	"FG-009": "Self-Hosted Runner",
	"FG-010": "Cache Poisoning",
	"FG-011": "Bot Actor Guard TOCTOU",
	"FG-012": "If Always True",
	"FG-013": "All Secrets Exposed",
	"FG-014": "Missing Permissions on Risky Events",
	"FG-015": "Unverified Script Execution",
	"FG-016": "Local Action After Untrusted Checkout",
	"FG-017": "GitHub Script Injection",
	"FG-018": "Impostor Commit",
	"FG-019": "Hardcoded Container Credentials",
	"FG-020": "Ref Confusion",
	"FG-021": "Cross-Step Output Taint",
	"FG-022": "Known Vulnerable Action",
	"FG-023": "Artifact Credential Leak",
	"FG-024": "GitHub Env Injection",
	"FG-025": "Known Threat-Actor IOC",
	"FG-026": "Lifecycle Install Before Credentialed Operation",
	"FG-027": "TOCTOU Label Gate",
}
