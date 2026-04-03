package scanner

import pkgscanner "github.com/north-echo/fluxgate/pkg/scanner"

// Rule is a function that checks a workflow and returns findings.
type Rule = pkgscanner.Rule

var AllRules = pkgscanner.AllRules
var RuleDescriptions = pkgscanner.RuleDescriptions

// Re-export individual rule functions
var CheckPwnRequest = pkgscanner.CheckPwnRequest
var CheckScriptInjection = pkgscanner.CheckScriptInjection
var CheckTagPinning = pkgscanner.CheckTagPinning
var CheckBroadPermissions = pkgscanner.CheckBroadPermissions
var CheckSecretsInLogs = pkgscanner.CheckSecretsInLogs
var CheckForkPRCodeExec = pkgscanner.CheckForkPRCodeExec
var CheckTokenExposure = pkgscanner.CheckTokenExposure
var CheckOIDCMisconfiguration = pkgscanner.CheckOIDCMisconfiguration
var CheckSelfHostedRunner = pkgscanner.CheckSelfHostedRunner
var CheckCachePoisoning = pkgscanner.CheckCachePoisoning
var CheckBotActorTOCTOU = pkgscanner.CheckBotActorTOCTOU
var CheckIfAlwaysTrue = pkgscanner.CheckIfAlwaysTrue
var CheckAllSecretsExposed = pkgscanner.CheckAllSecretsExposed
var CheckMissingPermsRisky = pkgscanner.CheckMissingPermsRisky
var CheckCurlPipeBash = pkgscanner.CheckCurlPipeBash
var CheckLocalActionUntrustedCheckout = pkgscanner.CheckLocalActionUntrustedCheckout
var CheckGitHubScriptInjection = pkgscanner.CheckGitHubScriptInjection

// Re-export types used in tests
type MitigationAnalysis = pkgscanner.MitigationAnalysis
type ExecutionAnalysis = pkgscanner.ExecutionAnalysis

// classifyPipInstall is a wrapper for the test helper.
// The test file (package scanner) calls this directly.
func classifyPipInstall(args string) (bool, string) {
	return pkgscanner.ClassifyPipInstall(args)
}
