package scanner

import pkgscanner "github.com/north-echo/fluxgate/pkg/scanner"

// Rule is a function that checks a workflow and returns findings.
type Rule = pkgscanner.Rule

var AllRules = pkgscanner.AllRules
var RuleDescriptions = pkgscanner.RuleDescriptions
