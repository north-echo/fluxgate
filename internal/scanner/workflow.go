package scanner

import pkgscanner "github.com/north-echo/fluxgate/pkg/scanner"

type Workflow = pkgscanner.Workflow
type TriggerConfig = pkgscanner.TriggerConfig
type PermissionsConfig = pkgscanner.PermissionsConfig
type Job = pkgscanner.Job
type Step = pkgscanner.Step

var ParseWorkflow = pkgscanner.ParseWorkflow
var ParseWorkflowFile = pkgscanner.ParseWorkflowFile
var HasElevatedPermissions = pkgscanner.HasElevatedPermissions
var AccessesSecrets = pkgscanner.AccessesSecrets
