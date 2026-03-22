# Fluxgate v0.4.0 — Mitigation Detection Gaps

**Date:** 2026-03-22
**Author:** Generated from triage-analysis.txt findings
**Status:** Spec

---

## Problem Statement

Manual triage of 11 FG-001 findings from the Red Hat rescan revealed four classes
of defensive controls that Fluxgate v0.3.0 does not detect. This causes:

- **False criticals:** Repos with solid gates (rhdh-operator environment approvals,
  image-builder-cli permission checks) report as critical instead of medium/high.
- **False positives:** Bot-gated workflows (backstage-community-plugins,
  rhdh-plugins) that can never fire from external forks report as critical
  instead of being suppressed.
- **Missed nuance:** Data-only fork checkouts (quarkusio l10n repos) where base
  branch scripts run on fork *data*, not fork *code*, report as confirmed
  code execution.

The manual triage downgraded or dismissed 9 of 11 findings. Fluxgate should
catch at least 7 of these automatically.

---

## Gap 1: Actor Guards

### What Fluxgate misses

Job-level `if:` conditions that restrict execution to specific bot accounts:

```yaml
if: github.actor == 'renovate[bot]' && github.repository == 'redhat-developer/rhdh-plugins'
```

```yaml
if: github.actor == 'backstage-goalie[bot]' && github.repository == 'backstage/community-plugins'
```

These make the workflow unreachable from external fork PRs — only the named bot
can trigger execution.

### Real-world examples from triage

| # | Repo | Guard | Triage result |
|---|------|-------|---------------|
| 7 | redhat-appstudio/backstage-community-plugins | `github.actor == 'backstage-goalie[bot]'` | FALSE POSITIVE |
| 11 | redhat-developer/rhdh-plugins | `github.actor == 'renovate[bot]'` | FALSE POSITIVE |

### Detection approach

Add actor guard detection to `analyzeMitigations` alongside the existing fork
guard and label check logic.

**New field on `MitigationAnalysis`:**

```go
ActorGuard bool // Job if: restricts execution to specific actor(s)
```

**New helper function `containsActorGuard`:**

```go
func containsActorGuard(ifExpr string) bool {
    // Match patterns like:
    //   github.actor == 'name[bot]'
    //   github.actor == "name[bot]"
    //   github.triggering_actor == 'name[bot]'
    // Only treat as a guard if the actor is a bot account ([bot] suffix)
    // or a known service account pattern.
    actorPatterns := []string{
        "github.actor ==",
        "github.triggering_actor ==",
    }
    lower := strings.ToLower(ifExpr)
    for _, p := range actorPatterns {
        if strings.Contains(lower, p) && strings.Contains(lower, "[bot]") {
            return true
        }
    }
    return false
}
```

**Severity adjustment:**

Actor guard to a bot account is a strong defense — external users cannot
impersonate GitHub App bots. Treat as equivalent to fork guard:

```
ActorGuard (bot) → severity = info, confidence = pattern-only
```

Rationale: A `github.actor == 'renovate[bot]'` check is *stronger* than a fork
guard — it restricts to a single bot identity, not just "any internal
contributor." The only bypass requires compromising the bot's GitHub App
credentials.

**Edge case — non-bot actors:**

If the `if:` checks `github.actor` against a human username (not `[bot]`), treat
it as a weaker mitigation (equivalent to maintainer check, downgrade by 1). Human
accounts can be compromised via phishing, leaked credentials, etc.

```go
func containsActorGuard(ifExpr string) (isBot bool, isHuman bool) {
    // Returns (true, false) for bot guards, (false, true) for human guards
}
```

**Also detect repo guards:**

Several actor-gated workflows also include `github.repository == 'org/repo'`
checks. When the workflow is in a *different* repo (e.g., backstage-community-plugins
has `github.repository == 'backstage/community-plugins'` but lives in
redhat-appstudio), the job can *never* execute — it's dead code. Fluxgate
could detect this by comparing the guard value against the scanned repo's
`owner/name`, but this requires passing the repo identity into the scanner.

For now, note this as a possible enhancement. The actor guard alone is sufficient
to suppress the false positive.

### Parser changes

None. The existing `job.If` field already captures the raw `if:` string. The
new detection is purely in `analyzeMitigations`.

### Test fixtures needed

**`test/fixtures/pwn-request-actor-guard-bot.yaml`:**
```yaml
name: Bot Only
on:
  pull_request_target:
    paths: ['**/yarn.lock']
jobs:
  generate:
    runs-on: ubuntu-latest
    if: github.actor == 'renovate[bot]'
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
      - run: node ./scripts/generate-changesets.js
```
Expected: FG-001 info severity (actor guard to bot).

**`test/fixtures/pwn-request-actor-guard-human.yaml`:**
```yaml
name: Allowed User
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  build:
    runs-on: ubuntu-latest
    if: contains(fromJSON('["alice","bob"]'), github.actor)
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make build
```
Expected: FG-001 high severity (downgraded by 1 for human actor guard).

---

## Gap 2: Action-Based Permission Gates

### What Fluxgate misses

Pre-checkout steps that use third-party actions to verify the triggering user
has write/admin permission on the repo:

```yaml
- name: Get User Permission
  id: checkAccess
  uses: actions-cool/check-user-permission@v2
  with:
    require: write
    username: ${{ github.triggering_actor }}
- name: Check User Permission
  if: steps.checkAccess.outputs.require-result == 'false'
  run: exit 1
```

This is functionally identical to the `getCollaboratorPermissionLevel` pattern
that Fluxgate already detects via `containsMaintainerCheck`, but uses a
pre-built action instead of `actions/github-script`.

### Real-world examples from triage

| # | Repo | Action | Triage result |
|---|------|--------|---------------|
| 3 | osbuild/image-builder-cli | `actions-cool/check-user-permission@v2` | HIGH (mitigated) |

### Detection approach

Expand `containsMaintainerCheck` to recognize common permission-checking actions
by their action reference, not just by script content.

**Updated `containsMaintainerCheck`:**

```go
func containsMaintainerCheck(step Step) bool {
    // 1. Check for known permission-checking actions
    permissionActions := []string{
        "actions-cool/check-user-permission",
        "prince-chrismc/check-actor-permissions-action",
        "lannonbr/repo-permission-check-action",
        "TheModdingInquisition/actions-team-membership",
    }
    for _, action := range permissionActions {
        if strings.Contains(step.Uses, action) {
            return true
        }
    }

    // 2. Check for permission verification in subsequent if: conditions
    //    (the step after the action checks outputs.require-result)
    //    — handled separately, see below

    // 3. Existing: check script content for API calls
    checkPatterns := []string{
        "getCollaboratorPermissionLevel",
        "repos.getCollaboratorPermission",
        "permission.permission",
    }
    searchText := step.Run
    if step.Uses != "" && strings.Contains(step.Uses, "actions/github-script") {
        if script, ok := step.With["script"]; ok {
            searchText = script
        }
    }
    for _, p := range checkPatterns {
        if strings.Contains(searchText, p) {
            return true
        }
    }
    return false
}
```

**Additional detection — exit-on-fail pattern:**

The permission action alone is not a gate unless a subsequent step exits on
failure. Look for the common pattern:

```yaml
- if: steps.checkAccess.outputs.require-result == 'false'
  run: exit 1
```

Update `analyzeMitigations` to scan pre-checkout steps as a sequence: if step N
is a permission action and step N+1 has an `if:` that references the permission
step's output and runs `exit 1`, treat the pair as a maintainer check.

```go
// In analyzeMitigations, after the existing pre-checkout loop:
for i, step := range preCheckoutSteps {
    if containsMaintainerCheck(step) {
        m.MaintainerCheck = true
        m.Details = append(m.Details, fmt.Sprintf(
            "pre-checkout permission check via %s (line %d)",
            truncate(step.Uses, 60), step.Line,
        ))
        break
    }
    // Also check for exit-on-fail after a permission action
    if i+1 < len(preCheckoutSteps) {
        next := preCheckoutSteps[i+1]
        if strings.Contains(next.If, step.Uses) || strings.Contains(next.If, "checkAccess") {
            if strings.Contains(next.Run, "exit 1") {
                m.MaintainerCheck = true
                m.Details = append(m.Details, fmt.Sprintf(
                    "pre-checkout permission gate with exit-on-fail (line %d)",
                    step.Line,
                ))
                break
            }
        }
    }
}
```

**Severity adjustment:**

Same as existing maintainer check — downgrade by 1 level.

### Parser changes

None. Step `Uses`, `If`, and `Run` fields are already captured.

### Test fixtures needed

**`test/fixtures/pwn-request-action-perm-gate.yaml`:**
```yaml
name: RHEL Test
on:
  pull_request_target:
    types: [opened, synchronize, reopened]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Get User Permission
        id: checkAccess
        uses: actions-cool/check-user-permission@v2
        with:
          require: write
          username: ${{ github.triggering_actor }}
      - name: Check User Permission
        if: steps.checkAccess.outputs.require-result == 'false'
        run: exit 1
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: pytest test/
```
Expected: FG-001 high severity (downgraded from critical by 1 for maintainer
check via action).

---

## Gap 3: Cross-Job `needs:` Gating (Authorize Pattern)

### What Fluxgate misses

A common pattern where an "authorize" job gates all subsequent jobs via `needs:`.
The authorize job uses GitHub environment protection to require manual approval
for external fork PRs:

```yaml
jobs:
  authorize:
    environment:
      ${{ (github.event.pull_request.head.repo.full_name == github.repository ||
      contains(fromJSON('["user1","user2"]'), github.event.pull_request.user.login))
      && 'internal' || 'external' }}
    runs-on: ubuntu-latest
    steps:
      - run: echo "✓"

  build:
    needs: authorize       # <-- THIS IS THE GATE
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make build
```

The `build` job cannot run until `authorize` completes. The `authorize` job uses
the `external` environment (configured with required reviewers) for fork PRs.
This is a solid gate — a maintainer must manually approve before fork code
executes.

Fluxgate currently checks `job.Environment` on the *executing* job but misses
the case where the environment gate is on an *upstream dependency* job.

### Real-world examples from triage

| # | Repo | Pattern | Triage result |
|---|------|---------|---------------|
| 8 | redhat-developer/rhdh-operator | `needs: authorize` → env `internal`/`external` | MEDIUM-HIGH |
| 9 | redhat-developer/rhdh-operator | `needs: authorize` → env `internal`/`external` | MEDIUM-HIGH |
| 10 | redhat-developer/rhdh-operator | `needs: authorize` → env `internal`/`external` | MEDIUM-HIGH |

All three rhdh-operator findings should have been downgraded from critical.

### Detection approach

#### Parser changes — add `Needs` field to Job

**Updated `rawJob`:**
```go
type rawJob struct {
    Name        string            `yaml:"name"`
    If          string            `yaml:"if"`
    Environment yaml.Node         `yaml:"environment"`
    Permissions yaml.Node         `yaml:"permissions"`
    Steps       []rawStep         `yaml:"steps"`
    Secrets     string            `yaml:"secrets"`
    Needs       yaml.Node         `yaml:"needs"`      // NEW
}
```

**Updated `Job`:**
```go
type Job struct {
    Name        string
    If          string
    Environment string
    Permissions PermissionsConfig
    Steps       []Step
    Secrets     string
    Needs       []string  // NEW — list of job IDs this job depends on
}
```

**Parsing `needs:`:**

The `needs` field can be either a string or a list:

```yaml
needs: authorize          # string
needs: [authorize, lint]  # list
```

```go
func parseNeeds(node yaml.Node) []string {
    if node.Kind == yaml.ScalarNode {
        return []string{node.Value}
    }
    if node.Kind == yaml.SequenceNode {
        var needs []string
        for _, n := range node.Content {
            needs = append(needs, n.Value)
        }
        return needs
    }
    return nil
}
```

#### Mitigation detection — follow `needs:` chain

**New field on `MitigationAnalysis`:**
```go
NeedsGate bool // Job depends on an upstream job with environment/fork guard
```

**Updated `analyzeMitigations` signature:**

The function currently receives a single `Job`. To follow `needs:` chains, it
needs access to all jobs in the workflow:

```go
func analyzeMitigations(wf *Workflow, job Job, checkoutIdx int,
    postCheckoutSteps []Step, allJobs map[string]Job) MitigationAnalysis {
```

**New logic in `analyzeMitigations`:**

```go
// 6. Check needs: chain for upstream environment/fork gates
for _, depName := range job.Needs {
    if dep, ok := allJobs[depName]; ok {
        if dep.Environment != "" {
            m.NeedsGate = true
            m.EnvironmentGated = true
            m.Details = append(m.Details, fmt.Sprintf(
                "depends on job '%s' with environment '%s' (requires approval)",
                depName, dep.Environment,
            ))
        }
        if dep.If != "" && containsForkGuard(dep.If) {
            m.NeedsGate = true
            m.ForkGuard = true
            m.Details = append(m.Details, fmt.Sprintf(
                "depends on job '%s' with fork guard",
                depName,
            ))
        }
    }
}
```

**Handling dynamic environment expressions:**

The rhdh-operator authorize job uses a *ternary expression* for the environment
name:

```yaml
environment:
  ${{ (...) && 'internal' || 'external' }}
```

This evaluates to either `internal` or `external` at runtime. The parser
currently captures this as the literal string
`${{ (...) && 'internal' || 'external' }}`. That's fine — any non-empty
environment value should be treated as potentially gated. The key signal is
that an environment exists, not which specific environment name it is.

**Depth limit:**

Only follow one level of `needs:`. Deeper chains are rare and add complexity
without proportional value. If job A `needs: B` and job B `needs: C`, only
check B's gates, not C's.

**Severity adjustment:**

Same as direct environment gate — the protection is equally strong whether it's
on the job itself or an upstream dependency:

```
NeedsGate with environment → same as EnvironmentGated (downgrade by 1)
NeedsGate with fork guard  → same as ForkGuard (severity = info)
```

### Caller changes

`CheckPwnRequest` needs to pass `wf.Jobs` (as a map) to `analyzeMitigations`.
The `Workflow.Jobs` field is currently a `[]Job` (slice). Either:

(a) Change `Workflow.Jobs` to `map[string]Job` — breaking change but more
    natural for job lookups.
(b) Keep the slice, add a `JobsByName map[string]Job` field populated during
    parsing.
(c) Build the map in `CheckPwnRequest` before calling `analyzeMitigations`.

**Recommendation:** Option (c) — minimal blast radius. Build a local map:

```go
jobMap := make(map[string]Job, len(wf.Jobs))
for _, j := range wf.Jobs {
    jobMap[j.Name] = j
}
```

**Important:** The job map key must be the YAML key (e.g., `authorize`), not the
`name:` field (e.g., `"PR Bundle Manifests Validator"`). Currently `Job.Name` is
set from the YAML key in the parser. Verify this is the case.

### Test fixtures needed

**`test/fixtures/pwn-request-needs-gate.yaml`:**
```yaml
name: Gated Build
on:
  pull_request_target:
    types: [opened, synchronize, reopened]
jobs:
  authorize:
    environment:
      ${{ github.event.pull_request.head.repo.full_name == github.repository && 'internal' || 'external' }}
    runs-on: ubuntu-latest
    steps:
      - run: echo "approved"
  build:
    needs: authorize
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make build
```
Expected: FG-001 high severity (downgraded from critical by 1 for environment
gate via needs chain). Mitigations should list: "depends on job 'authorize' with
environment '...' (requires approval)".

**`test/fixtures/pwn-request-needs-fork-guard.yaml`:**
```yaml
name: Fork Gated
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  check:
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    steps:
      - run: echo "internal PR"
  build:
    needs: check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
```
Expected: FG-001 info severity (fork guard via needs chain).

---

## Gap 4: Data-Only Fork Checkout

### What Fluxgate misses

Workflows that checkout fork code to a subdirectory and only copy *data files*
from it, while executing scripts exclusively from the base branch:

```yaml
steps:
  - name: Checkout base branch
    uses: actions/checkout@v3                    # base branch (safe)
  - name: Checkout fork to 'merged' dir
    uses: actions/checkout@v3
    with:
      ref: ${{ github.event.pull_request.head.sha }}
      path: merged                               # fork code isolated in subdir
  - run: cp -r merged/l10n ./                    # copy DATA only
  - run: bin/setup-build-env-on-ubuntu           # base branch script
  - run: vendor/quarkus-l10n-utils/bin/build-for-preview  # base branch script
```

Fluxgate sees `actions/checkout` with `ref: PR head` and flags it. Then
`analyzePostCheckoutExecution` sees `run:` blocks and classifies them as
confirmed execution. But the `run:` blocks execute base branch scripts, not
fork code.

### Real-world examples from triage

| # | Repo | Pattern | Triage result |
|---|------|---------|---------------|
| 5 | quarkusio/ja.quarkus.io | fork to `merged/`, copy `l10n/`, base scripts | HIGH (pattern-only) |
| 6 | quarkusio/pt.quarkus.io | same pattern | HIGH (pattern-only) |

### Detection approach

This is the hardest gap to close reliably. The challenge is distinguishing:

- `cp -r merged/l10n ./` (data copy — no execution)
- `cd merged && make build` (direct fork code execution)
- `pip install -e merged/` (indirect fork code execution via setup.py)

#### Approach: Detect `path:` isolation on checkout

When a checkout uses the `path:` parameter, fork code is isolated in that
subdirectory. If no subsequent `run:` block references that path in an
execution context, the risk is lower.

**Step 1 — Track checkout path in `CheckPwnRequest`:**

```go
checkoutPath := step.With["path"]  // e.g., "merged"
```

**Step 2 — Classify post-checkout commands by fork code interaction:**

Add a new analysis function:

```go
type ForkCodeInteraction int

const (
    ForkExecDirect   ForkCodeInteraction = iota // cd merged && make
    ForkExecIndirect                            // pip install merged/
    ForkDataOnly                                // cp merged/data ./
    ForkNoInteraction                           // runs unrelated commands
)

func classifyForkInteraction(step Step, checkoutPath string) ForkCodeInteraction
```

**Classification rules:**

| Pattern | Classification | Example |
|---------|---------------|---------|
| `cd <path>` followed by build command | ForkExecDirect | `cd merged && make build` |
| `<path>/script` or `./<path>/script` | ForkExecDirect | `./merged/build.sh` |
| `pip install <path>` / `pip install -e <path>` | ForkExecIndirect | `pip install -e merged/` |
| `npm install --prefix <path>` | ForkExecIndirect | |
| `go test ./<path>/...` | ForkExecDirect | |
| `cp -r <path>/subdir ./` | ForkDataOnly | `cp -r merged/l10n ./` |
| `mv <path>/file ./` | ForkDataOnly | |
| `rsync <path>/dir ./dest` | ForkDataOnly | |
| No reference to `<path>` | ForkNoInteraction | `bin/setup-build-env` |

**Step 3 — Adjust confidence and severity:**

If the checkout has a `path:` and all post-checkout steps are `ForkDataOnly` or
`ForkNoInteraction`:

```go
if checkoutPath != "" && allStepsAreDataOnlyOrNoInteraction {
    confidence = ConfidencePatternOnly
    severity = downgradeBy(severity, 1)
    // Add detail: "fork code checked out to 'merged/' — only data files copied"
}
```

### Caveats and limitations

1. **Symlink attacks:** `cp -r merged/l10n ./` will follow symlinks. A malicious
   fork could place a symlink at `merged/l10n/evil -> ../../.github/workflows/`
   to overwrite base branch workflow files. Fluxgate should note this as a
   residual risk in the details, not suppress the finding entirely.

2. **Build tool config poisoning:** Even if only data files are copied, some
   build tools read config from the working directory. If `merged/l10n/` contains
   a `.babelrc`, `tsconfig.json`, or `Makefile`, the base branch build scripts
   might pick it up. This is hard to detect statically.

3. **False negatives:** If the classification is wrong (e.g., a `cp` command
   copies executable scripts that are later run), we'd suppress a real finding.

**Recommendation:** Implement the `path:` isolation detection but only downgrade
confidence, not severity. Change the finding message to indicate the fork code
is path-isolated but note the residual symlink/config risk.

```go
if checkoutPath != "" && noDirectForkExec {
    confidence = ConfidencePatternOnly  // not "confirmed"
    msg += " (fork code isolated to '" + checkoutPath + "/' — " +
           "no direct execution detected, verify data-only usage)"
}
```

This avoids the false "confirmed" classification while keeping the finding
visible for manual review.

### Parser changes

None. The `With` map already captures `path`.

### Test fixtures needed

**`test/fixtures/pwn-request-path-isolated.yaml`:**
```yaml
name: L10n Preview
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: merged
      - run: |
          rm -rf l10n
          cp -r merged/l10n ./
      - run: bin/build-preview
```
Expected: FG-001 high severity, confidence pattern-only (not confirmed). Details
should note path isolation.

**`test/fixtures/pwn-request-path-exec.yaml`:**
```yaml
name: Fork Build
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: pr
      - run: cd pr && make build
```
Expected: FG-001 critical, confidence confirmed. Path isolation does not help
when the fork code is directly executed.

---

## Implementation Priority

| Gap | Impact | Effort | Priority |
|-----|--------|--------|----------|
| Gap 1: Actor Guards | 2 false positives eliminated | Small — string matching only | P1 |
| Gap 3: Needs Gating | 3 false criticals fixed | Medium — parser + detection | P1 |
| Gap 2: Action Perm Gates | 1 false critical fixed | Small — pattern list expansion | P2 |
| Gap 4: Path Isolation | 2 confidence corrections | Large — command classification | P3 |

**Recommended order:** Gap 1 → Gap 3 → Gap 2 → Gap 4

Gaps 1-3 are high-confidence detections with clear true/false semantics. Gap 4
involves heuristic command classification and should be approached conservatively.

---

## Validation Plan

After implementation, rescan all 11 triage repos and verify:

| # | Repo | v0.3.0 | Expected v0.4.0 |
|---|------|--------|-----------------|
| 1 | konflux-ci/konflux-ui | critical | critical (custom shell gate — not detectable without deep analysis) |
| 2 | openshift/openstack-resource-controller | critical | critical (no change — unmitigated) |
| 3 | osbuild/image-builder-cli | critical | high (action perm gate detected) |
| 4 | osbuild/images | critical (×2) | critical (no change — unmitigated) |
| 5 | quarkusio/ja.quarkus.io | critical | critical or high, confidence → pattern-only (path isolation) |
| 6 | quarkusio/pt.quarkus.io | critical | critical or high, confidence → pattern-only (path isolation) |
| 7 | redhat-appstudio/backstage-community-plugins | critical | info (actor guard to bot) |
| 8 | redhat-developer/rhdh-operator | critical | high (needs gate → environment) |
| 9 | redhat-developer/rhdh-operator | critical | high (needs gate → environment) |
| 10 | redhat-developer/rhdh-operator | critical | high (needs gate → environment) |
| 11 | redhat-developer/rhdh-plugins | critical | info (actor guard to bot) |

Also rescan the 20 validation repos to verify no regressions.

---

## Non-Goals

- **Custom shell script analysis** (konflux-ui's bash-based allowed users list) —
  too fragile to parse arbitrary shell logic. The allowed users pattern in #1 is
  bespoke and rare.
- **GitHub repository settings detection** (required reviewers, branch protection) —
  this requires API calls beyond workflow file analysis.
- **Deep `needs:` chain traversal** — only follow one level. Multi-hop chains
  are rare.
- **Makefile/script content analysis** — analyzing what `make build` actually
  executes is out of scope for a workflow-level scanner.
