# Phase 2: Milestone Governance Gates - Research

**Researched:** 2026-03-01
**Domain:** GSD milestone completion governance (fail-closed audit gate)
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
### Audit Contract
- Canonical audit path for gate checks is `.planning/vX.Y-MILESTONE-AUDIT.md` (root path only in this phase).
- Gate pass condition is strict: only `status: passed` is accepted.
- Audit staleness blocks completion when roadmap/state changes occur after audit timestamp.
- Audit artifacts missing required sections are treated as invalid and fail closed.

### Failure Output
- Gate failures must return a checklist-style output with concrete fixes and one deterministic retry command.
- Multiple failures should be grouped by failure type (missing file, invalid status, stale audit, malformed sections).
- Output severity model is error-only for phase 2 (no warning bypass mode).
- Retry guidance must always be present in failure output.

### Gate Timing
- Enforcement point is milestone completion boundary (`$gsd-complete-milestone`).
- Add explicit non-blocking readiness precheck command/path before final completion attempt.
- Evaluation inputs are audit artifact plus roadmap/state metadata needed for staleness/coherence checks.
- On gate failure, completion flow must abort before state advancement, archive finalization, and git tagging.

### Claude's Discretion
- Exact wording/format of remediation checklist output.
- Exact command name/shape for precheck surface, as long as behavior matches locked decisions.

### Deferred Ideas (OUT OF SCOPE)
- Exception workflow with temporary bypass (owner, expiry, remediation) deferred to Phase 4.
- Rich traceability/coverage matrix generation deferred to later phases (3-4).
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| GOV-01 | Milestone completion fails when the milestone audit artifact is missing. | Add mandatory gate check at start of `milestone complete`; fail before any archive/state mutation. |
| GOV-02 | Milestone completion fails when audit status is not `passed`. | Parse audit frontmatter and enforce exact `status === "passed"`; treat missing/invalid status as hard failure. |
| GOV-03 | Gate failure output includes actionable remediation steps for the operator. | Reuse structured issue envelope pattern (`code`, `message`, `fix`) and print checklist + deterministic retry command. |
</phase_requirements>

## Summary

Phase 2 should be planned as a focused change to milestone completion flow in `gsd-tools`: insert a fail-closed governance gate at the very beginning of `milestone complete`, plus a non-blocking precheck command that runs the same checks without mutating state. The current implementation in `lib/milestone.cjs` archives files and updates `MILESTONES.md`/`STATE.md` with no audit validation, so governance can be bypassed today.

The gate contract must be deterministic and narrow: validate canonical audit file path, validate frontmatter contract (including required sections), validate strict `status: passed`, and validate staleness against `ROADMAP.md`/`STATE.md` timestamps. Any failure must stop completion immediately and return grouped remediation errors with one copy-paste retry command.

**Primary recommendation:** Implement a shared `evaluateMilestoneGovernanceGate()` function used by both `milestone precheck` (new) and `milestone complete` (enforced), with identical failure classification and output.

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Node.js `fs`/`path` | Existing runtime | File existence, read, stat timestamps | Already used in `milestone.cjs`; no new dependency needed |
| `extractFrontmatter` (`lib/frontmatter.cjs`) | Existing in GSD tools | Parse audit frontmatter keys like `status`, `audited` | Existing parser used across tooling; keeps behavior consistent |
| `output`/`error` (`lib/core.cjs`) | Existing in GSD tools | Deterministic CLI output in raw/text modes | Required for consistent UX across workflow commands |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `verify.cjs` issue envelope pattern (`addIssue`) | Existing | Structured error objects with fix guidance | Reuse for grouped gate failure output |
| `.planning/STATE.md` frontmatter (`last_updated`) | Existing project artifact | Coherence/staleness reference timestamp | Compare against audit timestamp |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Reusing `extractFrontmatter` | Bring YAML parser dependency | Unnecessary for this scope; larger change surface |
| Gating only in workflow markdown | Enforce in CLI code (`milestone.cjs`) | Workflow-only checks are bypassable; CLI enforcement is required |

## Architecture Patterns

### Recommended Project Structure

```text
~/.claude/get-shit-done/bin/lib/
  milestone.cjs          # Add gate evaluation call + precheck subcommand handler target
  verify.cjs             # Optional home for shared gate validation helpers
  core.cjs               # Reuse output/error helper
```

### Pattern 1: Shared Gate Evaluator (single source of truth)
**What:** One function returns `{ passed, failures_by_type, retry_command }`.
**When to use:** Both precheck and completion enforcement.
**Example:**

```javascript
function evaluateMilestoneGovernanceGate(cwd, version) {
  // 1) resolve audit path
  // 2) validate required sections/frontmatter keys
  // 3) validate status === 'passed'
  // 4) validate staleness versus STATE/ROADMAP timestamps
  // 5) return grouped failures + fixes + deterministic retry command
}
```

### Pattern 2: Fail Before Mutation
**What:** Run gate before any archive, rename, or state update.
**When to use:** `cmdMilestoneComplete` entry point.
**Example:**

```javascript
const gate = evaluateMilestoneGovernanceGate(cwd, version);
if (!gate.passed) {
  output(gate, raw, 'blocked');
  return;
}
// Existing archival/state logic starts here
```

### Pattern 3: Non-Blocking Readiness Surface
**What:** Add `milestone precheck <version>` command using same evaluator.
**When to use:** Operator wants to verify readiness before final complete.
**Example:**

```bash
node ~/.claude/get-shit-done/bin/gsd-tools.cjs milestone precheck v1.1 --raw
```

### Anti-Patterns to Avoid
- **Duplicate logic for precheck vs complete:** causes drift and conflicting results.
- **Partial writes before gate result:** violates fail-closed behavior and complicates rollback.
- **Ad-hoc string parsing for all audit semantics:** use frontmatter parsing and explicit required-key checks.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| CLI result formatting | Custom print branches per check | Existing `output()` helper + structured object | Keeps raw and human output deterministic |
| YAML parsing | New parser implementation | Existing `extractFrontmatter()` | Already available and sufficient for gate fields |
| Error taxonomy | Free-form prose strings | Typed failure groups (`missing_file`, `invalid_status`, `stale_audit`, `malformed_sections`) | Needed for actionable remediation and reliable tests |

**Key insight:** This phase is governance behavior at one boundary, not a new subsystem. Plan for minimal, centralized checks with strong determinism.

## Common Pitfalls

### Pitfall 1: Enforcing gate too late
**What goes wrong:** Milestone artifacts are already archived/updated before failure is detected.
**Why it happens:** Gate check inserted mid-function in `cmdMilestoneComplete`.
**How to avoid:** Make gate the first operation after argument validation.
**Warning signs:** `MILESTONES.md` changes even when audit is invalid.

### Pitfall 2: Ambiguous staleness semantics
**What goes wrong:** Operators see inconsistent stale/non-stale results.
**Why it happens:** No explicit precedence between `audited` frontmatter time and artifact modification times.
**How to avoid:** Define deterministic rule order in plan: parse `audited`; if missing/invalid -> malformed failure; compare against `STATE.md` frontmatter `last_updated` and `ROADMAP.md` mtime.
**Warning signs:** Same inputs produce different gate outcomes across runs.

### Pitfall 3: Non-actionable failure output
**What goes wrong:** Gate blocks completion but does not explain exact fix path.
**Why it happens:** Generic errors without grouped remediation and retry command.
**How to avoid:** Each failure group must include concrete fix and include one deterministic retry command every time.
**Warning signs:** Operators ask which command to run next after a block.

## Code Examples

Verified patterns from existing codebase:

### Existing completion mutation point (must be guarded first)
Source: `~/.claude/get-shit-done/bin/lib/milestone.cjs`

```javascript
// Archive ROADMAP.md
if (fs.existsSync(roadmapPath)) {
  const roadmapContent = fs.readFileSync(roadmapPath, 'utf-8');
  fs.writeFileSync(path.join(archiveDir, `${version}-ROADMAP.md`), roadmapContent, 'utf-8');
}
```

### Existing structured issue pattern to mirror
Source: `~/.claude/get-shit-done/bin/lib/verify.cjs`

```javascript
const addIssue = (severity, code, message, fix, repairable = false) => {
  const issue = { code, message, fix, repairable };
  if (severity === 'error') errors.push(issue);
  else if (severity === 'warning') warnings.push(issue);
  else info.push(issue);
};
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Milestone completion without mandatory gate | Fail-closed completion gate with precheck-first workflow | Phase 2 target (2026-03 planning) | Prevents silent governance drift and incomplete milestone closure |

**Deprecated/outdated:**
- Milestone completion based only on phase stats/archive operations without validating audit contract.

## Open Questions

1. **Required audit sections contract (exact list)**
- What we know: malformed/missing required sections must fail closed.
- What's unclear: exact mandatory keys/sections to enforce in this phase.
- Recommendation: lock a minimal explicit contract in plan (frontmatter keys + required markdown section headers) and test each missing-key path.

2. **Precheck command naming**
- What we know: must be explicit and non-blocking.
- What's unclear: final UX shape (`milestone precheck` vs `verify milestone-gate`).
- Recommendation: choose `milestone precheck <version>` to keep milestone operations grouped and discoverable.

## Sources

### Primary (HIGH confidence)
- `.planning/phases/02-milestone-governance-gates/02-CONTEXT.md` - locked decisions, timing, failure output requirements.
- `.planning/REQUIREMENTS.md` - GOV-01/02/03 requirement definitions.
- `~/.claude/get-shit-done/bin/lib/milestone.cjs` - current milestone completion behavior and missing gate.
- `~/.claude/get-shit-done/bin/gsd-tools.cjs` - current CLI routing; confirms no precheck subcommand exists.
- `~/.claude/get-shit-done/bin/lib/verify.cjs` - structured issue/reporting pattern reusable for remediation output.
- `~/.claude/get-shit-done/bin/lib/frontmatter.cjs` - current frontmatter parsing behavior.

### Secondary (MEDIUM confidence)
- `~/.claude/get-shit-done/workflows/audit-milestone.md` - expected audit artifact semantics and fields.
- `~/.claude/get-shit-done/workflows/complete-milestone.md` - operator flow and readiness expectations.

### Tertiary (LOW confidence)
- None.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - relies on directly inspected runtime modules already in use.
- Architecture: HIGH - based on actual command routing and mutation points in current milestone path.
- Pitfalls: MEDIUM - derived from code-path analysis and workflow contracts; still needs plan-level contract lock for required section list.

**Research date:** 2026-03-01
**Valid until:** 2026-03-31
