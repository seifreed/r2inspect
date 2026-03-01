# Phase 2: Milestone Governance Gates - Context

**Gathered:** 2026-03-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Implement fail-closed milestone governance gates so milestone completion only succeeds when required audit evidence exists, passes, and provides actionable remediation feedback when blocked. This phase defines gate behavior at milestone-completion boundary; it does not implement broader requirements-contract or traceability engines (those are later phases).

</domain>

<decisions>
## Implementation Decisions

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

</decisions>

<specifics>
## Specific Ideas

- Prioridad en esta fase: comportamiento determinista y fail-closed para evitar repetir cierre de milestone sin auditoría.
- Salida de error debe permitir reintento inmediato con comando copy-paste.

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `scripts/quick_bootstrap.py`: existing fail-fast preflight and deterministic error handling patterns that can be mirrored for milestone gate behavior.
- `.planning/ROADMAP.md`, `.planning/STATE.md`: existing lifecycle artifacts already updated by workflow tools and usable as coherence/staleness inputs.
- `.planning/MILESTONES.md`: shipped milestone history available for version-context and completion reporting.

### Established Patterns
- GSD workflow gating is command-centric and artifact-driven (checks happen at workflow boundaries, not continuously in background).
- `.planning` markdown artifacts act as source of truth for planning state and completion metadata.
- Deterministic outputs and explicit next-step commands are already expected in quick workflow summaries.

### Integration Points
- `gsd-tools` milestone completion path is the required enforcement point for hard gate behavior.
- Milestone readiness/precheck should integrate ahead of final completion execution.
- Gate outcomes should be surfaced in completion flow without mutating completion state on failure.

</code_context>

<deferred>
## Deferred Ideas

- Exception workflow with temporary bypass (owner, expiry, remediation) deferred to Phase 4.
- Rich traceability/coverage matrix generation deferred to later phases (3-4).

</deferred>

---

*Phase: 02-milestone-governance-gates*
*Context gathered: 2026-03-01*
