# Phase 4: Traceability and Drift Enforcement - Context

**Gathered:** 2026-03-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Enforce strict requirement traceability and cross-artifact drift detection so phase and milestone transitions only pass when requirement-to-phase links are one-to-one and consistent across `.planning/REQUIREMENTS.md`, `.planning/ROADMAP.md`, and execution state evidence.

</domain>

<decisions>
## Implementation Decisions

### Traceability Contract
- Canonical source of requirement-to-phase mapping is the Traceability table in `.planning/REQUIREMENTS.md`.
- One-to-one enforcement applies to `v1` and `v2` active requirements.
- Mapping identity must normalize to canonical numeric phase IDs (`2`, `3`, `4`, `2.1`), with aliases such as `Phase 4` interpreted to the same canonical token.
- Any requirement mapped to zero phases or more than one phase is a hard error.

### Drift Error Policy
- Missing mapping for an active requirement is a hard error.
- Mapping to a phase not present in roadmap is a hard error.
- State-vs-mapping mismatches are hard errors (for example requirement marked complete while mapped phase is not complete, or inverse).
- Drift failures must be grouped deterministically in fixed order.

### Phase Complete Blocking Rules
- `phase complete` validates touched requirement IDs only (`--requirement-id` scope), and hard-fails on unknown, unmapped, or inconsistent IDs.
- `phase complete` must hard-fail when no touched requirement IDs are provided.
- Requirement `Complete` status is valid only when the mapped phase is complete.
- Successful checks must record deterministic evidence including command, scope, and sorted touched requirement IDs.

### Remediation and Output Contract
- Default operator output remains grouped checklist format (issue + fix) aligned with existing governance gate style.
- Failure output must include explicit retry command text.
- Failure group rendering order is fixed/canonical for deterministic tests and operator scanning.
- Precheck remains non-blocking (exit `0`) while still surfacing drift failures clearly in output/payload.

### Claude's Discretion
- Exact failure group names, provided they remain stable/deterministic and cover the agreed mismatch taxonomy.
- Exact wording of checklist and remediation text.
- Exact payload shape additions beyond required gate evidence fields.

</decisions>

<specifics>
## Specific Ideas

- Preserve fail-closed transitions for completion commands; precheck stays readiness-focused and non-blocking.
- Keep operator experience consistent with existing governance/requirements gates (grouped failures + actionable remediation).

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `scripts/governance_gates.py`: Existing deterministic gate engine, grouped failure taxonomy, and remediation formatter patterns.
- `scripts/quick_bootstrap.py`: Existing transition wrapper and evidence logging paths for `milestone`, `roadmap`, `requirements`, and `phase complete`.
- `tests/unit/test_governance_gates.py`: Existing test style for ordered failure groups and contract validation behavior.
- `tests/unit/test_quick_bootstrap.py`: Existing transition-enforcement tests for fail-closed and read-only blocked paths.

### Established Patterns
- Gate logic is centralized in `scripts/governance_gates.py` and consumed by CLI wrappers.
- Failure output uses deterministic grouped checklists with retry guidance.
- Blocked transitions record gate evidence without advancing success state.

### Integration Points
- Extend requirements gate evaluation to validate traceability table semantics and cross-artifact drift checks.
- Wire traceability enforcement into `phase complete` touched-scope checks and existing milestone/roadmap paths where consistency guarantees are required.
- Record pass/fail traceability evidence in `.planning/STATE.md` via existing gate activity update mechanisms.

</code_context>

<deferred>
## Deferred Ideas

- Automated traceability matrix generation UX enhancements (tracked under v2 `GUX-01`).
- Advanced bypass/exception workflows and delta reports (tracked under `ATR-*`).

</deferred>

---

*Phase: 04-traceability-and-drift-enforcement*
*Context gathered: 2026-03-01*
