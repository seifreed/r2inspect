# Phase 3: Requirements Contract Enforcement - Context

**Gathered:** 2026-03-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Enforce a strict, deterministic `REQUIREMENTS.md` contract so roadmap and milestone transitions only proceed when requirement entries are structurally valid and complete. This phase is about contract validity and transition gating, not full cross-artifact traceability reconciliation (phase 4).

</domain>

<decisions>
## Implementation Decisions

### Requirement ID Rules
- Active requirement IDs must follow strict `CAT-NN` format (uppercase category + hyphen + numeric suffix of at least two digits).
- Requirement IDs must be globally unique within v1 requirements.
- Numbering continuity is not required (gaps allowed).
- Legacy non-compliant IDs are hard-blocked until migrated to compliant format.

### Required Fields Contract
- Every active requirement must include: stable ID, status token, and acceptance criteria.
- Allowed status tokens are strict finite set: `Pending`, `In Progress`, `Complete`, `Blocked`.
- Acceptance criteria must be non-empty and testable (concrete verifiable behavior).
- Strict schema applies to all sections (`v1`, `v2`, and `Out of Scope`) in this phase.

### Validation Timing and Gate Behavior
- Contract validation hard-blocks before roadmap creation/revision and before milestone completion.
- Phase completion should also enforce contract validity for touched requirements.
- Gate failures are read-only: no advancement writes to roadmap/requirements/state on failed validation.
- Add explicit non-blocking requirements precheck command/path for readiness checks.

### Claude's Discretion
- Exact precheck command naming and CLI output shape.
- Exact wording and grouping format for validation diagnostics, as long as contract semantics remain locked.

</decisions>

<specifics>
## Specific Ideas

- Goal is deterministic governance behavior: invalid requirement contracts must fail predictably before transitions.
- Precheck should make fixes obvious and reduce failed completion attempts.

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `scripts/governance_gates.py`: existing fail-closed gate engine pattern with deterministic grouped failures and retry hints.
- `scripts/quick_bootstrap.py`: existing command routing pattern already wired for milestone precheck/complete gate usage.
- `tests/unit/test_governance_gates.py` and milestone flow tests: reusable structure for new requirements-contract validation tests.
- `.planning/REQUIREMENTS.md`: active contract artifact already present with ID/status mappings and traceability table.

### Established Patterns
- Gate logic is centralized and reusable across precheck and transition commands.
- Failures are grouped by deterministic categories and surfaced with actionable remediation.
- Transition gates are fail-closed and avoid state advancement on validation failures.

### Integration Points
- Requirements contract validator should integrate with roadmap creation path and milestone completion flow.
- Phase completion flow should invoke validator for touched requirements before final completion.
- Precheck path should share core validator logic (no duplicated rule implementation).

</code_context>

<deferred>
## Deferred Ideas

- Full requirement-to-roadmap/state drift enforcement remains Phase 4 scope.
- Exception governance with temporary bypass and expiry remains deferred beyond this phase.

</deferred>

---

*Phase: 03-requirements-contract-enforcement*
*Context gathered: 2026-03-01*
