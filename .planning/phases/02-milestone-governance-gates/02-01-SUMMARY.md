---
phase: 02-milestone-governance-gates
plan: 1
subsystem: governance
tags: [milestone, gate, audit, pytest]
requires:
  - phase: 01-quick-bootstrap
    provides: deterministic planning artifacts in .planning
provides:
  - fail-closed milestone governance evaluator
  - canonical v1.1 milestone audit artifact contract
  - deterministic grouped failure formatter with retry guidance
affects: [milestone completion, precheck, roadmap-state coherence]
tech-stack:
  added: []
  patterns: [fail-closed gate evaluation, deterministic failure grouping, TDD red-green cycle]
key-files:
  created:
    - scripts/governance_gates.py
    - tests/unit/test_governance_gates.py
    - .planning/v1.1-MILESTONE-AUDIT.md
  modified:
    - scripts/governance_gates.py
    - tests/unit/test_governance_gates.py
key-decisions:
  - "Gate validity requires exact status=passed plus required markdown sections."
  - "Failure groups are returned in canonical order: missing_file, invalid_status, malformed_sections, stale_audit."
patterns-established:
  - "Governance checks return structured failure_groups with severity=error only."
  - "Formatter output always ends with a single copy-paste retry command."
requirements-completed: [GOV-01, GOV-02]
duration: 2 min
completed: 2026-03-01
---

# Phase 2 Plan 1: Milestone Governance Gates Summary

**Fail-closed milestone governance gate now blocks missing/invalid/stale audit artifacts with deterministic grouped failures and retry guidance.**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-01T13:02:07Z
- **Completed:** 2026-03-01T13:04:23Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- Added `evaluate_milestone_governance_gate()` with canonical audit path resolution and fail-closed checks.
- Added `format_gate_failures()` with actionable checklist output and single retry command.
- Added test coverage for missing file, invalid status, malformed sections, stale audit, grouping determinism, and formatter guidance.

## Task Commits

Each task was committed atomically (TDD produced RED and GREEN commits per task):

1. **Task 1 (RED):** `b7085fc` (`test`)
2. **Task 1 (GREEN):** `85af5cb` (`feat`)
3. **Task 2 (RED):** `699ceb7` (`test`)
4. **Task 2 (GREEN):** `3a7eda1` (`feat`)

## Files Created/Modified
- `scripts/governance_gates.py` - Gate evaluator, staleness checks, deterministic grouping, and formatter.
- `tests/unit/test_governance_gates.py` - Unit tests covering fail-closed and stale/grouped/retry behavior.
- `.planning/v1.1-MILESTONE-AUDIT.md` - Canonical milestone audit artifact with required contract sections.

## Decisions Made
- Enforced exact `status: passed` as the only pass condition for GOV-02.
- Required explicit audit sections (`Scope`, `Checks`, `Findings`, `Remediation`) to prevent malformed artifacts passing.
- Used `STATE.md:last_updated` and `ROADMAP.md` mtime as staleness signals for gate evaluation.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Pre-commit `black` reformatted the new test file before first RED commit; resolved by re-staging and committing.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Plan `02-02-PLAN.md` can now consume the shared evaluator and formatter for milestone precheck/complete integration.

## Self-Check: PASSED

- Verified required files exist on disk.
- Verified all task commit hashes exist in git history.
