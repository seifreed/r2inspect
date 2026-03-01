---
phase: 03-requirements-contract-enforcement
plan: 01
subsystem: testing
tags: [governance, requirements, validation, pytest]
requires:
  - phase: 02-milestone-governance-gates
    provides: deterministic gate evaluation envelope and remediation formatting patterns
provides:
  - Canonical REQUIREMENTS.md entry schema with explicit id/status/acceptance_criteria fields
  - Shared requirements contract evaluator with deterministic failure groups
  - Requirements contract failure formatter with grouped remediation checklist
affects: [phase-04-traceability-drift-enforcement, quick-bootstrap-gates]
tech-stack:
  added: []
  patterns: [fail-closed deterministic validation, grouped remediation formatting]
key-files:
  created: [.planning/phases/03-requirements-contract-enforcement/03-01-SUMMARY.md]
  modified: [.planning/REQUIREMENTS.md, scripts/governance_gates.py, tests/unit/test_governance_gates.py]
key-decisions:
  - "Requirement entries are parsed only from v1/v2/Out of Scope sections using explicit `#### Requirement` blocks."
  - "Missing acceptance criteria is tracked under `missing_acceptance_criteria` while missing id/status is `malformed_entry`."
patterns-established:
  - "Requirements contract gate returns stable envelope: passed/failure_groups/retry_command/requirements_file."
  - "Failure groups for requirements are canonicalized as missing_file, malformed_entry, invalid_id_format, duplicate_id, invalid_status, missing_acceptance_criteria."
requirements-completed: [REQ-01, REQ-02]
duration: 3 min
completed: 2026-03-01
---

# Phase 3 Plan 1: Requirements Contract Enforcement Summary

**Canonical requirements contract enforcement with deterministic schema parsing, ID/status validation, and grouped remediation output**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-01T13:36:45Z
- **Completed:** 2026-03-01T13:40:38Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- Migrated `.planning/REQUIREMENTS.md` to explicit per-requirement `id`, `status`, and `acceptance_criteria` fields.
- Added shared `evaluate_requirements_contract_gate` in `scripts/governance_gates.py` with deterministic fail-closed taxonomy.
- Added `format_requirements_contract_failures` plus unit coverage for malformed entries, ID format, duplicates, status, acceptance criteria, and stable success envelope.

## Task Commits

Each task was committed atomically:

1. **Task 1: Introduce explicit requirements-entry schema and deterministic parser tests**
- `76e06a6` (test): RED tests for malformed entry, invalid ID format, duplicate IDs, and deterministic order.
- `0f193b5` (feat): Canonical schema migration and initial requirements gate implementation.
2. **Task 2: Implement shared requirements contract gate and remediation formatter**
- `8f9e363` (test): RED tests for invalid status, missing acceptance criteria, formatter output, and stable passed envelope.
- `1e59a80` (feat): Status/acceptance validation and requirements formatter implementation.

## Files Created/Modified
- `.planning/REQUIREMENTS.md` - Canonical requirement schema entries across v1, v2, and Out of Scope.
- `scripts/governance_gates.py` - Added `evaluate_requirements_contract_gate` and `format_requirements_contract_failures`.
- `tests/unit/test_governance_gates.py` - Added requirements-gate unit coverage and deterministic order assertions.

## Decisions Made
- Parse contract entries only from explicit `#### Requirement` blocks in `v1`, `v2`, and `Out of Scope` sections to keep validation deterministic.
- Keep acceptance criteria errors in dedicated `missing_acceptance_criteria` group for clearer remediation and stable taxonomy.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
- During RED validation, the shared test fixture initially used `V2-01`, which violated `CAT-NN` and masked status assertions. Updated fixture to `AUX-01` and continued.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Requirements contract gate is ready for integration into transition/precheck command paths.
- Phase 03 has remaining plan `03-02` pending.

## Self-Check: PASSED

---
*Phase: 03-requirements-contract-enforcement*
*Completed: 2026-03-01*
