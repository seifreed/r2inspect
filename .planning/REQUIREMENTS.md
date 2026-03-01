# Requirements: r2inspect v1.1 Hardening

**Defined:** 2026-03-01
**Core Value:** Mantener entregas pequenas, verificables y acumulables.

## v1 Requirements

### Milestone Governance

#### Requirement

- id: GOV-01
- status: Complete
- acceptance_criteria: Milestone completion fails when the milestone audit artifact is missing.

#### Requirement

- id: GOV-02
- status: Complete
- acceptance_criteria: Milestone completion fails when audit status is not `passed`.

#### Requirement

- id: GOV-03
- status: Complete
- acceptance_criteria: Gate failure output includes actionable remediation steps for the operator.

### Requirements Contract

#### Requirement

- id: REQ-01
- status: Pending
- acceptance_criteria: "`REQUIREMENTS.md` enforces stable requirement IDs with deterministic format validation."

#### Requirement

- id: REQ-02
- status: Pending
- acceptance_criteria: Every active requirement includes status and acceptance criteria fields before planning continues.

#### Requirement

- id: REQ-03
- status: Pending
- acceptance_criteria: Requirement definitions are validated before roadmap creation and before milestone completion.

### Traceability & Drift

#### Requirement

- id: TRC-01
- status: Pending
- acceptance_criteria: Every active requirement is mapped to exactly one roadmap phase.

#### Requirement

- id: TRC-02
- status: Pending
- acceptance_criteria: Drift validation detects mismatches across `ROADMAP.md`, `REQUIREMENTS.md`, and execution state.

#### Requirement

- id: TRC-03
- status: Pending
- acceptance_criteria: Phase completion can only pass when requirement traceability links are complete and internally consistent.

## v2 Requirements

### Governance UX

#### Requirement

- id: GUX-01
- status: Pending
- acceptance_criteria: System auto-generates a requirement coverage matrix for each phase/milestone.

#### Requirement

- id: GUX-02
- status: Pending
- acceptance_criteria: Gate failures provide ranked remediation hints by impact.

### Advanced Traceability

#### Requirement

- id: ATR-01
- status: Pending
- acceptance_criteria: Exception workflow for temporary governance bypass with owner, expiry, and remediation task.

#### Requirement

- id: ATR-02
- status: Pending
- acceptance_criteria: Delta traceability reports showing coverage changes between consecutive quick tasks.

## Out of Scope

#### Requirement

- id: OOS-01
- status: Blocked
- acceptance_criteria: Spreadsheet-first external traceability remains out of scope because it creates dual source of truth and audit drift risk.

#### Requirement

- id: OOS-02
- status: Blocked
- acceptance_criteria: Manual milestone completion overrides without audit trail remain out of scope because they break governance guarantees and accountability.

#### Requirement

- id: OOS-03
- status: Blocked
- acceptance_criteria: Full ALM platform replication inside GSD quick workflow remains out of scope due to scope explosion relative to v1.1 hardening goals.

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| GOV-01 | Phase 2 | Complete |
| GOV-02 | Phase 2 | Complete |
| GOV-03 | Phase 2 | Complete |
| REQ-01 | Phase 3 | Complete |
| REQ-02 | Phase 3 | Complete |
| REQ-03 | Phase 3 | Complete |
| TRC-01 | Phase 4 | Pending |
| TRC-02 | Phase 4 | Pending |
| TRC-03 | Phase 4 | Pending |

**Coverage:**
- v1 requirements: 9 total
- Mapped to phases: 9
- Unmapped: 0

---
*Requirements defined: 2026-03-01*
*Last updated: 2026-03-01 after roadmap creation*
