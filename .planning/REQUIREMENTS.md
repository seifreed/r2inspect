# Requirements: r2inspect v1.1 Hardening

**Defined:** 2026-03-01
**Core Value:** Mantener entregas pequenas, verificables y acumulables.

## v1 Requirements

### Milestone Governance

- [x] **GOV-01**: Milestone completion fails when the milestone audit artifact is missing.
- [x] **GOV-02**: Milestone completion fails when audit status is not `passed`.
- [x] **GOV-03**: Gate failure output includes actionable remediation steps for the operator.

### Requirements Contract

- [ ] **REQ-01**: `REQUIREMENTS.md` enforces stable requirement IDs with deterministic format validation.
- [ ] **REQ-02**: Every active requirement includes status and acceptance criteria fields before planning continues.
- [ ] **REQ-03**: Requirement definitions are validated before roadmap creation and before milestone completion.

### Traceability & Drift

- [ ] **TRC-01**: Every active requirement is mapped to exactly one roadmap phase.
- [ ] **TRC-02**: Drift validation detects mismatches across `ROADMAP.md`, `REQUIREMENTS.md`, and execution state.
- [ ] **TRC-03**: Phase completion can only pass when requirement traceability links are complete and internally consistent.

## v2 Requirements

### Governance UX

- **GUX-01**: System auto-generates a requirement coverage matrix for each phase/milestone.
- **GUX-02**: Gate failures provide ranked remediation hints by impact.

### Advanced Traceability

- **ATR-01**: Exception workflow for temporary governance bypass with owner, expiry, and remediation task.
- **ATR-02**: Delta traceability reports showing coverage changes between consecutive quick tasks.

## Out of Scope

| Feature | Reason |
|---------|--------|
| Spreadsheet-first external traceability | Creates dual source of truth and audit drift risk |
| Manual milestone completion overrides without audit trail | Breaks governance guarantees and accountability |
| Full ALM platform replication inside GSD quick workflow | Scope explosion relative to v1.1 hardening goals |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| GOV-01 | Phase 2 | Complete |
| GOV-02 | Phase 2 | Complete |
| GOV-03 | Phase 2 | Complete |
| REQ-01 | Phase 3 | Pending |
| REQ-02 | Phase 3 | Pending |
| REQ-03 | Phase 3 | Pending |
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
