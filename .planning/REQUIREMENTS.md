# Requirements: r2inspect v1.2 Governance UX

**Defined:** 2026-03-01
**Core Value:** Mantener entregas pequenas, verificables y acumulables.

## v1 Requirements

### Governance UX

#### Requirement

- id: GUX-01
- status: Complete
- acceptance_criteria: Operators can generate a deterministic requirement coverage matrix for phase and milestone scope using current planning artifacts only.

#### Requirement

- id: GUX-02
- status: Complete
- acceptance_criteria: Operators receive deterministic remediation hints ranked by impact, with actionable next steps and retry commands.

## v2 Requirements

### Advanced Traceability

#### Requirement

- id: ATR-01
- status: Pending
- acceptance_criteria: Exception workflow supports temporary governance bypass with owner, expiry, and mandatory remediation task.

#### Requirement

- id: ATR-02
- status: Pending
- acceptance_criteria: Delta traceability reports highlight coverage changes between consecutive execution cycles.

## Out of Scope

#### Requirement

- id: OOS-01
- status: Blocked
- acceptance_criteria: Full ALM platform replication remains out of scope to avoid workflow scope explosion.

#### Requirement

- id: OOS-02
- status: Blocked
- acceptance_criteria: Automatic mutation of planning artifacts from remediation hints remains out of scope pending explicit approval workflow design.

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| GUX-01 | 5 | Complete |
| GUX-02 | 6 | Complete |

**Coverage:**
- v1 requirements: 2 total
- Mapped to phases: 2
- Unmapped: 0
- Coverage: 100%

---
*Requirements defined: 2026-03-01*
*Last updated: 2026-03-01 after plan 06-03 completion*
