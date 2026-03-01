# Roadmap: r2inspect

## Milestones

- ✅ **v1.0 Quick Stabilization** - Phase 1 (shipped 2026-03-01)
- 🚧 **v1.1 Hardening** - Phases 2-4 (in progress)

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

### 🚧 v1.1 Hardening (In Progress)

**Milestone Goal:** Fortalecer gobernanza y trazabilidad del flujo GSD para evitar cierres de milestone con gaps documentales.

- [x] **Phase 2: Milestone Governance Gates** - Milestone completion is fail-closed on audit presence, status, and remediation guidance.
- [x] **Phase 3: Requirements Contract Enforcement** - Active requirements are structurally valid before planning and completion transitions.
- [ ] **Phase 4: Traceability and Drift Enforcement** - Requirement-to-phase links remain one-to-one and consistent with roadmap and execution state.

## Phase Details

### Phase 2: Milestone Governance Gates
**Goal**: Operators can only complete milestones when audit evidence exists, passes, and provides actionable remediation on failure.
**Depends on**: Phase 1
**Requirements**: GOV-01, GOV-02, GOV-03
**Success Criteria** (what must be TRUE):
  1. Operator cannot complete a milestone when the required audit artifact is missing.
  2. Operator cannot complete a milestone when audit status is not `passed`.
  3. Operator receives clear remediation steps in gate failure output and can follow them to re-attempt completion.
**Plans**: 2 plans

Plans:
- [x] 02-01-PLAN.md - Build shared fail-closed governance gate evaluator and audit contract checks.
- [x] 02-02-PLAN.md - Wire precheck/complete enforcement and remediation checklist output.

### Phase 3: Requirements Contract Enforcement
**Goal**: Operators maintain a valid, complete `REQUIREMENTS.md` contract before roadmap and milestone transitions proceed.
**Depends on**: Phase 2
**Requirements**: REQ-01, REQ-02, REQ-03
**Success Criteria** (what must be TRUE):
  1. Operator sees deterministic validation failures when requirement IDs do not match the required stable format.
  2. Operator cannot continue planning when an active requirement is missing status or acceptance criteria.
  3. Operator cannot complete a milestone until requirement definitions pass validation checks.
**Plans**: 3 plans

Plans:
- [x] 03-01-PLAN.md - Define canonical REQUIREMENTS contract and implement deterministic validator.
- [x] 03-02-PLAN.md - Wire requirements precheck and fail-closed transition enforcement (roadmap/milestone/phase completion).
- [x] 03-03-PLAN.md - Close verification test gaps for requirements-first milestone complete ordering and grouped failure coverage.

### Phase 4: Traceability and Drift Enforcement
**Goal**: Operators can only complete phases and milestones when requirement mapping and cross-artifact consistency remain intact.
**Depends on**: Phase 3
**Requirements**: TRC-01, TRC-02, TRC-03
**Success Criteria** (what must be TRUE):
  1. Operator can confirm every active requirement is mapped to exactly one roadmap phase.
  2. Operator receives explicit drift errors when `ROADMAP.md`, `REQUIREMENTS.md`, and execution state disagree.
  3. Operator cannot pass phase completion checks until traceability links are complete and internally consistent.
**Plans**: 3 plans

Plans:
- [x] 04-01-PLAN.md - Build shared traceability/drift evaluator with strict parsing and deterministic ordering.
- [x] 04-02-PLAN.md - Wire traceability gate into transition paths and deterministic evidence updates.
- [ ] 04-03-PLAN.md - Close integration/flow verification gaps for traceability-first completion ordering.

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 2. Milestone Governance Gates | v1.1 | Complete    | 2026-03-01 | 2026-03-01 |
| 3. Requirements Contract Enforcement | Complete | Complete    | 2026-03-01 | 2026-03-01 |
| 4. Traceability and Drift Enforcement | v1.1 | 2/3 | In Progress | - |
