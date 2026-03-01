# Roadmap: r2inspect

## Milestones

- ✅ **v1.0 Quick Stabilization** - Phase 1 (shipped 2026-03-01) — [archive](/Users/seifreed/tools/malware/r2inspect/.planning/milestones/v1.0-ROADMAP.md)
- ✅ **v1.1 Hardening** - Phases 2-4 (shipped 2026-03-01) — [archive](/Users/seifreed/tools/malware/r2inspect/.planning/milestones/v1.1-ROADMAP.md)
- 🚧 **v1.2 Governance UX** - Phases 5-6 (planned)

## Phases

### Phase 5: Requirement Coverage Matrix (GUX-01)

**Requirement mapping:** GUX-01 only

**Success criteria (observable operator behaviors):**
- Operator runs governance precheck and receives a deterministic `coverage_matrix` for phase scope.
- Operator runs governance precheck and receives a deterministic `coverage_matrix` for milestone scope.
- Operator sees uncovered or stale requirement links as explicit, reproducible matrix entries.
- Operator reruns the same command with unchanged inputs and observes byte-stable matrix ordering.

### Phase 6: Impact-Ranked Remediation Hints (GUX-02)

**Requirement mapping:** GUX-02 only

**Success criteria (observable operator behaviors):**
- Operator receives remediation hints ranked by impact in deterministic order.
- Operator sees each hint include blocking reason, minimal fix, and retry command.
- Operator can follow top-ranked hint to resolve the highest-impact governance failure first.
- Operator reruns precheck after remediation and observes updated ranking consistent with remaining failures.

## Coverage Validation

| Requirement | Assigned Phase | Mapping Status |
|-------------|----------------|----------------|
| GUX-01 | 5 | Exactly one phase |
| GUX-02 | 6 | Exactly one phase |

- v1 requirements in this milestone: 2
- Mapped to phases: 2
- Unmapped: 0
- Coverage: 100%

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Quick Stabilization | v1.0 | Complete | Complete | 2026-03-01 |
| 2-4. Hardening | v1.1 | Complete | Complete | 2026-03-01 |
| 5. Requirement Coverage Matrix | v1.2 | 3/3 | Complete | 2026-03-01 |
| 6. Impact-Ranked Remediation Hints | v1.2 | 3/3 | Complete | 2026-03-01 |
