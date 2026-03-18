# Roadmap: r2inspect

## Milestones

- ✅ **v1.3 Advanced Traceability** - Phases 7-8 (shipped 2026-03-01) — [archive](/Users/seifreed/tools/malware/r2inspect/.planning/milestones/v1.3-ROADMAP.md)
- ✅ **v1.2 Governance UX** - Phases 5-6 (shipped 2026-03-01) — [archive](/Users/seifreed/tools/malware/r2inspect/.planning/milestones/v1.2-ROADMAP.md)
- ✅ **v1.1 Hardening** - Phases 2-4 (shipped 2026-03-01) — [archive](/Users/seifreed/tools/malware/r2inspect/.planning/milestones/v1.1-ROADMAP.md)
- ✅ **v1.0 Quick Stabilization** - Phase 1 (shipped 2026-03-01) — [archive](/Users/seifreed/tools/malware/r2inspect/.planning/milestones/v1.0-ROADMAP.md)
- 🚧 **v1.4 Governance Operations Hardening** - Phases 9-10

## Phases

### Phase 7: Governance Exception Workflow (ATR-01)

**Requirement mapping:** ATR-01 only

**Success criteria (observable operator behaviors):**
- Operator can request an exception for blocked governance transitions with owner and rationale.
- Exception command/output records expiry and required remediation task.
- Temporary bypass is auditable and is rejected when owner, expiry, or task constraints are missing.
- Governance commands block when exception conditions are expired or misconfigured.

### Phase 8: Traceability Delta Reporting (ATR-02)

**Requirement mapping:** ATR-02 only

**Success criteria (observable operator behaviors):**
- Operator can generate a delta traceability report between consecutive cycle snapshots.
- Operator sees explicit added, removed, and changed mapping entries with deterministic ordering.
- Delta output highlights critical stale/coverage regressions before phase/milestone transitions.
- Snapshot state is stable across reruns when inputs are unchanged.

### Phase 9: Governance Exception Retention Controls (GOV-01)

**Requirement mapping:** GOV-01 only

**Success criteria (observable operator behaviors):**
- Operator can configure retention policy for governance exception evidence by scope (global/project/requirement family).
- Operator can inspect active retention configuration and pending/expired exception events.
- Retention policy applies without weakening existing exception payload validation rules.
- Expired or revoked exceptions are not hidden in auditability paths.

### Phase 10: Readonly Traceability Persistence Control (TRC-01)

**Requirement mapping:** TRC-01 only

**Success criteria (observable operator behaviors):**
- Operator can run with persistence suppression flag and still receive full delta diagnostics.
- In suppression mode, traceability snapshot write failures are reported but do not block command completion.
- Persistence mode is explicitly visible in command output/evidence paths.
- Operator can run a normal mode later without requiring extra cleanup from suppressed runs.

## Coverage Validation

| Requirement | Assigned Phase | Mapping Status |
|-------------|----------------|----------------|
| ATR-01 | 7 | Complete |
| ATR-02 | 8 | Complete |
| GOV-01 | 9 | Pending |
| GOV-02 | 9 | Pending |
| TRC-01 | 10 | Pending |
| TRC-02 | 10 | Pending |

- v1 requirements in this milestone: 4
- Mapped to phases: 4
- Unmapped: 0
- Coverage: 100%

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Quick Stabilization | v1.0 | Complete | Complete | 2026-03-01 |
| 2-4. Hardening | v1.1 | 3/3 | Complete | 2026-03-01 |
| 5. Requirement Coverage Matrix | v1.2 | 3/3 | Complete | 2026-03-01 |
| 6. Impact-Ranked Remediation Hints | v1.2 | 3/3 | Complete | 2026-03-01 |
| 7. Governance Exception Workflow | v1.3 | 3/3 | Complete | 2026-03-01 |
| 8. Traceability Delta Reporting | v1.3 | 3/3 | Complete | 2026-03-01 |
| 9. Exception Retention Controls | v1.4 | 0/2 | In progress | - |
| 10. Readonly Persistence Control | v1.4 | 0/2 | Planned | - |
