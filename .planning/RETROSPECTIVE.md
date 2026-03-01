# Project Retrospective

*A living document updated after each milestone. Lessons feed forward into future planning.*

## Milestone: v1.0 — milestone

**Shipped:** 2026-03-01
**Phases:** 1 | **Plans:** 1 | **Sessions:** 1

### What Was Built
- Deterministic quick bootstrap wrapper with preflight checks and bounded retry.
- Versioned quick `PLAN`/`SUMMARY` templates with measurable verification sections.
- State/evidence synchronization path for quick closure outcomes.

### What Worked
- TDD-style plan execution produced clear commits and verification artifacts.
- Template-driven scaffolding reduced ambiguity and improved consistency.

### What Was Inefficient
- Missing milestone audit and missing live `REQUIREMENTS.md` reduced formal governance.
- One CLI parsing bug surfaced late and required deviation fix commit.

### Patterns Established
- `gsd-tools init quick --raw` is the canonical quick bootstrap contract.
- Quick tasks should always emit structured closure evidence for recovery.

### Key Lessons
1. Run milestone audit before completion to avoid known-gap carryover.
2. Keep `REQUIREMENTS.md` active from milestone start even for infra-heavy work.

### Cost Observations
- Model mix: 0% opus, 100% sonnet, 0% haiku
- Sessions: 1
- Notable: Single-phase milestone shipped quickly with strong test/verification discipline.

---

## Milestone: v1.1 — Hardening

**Shipped:** 2026-03-01
**Phases:** 3 | **Plans:** 8 | **Sessions:** 1

### What Was Built
- Milestone governance gates now fail closed on missing, invalid, or stale audits.
- Requirements contract validation now blocks roadmap/milestone/phase transitions when malformed.
- Traceability drift checks now enforce one-to-one requirement mapping and cross-artifact consistency.

### What Worked
- Deterministic failure grouping kept test assertions stable while gate logic expanded.
- Wave-based execution with strict verification kept phase delivery fast and auditable.

### What Was Inefficient
- Multiple state/requirements helper paths required manual fallback updates due parser assumptions.
- Milestone audit timestamp went stale during late-phase changes and needed explicit refresh before closure.

### Patterns Established
- Requirements-first then traceability-first gate ordering is now the default transition safety model.
- Traceability evidence logging in STATE is useful for post-failure remediation and audit replay.

### Key Lessons
1. Re-run milestone audit after late roadmap/state edits before calling complete.
2. Keep milestone-close artifact naming strict (`NN-VERIFICATION.md`) to avoid closure friction.

### Cost Observations
- Model mix: 0% opus, 100% sonnet, 0% haiku
- Sessions: 1
- Notable: Sequential wave execution with targeted TDD kept regressions contained.

---

## Cross-Milestone Trends

### Process Evolution

| Milestone | Sessions | Phases | Key Change |
|-----------|----------|--------|------------|
| v1.0 | 1 | 1 | Introduced deterministic quick bootstrap + template scaffold workflow |
| v1.1 | 1 | 3 | Added fail-closed requirements + traceability gates across transitions |

### Cumulative Quality

| Milestone | Tests | Coverage | Zero-Dep Additions |
|-----------|-------|----------|-------------------|
| v1.0 | Added focused quick bootstrap tests | 100% repo coverage previously established; quick bootstrap tests green | 1 (`scripts/quick_bootstrap.py`) |
| v1.1 | Added governance/traceability unit+integration regressions | Critical gate paths now regression-locked for milestone closure flows | 0 |

### Top Lessons (Verified Across Milestones)

1. Deterministic scaffolding + strict verification reduces execution ambiguity.
2. Documentation governance (audit/requirements) must stay active even in small milestones.
