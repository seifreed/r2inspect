# r2inspect

## What This Is
Python malware-inspection toolkit plus a hardened GSD governance workflow that enforces milestone, requirements, and traceability gates before transitions.

## Core Value
Mantener entregas pequenas, verificables y acumulables.

## Current State
- **Latest shipped milestone:** v1.1 Hardening (2026-03-01)
- **Shipped scope:** Phases 2-4 completed and archived
- **Archive:** `.planning/milestones/v1.1-ROADMAP.md`, `.planning/milestones/v1.1-REQUIREMENTS.md`, `.planning/milestones/v1.1-MILESTONE-AUDIT.md`

## Requirements

### Validated
- ✓ Milestone completion is fail-closed on missing/invalid/stale audit evidence — v1.1
- ✓ Requirements contract is validated before roadmap/milestone/phase transitions — v1.1
- ✓ Requirement traceability drift is enforced with deterministic diagnostics — v1.1

### Active
- [ ] Define v1.2 Governance UX requirements and traceability targets
- [ ] Implement requirement coverage matrix generation for phase and milestone contexts
- [ ] Implement ranked remediation hints by impact for gate failures

### Out of Scope
- Full ALM platform replication inside the quick workflow

## Context
The governance layer now has deterministic fail-closed ordering: requirements gate -> traceability gate -> milestone governance/delegate.

## Constraints
- **Tooling:** use local `~/.codex/get-shit-done` binaries and workflow contracts
- **Safety:** preserve auditable planning artifacts for milestone close decisions

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Deterministic grouped failures for all gate families | Keep operator remediation stable and testable | ✓ Good |
| Requirements-first then traceability-first transition ordering | Prevent false advancement on partial contract drift | ✓ Good |
| Canonical phase normalization for traceability matching | Eliminate alias drift (`Phase 4` vs `04` vs `4`) | ✓ Good |

## Current Milestone: v1.2 Governance UX

**Goal:** Improve operator usability on top of existing fail-closed governance by adding clear coverage visibility and prioritized remediation guidance.

**Target features:**
- Requirement coverage matrix generated for each phase and milestone
- Ranked remediation hints by impact for failed governance checks
- Deterministic UX output contracts preserved for test stability

## Next Milestone Goals
- Ship governance UX baseline without relaxing fail-closed semantics
- Keep requirement/traceability enforcement deterministic while improving operator guidance
- Maintain small, verifiable phase slices aligned to v1.2 scope

---
*Last updated: 2026-03-01 after starting v1.2 Governance UX milestone*
