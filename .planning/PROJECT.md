# r2inspect

## What This Is
Python malware-inspection toolkit plus a hardened GSD governance workflow that enforces milestone, requirements, and traceability gates before transitions.

## Core Value
Mantener entregas pequenas, verificables y acumulables.

## Current State
- **Latest shipped milestone:** v1.3 Advanced Traceability (2026-03-01)
- **Shipped scope:** Phases 7-8 completed and closed
- **Archive:** `.planning/milestones/v1.3-ROADMAP.md`, `.planning/milestones/v1.3-REQUIREMENTS.md`, `.planning/milestones/v1.3-MILESTONE-AUDIT.md`, `.planning/milestones/v1.2-ROADMAP.md`, `.planning/milestones/v1.2-REQUIREMENTS.md`

## Requirements

### Validated
- ✓ Milestone completion is fail-closed on missing/invalid/stale audit evidence — v1.1
- ✓ Requirements contract is validated before roadmap/milestone/phase transitions — v1.1
- ✓ Requirement traceability drift is enforced with deterministic diagnostics — v1.1
- ✓ Requirement coverage matrix generated for phase and milestone scope — v1.2
- ✓ Remediation hints are ranked by deterministic impact with copy-pasteable retry commands — v1.2
- ✓ Top-rank hint state and rerun guidance are tracked additively in STATE.md — v1.2
- ✓ Governance exception workflow is auditable and constrained by owner/expiry/task fields — v1.3
- ✓ Traceability delta reporting is deterministic and non-blocking on persistence failures — v1.3

### Active
- [ ] Expand governance exception observability with per-scope retention policy and expiry auditing (GOV-01)
- [ ] Add policy inspection for near-term exception expiry and stale bypass conditions (GOV-02)
- [ ] Add CLI readonly mode for traceability persistence suppression (TRC-01)
- [ ] Keep delta diagnostics deterministic and complete while persistence is intentionally suppressed (TRC-02)

### Out of Scope
- Full ALM platform replication inside the quick workflow
- Automatic mutation of planning artifacts from remediation hints without explicit approval workflow

## Context
The governance layer now has deterministic fail-closed ordering: requirements gate -> traceability gate -> milestone governance/delegate, with additive coverage updates and evidence retention.

## Constraints
- **Tooling:** use local `~/.codex/get-shit-done` binaries and workflow contracts
- **Safety:** preserve auditable planning artifacts for milestone close decisions

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Deterministic grouped failures for all gate families | Keep operator remediation stable and testable | ✓ Good |
| Requirements-first then traceability-first transition ordering | Prevent false advancement on partial contract drift | ✓ Good |
| Canonical phase normalization for traceability matching | Eliminate alias drift (`Phase 4` vs `04` vs `4`) | ✓ Good |
| Keep exception bypass opt-in and scope-constrained | Maintains fail-closed posture while allowing operational recovery | ✓ Good |

## Current Milestone: v1.4 Governance Operations Hardening (Requirements)

**Goal:** Strengthen governance operations and traceability control by adding retention discipline and controlled readonly execution behavior.

**Target features:**
- Per-scope governance exception retention policy and expiry visibility.
- Governance exception reporting for near-expiry, expired, and revoked entries.
- Readonly mode that suppresses snapshot persistence while preserving full delta diagnostics.

---
*Last updated: 2026-03-01 after v1.4 start*
