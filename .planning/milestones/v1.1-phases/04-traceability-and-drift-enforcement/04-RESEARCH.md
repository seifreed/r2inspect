# Phase 4: Traceability and Drift Enforcement - Research

**Researched:** 2026-03-01
**Domain:** Requirement-to-phase traceability contract and cross-artifact drift enforcement
**Confidence:** HIGH

<user_constraints>
## User Constraints (from 04-CONTEXT.md)

### Locked Decisions
### Traceability Contract
- Canonical source of requirement-to-phase mapping is the `## Traceability` table in `.planning/REQUIREMENTS.md`.
- One-to-one mapping enforcement applies to active requirements in `v1` and `v2` sections.
- Mapping identity must normalize to canonical phase IDs (`2`, `3`, `4`, `2.1`) while accepting aliases like `Phase 4`.
- Any active requirement mapped to zero phases or more than one phase is a hard error.

### Drift Error Policy
- Missing mapping for an active requirement is a hard error.
- Mapping to a phase not present in roadmap is a hard error.
- State-vs-mapping mismatches are hard errors (for example requirement `Complete` while mapped phase is not complete, and inverse).
- Drift failures must be grouped and rendered in deterministic order.

### Phase Complete Blocking Rules
- `phase complete` validates touched requirement IDs only (`--requirement-id` scope).
- `phase complete` hard-fails on unknown, unmapped, or inconsistent touched IDs.
- `phase complete` hard-fails when no touched requirement IDs are provided.
- Requirement `Complete` status is valid only when mapped phase is complete.
- Successful checks must record deterministic evidence including command, scope, and sorted touched requirement IDs.

### Remediation and Output Contract
- Failure output keeps existing grouped checklist style (`issue + fix`) aligned with governance gate UX.
- Failures include explicit retry command text.
- Failure group rendering order must be canonical and stable.
- Precheck remains non-blocking (`exit 0`) while surfacing drift failures clearly.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| TRC-01 | Every active requirement is mapped to exactly one roadmap phase. | Parse active requirements + traceability table, normalize phase IDs, enforce exactly-one mapping for each active ID. |
| TRC-02 | Drift validation detects mismatches across `ROADMAP.md`, `REQUIREMENTS.md`, and execution state. | Add shared drift evaluator that cross-checks traceability rows, roadmap phase catalog/completion state, and state evidence. |
| TRC-03 | Phase completion passes only when traceability links are complete and internally consistent. | Wire traceability gate into `phase complete` fail-closed path (touched scope), before transition delegation. |
</phase_requirements>

## Summary

Phase 4 should be planned as a strict extension of the existing gate architecture in `scripts/governance_gates.py` and `scripts/quick_bootstrap.py`. The project already has deterministic failure grouping, precheck vs complete semantics, and touched-scope enforcement for requirements. What is missing is a shared traceability/drift evaluator and transition wiring that uses it consistently.

The safest path is to keep one canonical evaluator for traceability and call it from each relevant boundary:
- Non-blocking precheck surface for operator visibility.
- Blocking `phase complete` touched-scope enforcement before delegation.
- Blocking `milestone complete` all-scope enforcement before governance gate.

This phase should not introduce a new subsystem. It should add parsers and checks that fit the existing envelope and state recording model.

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Python stdlib (`pathlib`, `re`, `typing`, `datetime`) | Existing runtime | Parse markdown artifacts and evaluate deterministic drift rules | Already used in current governance gates; no dependency expansion |
| `scripts/governance_gates.py` | Existing | Central gate evaluator and grouped failure formatter | Existing pattern for deterministic failures and remediation output |
| `scripts/quick_bootstrap.py` | Existing | Transition routing and gate enforcement points | Current place where milestone/roadmap/phase checks are already enforced |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `pytest` + monkeypatch patterns | Existing | Stable unit/integration coverage for gate outcomes and no-mutation guarantees | Extend `tests/unit/test_governance_gates.py`, `tests/unit/test_quick_bootstrap.py`, `tests/integration/test_milestone_governance_flow.py` |
| Existing checklist formatter style | Existing | Operator-facing grouped failures + retry | Keep consistency with previous phases |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Parsing markdown with custom ad-hoc logic in each command | Shared parsing helpers + one evaluator | Command-local parsing will drift and break determinism |
| Relaxed warnings for drift | Hard errors only for TRC scope | Conflicts with locked fail-closed decisions |
| New traceability file | Keep `## Traceability` in `REQUIREMENTS.md` as canonical source | Introducing another artifact creates dual source of truth |

## Architecture Patterns

### Recommended Project Structure
```text
scripts/
  governance_gates.py      # add traceability parser + drift evaluator + formatter mapping
  quick_bootstrap.py       # wire traceability precheck/complete enforcement and evidence logging
tests/unit/
  test_governance_gates.py # traceability evaluator rule coverage + deterministic group order
  test_quick_bootstrap.py  # routing, retry command, touched-scope blocking/pass paths
tests/integration/
  test_milestone_governance_flow.py # requirements->traceability->milestone gate ordering and fail-closed behavior
```

### Pattern 1: Canonical Artifact Model Before Validation
**What:** Parse each artifact once into typed intermediate structures, then run deterministic rule checks.
**Why:** Prevents duplicated parse assumptions and keeps errors explainable.

Recommended parse outputs:
- `requirements_entries`: `{id, status, section}` from `v1/v2/Out of Scope` blocks.
- `active_requirement_ids`: IDs from `v1` and `v2` only.
- `traceability_rows`: `{requirement_id, phase_token, status}` from table rows.
- `roadmap_phase_catalog`: normalized phase IDs present in `ROADMAP.md`.
- `roadmap_phase_completion`: normalized phase ID -> `complete|incomplete` based on checkbox lines.
- `state_snapshot`: frontmatter + last known gate activity needed for evidence/drift checks.

### Pattern 2: Two-Scope Traceability Evaluator
**What:** `evaluate_traceability_drift_gate(planning_root, scope, touched_requirement_ids)`
**Scope behavior:**
- `all`: validate all active requirements for precheck/milestone completion.
- `touched`: validate only touched set for `phase complete` (but still reject unknown IDs).

Return envelope should mirror existing gates:
```python
{
  "passed": bool,
  "failure_groups": {"group_code": [issue, ...]},
  "retry_command": str,
  "evidence": {
    "scope": "all|touched",
    "touched_requirement_ids": [...],
  },
}
```

### Pattern 3: Deterministic Failure Taxonomy and Order
Use fixed order so outputs/tests stay stable. Suggested canonical order:
1. `missing_file`
2. `malformed_traceability_table`
3. `missing_touched_requirements`
4. `unknown_touched_requirement`
5. `unmapped_requirement`
6. `multi_phase_mapping`
7. `unknown_mapped_phase`
8. `state_mapping_mismatch`

This ordering cleanly separates parse/contract failures from mapping failures and cross-artifact drift failures.

### Pattern 4: Fail-Closed Wiring Order
For `milestone complete`, enforce in this sequence:
1. requirements contract gate
2. traceability/drift gate
3. milestone governance gate
4. delegate completion

For `phase complete`:
1. requirements contract gate (`scope=touched`)
2. traceability/drift gate (`scope=touched`)
3. delegate completion

### Anti-Patterns to Avoid
- Adding traceability checks in formatter/output layers instead of evaluator core.
- Mixing roadmap parsing with state mutation logic.
- Letting `phase complete` pass when touched IDs are syntactically valid but unmapped.
- Inferring phase completion from requirement status instead of roadmap completion markers.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Per-command drift logic | Separate checks in each CLI branch | Shared evaluator in `governance_gates.py` | Prevents drift between precheck and completion paths |
| Free-form failure prose | Unstructured strings | Existing grouped failure envelope (`code`, `message`, `fix`) | Keeps checklist UX and test determinism |
| New evidence storage format in random sections | Ad-hoc text append | Dedicated deterministic gate activity table update helper | Makes audits and tests reliable |

## Common Pitfalls

### Pitfall 1: Active requirement scope ambiguity
**What goes wrong:** Validator accidentally includes `Out of Scope` rows in one-to-one checks.
**Avoid:** Define `active = v1 + v2 only` in one parser helper and test it explicitly.

### Pitfall 2: Phase ID normalization drift
**What goes wrong:** `Phase 4`, `4`, and `04` are treated differently in different checks.
**Avoid:** Centralize `normalize_phase_id()` and use it for traceability rows, roadmap entries, and touched-scope diagnostics.

### Pitfall 3: False drift due to unclear phase completion source
**What goes wrong:** Requirement status mismatch checks disagree with roadmap reality.
**Avoid:** Lock a single source for phase completion (roadmap checkbox state) and document fallback when not parseable.

### Pitfall 4: Breaking existing precheck contract
**What goes wrong:** `precheck` starts exiting non-zero on drift failure.
**Avoid:** Keep non-blocking semantics (`exit 0`) while embedding full failure payload/checklist.

### Pitfall 5: Evidence logging regressions
**What goes wrong:** Gate decisions are made but state evidence misses touched IDs/scope ordering.
**Avoid:** Add deterministic evidence helper and assert exact row format in tests.

## Code Examples

Verified patterns to extend:

### Existing touched-scope enforcement input (phase complete)
Source: `scripts/quick_bootstrap.py`
```python
requirements_result = evaluate_requirements_contract_gate(
    planning_root,
    scope="touched",
    touched_requirement_ids=touched_ids,
)
```

### Existing deterministic failure envelope helper
Source: `scripts/governance_gates.py`
```python
def _add_failure(failure_groups, code, message, fix):
    failure_groups.setdefault(code, []).append(
        {"code": code, "severity": "error", "message": message, "fix": fix}
    )
```

### Existing grouped checklist formatter contract
Source: `scripts/governance_gates.py`
```python
lines = ["Requirements contract gate failed.", "", "Checklist:"]
...
lines.append(f"Retry: {effective_retry}")
```

## Planning Checklist (What You Must Decide Before PLAN.md)

1. Lock the exact regex/parser for extracting roadmap phase IDs and completion checkboxes.
2. Lock canonical phase normalization rules (`Phase 4` -> `4`, preserve decimals like `2.1`).
3. Lock active requirement scope (`v1` + `v2`) and whether any future status values are excluded.
4. Lock mismatch semantics for TRC-02:
- Requirement `Complete` but mapped phase incomplete.
- Mapped phase complete but requirement not `Complete`.
5. Lock whether traceability checks run in `requirements precheck` command output or a new command surface.
6. Lock exact state evidence write location/format for touched requirement IDs.
7. Lock canonical failure group names and order once, then freeze in tests.

## State of the Art

| Old Approach | Current Approach | Impact |
|--------------|------------------|--------|
| Requirements gate validates structure only (IDs/status/criteria) | Add traceability and drift as first-class governance checks | Prevents phase/milestone closure when cross-artifact consistency is broken |
| `phase complete` enforces touched IDs exist structurally | `phase complete` also enforces touched IDs are mapped and drift-free | Ensures completion reflects real roadmap execution state |

## Open Questions

1. What is the canonical machine-readable source for phase completion state: roadmap checkboxes only, or roadmap plus state frontmatter reconciliation?
2. Should traceability validation be exposed as `requirements precheck` extension or a dedicated `traceability precheck` command?
3. For duplicate rows in traceability table with same requirement and same phase alias, should this be treated as one mapping (dedup) or malformed duplicate row error?
4. Should `status` column in traceability table be validated semantically in Phase 4, or treated as informational?

## Sources

### Primary (HIGH confidence)
- `.planning/phases/04-traceability-and-drift-enforcement/04-CONTEXT.md`
- `.planning/REQUIREMENTS.md`
- `.planning/ROADMAP.md`
- `.planning/STATE.md`
- `scripts/governance_gates.py`
- `scripts/quick_bootstrap.py`
- `tests/unit/test_governance_gates.py`
- `tests/unit/test_quick_bootstrap.py`
- `tests/integration/test_milestone_governance_flow.py`

### Secondary (MEDIUM confidence)
- `.planning/phases/03-requirements-contract-enforcement/03-RESEARCH.md` (pattern continuity)
- `.planning/phases/02-milestone-governance-gates/02-RESEARCH.md` (pattern continuity)

### Tertiary (LOW confidence)
- None

## Metadata

**Confidence breakdown:**
- Stack and integration points: HIGH (directly inspected existing implementation).
- Failure taxonomy proposal: HIGH (aligned with locked deterministic-output decisions).
- Drift-semantics edge details: MEDIUM (needs explicit lock during planning for roadmap/state precedence).

**Research date:** 2026-03-01
**Valid until:** 2026-03-31
