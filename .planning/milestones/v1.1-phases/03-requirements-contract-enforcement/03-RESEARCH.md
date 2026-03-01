# Phase 3: Requirements Contract Enforcement - Research

**Researched:** 2026-03-01
**Domain:** Deterministic REQUIREMENTS.md contract validation and transition gating
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
### Requirement ID Rules
- Active requirement IDs must follow strict `CAT-NN` format (uppercase category + hyphen + numeric suffix of at least two digits).
- Requirement IDs must be globally unique within v1 requirements.
- Numbering continuity is not required (gaps allowed).
- Legacy non-compliant IDs are hard-blocked until migrated to compliant format.

### Required Fields Contract
- Every active requirement must include: stable ID, status token, and acceptance criteria.
- Allowed status tokens are strict finite set: `Pending`, `In Progress`, `Complete`, `Blocked`.
- Acceptance criteria must be non-empty and testable (concrete verifiable behavior).
- Strict schema applies to all sections (`v1`, `v2`, and `Out of Scope`) in this phase.

### Validation Timing and Gate Behavior
- Contract validation hard-blocks before roadmap creation/revision and before milestone completion.
- Phase completion should also enforce contract validity for touched requirements.
- Gate failures are read-only: no advancement writes to roadmap/requirements/state on failed validation.
- Add explicit non-blocking requirements precheck command/path for readiness checks.

### Claude's Discretion
- Exact precheck command naming and CLI output shape.
- Exact wording and grouping format for validation diagnostics, as long as contract semantics remain locked.

### Deferred Ideas (OUT OF SCOPE)
- Full requirement-to-roadmap/state drift enforcement remains Phase 4 scope.
- Exception governance with temporary bypass and expiry remains deferred beyond this phase.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| REQ-01 | `REQUIREMENTS.md` enforces stable requirement IDs with deterministic format validation. | Add strict ID parser + validator (`^[A-Z]+-[0-9]{2,}$`), enforce uniqueness within active v1 requirements, and return deterministic grouped failures. |
| REQ-02 | Every active requirement includes status and acceptance criteria fields before planning continues. | Add contract parser for requirement entries that requires `id`, `status`, and non-empty testable acceptance criteria; block planning/roadmap transitions on missing fields. |
| REQ-03 | Requirement definitions are validated before roadmap creation and before milestone completion. | Reuse one shared evaluator for both non-blocking precheck and hard-blocking transition commands (roadmap create/revise, milestone complete, and phase completion touched-set check). |
</phase_requirements>

## Summary

Phase 3 should be planned as an extension of the existing fail-closed governance pattern already implemented for milestone audits. The most reliable approach is to add a shared requirements-contract evaluator in `scripts/governance_gates.py` that returns deterministic grouped failures, then wire it into transition entry points in `scripts/quick_bootstrap.py` (and any roadmap transition entrypoint in the surrounding GSD toolchain).

Current repository behavior confirms milestone gating exists, but no requirements-contract validator exists yet. `REQUIREMENTS.md` also does not currently encode explicit per-requirement status tokens and acceptance-criteria fields, so this phase must include contract-shape migration in the artifact itself and matching parser logic.

**Primary recommendation:** Build one canonical `evaluate_requirements_contract_gate(planning_root, context)` function and call it from both `requirements precheck` and hard-block transition paths, reusing current failure-group and remediation formatting style.

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Python stdlib (`pathlib`, `re`, `datetime`) | Existing runtime | Parse and validate markdown contract deterministically | Already used in `scripts/governance_gates.py`; no new dependency surface |
| `scripts/governance_gates.py` evaluator pattern | Existing | Centralized fail-closed gate logic + grouped failures | Matches established governance implementation and tests |
| `scripts/quick_bootstrap.py` argparse routing | Existing | Expose precheck and transition gating surfaces | Existing command orchestration path for milestone gates |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `pytest` + monkeypatch patterns | Existing test stack | Unit/integration coverage for gate behavior and no-mutation failures | Reuse `tests/unit/test_governance_gates.py`, `tests/unit/test_quick_bootstrap.py`, `tests/integration/test_milestone_governance_flow.py` style |
| JSON CLI payload output (`json.dumps`) | Existing | Deterministic machine-readable precheck output | Use for non-blocking precheck command responses |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Local line-oriented parser in current scripts | Full markdown AST parser dependency | Overkill for locked deterministic contract; larger failure surface |
| Separate validators per command | Single shared evaluator | Duplicated rule logic will drift and break deterministic behavior |
| Soft warnings for malformed contracts | Fail-closed errors only | Conflicts with locked hard-block decision semantics |

## Architecture Patterns

### Recommended Project Structure
```text
scripts/
  governance_gates.py      # add requirements contract evaluator + formatter
  quick_bootstrap.py       # add requirements precheck + transition enforcement wiring
tests/unit/
  test_governance_gates.py # evaluator unit coverage for REQ-01/02 rule set
  test_quick_bootstrap.py  # CLI routing and fail-closed behavior coverage
tests/integration/
  test_milestone_governance_flow.py  # extend/parallel for requirements-gated transitions
```

### Pattern 1: Shared Contract Evaluator
**What:** One function parses `REQUIREMENTS.md`, validates IDs/status/acceptance criteria, and returns `{passed, failure_groups, retry_command, contract_file}`.
**When to use:** Every place that needs contract validity checks.
**Example:**
```python
def evaluate_requirements_contract_gate(planning_root: Path, transition: str) -> dict[str, Any]:
    # Parse REQUIREMENTS.md once
    # Validate entry schema and deterministic rules
    # Return grouped failures in canonical order
```

### Pattern 2: Deterministic Failure Taxonomy
**What:** Fixed failure group codes and ordering (for predictable UX/tests).
**When to use:** All requirement validation failures.
**Recommended groups:** `missing_file`, `malformed_entry`, `invalid_id_format`, `duplicate_id`, `invalid_status`, `missing_acceptance_criteria`.

### Pattern 3: Precheck + Hard-Block Split
**What:** Non-blocking `requirements precheck` returns JSON payload; blocking transition commands abort with remediation output on failure.
**When to use:** Operator readiness checks vs state-changing transitions.

### Anti-Patterns to Avoid
- **Command-specific rule duplication:** precheck and completion must call the same evaluator.
- **Heuristic acceptance criteria checks with no deterministic rule:** define explicit minimum validation conditions in plan.
- **Transition writes before gate evaluation:** violates locked read-only failure behavior.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Inconsistent gate output format | Ad-hoc print branches per command | Existing grouped checklist formatter style from `format_gate_failures()` | Preserves deterministic operator UX |
| Multiple markdown parsers in different commands | Inline regex blocks scattered across CLI handlers | Single parser/validator helper in `governance_gates.py` | Prevents drift and test duplication |
| Requirement status interpretation via checkbox state only | Implicit status from `[x]/[ ]` | Explicit status token field with finite allowed values | Required by locked contract decision |

**Key insight:** The hard part is not parsing markdown; it is enforcing one canonical contract at all transition boundaries with zero ambiguity.

## Common Pitfalls

### Pitfall 1: Contract migration not planned
**What goes wrong:** New validator is correct, but current `REQUIREMENTS.md` shape immediately hard-fails all transitions.
**Why it happens:** Existing requirement entries do not yet provide explicit status/acceptance-criteria fields per entry.
**How to avoid:** Include an explicit migration task and test fixtures for both pre- and post-migration shapes.
**Warning signs:** Every gate run returns only malformed/missing-field failures after rollout.

### Pitfall 2: “Active requirement” scope ambiguity
**What goes wrong:** Different commands validate different subsets (v1 only vs all sections).
**Why it happens:** No canonical section-scoping rule in parser.
**How to avoid:** Encode section eligibility and active-entry criteria in one parser function and document it in tests.
**Warning signs:** Same file passes in precheck but fails in completion path.

### Pitfall 3: Roadmap transition hook missing
**What goes wrong:** Milestone completion is gated, but roadmap creation/revision still bypasses requirements checks.
**Why it happens:** Hook is added only in `quick_bootstrap.py` where roadmap creation is not currently routed.
**How to avoid:** Identify exact roadmap transition command entrypoint in Wave 0 and wire shared evaluator there.
**Warning signs:** Operators can create/revise roadmap while requirements precheck fails.

## Code Examples

Verified patterns from existing codebase:

### Existing grouped failure envelope helper
Source: `scripts/governance_gates.py`
```python
def _add_failure(failure_groups: dict[str, list[dict[str, str]]], code: str, message: str, fix: str) -> None:
    failure_groups.setdefault(code, []).append(
        {
            "code": code,
            "severity": "error",
            "message": message,
            "fix": fix,
        }
    )
```

### Existing precheck vs complete routing pattern
Source: `scripts/quick_bootstrap.py`
```python
if milestone_command == "precheck":
    passed = bool(result.get("passed", False))
    ...

if not bool(result.get("passed", False)):
    ...
    return 1
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Requirements treated mainly as roadmap reference content | Requirements as hard governance contract at transition boundaries | Phase 3 target (2026-03 planning) | Prevents planning/completion progress with structurally invalid requirement definitions |

**Deprecated/outdated:**
- Treating checkbox-only requirement lines as sufficient contract representation.
- Running milestone gates without REQUIREMENTS contract validation.

## Open Questions

1. **Canonical entry schema in `REQUIREMENTS.md`**
- What we know: each active requirement needs stable ID, status token, and acceptance criteria.
- What's unclear: exact markdown shape to enforce (single-line tokens vs multiline block fields).
- Recommendation: lock one explicit schema in plan first, then implement parser and fixtures against that schema only.

2. **Roadmap create/revise hook location**
- What we know: requirement validation must hard-block before roadmap transitions.
- What's unclear: exact command/file in this repo or upstream GSD runtime that performs roadmap create/revise for this workflow.
- Recommendation: make Wave 0 include hook discovery and boundary decision before coding enforcement.

3. **Definition of “testable” acceptance criteria**
- What we know: criteria must be non-empty and concrete verifiable behavior.
- What's unclear: minimal deterministic heuristic to validate “testable” without NLP ambiguity.
- Recommendation: use objective structural checks in Phase 3 (non-empty, verb+observable outcome pattern) and defer semantic depth to future phase if needed.

## Sources

### Primary (HIGH confidence)
- `.planning/phases/03-requirements-contract-enforcement/03-CONTEXT.md` - locked decisions, discretion, and out-of-scope constraints.
- `.planning/REQUIREMENTS.md` - REQ-01/02/03 definitions and current contract shape.
- `.planning/ROADMAP.md` - phase goal/success criteria and transition expectations.
- `.planning/STATE.md` - current lifecycle state and gate evidence conventions.
- `scripts/governance_gates.py` - existing fail-closed gate implementation pattern and deterministic formatting approach.
- `scripts/quick_bootstrap.py` - current CLI routing and milestone precheck/complete enforcement pattern.
- `tests/unit/test_governance_gates.py` - deterministic gate taxonomy and ordering assertions.
- `tests/unit/test_quick_bootstrap.py` - non-blocking precheck and fail-closed complete behavior patterns.
- `tests/integration/test_milestone_governance_flow.py` - integration expectations for blocked vs passed transitions.

### Secondary (MEDIUM confidence)
- None.

### Tertiary (LOW confidence)
- None.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - based on direct inspection of existing implementation and tests.
- Architecture: HIGH - same proven governance gate pattern can be extended to requirements contract enforcement.
- Pitfalls: MEDIUM - one critical integration point (roadmap create/revise hook) is not yet located in inspected files.

**Research date:** 2026-03-01
**Valid until:** 2026-03-31
