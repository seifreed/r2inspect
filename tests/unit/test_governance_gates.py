from __future__ import annotations

import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "governance_gates.py"
SPEC = importlib.util.spec_from_file_location("governance_gates", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load governance module from {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
evaluate_milestone_governance_gate = MODULE.evaluate_milestone_governance_gate
format_gate_failures = MODULE.format_gate_failures
evaluate_requirements_contract_gate = getattr(MODULE, "evaluate_requirements_contract_gate", None)
format_requirements_contract_failures = getattr(
    MODULE, "format_requirements_contract_failures", None
)
evaluate_traceability_drift_gate = getattr(MODULE, "evaluate_traceability_drift_gate", None)
normalize_phase_id = getattr(MODULE, "_normalize_phase_id", None)


REQUIRED_SECTIONS = (
    "## Scope",
    "## Checks",
    "## Findings",
    "## Remediation",
)


def _write_audit(
    planning_root: Path,
    *,
    version: str,
    status: str = "passed",
    audited: str = "2026-03-01T12:46:34Z",
    sections: tuple[str, ...] = REQUIRED_SECTIONS,
) -> None:
    lines = [
        "---",
        f"milestone: {version}",
        f"status: {status}",
        f'audited: "{audited}"',
        "---",
        "",
        "# Milestone Audit",
        "",
    ]
    for section in sections:
        lines.extend([section, "- ok", ""])
    (planning_root / f"{version}-MILESTONE-AUDIT.md").write_text("\n".join(lines), encoding="utf-8")


def _write_state(planning_root: Path, last_updated: str) -> None:
    (planning_root / "STATE.md").write_text(
        "\n".join(
            [
                "---",
                f'last_updated: "{last_updated}"',
                "---",
                "",
                "# State",
            ]
        ),
        encoding="utf-8",
    )


def _write_roadmap(planning_root: Path) -> Path:
    roadmap_path = planning_root / "ROADMAP.md"
    roadmap_path.write_text("# Roadmap\n", encoding="utf-8")
    return roadmap_path


def _write_requirements_contract(
    planning_root: Path,
    body: str,
) -> Path:
    requirements_path = planning_root / "REQUIREMENTS.md"
    requirements_path.write_text(body, encoding="utf-8")
    return requirements_path


def _requirements_contract_content(entries: str) -> str:
    return "\n".join(
        [
            "# Requirements: Example",
            "",
            "## v1 Requirements",
            "",
            "### Group One",
            "",
            entries,
            "",
            "## v2 Requirements",
            "",
            "### Group Two",
            "",
            "#### Requirement",
            "",
            "- id: AUX-01",
            "- status: Pending",
            "- acceptance_criteria: Keep v2 parseable.",
            "",
            "## Out of Scope",
            "",
            "#### Requirement",
            "",
            "- id: OOS-01",
            "- status: Blocked",
            "- acceptance_criteria: Keep out-of-scope parseable.",
            "",
        ]
    )


def _requirements_with_traceability(entries: str, traceability_rows: str) -> str:
    return "\n".join(
        [
            "# Requirements: Example",
            "",
            "## v1 Requirements",
            "",
            "### Group One",
            "",
            entries,
            "",
            "## v2 Requirements",
            "",
            "### Group Two",
            "",
            "#### Requirement",
            "",
            "- id: AUX-01",
            "- status: Pending",
            "- acceptance_criteria: Keep v2 parseable.",
            "",
            "## Out of Scope",
            "",
            "#### Requirement",
            "",
            "- id: OOS-01",
            "- status: Blocked",
            "- acceptance_criteria: Keep out-of-scope parseable.",
            "",
            "## Traceability",
            "",
            "| Requirement | Phase | Status |",
            "|-------------|-------|--------|",
            traceability_rows,
            "",
        ]
    )


def _write_traceability_fixture(planning_root: Path, rows: str) -> None:
    entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Pending",
            "- acceptance_criteria: Must map to one active phase.",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_with_traceability(entries, rows),
    )


def _write_traceability_roadmap(planning_root: Path) -> None:
    (planning_root / "ROADMAP.md").write_text(
        "\n".join(
            [
                "# Roadmap",
                "",
                "### 🚧 v1.1 Hardening (In Progress)",
                "",
                "- [x] **Phase 2: Milestone Governance Gates**",
                "- [x] **Phase 3: Requirements Contract Enforcement**",
                "- [ ] **Phase 4: Traceability and Drift Enforcement**",
            ]
        ),
        encoding="utf-8",
    )


def _evaluate_requirements(planning_root: Path) -> dict[str, object]:
    assert (
        evaluate_requirements_contract_gate is not None
    ), "evaluate_requirements_contract_gate must be implemented in scripts/governance_gates.py"
    return evaluate_requirements_contract_gate(planning_root)


def _evaluate_traceability(planning_root: Path) -> dict[str, object]:
    assert (
        evaluate_traceability_drift_gate is not None
    ), "evaluate_traceability_drift_gate must be implemented in scripts/governance_gates.py"
    return evaluate_traceability_drift_gate(planning_root)


def test_traceability_normalize_phase_aliases_to_canonical_token() -> None:
    assert normalize_phase_id is not None, "_normalize_phase_id must be implemented"
    assert normalize_phase_id("Phase 4") == "4"
    assert normalize_phase_id("4") == "4"
    assert normalize_phase_id("04") == "4"
    assert normalize_phase_id("2.1") == "2.1"


def test_traceability_malformed_table_when_traceability_section_missing(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Pending",
            "- acceptance_criteria: Missing traceability table should fail.",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_contract_content(entries),
    )
    _write_traceability_roadmap(planning_root)

    result = _evaluate_traceability(planning_root)

    assert result["passed"] is False
    assert "malformed_traceability_table" in result["failure_groups"]


def test_traceability_active_scope_excludes_out_of_scope_requirements(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Pending",
            "- acceptance_criteria: Must map to Phase 4.",
        ]
    )
    traceability_rows = "\n".join(
        [
            "| REQ-01 | Phase 4 | Pending |",
            "| AUX-01 | 4 | Pending |",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_with_traceability(entries, traceability_rows),
    )
    _write_traceability_roadmap(planning_root)

    result = _evaluate_traceability(planning_root)

    assert result["passed"] is True
    assert result["failure_groups"] == {}


def test_gate_fails_when_audit_file_missing(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)

    result = evaluate_milestone_governance_gate(planning_root, "v1.1")

    assert result["passed"] is False
    assert "missing_file" in result["failure_groups"]
    assert result["failure_groups"]["missing_file"][0]["code"] == "missing_file"


def test_gate_fails_when_status_is_not_passed(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    _write_audit(planning_root, version="v1.1", status="failed")

    result = evaluate_milestone_governance_gate(planning_root, "v1.1")

    assert result["passed"] is False
    assert "invalid_status" in result["failure_groups"]
    assert result["failure_groups"]["invalid_status"][0]["code"] == "invalid_status"


def test_gate_fails_when_required_sections_are_missing(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    _write_audit(
        planning_root,
        version="v1.1",
        sections=("## Scope", "## Findings"),
    )

    result = evaluate_milestone_governance_gate(planning_root, "v1.1")

    assert result["passed"] is False
    assert "malformed_sections" in result["failure_groups"]
    assert result["failure_groups"]["malformed_sections"][0]["code"] == "malformed_sections"


def test_gate_fails_when_audit_is_stale_against_state_or_roadmap(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    _write_audit(planning_root, version="v1.1", audited="2026-03-01T00:00:00Z")
    _write_state(planning_root, "2026-03-01T12:00:00Z")
    _write_roadmap(planning_root)

    result = evaluate_milestone_governance_gate(planning_root, "v1.1")

    assert result["passed"] is False
    assert "stale_audit" in result["failure_groups"]
    assert result["failure_groups"]["stale_audit"][0]["code"] == "stale_audit"


def test_gate_groups_multiple_failures_in_deterministic_order(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    _write_audit(
        planning_root,
        version="v1.1",
        status="failed",
        audited="2026-03-01T00:00:00Z",
        sections=("## Scope",),
    )
    _write_state(planning_root, "2026-03-01T12:00:00Z")
    _write_roadmap(planning_root)

    result = evaluate_milestone_governance_gate(planning_root, "v1.1")

    assert result["passed"] is False
    assert list(result["failure_groups"]) == [
        "invalid_status",
        "malformed_sections",
        "stale_audit",
    ]


def test_formatter_includes_actionable_checklist_and_retry_command(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    _write_audit(planning_root, version="v1.1", status="failed")

    result = evaluate_milestone_governance_gate(planning_root, "v1.1")
    rendered = format_gate_failures(result, "gsd-tools milestone complete v1.1")

    assert "Checklist:" in rendered
    assert "Fix:" in rendered
    assert "Retry: gsd-tools milestone complete v1.1" in rendered


def test_requirements_gate_fails_on_malformed_entry_structure(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    malformed_entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- acceptance_criteria: Missing status should be malformed.",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_contract_content(malformed_entries),
    )

    result = _evaluate_requirements(planning_root)

    assert result["passed"] is False
    assert "malformed_entry" in result["failure_groups"]


def test_requirements_gate_fails_on_invalid_id_format(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    invalid_id_entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: req-1",
            "- status: Pending",
            "- acceptance_criteria: Must fail deterministic ID validation.",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_contract_content(invalid_id_entries),
    )

    result = _evaluate_requirements(planning_root)

    assert result["passed"] is False
    assert "invalid_id_format" in result["failure_groups"]
    assert result["failure_groups"]["invalid_id_format"][0]["code"] == "invalid_id_format"


def test_requirements_gate_fails_on_duplicate_id(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    duplicate_id_entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Pending",
            "- acceptance_criteria: First entry.",
            "",
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Pending",
            "- acceptance_criteria: Duplicate entry.",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_contract_content(duplicate_id_entries),
    )

    result = _evaluate_requirements(planning_root)

    assert result["passed"] is False
    assert "duplicate_id" in result["failure_groups"]
    assert result["failure_groups"]["duplicate_id"][0]["code"] == "duplicate_id"


def test_requirements_gate_groups_failures_in_deterministic_order_for_malformed_entry(
    tmp_path: Path,
) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    mixed_invalid_entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: req-1",
            "- status: Pending",
            "- acceptance_criteria: Bad id format.",
            "",
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Pending",
            "- acceptance_criteria: First duplicate id.",
            "",
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Pending",
            "- acceptance_criteria: Second duplicate id.",
            "",
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- acceptance_criteria: Missing status should be malformed.",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_contract_content(mixed_invalid_entries),
    )

    result = _evaluate_requirements(planning_root)

    assert result["passed"] is False
    assert list(result["failure_groups"]) == [
        "malformed_entry",
        "invalid_id_format",
        "duplicate_id",
    ]


def test_requirements_gate_fails_on_invalid_status(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    invalid_status_entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Done",
            "- acceptance_criteria: Invalid status must be blocked.",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_contract_content(invalid_status_entries),
    )

    result = _evaluate_requirements(planning_root)

    assert result["passed"] is False
    assert "invalid_status" in result["failure_groups"]
    assert result["failure_groups"]["invalid_status"][0]["code"] == "invalid_status"


def test_requirements_gate_fails_on_missing_acceptance_criteria(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    missing_acceptance_entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Pending",
            "- acceptance_criteria: ",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_contract_content(missing_acceptance_entries),
    )

    result = _evaluate_requirements(planning_root)

    assert result["passed"] is False
    assert "missing_acceptance_criteria" in result["failure_groups"]
    assert (
        result["failure_groups"]["missing_acceptance_criteria"][0]["code"]
        == "missing_acceptance_criteria"
    )


def test_requirements_gate_passed_envelope_is_stable(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    valid_entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Pending",
            "- acceptance_criteria: Valid requirement entry.",
        ]
    )
    requirements_path = _write_requirements_contract(
        planning_root,
        _requirements_contract_content(valid_entries),
    )

    result = _evaluate_requirements(planning_root)

    assert result == {
        "passed": True,
        "failure_groups": {},
        "retry_command": "node ~/.claude/get-shit-done/bin/gsd-tools.cjs requirements precheck",
        "requirements_file": str(requirements_path),
    }


def test_requirements_formatter_includes_checklist_and_retry_command(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    invalid_status_entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Done",
            "- acceptance_criteria: Invalid status should render remediation.",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_contract_content(invalid_status_entries),
    )
    result = _evaluate_requirements(planning_root)
    assert (
        format_requirements_contract_failures is not None
    ), "format_requirements_contract_failures must be implemented in scripts/governance_gates.py"

    rendered = format_requirements_contract_failures(
        result,
        "gsd-tools requirements precheck",
    )

    assert "Requirements contract gate failed." in rendered
    assert "Checklist:" in rendered
    assert "Group invalid_status" in rendered
    assert "Retry: gsd-tools requirements precheck" in rendered
