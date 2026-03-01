from __future__ import annotations

import importlib.util
import json
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
build_requirement_coverage_matrix = getattr(MODULE, "build_requirement_coverage_matrix", None)
build_impact_ranked_remediation_hints = getattr(
    MODULE, "build_impact_ranked_remediation_hints", None
)
format_impact_ranked_remediation_hints = getattr(
    MODULE, "format_impact_ranked_remediation_hints", None
)
derive_coverage_state = getattr(MODULE, "_derive_coverage_state", None)
order_cause_codes = getattr(MODULE, "_order_cause_codes", None)
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


def _write_traceability_roadmap_with_completion(
    planning_root: Path,
    *,
    phase2_complete: bool = True,
    phase3_complete: bool = True,
    phase4_complete: bool = False,
) -> None:
    phase2_marker = "x" if phase2_complete else " "
    phase3_marker = "x" if phase3_complete else " "
    phase4_marker = "x" if phase4_complete else " "
    (planning_root / "ROADMAP.md").write_text(
        "\n".join(
            [
                "# Roadmap",
                "",
                "### 🚧 v1.1 Hardening (In Progress)",
                "",
                f"- [{phase2_marker}] **Phase 2: Milestone Governance Gates**",
                f"- [{phase3_marker}] **Phase 3: Requirements Contract Enforcement**",
                f"- [{phase4_marker}] **Phase 4: Traceability and Drift Enforcement**",
            ]
        ),
        encoding="utf-8",
    )


def _write_traceability_fixture_with_statuses(
    planning_root: Path,
    *,
    req_status: str,
    aux_status: str,
    rows: str,
) -> None:
    entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: REQ-01",
            f"- status: {req_status}",
            "- acceptance_criteria: Must map to one active phase.",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_with_traceability(
            entries,
            rows.replace("AUX_STATUS", aux_status),
        ),
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


def test_impact_ranked_builder_orders_by_impact_then_check_key_deterministic() -> None:
    assert (
        build_impact_ranked_remediation_hints is not None
    ), "build_impact_ranked_remediation_hints must be implemented in scripts/governance_gates.py"
    result = {
        "failure_groups": {
            "unknown_mapped_phase": [
                {
                    "code": "unknown-mapped-phase",
                    "severity": "error",
                    "message": "Requirement REQ-10 maps to unknown phase 99.",
                    "fix": "Map REQ-10 to a known phase.",
                }
            ],
            "unmapped_requirement": [
                {
                    "code": "missing-traceability-row",
                    "severity": "error",
                    "message": "Requirement GUX-02 has no traceability row.",
                    "fix": "Add a traceability row for GUX-02.",
                }
            ],
        }
    }
    coverage_matrix = {
        "rows": [
            {"requirement_id": "GUX-02", "cause_codes": ["unmapped_requirement"]},
            {"requirement_id": "REQ-10", "cause_codes": ["unknown_mapped_phase"]},
            {"requirement_id": "REQ-11", "cause_codes": ["unknown_mapped_phase"]},
        ]
    }

    ranked = build_impact_ranked_remediation_hints(
        result,
        coverage_matrix,
        retry_command="python scripts/quick_bootstrap.py traceability precheck --scope milestone",
    )

    assert [item["rank"] for item in ranked] == [1, 2]
    assert ranked[0]["failure_type"] == "unknown_mapped_phase"
    assert ranked[0]["blast_radius"] == 2
    assert ranked[0]["severity_weight"] == 3
    assert ranked[1]["failure_type"] == "unmapped_requirement"
    assert ranked[1]["blast_radius"] == 1
    assert ranked[0]["rank_key"] < ranked[1]["rank_key"]


def test_impact_ranked_hints_are_deterministic_for_identical_inputs() -> None:
    assert (
        build_impact_ranked_remediation_hints is not None
    ), "build_impact_ranked_remediation_hints must be implemented in scripts/governance_gates.py"
    result = {
        "failure_groups": {
            "unknown_touched_requirement": [
                {
                    "code": "missing-alpha",
                    "severity": "error",
                    "message": "Touched requirement id `ALPHA-01` does not exist.",
                    "fix": "Use a known requirement id.",
                },
                {
                    "code": "missing-beta",
                    "severity": "error",
                    "message": "Touched requirement id `BETA-01` does not exist.",
                    "fix": "Use a known requirement id.",
                },
            ]
        }
    }
    coverage_matrix = {"rows": []}
    retry = "python scripts/quick_bootstrap.py traceability precheck --scope touched --requirement-id ALPHA-01"

    first = build_impact_ranked_remediation_hints(result, coverage_matrix, retry_command=retry)
    second = build_impact_ranked_remediation_hints(result, coverage_matrix, retry_command=retry)
    first_serialized = json.dumps(first, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    second_serialized = json.dumps(second, ensure_ascii=True, separators=(",", ":"), sort_keys=True)

    assert first_serialized == second_serialized
    assert [item["check_key"] for item in first] == ["missing-alpha", "missing-beta"]


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


def test_traceability_unmapped_requirement_detected(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    _write_traceability_fixture(planning_root, "| REQ-01 | Phase 4 | Pending |")
    _write_traceability_roadmap(planning_root)

    result = _evaluate_traceability(planning_root)

    assert result["passed"] is False
    assert "unmapped_requirement" in result["failure_groups"]


def test_traceability_multi_phase_mapping_detected(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    rows = "\n".join(
        [
            "| REQ-01 | Phase 3 | Pending |",
            "| REQ-01 | Phase 4 | Pending |",
            "| AUX-01 | Phase 4 | Pending |",
        ]
    )
    _write_traceability_fixture(planning_root, rows)
    _write_traceability_roadmap(planning_root)

    result = _evaluate_traceability(planning_root)

    assert result["passed"] is False
    assert "multi_phase_mapping" in result["failure_groups"]


def test_traceability_unknown_mapped_phase_detected(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    rows = "\n".join(
        [
            "| REQ-01 | Phase 9 | Pending |",
            "| AUX-01 | Phase 4 | Pending |",
        ]
    )
    _write_traceability_fixture(planning_root, rows)
    _write_traceability_roadmap(planning_root)

    result = _evaluate_traceability(planning_root)

    assert result["passed"] is False
    assert "unknown_mapped_phase" in result["failure_groups"]


def test_traceability_ordering_is_deterministic_for_mapping_failures(tmp_path: Path) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    rows = "\n".join(
        [
            "| REQ-01 | Phase 9 | Pending |",
            "| REQ-01 | Phase 4 | Pending |",
        ]
    )
    _write_traceability_fixture(planning_root, rows)
    _write_traceability_roadmap(planning_root)

    result = _evaluate_traceability(planning_root)

    assert result["passed"] is False
    assert list(result["failure_groups"]) == [
        "unmapped_requirement",
        "multi_phase_mapping",
        "unknown_mapped_phase",
    ]


def test_traceability_detects_requirement_complete_mapped_to_incomplete_phase(
    tmp_path: Path,
) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    rows = "\n".join(
        [
            "| REQ-01 | Phase 4 | Complete |",
            "| AUX-01 | Phase 3 | AUX_STATUS |",
        ]
    )
    _write_traceability_fixture_with_statuses(
        planning_root,
        req_status="Complete",
        aux_status="Complete",
        rows=rows,
    )
    _write_traceability_roadmap_with_completion(phase4_complete=False, planning_root=planning_root)

    result = _evaluate_traceability(planning_root)

    assert result["passed"] is False
    assert "state_mapping_mismatch" in result["failure_groups"]


def test_traceability_detects_phase_complete_with_requirement_not_complete(
    tmp_path: Path,
) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    rows = "\n".join(
        [
            "| REQ-01 | Phase 3 | Pending |",
            "| AUX-01 | Phase 4 | AUX_STATUS |",
        ]
    )
    _write_traceability_fixture_with_statuses(
        planning_root,
        req_status="Pending",
        aux_status="Pending",
        rows=rows,
    )
    _write_traceability_roadmap_with_completion(
        planning_root=planning_root,
        phase3_complete=True,
        phase4_complete=False,
    )

    result = _evaluate_traceability(planning_root)

    assert result["passed"] is False
    assert "state_mapping_mismatch" in result["failure_groups"]


def test_traceability_failure_group_order_includes_state_mapping_mismatch_last(
    tmp_path: Path,
) -> None:
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    rows = "\n".join(
        [
            "| REQ-01 | Phase 3 | Complete |",
            "| REQ-01 | Phase 9 | Complete |",
        ]
    )
    _write_traceability_fixture_with_statuses(
        planning_root,
        req_status="Complete",
        aux_status="Pending",
        rows=rows,
    )
    _write_traceability_roadmap_with_completion(
        planning_root=planning_root,
        phase3_complete=False,
        phase4_complete=False,
    )

    result = _evaluate_traceability(planning_root)

    assert result["passed"] is False
    assert list(result["failure_groups"]) == [
        "unmapped_requirement",
        "multi_phase_mapping",
        "unknown_mapped_phase",
        "state_mapping_mismatch",
    ]


def test_coverage_matrix_rows_are_sorted_and_byte_stable(tmp_path: Path) -> None:
    assert (
        build_requirement_coverage_matrix is not None
    ), "build_requirement_coverage_matrix must be implemented in scripts/governance_gates.py"
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: REQ-10",
            "- status: Pending",
            "- acceptance_criteria: Must be deterministically ordered.",
            "",
            "#### Requirement",
            "",
            "- id: REQ-02",
            "- status: Pending",
            "- acceptance_criteria: Must be deterministically ordered.",
            "",
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Blocked",
            "- acceptance_criteria: Blocked requirements are excluded.",
        ]
    )
    traceability_rows = "\n".join(
        [
            "| REQ-10 | Phase 5 | Pending |",
            "| REQ-10 | Phase 9 | Pending |",
            "| REQ-02 | Phase 9 | Pending |",
            "| AUX-01 | Phase 5 | Pending |",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_with_traceability(entries, traceability_rows),
    )
    (planning_root / "ROADMAP.md").write_text(
        "\n".join(
            [
                "# Roadmap",
                "",
                "- [ ] **Phase 5: Coverage Matrix**",
            ]
        ),
        encoding="utf-8",
    )

    first = build_requirement_coverage_matrix(planning_root, scope="milestone")
    second = build_requirement_coverage_matrix(planning_root, scope="milestone")
    first_rows = first["coverage_matrix"]["rows"]
    second_rows = second["coverage_matrix"]["rows"]

    assert [row["requirement_id"] for row in first_rows] == ["AUX-01", "REQ-02", "REQ-10"]
    assert first_rows == second_rows


def test_coverage_matrix_is_byte_stable_across_repeated_builds(tmp_path: Path) -> None:
    assert (
        build_requirement_coverage_matrix is not None
    ), "build_requirement_coverage_matrix must be implemented in scripts/governance_gates.py"
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: GUX-01",
            "- status: Pending",
            "- acceptance_criteria: Deterministic serialization must be byte-stable.",
            "",
            "#### Requirement",
            "",
            "- id: GUX-02",
            "- status: Complete",
            "- acceptance_criteria: Deterministic serialization must be byte-stable.",
        ]
    )
    traceability_rows = "\n".join(
        [
            "| GUX-01 | Phase 5 | Pending |",
            "| GUX-02 | Phase 5 | Complete |",
            "| AUX-01 | Phase 6 | Pending |",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_with_traceability(entries, traceability_rows),
    )
    (planning_root / "ROADMAP.md").write_text(
        "\n".join(
            [
                "# Roadmap",
                "",
                "- [ ] **Phase 5: Requirement Coverage Matrix**",
                "- [ ] **Phase 6: Impact-Ranked Remediation Hints**",
            ]
        ),
        encoding="utf-8",
    )

    first = build_requirement_coverage_matrix(planning_root, scope="milestone")
    second = build_requirement_coverage_matrix(planning_root, scope="milestone")
    first_serialized = json.dumps(
        first["coverage_matrix"],
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    second_serialized = json.dumps(
        second["coverage_matrix"],
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )

    assert [row["requirement_id"] for row in first["coverage_matrix"]["rows"]] == [
        "AUX-01",
        "GUX-01",
        "GUX-02",
    ]
    assert first_serialized == second_serialized


def test_coverage_matrix_cause_ordering_is_canonical(tmp_path: Path) -> None:
    assert (
        build_requirement_coverage_matrix is not None
    ), "build_requirement_coverage_matrix must be implemented in scripts/governance_gates.py"
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Pending",
            "- acceptance_criteria: Cause ordering must be deterministic.",
        ]
    )
    traceability_rows = "\n".join(
        [
            "| REQ-01 | Phase 5 | Pending |",
            "| REQ-01 | Phase 9 | Pending |",
            "| AUX-01 | Phase 5 | Pending |",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_with_traceability(entries, traceability_rows),
    )
    (planning_root / "ROADMAP.md").write_text(
        "\n".join(
            [
                "# Roadmap",
                "",
                "- [ ] **Phase 5: Coverage Matrix**",
            ]
        ),
        encoding="utf-8",
    )

    result = build_requirement_coverage_matrix(planning_root, scope="milestone")
    rows = {row["requirement_id"]: row for row in result["coverage_matrix"]["rows"]}
    assert rows["REQ-01"]["cause_codes"] == ["multi_phase_mapping", "unknown_mapped_phase"]


def test_coverage_matrix_exclusions_ignore_blocked_and_out_of_scope(tmp_path: Path) -> None:
    assert (
        build_requirement_coverage_matrix is not None
    ), "build_requirement_coverage_matrix must be implemented in scripts/governance_gates.py"
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Pending",
            "- acceptance_criteria: Included in denominator.",
            "",
            "#### Requirement",
            "",
            "- id: REQ-02",
            "- status: Blocked",
            "- acceptance_criteria: Excluded from denominator.",
        ]
    )
    traceability_rows = "| REQ-01 | Phase 5 | Pending |"
    _write_requirements_contract(
        planning_root,
        _requirements_with_traceability(entries, traceability_rows),
    )
    (planning_root / "ROADMAP.md").write_text(
        "- [ ] **Phase 5: Coverage Matrix**\n", encoding="utf-8"
    )

    result = build_requirement_coverage_matrix(planning_root, scope="milestone")

    assert result["coverage_matrix"]["summary"]["total"] == 2
    assert [row["requirement_id"] for row in result["coverage_matrix"]["rows"]] == [
        "AUX-01",
        "REQ-01",
    ]


def test_coverage_matrix_schema_version_is_explicit(tmp_path: Path) -> None:
    assert (
        build_requirement_coverage_matrix is not None
    ), "build_requirement_coverage_matrix must be implemented in scripts/governance_gates.py"
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    _write_traceability_fixture(planning_root, "| REQ-01 | Phase 4 | Pending |")
    _write_traceability_roadmap(planning_root)

    result = build_requirement_coverage_matrix(planning_root, scope="milestone")

    assert result["schema_version"] == "coverage_matrix.v1"


def test_coverage_matrix_stale_state_overrides_other_causes(tmp_path: Path) -> None:
    assert (
        build_requirement_coverage_matrix is not None
    ), "build_requirement_coverage_matrix must be implemented in scripts/governance_gates.py"
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Complete",
            "- acceptance_criteria: Stale wins over all other causes.",
        ]
    )
    traceability_rows = "\n".join(
        [
            "| REQ-01 | Phase 5 | Complete |",
            "| REQ-01 | Phase 9 | Complete |",
            "| AUX-01 | Phase 5 | Pending |",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_with_traceability(entries, traceability_rows),
    )
    (planning_root / "ROADMAP.md").write_text(
        "\n".join(
            [
                "# Roadmap",
                "",
                "- [ ] **Phase 5: Coverage Matrix**",
            ]
        ),
        encoding="utf-8",
    )

    result = build_requirement_coverage_matrix(planning_root, scope="milestone")
    rows = {row["requirement_id"]: row for row in result["coverage_matrix"]["rows"]}

    assert "state_mapping_mismatch" in rows["REQ-01"]["cause_codes"]
    assert rows["REQ-01"]["coverage_state"] == "stale"


def test_coverage_matrix_covered_state_when_no_causes(tmp_path: Path) -> None:
    assert (
        build_requirement_coverage_matrix is not None
    ), "build_requirement_coverage_matrix must be implemented in scripts/governance_gates.py"
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Pending",
            "- acceptance_criteria: No causes means covered.",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_with_traceability(entries, "| REQ-01 | Phase 5 | Pending |"),
    )
    (planning_root / "ROADMAP.md").write_text(
        "\n".join(
            [
                "# Roadmap",
                "",
                "- [ ] **Phase 5: Coverage Matrix**",
            ]
        ),
        encoding="utf-8",
    )

    result = build_requirement_coverage_matrix(planning_root, scope="milestone")
    rows = {row["requirement_id"]: row for row in result["coverage_matrix"]["rows"]}

    assert rows["REQ-01"]["cause_codes"] == []
    assert rows["REQ-01"]["coverage_state"] == "covered"


def test_coverage_matrix_partial_state_for_valid_mapping_with_issues(tmp_path: Path) -> None:
    assert (
        build_requirement_coverage_matrix is not None
    ), "build_requirement_coverage_matrix must be implemented in scripts/governance_gates.py"
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Pending",
            "- acceptance_criteria: Valid mapping + issues means partial.",
        ]
    )
    traceability_rows = "\n".join(
        [
            "| REQ-01 | Phase 5 | Pending |",
            "| REQ-01 | Phase 9 | Pending |",
            "| AUX-01 | Phase 5 | Pending |",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_with_traceability(entries, traceability_rows),
    )
    (planning_root / "ROADMAP.md").write_text(
        "\n".join(
            [
                "# Roadmap",
                "",
                "- [ ] **Phase 5: Coverage Matrix**",
            ]
        ),
        encoding="utf-8",
    )

    result = build_requirement_coverage_matrix(planning_root, scope="milestone")
    rows = {row["requirement_id"]: row for row in result["coverage_matrix"]["rows"]}

    assert rows["REQ-01"]["cause_codes"] == ["multi_phase_mapping", "unknown_mapped_phase"]
    assert rows["REQ-01"]["coverage_state"] == "partial"


def test_coverage_matrix_uncovered_state_for_only_invalid_mappings(tmp_path: Path) -> None:
    assert (
        build_requirement_coverage_matrix is not None
    ), "build_requirement_coverage_matrix must be implemented in scripts/governance_gates.py"
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    entries = "\n".join(
        [
            "#### Requirement",
            "",
            "- id: REQ-01",
            "- status: Pending",
            "- acceptance_criteria: Missing valid mapping means uncovered.",
        ]
    )
    _write_requirements_contract(
        planning_root,
        _requirements_with_traceability(entries, "| REQ-01 | Phase 9 | Pending |"),
    )
    (planning_root / "ROADMAP.md").write_text(
        "\n".join(
            [
                "# Roadmap",
                "",
                "- [ ] **Phase 5: Coverage Matrix**",
            ]
        ),
        encoding="utf-8",
    )

    result = build_requirement_coverage_matrix(planning_root, scope="milestone")
    rows = {row["requirement_id"]: row for row in result["coverage_matrix"]["rows"]}

    assert rows["REQ-01"]["cause_codes"] == ["unknown_mapped_phase"]
    assert rows["REQ-01"]["coverage_state"] == "uncovered"


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
