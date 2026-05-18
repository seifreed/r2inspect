from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any


def _load_quick_bootstrap() -> Any:
    # Load through the real import system: quick_bootstrap.py combines
    # `from __future__ import annotations` with @dataclass, so the module
    # must be registered the way the import system does it (a bare
    # spec/exec_module is not enough); importlib.import_module handles that
    # with no manual module-table assignment in test code.
    scripts_path = str(Path(__file__).resolve().parents[2] / "scripts")
    if scripts_path not in sys.path:
        sys.path.insert(0, scripts_path)
    return importlib.import_module("quick_bootstrap")


def test_completion_aborts_without_state_mutation_on_gate_failure(tmp_path, capsys):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    def fake_gate(_planning_root, _version):
        return {
            "passed": False,
            "failure_groups": {
                "missing_file": [
                    {
                        "code": "missing_file",
                        "severity": "error",
                        "message": "Missing audit artifact",
                        "fix": "Create audit file.",
                    }
                ]
            },
            "retry_command": "python scripts/quick_bootstrap.py milestone complete v1.1",
        }

    deps = {
        "evaluate_requirements_contract_gate": lambda _planning_root: {
            "passed": True,
            "failure_groups": {},
            "retry_command": "unused",
        },
        "evaluate_milestone_governance_gate": fake_gate,
        "evaluate_traceability_drift_gate": lambda _planning_root, **_kwargs: {
            "passed": True,
            "failure_groups": {},
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
        "parse_args": lambda: quick_bootstrap.argparse.Namespace(
            command="milestone",
            milestone_command="complete",
            version="v1.1",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
        "format_gate_failures": lambda _result, retry_command: f"blocked\nRetry: {retry_command}",
    }

    exit_code = quick_bootstrap.main(deps=deps)
    output = capsys.readouterr().out
    after = state_path.read_text(encoding="utf-8")

    assert exit_code == 1
    assert "Retry: python scripts/quick_bootstrap.py milestone complete v1.1" in output
    assert "milestone complete v1.1 gate blocked" in after
    assert "| complete | v1.1 | blocked |" in after
    assert "milestone complete v1.1 gate passed" not in after


def test_completion_records_evidence_when_gate_passes(tmp_path, capsys):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    deps = {
        "evaluate_requirements_contract_gate": lambda _planning_root: {
            "passed": True,
            "failure_groups": {},
            "retry_command": "unused",
        },
        "evaluate_milestone_governance_gate": lambda _planning_root, _version: {
            "passed": True,
            "failure_groups": {},
            "retry_command": "python scripts/quick_bootstrap.py milestone complete v1.1",
        },
        "evaluate_traceability_drift_gate": lambda _planning_root, **_kwargs: {
            "passed": True,
            "failure_groups": {},
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
        "parse_args": lambda: quick_bootstrap.argparse.Namespace(
            command="milestone",
            milestone_command="complete",
            version="v1.1",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
    }

    exit_code = quick_bootstrap.main(deps=deps)
    payload = json.loads(capsys.readouterr().out)
    state_text = state_path.read_text(encoding="utf-8")

    assert exit_code == 0
    assert payload["command"] == "milestone complete"
    assert payload["passed"] is True
    assert "milestone complete v1.1 gate passed" in state_text


def test_blocked_completion_keeps_completion_state_unadvanced(tmp_path, capsys):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text(
        "# Project State\n\nLast activity: baseline\n\nstatus: in_progress\n",
        encoding="utf-8",
    )

    deps = {
        "evaluate_requirements_contract_gate": lambda _planning_root: {
            "passed": True,
            "failure_groups": {},
            "retry_command": "unused",
        },
        "evaluate_milestone_governance_gate": lambda _planning_root, _version: {
            "passed": False,
            "failure_groups": {
                "invalid_status": [{"message": "status must be passed", "fix": "set status passed"}]
            },
            "retry_command": "python scripts/quick_bootstrap.py milestone complete v1.1",
        },
        "evaluate_traceability_drift_gate": lambda _planning_root, **_kwargs: {
            "passed": True,
            "failure_groups": {},
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
        "parse_args": lambda: quick_bootstrap.argparse.Namespace(
            command="milestone",
            milestone_command="complete",
            version="v1.1",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
    }

    exit_code = quick_bootstrap.main(deps=deps)
    state_text = state_path.read_text(encoding="utf-8")
    _ = capsys.readouterr().out

    assert exit_code == 1
    assert "status: in_progress" in state_text
    assert "| complete | v1.1 | blocked |" in state_text


def test_remediation_output_uses_context_retry_command(tmp_path, capsys):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    deps = {
        "evaluate_requirements_contract_gate": lambda _planning_root: {
            "passed": True,
            "failure_groups": {},
            "retry_command": "unused",
        },
        "evaluate_milestone_governance_gate": lambda _planning_root, _version: {
            "passed": False,
            "failure_groups": {
                "missing_file": [
                    {"message": "Missing audit artifact", "fix": "Create audit file."}
                ],
                "malformed_sections": [
                    {"message": "Malformed audit", "fix": "Add required sections."}
                ],
            },
            "retry_command": "python scripts/quick_bootstrap.py milestone precheck v1.1",
        },
        "parse_args": lambda: quick_bootstrap.argparse.Namespace(
            command="milestone",
            milestone_command="complete",
            version="v1.1",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
    }

    exit_code = quick_bootstrap.main(deps=deps)
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "Retry: python scripts/quick_bootstrap.py milestone complete v1.1" in output
    assert "python scripts/quick_bootstrap.py milestone precheck v1.1" not in output


def test_milestone_complete_aborts_when_requirements_contract_gate_blocked(tmp_path, capsys):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\nstatus: in_progress\n", encoding="utf-8")

    called = {"milestone_gate": False}

    def fake_milestone_gate(_planning_root, _version):
        called["milestone_gate"] = True
        return {"passed": True, "failure_groups": {}, "retry_command": "unused"}

    deps = {
        "evaluate_requirements_contract_gate": lambda _planning_root: {
            "passed": False,
            "failure_groups": {
                "missing_acceptance_criteria": [{"message": "missing acceptance", "fix": "add"}]
            },
            "retry_command": "node ~/.claude/get-shit-done/bin/gsd-tools.cjs requirements precheck",
        },
        "evaluate_milestone_governance_gate": fake_milestone_gate,
        "parse_args": lambda: quick_bootstrap.argparse.Namespace(
            command="milestone",
            milestone_command="complete",
            version="v1.1",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
    }

    exit_code = quick_bootstrap.main(deps=deps)
    output = capsys.readouterr().out
    after = state_path.read_text(encoding="utf-8")

    assert exit_code == 1
    assert called["milestone_gate"] is False
    assert "Retry: python scripts/quick_bootstrap.py milestone complete v1.1" in output
    assert "status: in_progress" in after
    assert "| complete | all | blocked |" in after


def test_milestone_complete_blocks_on_traceability_drift_before_milestone_gate(tmp_path, capsys):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text(
        "# Project State\n\nLast activity: baseline\n\nstatus: in_progress\n",
        encoding="utf-8",
    )
    order: list[str] = []
    called = {"milestone_gate": False}

    def fake_requirements_gate(_planning_root):
        order.append("requirements")
        return {"passed": True, "failure_groups": {}, "retry_command": "unused"}

    def fake_traceability_gate(_planning_root, **_kwargs):
        order.append("traceability")
        return {
            "passed": False,
            "failure_groups": {
                "state_mapping_mismatch": [
                    {
                        "message": "TRC-01 complete while mapped phase is not complete",
                        "fix": "Align requirement status with roadmap completion.",
                    }
                ]
            },
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        }

    def fake_milestone_gate(_planning_root, _version):
        called["milestone_gate"] = True
        order.append("milestone")
        return {"passed": True, "failure_groups": {}, "retry_command": "unused"}

    deps = {
        "parse_args": lambda: quick_bootstrap.argparse.Namespace(
            command="milestone",
            milestone_command="complete",
            version="v1.1",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
        "evaluate_requirements_contract_gate": fake_requirements_gate,
        "evaluate_traceability_drift_gate": fake_traceability_gate,
        "evaluate_milestone_governance_gate": fake_milestone_gate,
    }

    exit_code = quick_bootstrap.main(deps=deps)
    output = capsys.readouterr().out
    after = state_path.read_text(encoding="utf-8")

    assert exit_code == 1
    assert order == ["requirements", "traceability"]
    assert called["milestone_gate"] is False
    assert output.count("Retry: ") == 1
    assert "Retry: python scripts/quick_bootstrap.py milestone complete v1.1" in output
    assert "status: in_progress" in after
    assert "| complete | all | passed |" in after
    assert "| complete | all | - | blocked |" in after
    assert "| complete | v1.1 | passed |" not in after


def test_traceability_precheck_matrix_additions_do_not_change_completion_gate_behavior(
    tmp_path, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\nstatus: in_progress\n", encoding="utf-8")

    args_queue = [
        quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
            scope="milestone",
            phase_id=None,
            matrix_detail="expanded",
        ),
        quick_bootstrap.argparse.Namespace(
            command="milestone",
            milestone_command="complete",
            version="v1.1",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
    ]
    called = {"milestone_gate": False}

    deps = {
        "parse_args": lambda: args_queue.pop(0),
        "evaluate_traceability_drift_gate": lambda _planning_root, **_kwargs: {
            "passed": False,
            "failure_groups": {
                "state_mapping_mismatch": [{"message": "mismatch", "fix": "align"}],
                "unmapped_requirement": [{"message": "unmapped", "fix": "map req"}],
            },
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
        "build_requirement_coverage_matrix": lambda _planning_root, **_kwargs: {
            "schema_version": "coverage_matrix.v1",
            "coverage_matrix": {
                "scope": "milestone",
                "scope_target": "all-active",
                "rows": [
                    {
                        "requirement_id": "GUX-01",
                        "coverage_state": "stale",
                        "cause_codes": ["state_mapping_mismatch"],
                        "remediation": "Align requirement status with mapped phase completion state.",
                        "retry_command": "python scripts/quick_bootstrap.py traceability precheck",
                    }
                ],
                "summary": {
                    "total": 1,
                    "covered": 0,
                    "partial": 0,
                    "uncovered": 0,
                    "stale": 1,
                },
            },
        },
        "evaluate_requirements_contract_gate": lambda _planning_root: {
            "passed": True,
            "failure_groups": {},
            "retry_command": "unused",
        },
        "evaluate_milestone_governance_gate": lambda _planning_root, _version: called.__setitem__(
            "milestone_gate", True
        )
        or {
            "passed": False,
            "failure_groups": {
                "missing_file": [{"message": "Missing audit artifact", "fix": "Create audit file."}]
            },
            "retry_command": "unused",
        },
    }

    precheck_exit = quick_bootstrap.main(deps=deps)
    precheck_payload = json.loads(capsys.readouterr().out)
    completion_exit = quick_bootstrap.main(deps=deps)
    completion_output = capsys.readouterr().out
    after = state_path.read_text(encoding="utf-8")

    assert precheck_exit == 0
    assert precheck_payload["schema_version"] == "coverage_matrix.v1"
    assert "coverage_matrix" in precheck_payload
    assert completion_exit == 1
    assert called["milestone_gate"] is False
    assert "Retry: python scripts/quick_bootstrap.py milestone complete v1.1" in completion_output
    assert "| complete | all | passed |" in after
    assert "| complete | all | - | blocked |" in after
    assert "| complete | v1.1 | passed |" not in after


def test_ranked_remediation_hints_are_additive_to_traceability_precheck_contract(
    tmp_path, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\nstatus: in_progress\n", encoding="utf-8")

    args_queue = [
        quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
            scope="milestone",
            phase_id=None,
            matrix_detail="expanded",
        ),
        quick_bootstrap.argparse.Namespace(
            command="milestone",
            milestone_command="complete",
            version="v1.1",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
    ]
    called = {"milestone_gate": False}

    deps = {
        "parse_args": lambda: args_queue.pop(0),
        "evaluate_traceability_drift_gate": lambda _planning_root, **_kwargs: {
            "passed": False,
            "failure_groups": {
                "state_mapping_mismatch": [{"message": "mismatch", "fix": "align"}],
                "unmapped_requirement": [{"message": "unmapped", "fix": "map req"}],
            },
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
        "build_requirement_coverage_matrix": lambda _planning_root, **_kwargs: {
            "schema_version": "coverage_matrix.v1",
            "coverage_matrix": {
                "scope": "milestone",
                "scope_target": "all-active",
                "rows": [
                    {
                        "requirement_id": "GUX-02",
                        "coverage_state": "stale",
                        "cause_codes": ["state_mapping_mismatch"],
                        "remediation": "Align requirement status with mapped phase completion state.",
                        "retry_command": "python scripts/quick_bootstrap.py traceability precheck",
                    }
                ],
                "summary": {
                    "total": 1,
                    "covered": 0,
                    "partial": 0,
                    "uncovered": 0,
                    "stale": 1,
                },
            },
        },
        "evaluate_requirements_contract_gate": lambda _planning_root: {
            "passed": True,
            "failure_groups": {},
            "retry_command": "unused",
        },
        "evaluate_milestone_governance_gate": lambda _planning_root, _version: called.__setitem__(
            "milestone_gate", True
        )
        or {
            "passed": False,
            "failure_groups": {
                "missing_file": [{"message": "Missing audit artifact", "fix": "Create audit file."}]
            },
            "retry_command": "unused",
        },
    }

    precheck_exit = quick_bootstrap.main(deps=deps)
    precheck_payload = json.loads(capsys.readouterr().out)
    completion_exit = quick_bootstrap.main(deps=deps)
    completion_output = capsys.readouterr().out
    after = state_path.read_text(encoding="utf-8")

    assert precheck_exit == 0
    assert precheck_payload["command"] == "traceability precheck"
    assert precheck_payload["schema_version"] == "coverage_matrix.v1"
    assert "coverage_matrix" in precheck_payload
    assert "#1 Rationale:" in precheck_payload["checklist"]
    assert "Top-ranked blocker baseline: none." in precheck_payload["checklist"]
    assert "Remediation by failure type:" in precheck_payload["checklist"]

    assert completion_exit == 1
    assert called["milestone_gate"] is False
    assert "Retry: python scripts/quick_bootstrap.py milestone complete v1.1" in completion_output
    assert "| complete | all | passed |" in after
    assert "| complete | all | - | blocked |" in after
    assert "| complete | v1.1 | passed |" not in after
