from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


def _load_quick_bootstrap():
    module_path = Path(__file__).resolve().parents[2] / "scripts" / "quick_bootstrap.py"
    spec = importlib.util.spec_from_file_location("quick_bootstrap", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load quick_bootstrap module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_completion_aborts_without_state_mutation_on_gate_failure(monkeypatch, tmp_path, capsys):
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

    monkeypatch.setattr(quick_bootstrap, "evaluate_milestone_governance_gate", fake_gate)
    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="milestone",
            milestone_command="complete",
            version="v1.1",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "format_gate_failures",
        lambda _result, retry_command: f"blocked\nRetry: {retry_command}",
    )

    exit_code = quick_bootstrap.main()
    output = capsys.readouterr().out
    after = state_path.read_text(encoding="utf-8")

    assert exit_code == 1
    assert "Retry: python scripts/quick_bootstrap.py milestone complete v1.1" in output
    assert "milestone complete v1.1 gate blocked" in after
    assert "| complete | v1.1 | blocked |" in after
    assert "milestone complete v1.1 gate passed" not in after


def test_completion_records_evidence_when_gate_passes(monkeypatch, tmp_path, capsys):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_milestone_governance_gate",
        lambda _planning_root, _version: {
            "passed": True,
            "failure_groups": {},
            "retry_command": "python scripts/quick_bootstrap.py milestone complete v1.1",
        },
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="milestone",
            milestone_command="complete",
            version="v1.1",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
    )

    exit_code = quick_bootstrap.main()
    payload = json.loads(capsys.readouterr().out)
    state_text = state_path.read_text(encoding="utf-8")

    assert exit_code == 0
    assert payload["command"] == "milestone complete"
    assert payload["passed"] is True
    assert "milestone complete v1.1 gate passed" in state_text


def test_blocked_completion_keeps_completion_state_unadvanced(monkeypatch, tmp_path, capsys):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text(
        "# Project State\n\nLast activity: baseline\n\nstatus: in_progress\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_milestone_governance_gate",
        lambda _planning_root, _version: {
            "passed": False,
            "failure_groups": {
                "invalid_status": [{"message": "status must be passed", "fix": "set status passed"}]
            },
            "retry_command": "python scripts/quick_bootstrap.py milestone complete v1.1",
        },
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="milestone",
            milestone_command="complete",
            version="v1.1",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
    )

    exit_code = quick_bootstrap.main()
    state_text = state_path.read_text(encoding="utf-8")
    _ = capsys.readouterr().out

    assert exit_code == 1
    assert "status: in_progress" in state_text
    assert "| complete | v1.1 | blocked |" in state_text


def test_remediation_output_uses_context_retry_command(monkeypatch, tmp_path, capsys):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_milestone_governance_gate",
        lambda _planning_root, _version: {
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
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="milestone",
            milestone_command="complete",
            version="v1.1",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
    )

    exit_code = quick_bootstrap.main()
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "Retry: python scripts/quick_bootstrap.py milestone complete v1.1" in output
    assert "python scripts/quick_bootstrap.py milestone precheck v1.1" not in output


def test_milestone_complete_aborts_when_requirements_contract_gate_fails(
    monkeypatch, tmp_path, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\nstatus: in_progress\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_requirements_contract_gate",
        lambda _planning_root: {
            "passed": False,
            "failure_groups": {
                "missing_acceptance_criteria": [{"message": "missing acceptance", "fix": "add"}]
            },
            "retry_command": "node ~/.claude/get-shit-done/bin/gsd-tools.cjs requirements precheck",
        },
    )
    called = {"milestone_gate": False}

    def fake_milestone_gate(_planning_root, _version):
        called["milestone_gate"] = True
        return {"passed": True, "failure_groups": {}, "retry_command": "unused"}

    monkeypatch.setattr(quick_bootstrap, "evaluate_milestone_governance_gate", fake_milestone_gate)
    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="milestone",
            milestone_command="complete",
            version="v1.1",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
    )

    exit_code = quick_bootstrap.main()
    output = capsys.readouterr().out
    after = state_path.read_text(encoding="utf-8")

    assert exit_code == 1
    assert called["milestone_gate"] is False
    assert "Retry: python scripts/quick_bootstrap.py milestone complete v1.1" in output
    assert "status: in_progress" in after
    assert "| complete | all | blocked |" in after
