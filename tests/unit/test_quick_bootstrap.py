from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def _load_quick_bootstrap():
    module_path = Path(__file__).resolve().parents[2] / "scripts" / "quick_bootstrap.py"
    spec = importlib.util.spec_from_file_location("quick_bootstrap", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load quick_bootstrap module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_preflight_fails_when_planning_or_roadmap_missing(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    payload = {
        "roadmap_exists": False,
        "planning_exists": True,
        "task_dir": str(tmp_path / ".planning" / "quick" / "9-sample"),
        "next_num": 9,
        "slug": "sample",
    }
    with pytest.raises(quick_bootstrap.PreflightError):
        quick_bootstrap.run_preflight(payload)


def test_valid_objective_generates_slug_and_2_to_3_checks_in_memory():
    quick_bootstrap = _load_quick_bootstrap()
    checks = quick_bootstrap.build_measurable_checks("Stabilize quick bootstrap behavior")
    assert 2 <= len(checks) <= 3
    slug = quick_bootstrap.slugify("Stabilize quick bootstrap behavior")
    assert slug.startswith("stabilize-quick-bootstrap")


def test_bootstrap_retries_once_after_minimal_autofix(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    calls = {"count": 0}

    def failing_runner(_objective: str, _gsd_tools_path: str):
        calls["count"] += 1
        raise quick_bootstrap.BootstrapError("bootstrap failed")

    retried = {"count": 0}

    def minimal_fix(_repo_root: Path):
        retried["count"] += 1
        return ["mkdir -p .planning/quick"]

    with pytest.raises(quick_bootstrap.BootstrapError):
        quick_bootstrap.execute_bootstrap(
            objective="Stabilize quick bootstrap behavior",
            gsd_tools_path="node fake",
            runner=failing_runner,
            autofix=minimal_fix,
            repo_root=tmp_path,
        )

    assert calls["count"] == 2
    assert retried["count"] == 1


def test_creates_quick_directory_and_plan(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "PLAN.template.md").write_text(
        "# Quick Task {number}: {objective}\n\n## Objective\n{objective}\n\n## Steps\n- Step\n\n## Verification\n{checks}\n",
        encoding="utf-8",
    )
    (template_dir / "SUMMARY.template.md").write_text(
        "# Quick Task {number} Summary\n\n## Verification\n- pending\n\n## Failure Block\nStatus: scaffolded\n",
        encoding="utf-8",
    )
    payload = {
        "roadmap_exists": True,
        "planning_exists": True,
        "task_dir": str(tmp_path / ".planning" / "quick" / "7-sample"),
        "next_num": 7,
        "slug": "sample",
    }
    checks = quick_bootstrap.build_measurable_checks("Stabilize quick bootstrap")
    artifacts = quick_bootstrap.create_quick_task(
        payload, "Stabilize quick bootstrap", checks, template_dir
    )
    assert artifacts["task_dir"].name == "7-sample"
    assert artifacts["plan_path"].exists()
    plan_text = artifacts["plan_path"].read_text(encoding="utf-8")
    assert "## Objective" in plan_text
    assert "## Steps" in plan_text
    assert "## Verification" in plan_text


def test_plan_has_exactly_2_or_3_measurable_checks(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "PLAN.template.md").write_text(
        "# Plan\n\n## Verification\n{checks}\n",
        encoding="utf-8",
    )
    (template_dir / "SUMMARY.template.md").write_text("# Summary\n", encoding="utf-8")
    payload = {
        "roadmap_exists": True,
        "planning_exists": True,
        "task_dir": str(tmp_path / ".planning" / "quick" / "8-checks"),
        "next_num": 8,
        "slug": "checks",
    }
    checks = quick_bootstrap.build_measurable_checks("Measure bootstrap checks")
    artifacts = quick_bootstrap.create_quick_task(
        payload, "Measure bootstrap checks", checks, template_dir
    )
    lines = [
        line.strip()
        for line in artifacts["plan_path"].read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("- ")
    ]
    assert len(lines) in (2, 3)


def test_summary_template_contains_failure_block(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "PLAN.template.md").write_text("# Plan\n{checks}\n", encoding="utf-8")
    (template_dir / "SUMMARY.template.md").write_text(
        "# Summary\n\n## Verification\n- pending\n\n## Failure Block\n- status: {status}\n- blocker: {blocker}\n- attempted commands:\n{attempted_commands}\n- continuation command: {continuation_command}\n",
        encoding="utf-8",
    )
    payload = {
        "roadmap_exists": True,
        "planning_exists": True,
        "task_dir": str(tmp_path / ".planning" / "quick" / "10-summary"),
        "next_num": 10,
        "slug": "summary",
    }
    checks = quick_bootstrap.build_measurable_checks("Write summary scaffold")
    artifacts = quick_bootstrap.create_quick_task(
        payload, "Write summary scaffold", checks, template_dir
    )
    summary_text = artifacts["summary_path"].read_text(encoding="utf-8")
    assert "## Verification" in summary_text
    assert "## Failure Block" in summary_text
    assert "status:" in summary_text
    assert "blocker:" in summary_text
    assert "attempted commands:" in summary_text
    assert "continuation command:" in summary_text


def test_state_updates_when_closing_task(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    task_dir = tmp_path / ".planning" / "quick" / "11-state-check"
    task_dir.mkdir(parents=True)
    summary = task_dir / "11-SUMMARY.md"
    summary.write_text("# Summary\n", encoding="utf-8")
    state_path = tmp_path / ".planning" / "STATE.md"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        "# Project State\n\nLast activity: 2026-01-01 — old\n\n## Quick Tasks Completed\n\n"
        "| # | Date | Description | Status |\n|---|------|-------------|--------|\n",
        encoding="utf-8",
    )

    quick_bootstrap.close_quick_task(
        task_dir=task_dir,
        status="completed",
        description="close task state sync",
        attempted_commands=["pytest -q"],
        state_path=state_path,
    )

    state_text = state_path.read_text(encoding="utf-8")
    assert "| 11 |" in state_text
    assert "| close task state sync | completed |" in state_text
    assert "Last activity:" in state_text


def test_failure_closure_writes_blocker_and_continuation(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    task_dir = tmp_path / ".planning" / "quick" / "12-failure"
    task_dir.mkdir(parents=True)
    summary = task_dir / "12-SUMMARY.md"
    summary.write_text("# Summary\n", encoding="utf-8")
    state_path = tmp_path / ".planning" / "STATE.md"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text("# Project State\n", encoding="utf-8")

    quick_bootstrap.close_quick_task(
        task_dir=task_dir,
        status="failed",
        description="bootstrap failed",
        blocker="init quick failed",
        attempted_commands=["node gsd-tools init quick"],
        continuation_command='python scripts/quick_bootstrap.py bootstrap "retry objective"',
        state_path=state_path,
    )

    summary_text = summary.read_text(encoding="utf-8")
    assert "status: failed" in summary_text
    assert "blocker: init quick failed" in summary_text
    assert "node gsd-tools init quick" in summary_text
    assert "continuation command: python scripts/quick_bootstrap.py bootstrap" in summary_text


def test_milestone_precheck_reports_structured_non_blocking_result(tmp_path, monkeypatch, capsys):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="milestone",
            milestone_command="precheck",
            version="v1.1",
            planning_root=str(planning_root),
            state_path=str(planning_root / "STATE.md"),
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_milestone_governance_gate",
        lambda _planning_root, _version: {
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
            "retry_command": "python scripts/quick_bootstrap.py milestone precheck v1.1",
        },
    )

    exit_code = quick_bootstrap.main()
    payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["command"] == "milestone precheck"
    assert payload["passed"] is False
    assert "missing_file" in payload["failure_groups"]


def test_milestone_complete_aborts_without_false_completion_on_gate_failure(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: unchanged\n", encoding="utf-8")

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
        "evaluate_requirements_contract_gate",
        lambda _planning_root: {
            "passed": False,
            "failure_groups": {
                "missing_acceptance_criteria": [
                    {"message": "missing", "fix": "add acceptance_criteria"}
                ]
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
        "format_requirements_contract_failures",
        lambda _result, retry_command: f"blocked\nRetry: {retry_command}",
    )

    exit_code = quick_bootstrap.main()
    output = capsys.readouterr().out
    after = state_path.read_text(encoding="utf-8")

    assert exit_code == 1
    assert called["milestone_gate"] is False
    assert "Retry: python scripts/quick_bootstrap.py milestone complete v1.1" in output
    assert "requirements complete gate blocked" in after
    assert "| complete | all | blocked |" in after
    assert "requirements complete gate passed" not in after


def test_milestone_complete_grouped_failures_output_has_grouped_failures_and_remediation(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    (planning_root / "REQUIREMENTS.md").write_text(
        (
            "# Requirements\n\n"
            "## v1 Requirements\n\n"
            "#### Requirement\n\n"
            "- id: REQ-01\n"
            "- status: Pending\n"
            "- acceptance_criteria: has criteria\n"
        ),
        encoding="utf-8",
    )
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: unchanged\n", encoding="utf-8")

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
        "evaluate_milestone_governance_gate",
        lambda _planning_root, _version: {
            "passed": False,
            "failure_groups": {
                "missing_file": [{"message": "missing", "fix": "create file"}],
                "invalid_status": [{"message": "status", "fix": "set passed"}],
                "stale_audit": [{"message": "stale", "fix": "rerun audit"}],
                "malformed_sections": [{"message": "sections", "fix": "add sections"}],
            },
            "retry_command": "python scripts/quick_bootstrap.py milestone complete v1.1",
        },
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": True,
            "failure_groups": {},
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
    )

    exit_code = quick_bootstrap.main()
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "Remediation by failure type:" in output
    assert "Group missing_file" in output
    assert "Group invalid_status" in output
    assert "Group stale_audit" in output
    assert "Group malformed_sections" in output


def test_milestone_retry_command_is_context_specific_and_single(tmp_path, monkeypatch, capsys):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: unchanged\n", encoding="utf-8")

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
        "evaluate_milestone_governance_gate",
        lambda _planning_root, _version: {
            "passed": False,
            "failure_groups": {"invalid_status": [{"message": "status", "fix": "set passed"}]},
            "retry_command": "python scripts/quick_bootstrap.py milestone precheck v1.1",
        },
    )

    exit_code = quick_bootstrap.main()
    output = capsys.readouterr().out

    assert exit_code == 1
    expected = "Retry: python scripts/quick_bootstrap.py milestone complete v1.1"
    assert expected in output
    assert output.count("Retry: ") == 1


def test_phase_complete_traceability_gate_uses_touched_scope_and_rejects_unknown_ids(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="phase",
            phase_command="complete",
            planning_root=str(planning_root),
            state_path=str(state_path),
            requirement_id=["REQ-03", "REQ-99"],
            delegate_args=[],
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_requirements_contract_gate",
        lambda _planning_root, **_kwargs: {"passed": True, "failure_groups": {}},
    )
    observed: dict[str, object] = {}

    def fake_traceability_gate(_planning_root, **kwargs):
        observed["scope"] = kwargs.get("scope")
        observed["touched_requirement_ids"] = kwargs.get("touched_requirement_ids")
        return {
            "passed": False,
            "failure_groups": {
                "unknown_touched_requirement": [
                    {"message": "REQ-99 unknown", "fix": "remove unknown touched id"}
                ]
            },
            "retry_command": "unused",
        }

    monkeypatch.setattr(quick_bootstrap, "evaluate_traceability_drift_gate", fake_traceability_gate)
    monkeypatch.setattr(
        quick_bootstrap,
        "run_transition_delegate",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("delegate should not run")),
    )

    exit_code = quick_bootstrap.main()
    output = capsys.readouterr().out
    after = state_path.read_text(encoding="utf-8")

    assert exit_code == 1
    assert observed["scope"] == "touched"
    assert observed["touched_requirement_ids"] == {"REQ-03", "REQ-99"}
    assert (
        "Retry: python scripts/quick_bootstrap.py phase complete --requirement-id REQ-03 --requirement-id REQ-99"
        in output
    )
    assert output.count("Retry: ") == 1
    assert "| phase complete | touched | REQ-03, REQ-99 | blocked |" in after


def test_phase_complete_traceability_gate_rejects_missing_touched_ids(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="phase",
            phase_command="complete",
            planning_root=str(planning_root),
            state_path=str(state_path),
            requirement_id=[],
            delegate_args=[],
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_requirements_contract_gate",
        lambda _planning_root, **_kwargs: {"passed": True, "failure_groups": {}},
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": False,
            "failure_groups": {
                "missing_touched_requirements": [
                    {"message": "missing touched ids", "fix": "pass --requirement-id"}
                ]
            },
            "retry_command": "unused",
        },
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "run_transition_delegate",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("delegate should not run")),
    )

    exit_code = quick_bootstrap.main()
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "Retry: python scripts/quick_bootstrap.py phase complete" in output
    assert output.count("Retry: ") == 1


def test_milestone_complete_traceability_ordering_runs_after_requirements_before_governance(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

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
    order: list[str] = []

    def fake_requirements(_planning_root):
        order.append("requirements")
        return {"passed": True, "failure_groups": {}}

    def fake_traceability(_planning_root, **_kwargs):
        order.append("traceability")
        return {"passed": True, "failure_groups": {}, "scope": "all", "touched_requirement_ids": []}

    def fake_milestone(_planning_root, _version):
        order.append("milestone")
        return {"passed": True, "failure_groups": {}}

    monkeypatch.setattr(quick_bootstrap, "evaluate_requirements_contract_gate", fake_requirements)
    monkeypatch.setattr(quick_bootstrap, "evaluate_traceability_drift_gate", fake_traceability)
    monkeypatch.setattr(quick_bootstrap, "evaluate_milestone_governance_gate", fake_milestone)

    exit_code = quick_bootstrap.main()
    payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["passed"] is True
    assert order == ["requirements", "traceability", "milestone"]


def test_milestone_complete_traceability_failure_blocks_and_emits_single_retry(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

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
        "evaluate_requirements_contract_gate",
        lambda _planning_root: {"passed": True, "failure_groups": {}},
    )
    called = {"milestone_gate": False}

    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": False,
            "failure_groups": {
                "unmapped_requirement": [
                    {"message": "TRC-02 missing mapping", "fix": "add mapping"}
                ]
            },
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
    )

    def fake_milestone_gate(_planning_root, _version):
        called["milestone_gate"] = True
        return {"passed": True, "failure_groups": {}}

    monkeypatch.setattr(quick_bootstrap, "evaluate_milestone_governance_gate", fake_milestone_gate)

    exit_code = quick_bootstrap.main()
    output = capsys.readouterr().out
    after = state_path.read_text(encoding="utf-8")

    assert exit_code == 1
    assert called["milestone_gate"] is False
    assert "Retry: python scripts/quick_bootstrap.py milestone complete v1.1" in output
    assert output.count("Retry: ") == 1
    assert "| complete | all | - | blocked |" in after


def test_requirements_precheck_reports_structured_non_blocking_result(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="requirements",
            requirements_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_requirements_contract_gate",
        lambda _planning_root: {
            "passed": False,
            "failure_groups": {
                "missing_acceptance_criteria": [
                    {
                        "message": "Requirement entry #1 missing acceptance criteria",
                        "fix": "Add acceptance_criteria",
                    }
                ]
            },
            "retry_command": "node ~/.claude/get-shit-done/bin/gsd-tools.cjs requirements precheck",
        },
    )

    exit_code = quick_bootstrap.main()
    payload = quick_bootstrap.json.loads(capsys.readouterr().out)
    after = state_path.read_text(encoding="utf-8")

    assert exit_code == 0
    assert payload["command"] == "requirements precheck"
    assert payload["passed"] is False
    assert "missing_acceptance_criteria" in payload["failure_groups"]
    assert (
        payload["retry_command"]
        == "python scripts/quick_bootstrap.py traceability precheck --scope phase --phase-id 05"
    )
    assert "Checklist:" in payload["checklist"]
    assert "requirements precheck gate blocked" in after
    assert "| precheck | all | blocked |" in after


def test_requirements_precheck_uses_shared_requirements_formatter(tmp_path, monkeypatch, capsys):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="requirements",
            requirements_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_requirements_contract_gate",
        lambda _planning_root: {
            "passed": True,
            "failure_groups": {},
            "retry_command": "node ~/.claude/get-shit-done/bin/gsd-tools.cjs requirements precheck",
        },
    )

    seen: dict[str, str] = {}

    def fake_formatter(result, retry_command):
        seen["retry_command"] = retry_command
        return f"formatted:{result.get('passed')}"

    monkeypatch.setattr(quick_bootstrap, "format_requirements_contract_failures", fake_formatter)

    exit_code = quick_bootstrap.main()
    payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["checklist"] == "formatted:True"
    assert seen["retry_command"] == "python scripts/quick_bootstrap.py requirements precheck"


def test_traceability_precheck_reports_structured_non_blocking_result(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": False,
            "failure_groups": {
                "unmapped_requirement": [
                    {
                        "message": "Requirement `TRC-02` missing traceability mapping",
                        "fix": "Add a Traceability table row",
                    }
                ]
            },
            "retry_command": "node ~/.claude/get-shit-done/bin/gsd-tools.cjs requirements precheck",
            "scope": "all",
            "touched_requirement_ids": [],
        },
    )

    exit_code = quick_bootstrap.main()
    payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["command"] == "traceability precheck"
    assert payload["passed"] is False
    assert payload["scope"] == "all"
    assert payload["touched_requirement_ids"] == []
    assert "unmapped_requirement" in payload["failure_groups"]
    assert (
        payload["retry_command"]
        == "python scripts/quick_bootstrap.py traceability precheck --scope phase --phase-id 05"
    )


def test_traceability_precheck_non_blocking_blocked_result_records_evidence(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": False,
            "failure_groups": {
                "unknown_mapped_phase": [
                    {
                        "message": "Requirement `TRC-03` maps to unknown phase `99`",
                        "fix": "Use a phase from ROADMAP.md",
                    }
                ]
            },
            "retry_command": "node ~/.claude/get-shit-done/bin/gsd-tools.cjs requirements precheck",
            "scope": "all",
            "touched_requirement_ids": [],
        },
    )

    exit_code = quick_bootstrap.main()
    _ = capsys.readouterr().out
    after = state_path.read_text(encoding="utf-8")

    assert exit_code == 0
    assert "traceability precheck gate blocked" in after
    assert "| precheck | all | - | blocked |" in after


def test_traceability_precheck_checklist_includes_grouped_remediation_and_retry_command(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": False,
            "failure_groups": {
                "unmapped_requirement": [
                    {
                        "message": "Requirement `TRC-02` is missing a traceability mapping",
                        "fix": "Add one row for TRC-02",
                    }
                ]
            },
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
    )

    exit_code = quick_bootstrap.main()
    payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert "Remediation by failure type:" in payload["checklist"]
    assert "Group unmapped_requirement" in payload["checklist"]
    assert "Retry: python scripts/quick_bootstrap.py traceability precheck" in payload["checklist"]


def test_traceability_precheck_scope_phase_requires_phase_id(tmp_path, monkeypatch):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(planning_root / "STATE.md"),
            scope="phase",
            phase_id=None,
            matrix_detail="compact",
        ),
    )

    with pytest.raises(quick_bootstrap.BootstrapError, match="--phase-id is required"):
        quick_bootstrap.main()


def test_traceability_precheck_includes_coverage_matrix_for_phase_scope(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
            scope="phase",
            phase_id="05",
            matrix_detail="compact",
        ),
    )

    observed: dict[str, object] = {"calls": 0}

    def fake_matrix_builder(_planning_root, **kwargs):
        observed["calls"] = int(observed["calls"]) + 1
        observed["scope"] = kwargs.get("scope")
        observed["phase_id"] = kwargs.get("phase_id")
        return {
            "schema_version": "coverage_matrix.v1",
            "coverage_matrix": {
                "scope": "phase",
                "scope_target": "5",
                "rows": [],
                "summary": {
                    "total": 0,
                    "covered": 0,
                    "partial": 0,
                    "uncovered": 0,
                    "stale": 0,
                },
            },
        }

    monkeypatch.setattr(quick_bootstrap, "build_requirement_coverage_matrix", fake_matrix_builder)
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": False,
            "failure_groups": {"unmapped_requirement": [{"message": "m", "fix": "f"}]},
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
    )

    exit_code = quick_bootstrap.main()
    payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert observed["calls"] == 1
    assert observed["scope"] == "phase"
    assert observed["phase_id"] == "05"
    assert payload["schema_version"] == "coverage_matrix.v1"
    assert payload["coverage_matrix"]["scope"] == "phase"
    assert payload["coverage_matrix"]["scope_target"] == "5"
    assert payload["command"] == "traceability precheck"
    assert payload["failure_groups"] == {"unmapped_requirement": [{"message": "m", "fix": "f"}]}
    assert (
        payload["retry_command"]
        == "python scripts/quick_bootstrap.py traceability precheck --scope phase --phase-id 05"
    )


def test_traceability_precheck_defaults_to_milestone_scope_when_unspecified(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
            scope="milestone",
            phase_id=None,
            matrix_detail="compact",
        ),
    )

    observed: dict[str, object] = {}

    def fake_matrix_builder(_planning_root, **kwargs):
        observed["scope"] = kwargs.get("scope")
        observed["phase_id"] = kwargs.get("phase_id")
        return {
            "schema_version": "coverage_matrix.v1",
            "coverage_matrix": {
                "scope": "milestone",
                "scope_target": "all-active",
                "rows": [],
                "summary": {
                    "total": 0,
                    "covered": 0,
                    "partial": 0,
                    "uncovered": 0,
                    "stale": 0,
                },
            },
        }

    monkeypatch.setattr(quick_bootstrap, "build_requirement_coverage_matrix", fake_matrix_builder)
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": True,
            "failure_groups": {},
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
    )

    exit_code = quick_bootstrap.main()
    payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert observed["scope"] == "milestone"
    assert observed["phase_id"] is None
    assert payload["schema_version"] == "coverage_matrix.v1"
    assert payload["coverage_matrix"]["scope"] == "milestone"


def test_traceability_precheck_matrix_scope_outputs_are_deterministic(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text(
        (
            "Last activity: baseline\n\n"
            "<!-- traceability_top_rank_key: state_mapping_mismatch:state drift|align state|0000 -->\n"
        ),
        encoding="utf-8",
    )

    parsed_args = quick_bootstrap.argparse.Namespace(
        command="traceability",
        traceability_command="precheck",
        planning_root=str(planning_root),
        state_path=str(state_path),
        scope="phase",
        phase_id="05",
        matrix_detail="compact",
    )
    monkeypatch.setattr(quick_bootstrap, "parse_args", lambda: parsed_args)
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": False,
            "failure_groups": {
                "unmapped_requirement": [{"message": "missing mapping", "fix": "add one row"}],
                "state_mapping_mismatch": [{"message": "state drift", "fix": "align state"}],
            },
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "build_requirement_coverage_matrix",
        lambda _planning_root, **_kwargs: {
            "schema_version": "coverage_matrix.v1",
            "coverage_matrix": {
                "scope": "phase",
                "scope_target": "5",
                "rows": [
                    {
                        "requirement_id": "GUX-01",
                        "coverage_state": "stale",
                        "cause_codes": ["state_mapping_mismatch"],
                        "remediation": "Align requirement status with mapped phase completion state.",
                        "retry_command": "python scripts/quick_bootstrap.py traceability precheck",
                    },
                    {
                        "requirement_id": "GUX-02",
                        "coverage_state": "uncovered",
                        "cause_codes": ["unmapped_requirement"],
                        "remediation": "Add exactly one Traceability row for the requirement.",
                        "retry_command": "python scripts/quick_bootstrap.py traceability precheck",
                    },
                ],
                "summary": {
                    "total": 2,
                    "covered": 0,
                    "partial": 0,
                    "uncovered": 1,
                    "stale": 1,
                },
            },
        },
    )

    first_exit = quick_bootstrap.main()
    first_payload = quick_bootstrap.json.loads(capsys.readouterr().out)
    second_exit = quick_bootstrap.main()
    second_payload = quick_bootstrap.json.loads(capsys.readouterr().out)
    first_serialized = quick_bootstrap.json.dumps(
        first_payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    second_serialized = quick_bootstrap.json.dumps(
        second_payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )

    assert first_exit == 0
    assert second_exit == 0
    assert first_payload["coverage_matrix"]["scope"] == "phase"
    assert first_payload["coverage_matrix"]["scope_target"] == "5"
    assert (
        first_payload["coverage_matrix"]["summary"] == second_payload["coverage_matrix"]["summary"]
    )
    assert first_serialized == second_serialized


def test_traceability_precheck_coverage_matrix_scope_outputs_are_deterministic(
    tmp_path, monkeypatch, capsys
):
    test_traceability_precheck_matrix_scope_outputs_are_deterministic(tmp_path, monkeypatch, capsys)


def test_traceability_precheck_compact_matrix_output_is_default(tmp_path, monkeypatch, capsys):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
            scope="milestone",
            phase_id=None,
            matrix_detail="compact",
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": True,
            "failure_groups": {},
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "build_requirement_coverage_matrix",
        lambda _planning_root, **_kwargs: {
            "schema_version": "coverage_matrix.v1",
            "coverage_matrix": {
                "scope": "milestone",
                "scope_target": "all-active",
                "rows": [
                    {
                        "requirement_id": "GUX-01",
                        "coverage_state": "covered",
                        "cause_codes": [],
                        "remediation": "",
                        "retry_command": "python scripts/quick_bootstrap.py traceability precheck",
                    }
                ],
                "summary": {
                    "total": 1,
                    "covered": 1,
                    "partial": 0,
                    "uncovered": 0,
                    "stale": 0,
                },
            },
        },
    )

    exit_code = quick_bootstrap.main()
    payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert "Coverage matrix (compact):" in payload["checklist"]
    assert "Coverage matrix (expanded):" not in payload["checklist"]


def test_traceability_precheck_expanded_matrix_output_preserves_json_row_order(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
            scope="milestone",
            phase_id=None,
            matrix_detail="expanded",
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": False,
            "failure_groups": {
                "unmapped_requirement": [{"message": "m", "fix": "f"}],
            },
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "build_requirement_coverage_matrix",
        lambda _planning_root, **_kwargs: {
            "schema_version": "coverage_matrix.v1",
            "coverage_matrix": {
                "scope": "milestone",
                "scope_target": "all-active",
                "rows": [
                    {
                        "requirement_id": "GUX-01",
                        "coverage_state": "partial",
                        "cause_codes": ["multi_phase_mapping"],
                        "remediation": "Keep exactly one canonical phase mapping for the requirement.",
                        "retry_command": "python scripts/quick_bootstrap.py traceability precheck",
                    },
                    {
                        "requirement_id": "GUX-02",
                        "coverage_state": "uncovered",
                        "cause_codes": ["unmapped_requirement"],
                        "remediation": "Add exactly one Traceability row for the requirement.",
                        "retry_command": "python scripts/quick_bootstrap.py traceability precheck",
                    },
                ],
                "summary": {
                    "total": 2,
                    "covered": 0,
                    "partial": 1,
                    "uncovered": 1,
                    "stale": 0,
                },
            },
        },
    )

    exit_code = quick_bootstrap.main()
    payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert "Coverage matrix (expanded):" in payload["checklist"]
    assert payload["checklist"].find("GUX-01") < payload["checklist"].find("GUX-02")


def test_traceability_precheck_expanded_matrix_includes_remediation_and_retry_context(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
            scope="milestone",
            phase_id=None,
            matrix_detail="expanded",
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": False,
            "failure_groups": {
                "state_mapping_mismatch": [{"message": "mismatch", "fix": "align state"}],
            },
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "build_requirement_coverage_matrix",
        lambda _planning_root, **_kwargs: {
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
                    },
                    {
                        "requirement_id": "GUX-02",
                        "coverage_state": "uncovered",
                        "cause_codes": ["unmapped_requirement"],
                        "remediation": "Add exactly one Traceability row for the requirement.",
                        "retry_command": "python scripts/quick_bootstrap.py traceability precheck",
                    },
                ],
                "summary": {
                    "total": 2,
                    "covered": 0,
                    "partial": 0,
                    "uncovered": 1,
                    "stale": 1,
                },
            },
        },
    )

    exit_code = quick_bootstrap.main()
    payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert "cause_codes: state_mapping_mismatch" in payload["checklist"]
    assert "cause_codes: unmapped_requirement" in payload["checklist"]
    assert (
        "remediation: Align requirement status with mapped phase completion state."
        in payload["checklist"]
    )
    assert "retry: python scripts/quick_bootstrap.py traceability precheck" in payload["checklist"]


def test_traceability_precheck_retry_command_and_failure_groups_stay_stable_with_matrix(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
            scope="milestone",
            phase_id=None,
            matrix_detail="compact",
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": False,
            "failure_groups": {
                "state_mapping_mismatch": [{"message": "state drift", "fix": "align state"}],
                "unmapped_requirement": [{"message": "missing mapping", "fix": "add mapping"}],
            },
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "build_requirement_coverage_matrix",
        lambda _planning_root, **_kwargs: {
            "schema_version": "coverage_matrix.v1",
            "coverage_matrix": {
                "scope": "milestone",
                "scope_target": "all-active",
                "rows": [],
                "summary": {
                    "total": 0,
                    "covered": 0,
                    "partial": 0,
                    "uncovered": 0,
                    "stale": 0,
                },
            },
        },
    )

    exit_code = quick_bootstrap.main()
    payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert list(payload["failure_groups"]) == ["state_mapping_mismatch", "unmapped_requirement"]
    assert payload["retry_command"] == "python scripts/quick_bootstrap.py traceability precheck"


def test_traceability_precheck_includes_ranked_hints_before_grouped_remediation(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
            scope="milestone",
            phase_id=None,
            matrix_detail="compact",
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": False,
            "failure_groups": {
                "state_mapping_mismatch": [
                    {"message": "state drift", "fix": "align"},
                    {"message": "state drift 2", "fix": "align 2"},
                ],
                "unmapped_requirement": [{"message": "missing mapping", "fix": "add mapping"}],
            },
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "build_requirement_coverage_matrix",
        lambda _planning_root, **_kwargs: {
            "schema_version": "coverage_matrix.v1",
            "coverage_matrix": {
                "scope": "milestone",
                "scope_target": "all-active",
                "rows": [],
                "summary": {"total": 0, "covered": 0, "partial": 0, "uncovered": 0, "stale": 0},
            },
        },
    )

    exit_code = quick_bootstrap.main()
    payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert exit_code == 0
    ranked_index = payload["checklist"].find("#1 Rationale:")
    grouped_index = payload["checklist"].find("Remediation by failure type:")
    matrix_index = payload["checklist"].find("Coverage matrix (compact):")
    assert ranked_index >= 0
    assert grouped_index >= 0
    assert matrix_index >= 0
    assert ranked_index < grouped_index
    assert grouped_index < matrix_index
    assert (
        payload["checklist"].count(
            "Retry command: python scripts/quick_bootstrap.py traceability precheck"
        )
        == 3
    )


def test_traceability_precheck_ranked_hints_are_deterministic_for_unchanged_inputs(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
            scope="milestone",
            phase_id=None,
            matrix_detail="compact",
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": False,
            "failure_groups": {
                "unmapped_requirement": [{"message": "missing mapping", "fix": "add mapping"}],
                "state_mapping_mismatch": [{"message": "state drift", "fix": "align state"}],
            },
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "build_requirement_coverage_matrix",
        lambda _planning_root, **_kwargs: {
            "schema_version": "coverage_matrix.v1",
            "coverage_matrix": {
                "scope": "milestone",
                "scope_target": "all-active",
                "rows": [
                    {
                        "requirement_id": "GUX-02",
                        "coverage_state": "stale",
                        "cause_codes": ["state_mapping_mismatch"],
                        "primary_cause": "state_mapping_mismatch",
                        "remediation": "align state",
                        "retry_command": "python scripts/quick_bootstrap.py traceability precheck",
                    }
                ],
                "summary": {"total": 1, "covered": 0, "partial": 0, "uncovered": 0, "stale": 1},
            },
        },
    )

    first_exit = quick_bootstrap.main()
    first_payload = quick_bootstrap.json.loads(capsys.readouterr().out)
    second_exit = quick_bootstrap.main()
    second_payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert first_exit == 0
    assert second_exit == 0
    first_ranked_block = first_payload["checklist"].split("\n\nTop-ranked blocker", 1)[0]
    second_ranked_block = second_payload["checklist"].split("\n\nTop-ranked blocker", 1)[0]
    assert first_ranked_block == second_ranked_block
    assert "#1 Rationale:" in first_ranked_block
    assert "#2 Rationale:" in first_ranked_block


def test_traceability_precheck_retry_command_is_scope_correct_for_phase_scope(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
            scope="phase",
            phase_id="06",
            matrix_detail="compact",
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": False,
            "failure_groups": {
                "unmapped_requirement": [{"message": "missing mapping", "fix": "add mapping"}]
            },
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "build_requirement_coverage_matrix",
        lambda _planning_root, **_kwargs: {
            "schema_version": "coverage_matrix.v1",
            "coverage_matrix": {
                "scope": "phase",
                "scope_target": "6",
                "rows": [],
                "summary": {"total": 0, "covered": 0, "partial": 0, "uncovered": 0, "stale": 0},
            },
        },
    )

    exit_code = quick_bootstrap.main()
    payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert (
        payload["retry_command"]
        == "python scripts/quick_bootstrap.py traceability precheck --scope phase --phase-id 06"
    )
    assert (
        "Retry command: python scripts/quick_bootstrap.py traceability precheck --scope phase --phase-id 06"
        in payload["checklist"]
    )


def test_traceability_precheck_top_rank_note_reports_no_baseline_on_first_run(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("# Project State\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
            scope="milestone",
            phase_id=None,
            matrix_detail="compact",
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": False,
            "failure_groups": {
                "unmapped_requirement": [{"message": "missing mapping", "fix": "add mapping"}]
            },
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "build_requirement_coverage_matrix",
        lambda _planning_root, **_kwargs: {
            "schema_version": "coverage_matrix.v1",
            "coverage_matrix": {
                "scope": "milestone",
                "scope_target": "all-active",
                "rows": [],
                "summary": {"total": 0, "covered": 0, "partial": 0, "uncovered": 0, "stale": 0},
            },
        },
    )

    exit_code = quick_bootstrap.main()
    payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert "Top-ranked blocker baseline: none." in payload["checklist"]
    assert "Stored current top-ranked blocker for next rerun." in payload["checklist"]


def test_traceability_precheck_top_rank_note_reports_unchanged_on_rerun(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("# Project State\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
            scope="milestone",
            phase_id=None,
            matrix_detail="compact",
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": False,
            "failure_groups": {
                "unmapped_requirement": [{"message": "missing mapping", "fix": "add mapping"}]
            },
            "retry_command": "unused",
            "scope": "all",
            "touched_requirement_ids": [],
        },
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "build_requirement_coverage_matrix",
        lambda _planning_root, **_kwargs: {
            "schema_version": "coverage_matrix.v1",
            "coverage_matrix": {
                "scope": "milestone",
                "scope_target": "all-active",
                "rows": [],
                "summary": {"total": 0, "covered": 0, "partial": 0, "uncovered": 0, "stale": 0},
            },
        },
    )

    first_exit = quick_bootstrap.main()
    _ = capsys.readouterr().out
    second_exit = quick_bootstrap.main()
    second_payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert first_exit == 0
    assert second_exit == 0
    assert "Top-ranked blocker unchanged" in second_payload["checklist"]
    assert (
        "Run deeper diagnostics for the same blocker before broad changes."
        in second_payload["checklist"]
    )


def test_traceability_precheck_top_rank_note_reports_changed_when_previous_resolved(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("# Project State\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
            scope="milestone",
            phase_id=None,
            matrix_detail="compact",
        ),
    )
    responses = iter(
        [
            {
                "passed": False,
                "failure_groups": {
                    "state_mapping_mismatch": [{"message": "drift", "fix": "align state"}]
                },
                "retry_command": "unused",
                "scope": "all",
                "touched_requirement_ids": [],
            },
            {
                "passed": False,
                "failure_groups": {
                    "unmapped_requirement": [{"message": "missing mapping", "fix": "add mapping"}]
                },
                "retry_command": "unused",
                "scope": "all",
                "touched_requirement_ids": [],
            },
        ]
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: next(responses),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "build_requirement_coverage_matrix",
        lambda _planning_root, **_kwargs: {
            "schema_version": "coverage_matrix.v1",
            "coverage_matrix": {
                "scope": "milestone",
                "scope_target": "all-active",
                "rows": [],
                "summary": {"total": 0, "covered": 0, "partial": 0, "uncovered": 0, "stale": 0},
            },
        },
    )

    first_exit = quick_bootstrap.main()
    _ = capsys.readouterr().out
    second_exit = quick_bootstrap.main()
    second_payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert first_exit == 0
    assert second_exit == 0
    assert "Top-ranked blocker changed" in second_payload["checklist"]
    assert (
        "Previous top-ranked blocker was resolved or deprioritized." in second_payload["checklist"]
    )


def test_traceability_precheck_top_rank_note_changes_after_remediation(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("# Project State\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="traceability",
            traceability_command="precheck",
            planning_root=str(planning_root),
            state_path=str(state_path),
            scope="milestone",
            phase_id=None,
            matrix_detail="compact",
        ),
    )
    responses = iter(
        [
            {
                "passed": False,
                "failure_groups": {
                    "state_mapping_mismatch": [{"message": "drift", "fix": "align state"}],
                    "unmapped_requirement": [{"message": "missing mapping", "fix": "add mapping"}],
                },
                "retry_command": "unused",
                "scope": "all",
                "touched_requirement_ids": [],
            },
            {
                "passed": False,
                "failure_groups": {
                    "unmapped_requirement": [{"message": "missing mapping", "fix": "add mapping"}],
                    "unknown_mapped_phase": [
                        {"message": "unknown phase", "fix": "map to known phase"}
                    ],
                },
                "retry_command": "unused",
                "scope": "all",
                "touched_requirement_ids": [],
            },
        ]
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: next(responses),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "build_requirement_coverage_matrix",
        lambda _planning_root, **_kwargs: {
            "schema_version": "coverage_matrix.v1",
            "coverage_matrix": {
                "scope": "milestone",
                "scope_target": "all-active",
                "rows": [],
                "summary": {"total": 0, "covered": 0, "partial": 0, "uncovered": 0, "stale": 0},
            },
        },
    )

    first_exit = quick_bootstrap.main()
    first_payload = quick_bootstrap.json.loads(capsys.readouterr().out)
    second_exit = quick_bootstrap.main()
    second_payload = quick_bootstrap.json.loads(capsys.readouterr().out)

    assert first_exit == 0
    assert second_exit == 0
    assert "Top-ranked blocker changed" in second_payload["checklist"]
    assert (
        "Previous top-ranked blocker was resolved or deprioritized." in second_payload["checklist"]
    )
    assert "#1 Rationale:" in first_payload["checklist"]
    assert "#1 Rationale:" in second_payload["checklist"]
    assert (
        "Retry command: python scripts/quick_bootstrap.py traceability precheck"
        in second_payload["checklist"]
    )


def test_milestone_complete_aborts_when_requirements_gate_fails_first(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\nstatus: in_progress\n", encoding="utf-8")

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
        "evaluate_requirements_contract_gate",
        lambda _planning_root: {
            "passed": False,
            "failure_groups": {
                "missing_acceptance_criteria": [{"message": "missing", "fix": "add"}]
            },
            "retry_command": "node ~/.claude/get-shit-done/bin/gsd-tools.cjs requirements precheck",
        },
    )
    called = {"milestone_gate": False}

    def fake_milestone_gate(_planning_root, _version):
        called["milestone_gate"] = True
        return {"passed": True, "failure_groups": {}, "retry_command": "n/a"}

    monkeypatch.setattr(quick_bootstrap, "evaluate_milestone_governance_gate", fake_milestone_gate)

    exit_code = quick_bootstrap.main()
    output = capsys.readouterr().out
    after = state_path.read_text(encoding="utf-8")

    assert exit_code == 1
    assert called["milestone_gate"] is False
    assert "Retry: python scripts/quick_bootstrap.py milestone complete v1.1" in output
    assert "status: in_progress" in after
    assert "| complete | all | blocked |" in after


def test_roadmap_create_aborts_fail_closed_when_requirements_gate_fails(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="roadmap",
            roadmap_command="create",
            planning_root=str(planning_root),
            state_path=str(state_path),
            delegate_args=["--dry-run"],
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_requirements_contract_gate",
        lambda _planning_root: {
            "passed": False,
            "failure_groups": {
                "missing_acceptance_criteria": [{"message": "missing", "fix": "add"}]
            },
            "retry_command": "node ~/.claude/get-shit-done/bin/gsd-tools.cjs requirements precheck",
        },
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "run_transition_delegate",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("delegate should not run")),
    )

    exit_code = quick_bootstrap.main()
    output = capsys.readouterr().out
    after = state_path.read_text(encoding="utf-8")

    assert exit_code == 1
    assert "Retry: python scripts/quick_bootstrap.py roadmap create" in output
    assert "| create | all | blocked |" in after


def test_roadmap_revise_delegates_when_requirements_gate_passes(tmp_path, monkeypatch, capsys):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="roadmap",
            roadmap_command="revise",
            planning_root=str(planning_root),
            state_path=str(state_path),
            delegate_args=["--focus", "contracts"],
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_requirements_contract_gate",
        lambda _planning_root: {"passed": True, "failure_groups": {}, "retry_command": "unused"},
    )
    captured: dict[str, object] = {}

    def fake_delegate(subcommand, delegate_args):
        captured["subcommand"] = subcommand
        captured["delegate_args"] = delegate_args
        return quick_bootstrap.argparse.Namespace(returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr(quick_bootstrap, "run_transition_delegate", fake_delegate)

    exit_code = quick_bootstrap.main()
    payload = quick_bootstrap.json.loads(capsys.readouterr().out)
    after = state_path.read_text(encoding="utf-8")

    assert exit_code == 0
    assert payload["command"] == "roadmap revise"
    assert payload["passed"] is True
    assert captured["subcommand"] == "roadmap revise"
    assert captured["delegate_args"] == ["--focus", "contracts"]
    assert "| revise | all | passed |" in after


def test_phase_complete_touched_requirements_aborts_when_gate_fails(tmp_path, monkeypatch, capsys):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="phase",
            phase_command="complete",
            planning_root=str(planning_root),
            state_path=str(state_path),
            requirement_id=["REQ-03", "REQ-99"],
            delegate_args=[],
        ),
    )
    observed: dict[str, object] = {}

    def fake_requirements_gate(_planning_root, **kwargs):
        observed["scope"] = kwargs.get("scope")
        observed["touched_requirement_ids"] = kwargs.get("touched_requirement_ids")
        return {
            "passed": False,
            "failure_groups": {
                "unknown_touched_requirement": [
                    {
                        "message": "Touched requirement id `REQ-99` does not exist",
                        "fix": "Use existing ids",
                    }
                ]
            },
            "retry_command": "node ~/.claude/get-shit-done/bin/gsd-tools.cjs requirements precheck",
        }

    monkeypatch.setattr(
        quick_bootstrap, "evaluate_requirements_contract_gate", fake_requirements_gate
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "run_transition_delegate",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("delegate should not run")),
    )

    exit_code = quick_bootstrap.main()
    output = capsys.readouterr().out
    after = state_path.read_text(encoding="utf-8")

    assert exit_code == 1
    assert observed["scope"] == "touched"
    assert observed["touched_requirement_ids"] == {"REQ-03", "REQ-99"}
    assert (
        "Retry: python scripts/quick_bootstrap.py phase complete --requirement-id REQ-03 --requirement-id REQ-99"
        in output
    )
    assert "| phase complete | touched | blocked |" in after


def test_phase_complete_touched_requirements_delegates_when_gate_passes(
    tmp_path, monkeypatch, capsys
):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    state_path = planning_root / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    monkeypatch.setattr(
        quick_bootstrap,
        "parse_args",
        lambda: quick_bootstrap.argparse.Namespace(
            command="phase",
            phase_command="complete",
            planning_root=str(planning_root),
            state_path=str(state_path),
            requirement_id=["REQ-03"],
            delegate_args=["--note", "phase3"],
        ),
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_requirements_contract_gate",
        lambda _planning_root, **_kwargs: {
            "passed": True,
            "failure_groups": {},
            "retry_command": "unused",
        },
    )
    monkeypatch.setattr(
        quick_bootstrap,
        "evaluate_traceability_drift_gate",
        lambda _planning_root, **_kwargs: {
            "passed": True,
            "failure_groups": {},
            "retry_command": "unused",
            "scope": "touched",
            "touched_requirement_ids": ["REQ-03"],
        },
    )
    captured: dict[str, object] = {}

    def fake_delegate(subcommand, delegate_args):
        captured["subcommand"] = subcommand
        captured["delegate_args"] = delegate_args
        return quick_bootstrap.argparse.Namespace(returncode=0, stdout="done\n", stderr="")

    monkeypatch.setattr(quick_bootstrap, "run_transition_delegate", fake_delegate)

    exit_code = quick_bootstrap.main()
    payload = quick_bootstrap.json.loads(capsys.readouterr().out)
    after = state_path.read_text(encoding="utf-8")

    assert exit_code == 0
    assert payload["command"] == "phase complete"
    assert payload["passed"] is True
    assert payload["touched_requirement_ids"] == ["REQ-03"]
    assert captured["subcommand"] == "phase complete"
    assert captured["delegate_args"] == ["--note", "phase3"]
    assert "| phase complete | touched | passed |" in after


def test_milestone_complete_aborts_when_traceability_gate_fails_after_requirements_pass(
    tmp_path, monkeypatch, capsys
):
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

    def fake_requirements_gate(_planning_root):
        order.append("requirements")
        return {"passed": True, "failure_groups": {}, "retry_command": "unused"}

    def fake_traceability_gate(_planning_root, **_kwargs):
        order.append("traceability")
        return {
            "passed": False,
            "failure_groups": {
                "state_mapping_mismatch": [
                    {"message": "drift mismatch", "fix": "align state and mapping"}
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

    monkeypatch.setattr(
        quick_bootstrap, "evaluate_requirements_contract_gate", fake_requirements_gate
    )
    monkeypatch.setattr(quick_bootstrap, "evaluate_traceability_drift_gate", fake_traceability_gate)
    monkeypatch.setattr(quick_bootstrap, "evaluate_milestone_governance_gate", fake_milestone_gate)

    exit_code = quick_bootstrap.main()
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
