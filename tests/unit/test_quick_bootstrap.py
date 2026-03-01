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
    assert payload["retry_command"] == "python scripts/quick_bootstrap.py requirements precheck"
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
    assert payload["retry_command"] == "python scripts/quick_bootstrap.py traceability precheck"


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
