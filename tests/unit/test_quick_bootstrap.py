"""Tests for scripts/quick_bootstrap.py — no mocks, no monkeypatch, no @patch.

Every test uses real temp files (tmp_path), real Config objects, real function
calls, and subprocess for CLI entry-point tests.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone, UTC
from pathlib import Path

import pytest

SCRIPT_PATH = str(Path(__file__).resolve().parents[2] / "scripts" / "quick_bootstrap.py")


def _load_quick_bootstrap():
    module_path = Path(__file__).resolve().parents[2] / "scripts" / "quick_bootstrap.py"
    spec = importlib.util.spec_from_file_location("quick_bootstrap", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load quick_bootstrap module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Pure function tests — no mocks needed
# ---------------------------------------------------------------------------


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


def test_preflight_fails_when_planning_missing(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    payload = {
        "roadmap_exists": True,
        "planning_exists": False,
        "task_dir": str(tmp_path / ".planning" / "quick" / "9-sample"),
        "next_num": 9,
        "slug": "sample",
    }
    with pytest.raises(quick_bootstrap.PreflightError):
        quick_bootstrap.run_preflight(payload)


def test_preflight_fails_when_task_dir_empty(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    payload = {
        "roadmap_exists": True,
        "planning_exists": True,
        "task_dir": "",
        "next_num": 9,
        "slug": "sample",
    }
    with pytest.raises(quick_bootstrap.PreflightError):
        quick_bootstrap.run_preflight(payload)


def test_preflight_passes_with_valid_payload(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    payload = {
        "roadmap_exists": True,
        "planning_exists": True,
        "task_dir": str(tmp_path / ".planning" / "quick" / "9-sample"),
        "next_num": 9,
        "slug": "sample",
    }
    # Should not raise
    quick_bootstrap.run_preflight(payload)


def test_valid_objective_generates_slug_and_2_to_3_checks_in_memory():
    quick_bootstrap = _load_quick_bootstrap()
    checks = quick_bootstrap.build_measurable_checks("Stabilize quick bootstrap behavior")
    assert 2 <= len(checks) <= 3
    slug = quick_bootstrap.slugify("Stabilize quick bootstrap behavior")
    assert slug.startswith("stabilize-quick-bootstrap")


def test_slugify_empty_returns_default():
    quick_bootstrap = _load_quick_bootstrap()
    assert quick_bootstrap.slugify("") == "quick-task"


def test_slugify_special_characters():
    quick_bootstrap = _load_quick_bootstrap()
    slug = quick_bootstrap.slugify("Hello World! (test) #123")
    assert slug == "hello-world-test-123"


def test_slugify_truncates_to_48_chars():
    quick_bootstrap = _load_quick_bootstrap()
    long_input = "a" * 100
    slug = quick_bootstrap.slugify(long_input)
    assert len(slug) <= 48


def test_build_measurable_checks_returns_max_3():
    quick_bootstrap = _load_quick_bootstrap()
    checks = quick_bootstrap.build_measurable_checks("Some objective")
    assert 2 <= len(checks) <= 3
    for check in checks:
        assert isinstance(check, str)
        assert len(check) > 0


def test_build_measurable_checks_empty_objective_uses_default():
    quick_bootstrap = _load_quick_bootstrap()
    checks = quick_bootstrap.build_measurable_checks("")
    assert 2 <= len(checks) <= 3
    # Default subject should be "quick task"
    assert any("quick task" in check for check in checks)


def test_parse_governance_exception_payload_valid():
    quick_bootstrap = _load_quick_bootstrap()
    now = datetime.now(UTC)
    future = (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    result = quick_bootstrap._parse_governance_exception_payload(
        quick_bootstrap.argparse.Namespace(
            governance_exception_owner="owner@example.org",
            governance_exception_task="T-01",
            governance_exception_rationale="Emergency path",
            governance_exception_until=future,
        )
    )
    assert result is not None
    assert result["owner"] == "owner@example.org"
    assert result["task"] == "T-01"
    assert result["rationale"] == "Emergency path"


def test_parse_governance_exception_payload_empty_task_returns_none():
    quick_bootstrap = _load_quick_bootstrap()
    now = datetime.now(UTC)
    future = (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    result = quick_bootstrap._parse_governance_exception_payload(
        quick_bootstrap.argparse.Namespace(
            governance_exception_owner="owner@example.org",
            governance_exception_task="",
            governance_exception_rationale="Emergency path",
            governance_exception_until=future,
        )
    )
    assert result is None


def test_parse_governance_exception_payload_expired_returns_none():
    quick_bootstrap = _load_quick_bootstrap()
    now = datetime.now(UTC)
    past = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    result = quick_bootstrap._parse_governance_exception_payload(
        quick_bootstrap.argparse.Namespace(
            governance_exception_owner="owner@example.org",
            governance_exception_task="T-01",
            governance_exception_rationale="Emergency path",
            governance_exception_until=past,
        )
    )
    assert result is None


def test_parse_governance_exception_payload_invalid_date_returns_none():
    quick_bootstrap = _load_quick_bootstrap()
    result = quick_bootstrap._parse_governance_exception_payload(
        quick_bootstrap.argparse.Namespace(
            governance_exception_owner="owner@example.org",
            governance_exception_task="T-01",
            governance_exception_rationale="Emergency path",
            governance_exception_until="not-a-date",
        )
    )
    assert result is None


# ---------------------------------------------------------------------------
# execute_bootstrap tests with real callables
# ---------------------------------------------------------------------------


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


def test_execute_bootstrap_empty_objective_raises():
    quick_bootstrap = _load_quick_bootstrap()
    with pytest.raises(quick_bootstrap.BootstrapError, match="Objective is required"):
        quick_bootstrap.execute_bootstrap(objective="  ", gsd_tools_path="fake")


def test_execute_bootstrap_success_with_real_runner(tmp_path):
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

    def real_runner(_objective: str, _gsd_tools_path: str):
        return {
            "roadmap_exists": True,
            "planning_exists": True,
            "task_dir": str(tmp_path / ".planning" / "quick" / "7-test"),
            "next_num": 7,
            "slug": "test",
        }

    result = quick_bootstrap.execute_bootstrap(
        objective="Test bootstrap",
        gsd_tools_path="fake",
        runner=real_runner,
        repo_root=tmp_path,
        template_dir=template_dir,
    )
    assert result.number == 7
    assert result.slug == "test"
    assert result.plan_path.exists()
    assert result.summary_path.exists()
    assert result.retries == 0


# ---------------------------------------------------------------------------
# create_quick_task tests
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# close_quick_task and state update tests
# ---------------------------------------------------------------------------


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


def test_close_quick_task_creates_summary_if_missing(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    task_dir = tmp_path / ".planning" / "quick" / "15-auto"
    task_dir.mkdir(parents=True)
    state_path = tmp_path / ".planning" / "STATE.md"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text("# Project State\n", encoding="utf-8")

    result = quick_bootstrap.close_quick_task(
        task_dir=task_dir,
        status="scaffolded",
        description="auto-created summary",
        state_path=state_path,
    )
    assert result.exists()
    text = result.read_text(encoding="utf-8")
    assert "status: scaffolded" in text


# ---------------------------------------------------------------------------
# record_*_activity tests — real file writes
# ---------------------------------------------------------------------------


def test_record_milestone_gate_activity_passed(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    state_path = tmp_path / ".planning" / "STATE.md"
    state_path.parent.mkdir(parents=True)
    state_path.write_text("Last activity: old\n", encoding="utf-8")

    quick_bootstrap.record_milestone_gate_activity(state_path, "v1.1", "precheck", True)

    text = state_path.read_text(encoding="utf-8")
    assert "milestone precheck v1.1 gate passed" in text
    assert "## Milestone Gate Activity" in text
    assert "| precheck | v1.1 | passed |" in text


def test_record_milestone_gate_activity_blocked(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    state_path = tmp_path / ".planning" / "STATE.md"
    state_path.parent.mkdir(parents=True)
    state_path.write_text("Last activity: old\n", encoding="utf-8")

    quick_bootstrap.record_milestone_gate_activity(state_path, "v2.0", "complete", False)

    text = state_path.read_text(encoding="utf-8")
    assert "milestone complete v2.0 gate blocked" in text
    assert "| complete | v2.0 | blocked |" in text


def test_record_requirements_gate_activity(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    state_path = tmp_path / ".planning" / "STATE.md"
    state_path.parent.mkdir(parents=True)
    state_path.write_text("Last activity: old\n", encoding="utf-8")

    quick_bootstrap.record_requirements_gate_activity(state_path, "precheck", False, scope="all")

    text = state_path.read_text(encoding="utf-8")
    assert "requirements precheck gate blocked" in text
    assert "## Requirements Gate Activity" in text
    assert "| precheck | all | blocked |" in text


def test_record_traceability_gate_activity(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    state_path = tmp_path / ".planning" / "STATE.md"
    state_path.parent.mkdir(parents=True)
    state_path.write_text("Last activity: old\n", encoding="utf-8")

    quick_bootstrap.record_traceability_gate_activity(
        state_path,
        "phase complete",
        False,
        scope="touched",
        touched_requirement_ids={"REQ-03", "REQ-99"},
    )

    text = state_path.read_text(encoding="utf-8")
    assert "traceability phase complete gate blocked" in text
    assert "## Traceability Gate Activity" in text
    assert "| phase complete | touched | REQ-03, REQ-99 | blocked |" in text


def test_record_governance_exception_activity(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    state_path = tmp_path / ".planning" / "STATE.md"
    state_path.parent.mkdir(parents=True)
    state_path.write_text("Last activity: old\n", encoding="utf-8")

    quick_bootstrap.record_governance_exception_activity(
        state_path,
        "milestone complete v2.0",
        scope="milestone",
        owner="owner@example.org",
        task="T-01",
        rationale="Emergency path",
        until="2026-12-31T23:59:59Z",
    )

    text = state_path.read_text(encoding="utf-8")
    assert "## Governance Exception Activity" in text
    assert "owner@example.org" in text
    assert "T-01" in text
    assert "milestone complete v2.0" in text


def test_record_traceability_gate_activity_writes_top_rank_key(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    state_path = tmp_path / ".planning" / "STATE.md"
    state_path.parent.mkdir(parents=True)
    state_path.write_text("Last activity: old\n", encoding="utf-8")

    quick_bootstrap.record_traceability_gate_activity(
        state_path,
        "precheck",
        False,
        scope="all",
        top_rank_key="unmapped_requirement:missing|add|0001",
    )

    text = state_path.read_text(encoding="utf-8")
    assert "<!-- traceability_top_rank_key:" in text
    assert "unmapped_requirement:missing|add|0001" in text

    # Verify we can read it back
    key = quick_bootstrap._read_traceability_top_rank_key(state_path)
    assert key == "unmapped_requirement:missing|add|0001"


# ---------------------------------------------------------------------------
# _read/_write traceability top rank key
# ---------------------------------------------------------------------------


def test_read_traceability_top_rank_key_missing_file(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    state_path = tmp_path / "nonexistent.md"
    assert quick_bootstrap._read_traceability_top_rank_key(state_path) is None


def test_read_traceability_top_rank_key_no_marker(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    state_path = tmp_path / "STATE.md"
    state_path.write_text("# State\nno marker here\n", encoding="utf-8")
    assert quick_bootstrap._read_traceability_top_rank_key(state_path) is None


def test_write_traceability_top_rank_key_creates_new(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    state_path = tmp_path / ".planning" / "STATE.md"
    quick_bootstrap._write_traceability_top_rank_key(state_path, "test-key")
    text = state_path.read_text(encoding="utf-8")
    assert "<!-- traceability_top_rank_key: test-key -->" in text


def test_write_traceability_top_rank_key_replaces_existing(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    state_path = tmp_path / "STATE.md"
    state_path.write_text(
        "# State\n\n<!-- traceability_top_rank_key: old-key -->\n",
        encoding="utf-8",
    )
    quick_bootstrap._write_traceability_top_rank_key(state_path, "new-key")
    text = state_path.read_text(encoding="utf-8")
    assert "new-key" in text
    assert "old-key" not in text


# ---------------------------------------------------------------------------
# _parse_iso_utc and _format_iso_utc
# ---------------------------------------------------------------------------


def test_parse_iso_utc_valid():
    quick_bootstrap = _load_quick_bootstrap()
    result = quick_bootstrap._parse_iso_utc("2026-03-15T10:00:00Z")
    assert result is not None
    assert result.tzinfo is not None


def test_parse_iso_utc_empty_returns_none():
    quick_bootstrap = _load_quick_bootstrap()
    assert quick_bootstrap._parse_iso_utc("") is None


def test_parse_iso_utc_invalid_returns_none():
    quick_bootstrap = _load_quick_bootstrap()
    assert quick_bootstrap._parse_iso_utc("not-a-date") is None


def test_format_iso_utc_roundtrip():
    quick_bootstrap = _load_quick_bootstrap()
    now = datetime.now(UTC)
    formatted = quick_bootstrap._format_iso_utc(now)
    assert formatted.endswith("Z")
    parsed_back = quick_bootstrap._parse_iso_utc(formatted)
    assert parsed_back is not None


# ---------------------------------------------------------------------------
# normalize_task_identity
# ---------------------------------------------------------------------------


def test_normalize_task_identity_uses_payload_number(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    payload = {
        "task_dir": str(tmp_path / ".planning" / "quick" / "7-test"),
        "next_num": 7,
        "slug": "test",
    }
    number, slug, task_dir = quick_bootstrap.normalize_task_identity(payload, "Test")
    assert number == 7
    assert slug == "test"
    assert task_dir.name == "7-test"


def test_normalize_task_identity_extracts_number_from_dir_name():
    quick_bootstrap = _load_quick_bootstrap()
    payload = {
        "task_dir": "/fake/path/99-extracted",
        "slug": "extracted",
    }
    number, slug, task_dir = quick_bootstrap.normalize_task_identity(payload, "Test")
    assert number == 99


def test_normalize_task_identity_invalid_number_raises():
    quick_bootstrap = _load_quick_bootstrap()
    payload = {
        "task_dir": "/fake/path/bad-name",
        "next_num": 0,
    }
    with pytest.raises(quick_bootstrap.PreflightError):
        quick_bootstrap.normalize_task_identity(payload, "Test")


# ---------------------------------------------------------------------------
# _render_template
# ---------------------------------------------------------------------------


def test_render_template():
    quick_bootstrap = _load_quick_bootstrap()
    template = "Hello {name}, you have {count} items."
    result = quick_bootstrap._render_template(template, {"name": "World", "count": "3"})
    assert result == "Hello World, you have 3 items."


# ---------------------------------------------------------------------------
# Traceability delta helpers
# ---------------------------------------------------------------------------


def test_normalize_traceability_delta_key():
    quick_bootstrap = _load_quick_bootstrap()
    assert (
        quick_bootstrap._normalize_traceability_delta_key("milestone", "all-active")
        == "milestone:all-active"
    )
    assert quick_bootstrap._normalize_traceability_delta_key("phase", "5") == "phase:5"
    assert quick_bootstrap._normalize_traceability_delta_key("", "") == "milestone:all-active"


def test_normalize_phase_snapshot_target():
    quick_bootstrap = _load_quick_bootstrap()
    assert quick_bootstrap._normalize_phase_snapshot_target("05") == "5"
    assert quick_bootstrap._normalize_phase_snapshot_target("10") == "10"
    assert quick_bootstrap._normalize_phase_snapshot_target(None) in ("", "all-active", "0")


def test_traceability_delta_read_write_roundtrip(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)

    payload = {
        "schema_version": quick_bootstrap.TRACEABILITY_DELTA_SCHEMA_VERSION,
        "generated_at": quick_bootstrap._format_iso_utc(datetime.now(UTC)),
        "snapshots": {
            "milestone:all-active": {
                "scope": "milestone",
                "scope_target": "all-active",
                "rows": [{"requirement_id": "REQ-01", "coverage_state": "covered"}],
                "summary": {"total": 1, "covered": 1, "partial": 0, "uncovered": 0, "stale": 0},
            }
        },
    }
    quick_bootstrap._write_traceability_delta_payload(planning_root, payload)

    read_back = quick_bootstrap._read_traceability_delta_payload(planning_root)
    assert read_back["schema_version"] == quick_bootstrap.TRACEABILITY_DELTA_SCHEMA_VERSION
    assert "milestone:all-active" in read_back["snapshots"]


def test_traceability_delta_read_nonexistent_returns_empty(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    planning_root = tmp_path / ".planning"
    planning_root.mkdir(parents=True)
    result = quick_bootstrap._read_traceability_delta_payload(planning_root)
    assert isinstance(result, dict)


def test_compare_traceability_rows():
    quick_bootstrap = _load_quick_bootstrap()
    previous = [
        {"requirement_id": "REQ-01", "coverage_state": "uncovered"},
        {"requirement_id": "REQ-02", "coverage_state": "stale"},
    ]
    current = [
        {"requirement_id": "REQ-01", "coverage_state": "covered"},
        {"requirement_id": "REQ-03", "coverage_state": "uncovered"},
    ]
    # Returns (added, removed, changed) as lists of requirement IDs
    added, removed, changed = quick_bootstrap._compare_traceability_rows(previous, current)
    assert "REQ-03" in added
    assert "REQ-02" in removed
    assert "REQ-01" in changed


def test_format_traceability_delta_report_baseline():
    quick_bootstrap = _load_quick_bootstrap()
    # When previous_rows and previous_summary are both empty/falsy, it's a baseline
    report = quick_bootstrap._format_traceability_delta_report(
        "milestone",
        "all-active",
        current_rows=[{"requirement_id": "REQ-01", "coverage_state": "covered"}],
        previous_rows=[],
        current_summary={"total": 1, "covered": 1, "partial": 0, "uncovered": 0, "stale": 0},
        previous_summary={},
    )
    assert "Traceability delta report:" in report
    assert "- baseline: none" in report


def test_format_traceability_delta_report_with_previous():
    quick_bootstrap = _load_quick_bootstrap()
    report = quick_bootstrap._format_traceability_delta_report(
        "milestone",
        "all-active",
        current_rows=[
            {"requirement_id": "REQ-01", "coverage_state": "covered"},
            {"requirement_id": "REQ-03", "coverage_state": "uncovered"},
        ],
        previous_rows=[
            {"requirement_id": "REQ-01", "coverage_state": "uncovered"},
            {"requirement_id": "REQ-02", "coverage_state": "stale"},
        ],
        current_summary={"total": 2, "covered": 1, "partial": 0, "uncovered": 1, "stale": 0},
        previous_summary={"total": 2, "covered": 0, "partial": 0, "uncovered": 1, "stale": 1},
    )
    assert "Traceability delta report:" in report
    assert "- added: 1" in report
    assert "- removed: 1" in report
    assert "- changed: 1" in report


def test_snapshot_rows_from_coverage_matrix():
    quick_bootstrap = _load_quick_bootstrap()
    matrix_payload = {
        "coverage_matrix": {
            "rows": [
                {"requirement_id": "REQ-01", "coverage_state": "covered"},
                {"requirement_id": "REQ-02", "coverage_state": "uncovered"},
            ],
        }
    }
    rows = quick_bootstrap._snapshot_rows_from_coverage_matrix(matrix_payload)
    assert len(rows) == 2
    assert rows[0]["requirement_id"] == "REQ-01"


def test_summary_from_coverage_matrix():
    quick_bootstrap = _load_quick_bootstrap()
    payload = {
        "coverage_matrix": {
            "summary": {"total": 5, "covered": 2, "partial": 1, "uncovered": 1, "stale": 1}
        }
    }
    summary = quick_bootstrap._summary_from_coverage_matrix(payload)
    assert summary["total"] == 5
    assert summary["covered"] == 2


def test_build_traceability_retry_command():
    quick_bootstrap = _load_quick_bootstrap()
    cmd = quick_bootstrap._build_traceability_retry_command("milestone", None)
    assert cmd == "python scripts/quick_bootstrap.py traceability precheck"

    cmd_phase = quick_bootstrap._build_traceability_retry_command("phase", "05")
    assert (
        cmd_phase
        == "python scripts/quick_bootstrap.py traceability precheck --scope phase --phase-id 05"
    )


def test_format_touched_requirement_ids():
    quick_bootstrap = _load_quick_bootstrap()
    assert quick_bootstrap._format_touched_requirement_ids(None) == "-"
    assert quick_bootstrap._format_touched_requirement_ids([]) == "-"
    assert quick_bootstrap._format_touched_requirement_ids(["REQ-03", "REQ-01"]) == "REQ-01, REQ-03"


# ---------------------------------------------------------------------------
# CLI subprocess tests — real invocations of quick_bootstrap.py
# ---------------------------------------------------------------------------


def _run_bootstrap_cli(*args: str, cwd: str | None = None) -> subprocess.CompletedProcess:
    """Run quick_bootstrap.py as a subprocess."""
    cmd = [sys.executable, SCRIPT_PATH, *args]
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)


def test_cli_milestone_precheck_missing_audit_file(tmp_path):
    """Milestone precheck against a planning dir with no audit file should
    return exit 0 (non-blocking) with failure_groups in JSON output."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: old\n", encoding="utf-8")

    result = _run_bootstrap_cli(
        "milestone",
        "precheck",
        "v1.1",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == "milestone precheck"
    assert payload["passed"] is False
    assert "missing_file" in payload["failure_groups"]


def test_cli_milestone_precheck_passed_audit(tmp_path):
    """Milestone precheck with a valid audit file should pass."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: old\n", encoding="utf-8")

    now_iso = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    audit_path = planning / "v1.1-MILESTONE-AUDIT.md"
    audit_path.write_text(
        f"---\nstatus: passed\naudited: {now_iso}\n---\n\n"
        "## Scope\nAll modules.\n\n## Checks\nUnit tests.\n\n"
        "## Findings\nNone.\n\n## Remediation\nN/A.\n",
        encoding="utf-8",
    )

    result = _run_bootstrap_cli(
        "milestone",
        "precheck",
        "v1.1",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == "milestone precheck"
    assert payload["passed"] is True


def test_cli_milestone_complete_with_governance_exception(tmp_path):
    """Milestone complete with valid governance exception short-circuits gates."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: old\n", encoding="utf-8")

    future = (datetime.now(UTC) + timedelta(hours=4)).isoformat().replace("+00:00", "Z")

    result = _run_bootstrap_cli(
        "milestone",
        "complete",
        "v2.0",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
        "--governance-exception-owner",
        "owner@example.org",
        "--governance-exception-task",
        "T-01",
        "--governance-exception-rationale",
        "Emergency path",
        "--governance-exception-until",
        future,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["passed"] is True
    assert payload["command"] == "milestone complete"
    assert payload["governance_exception"]["task"] == "T-01"

    after = state_path.read_text(encoding="utf-8")
    assert "## Governance Exception Activity" in after
    assert "owner@example.org" in after
    assert "T-01" in after
    assert "milestone complete v2.0" in after


def test_cli_milestone_complete_with_invalid_governance_exception_runs_gates(tmp_path):
    """Invalid governance exception (empty task) should run the gates normally."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: old\n", encoding="utf-8")
    # No REQUIREMENTS.md -> requirements gate will fail
    future = (datetime.now(UTC) + timedelta(hours=4)).isoformat().replace("+00:00", "Z")

    result = _run_bootstrap_cli(
        "milestone",
        "complete",
        "v2.0",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
        "--governance-exception-owner",
        "owner@example.org",
        "--governance-exception-task",
        "",
        "--governance-exception-rationale",
        "Emergency path",
        "--governance-exception-until",
        future,
    )

    assert result.returncode == 1
    assert "Retry: python scripts/quick_bootstrap.py milestone complete v2.0" in result.stdout


def test_cli_milestone_complete_requirements_gate_blocks(tmp_path):
    """Without REQUIREMENTS.md, the requirements gate blocks milestone complete."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: unchanged\n", encoding="utf-8")

    result = _run_bootstrap_cli(
        "milestone",
        "complete",
        "v1.1",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
    )

    assert result.returncode == 1
    after = state_path.read_text(encoding="utf-8")
    assert "requirements complete gate blocked" in after
    assert "Retry: python scripts/quick_bootstrap.py milestone complete v1.1" in result.stdout


def test_cli_milestone_complete_all_gates_pass(tmp_path):
    """With all required artifacts in place, milestone complete passes."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: unchanged\n", encoding="utf-8")

    # Create a valid REQUIREMENTS.md with Traceability section
    (planning / "REQUIREMENTS.md").write_text(
        "# Requirements\n\n## v1 Requirements\n\n"
        "#### Requirement\n\n"
        "- id: REQ-01\n"
        "- status: Complete\n"
        "- acceptance_criteria: has criteria\n\n"
        "## Traceability\n\n"
        "| Requirement | Phase | Status |\n"
        "|-------------|-------|--------|\n"
        "| REQ-01 | 1 | Complete |\n",
        encoding="utf-8",
    )

    # Create valid ROADMAP.md with phase definitions
    (planning / "ROADMAP.md").write_text(
        "# Roadmap\n\n## Phase 1\n\nSome phase description.\n\n" "- [x] Phase 1 complete\n",
        encoding="utf-8",
    )

    # Create a valid milestone audit file
    now_iso = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    (planning / "v1.1-MILESTONE-AUDIT.md").write_text(
        f"---\nstatus: passed\naudited: {now_iso}\n---\n\n"
        "## Scope\nAll modules.\n\n## Checks\nUnit tests.\n\n"
        "## Findings\nNone.\n\n## Remediation\nN/A.\n",
        encoding="utf-8",
    )

    result = _run_bootstrap_cli(
        "milestone",
        "complete",
        "v1.1",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["passed"] is True
    assert payload["command"] == "milestone complete"


def test_cli_requirements_precheck_missing_file(tmp_path):
    """Requirements precheck with no REQUIREMENTS.md reports failure."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    result = _run_bootstrap_cli(
        "requirements",
        "precheck",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == "requirements precheck"
    assert payload["passed"] is False
    assert "missing_file" in payload["failure_groups"]
    assert payload["retry_command"] == "python scripts/quick_bootstrap.py requirements precheck"

    after = state_path.read_text(encoding="utf-8")
    assert "requirements precheck gate blocked" in after
    assert "| precheck | all | blocked |" in after


def test_cli_requirements_precheck_with_valid_requirements(tmp_path):
    """Requirements precheck with valid REQUIREMENTS.md should pass."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    (planning / "REQUIREMENTS.md").write_text(
        "# Requirements\n\n## v1 Requirements\n\n"
        "#### Requirement\n\n"
        "- id: REQ-01\n"
        "- status: Complete\n"
        "- acceptance_criteria: has criteria\n",
        encoding="utf-8",
    )

    result = _run_bootstrap_cli(
        "requirements",
        "precheck",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == "requirements precheck"
    assert payload["passed"] is True


def test_cli_traceability_precheck_reports_result(tmp_path):
    """Traceability precheck reports structured result."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    # Without ROADMAP.md the traceability gate should fail
    (planning / "REQUIREMENTS.md").write_text(
        "# Requirements\n\n## v1 Requirements\n\n"
        "#### Requirement\n\n"
        "- id: REQ-01\n"
        "- status: Complete\n"
        "- acceptance_criteria: has criteria\n",
        encoding="utf-8",
    )

    result = _run_bootstrap_cli(
        "traceability",
        "precheck",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == "traceability precheck"
    assert "failure_groups" in payload
    assert "retry_command" in payload
    assert payload["retry_command"] == "python scripts/quick_bootstrap.py traceability precheck"


def test_cli_traceability_precheck_scope_phase_requires_phase_id(tmp_path):
    """Traceability precheck with --scope phase but no --phase-id raises error."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    result = _run_bootstrap_cli(
        "traceability",
        "precheck",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
        "--scope",
        "phase",
    )

    assert result.returncode != 0
    assert "--phase-id is required" in result.stderr or "--phase-id is required" in result.stdout


def test_cli_traceability_precheck_phase_scope_with_phase_id(tmp_path):
    """Traceability precheck with --scope phase --phase-id 05 should include
    scope info in output."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    (planning / "REQUIREMENTS.md").write_text(
        "# Requirements\n\n## v1 Requirements\n\n"
        "#### Requirement\n\n"
        "- id: REQ-01\n"
        "- status: Complete\n"
        "- acceptance_criteria: has criteria\n",
        encoding="utf-8",
    )
    (planning / "ROADMAP.md").write_text(
        "# Roadmap\n\n## Phase 5\n\n"
        "### Traceability\n\n"
        "| Requirement | Phase | Status |\n"
        "|-------------|-------|--------|\n"
        "| REQ-01 | 5 | Complete |\n",
        encoding="utf-8",
    )

    result = _run_bootstrap_cli(
        "traceability",
        "precheck",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
        "--scope",
        "phase",
        "--phase-id",
        "05",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == "traceability precheck"
    expected_retry = (
        "python scripts/quick_bootstrap.py traceability precheck --scope phase --phase-id 05"
    )
    assert payload["retry_command"] == expected_retry


def test_cli_traceability_precheck_expanded_matrix(tmp_path):
    """Expanded matrix detail should produce expanded output."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    (planning / "REQUIREMENTS.md").write_text(
        "# Requirements\n\n## v1 Requirements\n\n"
        "#### Requirement\n\n"
        "- id: REQ-01\n"
        "- status: Complete\n"
        "- acceptance_criteria: has criteria\n",
        encoding="utf-8",
    )
    (planning / "ROADMAP.md").write_text(
        "# Roadmap\n\n## Phase 1\n\n"
        "### Traceability\n\n"
        "| Requirement | Phase | Status |\n"
        "|-------------|-------|--------|\n"
        "| REQ-01 | 1 | Complete |\n",
        encoding="utf-8",
    )

    result = _run_bootstrap_cli(
        "traceability",
        "precheck",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
        "--matrix-detail",
        "expanded",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert "checklist" in payload


def test_cli_traceability_precheck_delta_tracks_changes(tmp_path):
    """Running traceability precheck twice should produce delta report."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    (planning / "REQUIREMENTS.md").write_text(
        "# Requirements\n\n## v1 Requirements\n\n"
        "#### Requirement\n\n"
        "- id: REQ-01\n"
        "- status: Complete\n"
        "- acceptance_criteria: has criteria\n",
        encoding="utf-8",
    )
    (planning / "ROADMAP.md").write_text(
        "# Roadmap\n\n## Phase 1\n\n"
        "### Traceability\n\n"
        "| Requirement | Phase | Status |\n"
        "|-------------|-------|--------|\n"
        "| REQ-01 | 1 | Complete |\n",
        encoding="utf-8",
    )

    # First run
    result1 = _run_bootstrap_cli(
        "traceability",
        "precheck",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
    )
    assert result1.returncode == 0
    payload1 = json.loads(result1.stdout)
    assert "Traceability delta report:" in payload1["checklist"]
    assert "- baseline: none" in payload1["checklist"]

    # Second run
    result2 = _run_bootstrap_cli(
        "traceability",
        "precheck",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
    )
    assert result2.returncode == 0
    payload2 = json.loads(result2.stdout)
    assert "Traceability delta report:" in payload2["checklist"]

    # Delta file should exist
    delta_path = planning / "traceability-delta.json"
    assert delta_path.exists()


def test_cli_traceability_precheck_deterministic_output(tmp_path):
    """Running traceability precheck twice with same input produces same structure."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    (planning / "REQUIREMENTS.md").write_text(
        "# Requirements\n\n## v1 Requirements\n\n"
        "#### Requirement\n\n"
        "- id: REQ-01\n"
        "- status: Complete\n"
        "- acceptance_criteria: has criteria\n",
        encoding="utf-8",
    )
    (planning / "ROADMAP.md").write_text(
        "# Roadmap\n\n## Phase 1\n\n"
        "### Traceability\n\n"
        "| Requirement | Phase | Status |\n"
        "|-------------|-------|--------|\n"
        "| REQ-01 | 1 | Complete |\n",
        encoding="utf-8",
    )

    # Run twice
    result1 = _run_bootstrap_cli(
        "traceability",
        "precheck",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
    )
    result2 = _run_bootstrap_cli(
        "traceability",
        "precheck",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
    )

    assert result1.returncode == 0
    assert result2.returncode == 0
    p1 = json.loads(result1.stdout)
    p2 = json.loads(result2.stdout)
    # Both should have same command, passed state, and retry_command
    assert p1["command"] == p2["command"]
    assert p1["passed"] == p2["passed"]
    assert p1["retry_command"] == p2["retry_command"]
    # Failure groups should be identical
    assert p1["failure_groups"] == p2["failure_groups"]


def test_cli_phase_complete_with_governance_exception(tmp_path):
    """Phase complete with valid governance exception short-circuits and
    attempts to run delegate (which will fail since no gsd-tools, but the
    governance exception path is exercised)."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: old\n", encoding="utf-8")

    future = (datetime.now(UTC) + timedelta(hours=4)).isoformat().replace("+00:00", "Z")

    _run_bootstrap_cli(
        "phase",
        "complete",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
        "--requirement-id",
        "REQ-03",
        "--governance-exception-owner",
        "owner@example.org",
        "--governance-exception-task",
        "P-01",
        "--governance-exception-rationale",
        "Release exception",
        "--governance-exception-until",
        future,
    )

    # Delegate will fail (no gsd-tools) so exit code may be nonzero
    # But governance exception recording should happen
    after = state_path.read_text(encoding="utf-8")
    assert "## Governance Exception Activity" in after
    assert "owner@example.org" in after
    assert "P-01" in after
    assert "phase complete" in after


def test_cli_phase_complete_requirements_gate_blocks(tmp_path):
    """Phase complete without REQUIREMENTS.md should be blocked by
    requirements gate."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: baseline\n", encoding="utf-8")

    result = _run_bootstrap_cli(
        "phase",
        "complete",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
        "--requirement-id",
        "REQ-03",
    )

    assert result.returncode == 1
    assert "Retry: python scripts/quick_bootstrap.py phase complete" in result.stdout


def test_cli_milestone_complete_grouped_failures_output(tmp_path):
    """With a REQUIREMENTS.md but missing acceptance criteria, the grouped
    failure output should include remediation guidance."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: unchanged\n", encoding="utf-8")

    # Create REQUIREMENTS.md with missing acceptance criteria
    (planning / "REQUIREMENTS.md").write_text(
        "# Requirements\n\n## v1 Requirements\n\n"
        "#### Requirement\n\n"
        "- id: REQ-01\n"
        "- status: Pending\n",
        encoding="utf-8",
    )

    result = _run_bootstrap_cli(
        "milestone",
        "complete",
        "v1.1",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
    )

    assert result.returncode == 1
    # Should show remediation guidance
    assert "Retry: python scripts/quick_bootstrap.py milestone complete v1.1" in result.stdout


def test_cli_milestone_complete_retry_command_appears_once(tmp_path):
    """Retry command should appear exactly once in output."""
    planning = tmp_path / ".planning"
    planning.mkdir(parents=True)
    state_path = planning / "STATE.md"
    state_path.write_text("Last activity: unchanged\n", encoding="utf-8")

    result = _run_bootstrap_cli(
        "milestone",
        "complete",
        "v1.1",
        "--planning-root",
        str(planning),
        "--state-path",
        str(state_path),
    )

    assert result.returncode == 1
    expected = "Retry: python scripts/quick_bootstrap.py milestone complete v1.1"
    assert expected in result.stdout
    assert result.stdout.count("Retry: ") == 1


def test_cli_close_via_subprocess(tmp_path):
    """Test the close command via subprocess."""
    task_dir = tmp_path / ".planning" / "quick" / "20-cli-close"
    task_dir.mkdir(parents=True)
    summary = task_dir / "20-SUMMARY.md"
    summary.write_text("# Summary\n", encoding="utf-8")
    state_path = tmp_path / ".planning" / "STATE.md"
    state_path.write_text("# Project State\n", encoding="utf-8")

    result = _run_bootstrap_cli(
        "close",
        "--task-dir",
        str(task_dir),
        "--status",
        "completed",
        "--description",
        "cli close test",
        "--state-path",
        str(state_path),
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "completed"

    state_text = state_path.read_text(encoding="utf-8")
    assert "| 20 |" in state_text
    assert "| cli close test | completed |" in state_text


def test_cli_missing_command():
    """No command argument should produce an error."""
    result = _run_bootstrap_cli()
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# update_global_state direct tests
# ---------------------------------------------------------------------------


def test_update_global_state_creates_table_if_missing(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    state_path = tmp_path / "STATE.md"
    # File does not exist
    quick_bootstrap.update_global_state(state_path, 5, "test task", "completed")
    text = state_path.read_text(encoding="utf-8")
    assert "## Quick Tasks Completed" in text
    assert "| 5 |" in text
    assert "| test task | completed |" in text


def test_update_global_state_appends_to_existing_table(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    state_path = tmp_path / "STATE.md"
    state_path.write_text(
        "# Project State\n\nLast activity: old\n\n## Quick Tasks Completed\n\n"
        "| # | Date | Description | Status |\n|---|------|-------------|--------|\n",
        encoding="utf-8",
    )
    quick_bootstrap.update_global_state(state_path, 3, "first task", "completed")
    quick_bootstrap.update_global_state(state_path, 4, "second task", "failed")
    text = state_path.read_text(encoding="utf-8")
    assert "| first task | completed |" in text
    assert "| second task | failed |" in text


def test_update_global_state_does_not_duplicate(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    state_path = tmp_path / "STATE.md"
    state_path.write_text(
        "# Project State\n\nLast activity: old\n\n## Quick Tasks Completed\n\n"
        "| # | Date | Description | Status |\n|---|------|-------------|--------|\n",
        encoding="utf-8",
    )
    quick_bootstrap.update_global_state(state_path, 3, "same task", "completed")
    quick_bootstrap.update_global_state(state_path, 3, "same task", "completed")
    text = state_path.read_text(encoding="utf-8")
    assert text.count("same task") == 1


# ---------------------------------------------------------------------------
# _build_traceability_delta_snapshot
# ---------------------------------------------------------------------------


def test_build_traceability_delta_snapshot():
    quick_bootstrap = _load_quick_bootstrap()
    matrix_payload = {
        "coverage_matrix": {
            "rows": [
                {"requirement_id": "REQ-01", "coverage_state": "covered"},
            ],
            "summary": {"total": 1, "covered": 1, "partial": 0, "uncovered": 0, "stale": 0},
        }
    }
    snapshot = quick_bootstrap._build_traceability_delta_snapshot(
        "milestone", "all-active", matrix_payload
    )
    assert snapshot["scope"] == "milestone"
    assert snapshot["scope_target"] == "all-active"
    assert len(snapshot["rows"]) == 1
    assert snapshot["summary"]["total"] == 1
