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
