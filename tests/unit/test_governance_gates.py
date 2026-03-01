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
