from __future__ import annotations

from pathlib import Path
from typing import Any


REQUIRED_AUDIT_SECTIONS = (
    "## Scope",
    "## Checks",
    "## Findings",
    "## Remediation",
)


def _parse_frontmatter(text: str) -> dict[str, str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}

    frontmatter: dict[str, str] = {}
    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "---":
            break
        if ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        frontmatter[key.strip()] = raw_value.strip().strip("'\"")
    return frontmatter


def _add_failure(failure_groups: dict[str, list[dict[str, str]]], code: str, message: str, fix: str) -> None:
    failure_groups.setdefault(code, []).append(
        {
            "code": code,
            "severity": "error",
            "message": message,
            "fix": fix,
        }
    )


def evaluate_milestone_governance_gate(
    planning_root: Path, milestone_version: str
) -> dict[str, Any]:
    audit_path = planning_root / f"{milestone_version}-MILESTONE-AUDIT.md"
    retry_command = f"node ~/.claude/get-shit-done/bin/gsd-tools.cjs milestone precheck {milestone_version}"
    failure_groups: dict[str, list[dict[str, str]]] = {}

    if not audit_path.exists():
        _add_failure(
            failure_groups,
            "missing_file",
            f"Missing audit artifact: {audit_path}",
            f"Create {audit_path} with status: passed and required sections.",
        )
        return {
            "passed": False,
            "failure_groups": failure_groups,
            "retry_command": retry_command,
            "audit_file": str(audit_path),
        }

    content = audit_path.read_text(encoding="utf-8")
    frontmatter = _parse_frontmatter(content)
    status = frontmatter.get("status")
    if status != "passed":
        _add_failure(
            failure_groups,
            "invalid_status",
            "Audit status must be exactly 'passed'.",
            "Set frontmatter field status: passed and rerun precheck.",
        )

    missing_sections = [section for section in REQUIRED_AUDIT_SECTIONS if section not in content]
    if missing_sections:
        joined = ", ".join(missing_sections)
        _add_failure(
            failure_groups,
            "malformed_sections",
            f"Audit artifact is missing required sections: {joined}",
            "Add all required sections: Scope, Checks, Findings, Remediation.",
        )

    return {
        "passed": not failure_groups,
        "failure_groups": failure_groups,
        "retry_command": retry_command,
        "audit_file": str(audit_path),
    }


def format_gate_failures(result: dict[str, Any], retry_command: str) -> str:
    failure_groups = result.get("failure_groups", {})
    if not failure_groups:
        return "Milestone governance gate passed."

    lines = [
        "Milestone governance gate failed.",
        "",
        "Checklist:",
    ]
    for failure_type in sorted(failure_groups):
        for issue in failure_groups[failure_type]:
            lines.append(f"- [{failure_type}] {issue['message']}")
            lines.append(f"  Fix: {issue['fix']}")
    lines.append("")
    lines.append(f"Retry: {retry_command}")
    return "\n".join(lines)
