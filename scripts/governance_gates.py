from __future__ import annotations

from datetime import datetime, timezone
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


def _parse_iso_utc(value: str) -> datetime | None:
    normalized = value.strip()
    if not normalized:
        return None
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _ordered_failure_groups(
    failure_groups: dict[str, list[dict[str, str]]]
) -> dict[str, list[dict[str, str]]]:
    order = ("missing_file", "invalid_status", "malformed_sections", "stale_audit")
    ordered: dict[str, list[dict[str, str]]] = {}
    for key in order:
        if key in failure_groups:
            ordered[key] = failure_groups[key]
    for key in sorted(failure_groups):
        if key not in ordered:
            ordered[key] = failure_groups[key]
    return ordered


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

    audited_value = frontmatter.get("audited", "")
    audited_at = _parse_iso_utc(audited_value)
    if audited_at is None:
        _add_failure(
            failure_groups,
            "malformed_sections",
            "Audit frontmatter requires a valid audited timestamp.",
            "Set audited to an ISO-8601 UTC timestamp like 2026-03-01T12:46:34Z.",
        )
    else:
        stale_reasons: list[str] = []
        state_path = planning_root / "STATE.md"
        if state_path.exists():
            state_frontmatter = _parse_frontmatter(state_path.read_text(encoding="utf-8"))
            state_updated = _parse_iso_utc(state_frontmatter.get("last_updated", ""))
            if state_updated and state_updated > audited_at:
                stale_reasons.append("STATE.md last_updated is newer than audit timestamp")

        roadmap_path = planning_root / "ROADMAP.md"
        if roadmap_path.exists():
            roadmap_updated = datetime.fromtimestamp(roadmap_path.stat().st_mtime, tz=timezone.utc)
            if roadmap_updated > audited_at:
                stale_reasons.append("ROADMAP.md modification time is newer than audit timestamp")

        if stale_reasons:
            _add_failure(
                failure_groups,
                "stale_audit",
                "Audit is stale: " + "; ".join(stale_reasons),
                "Re-run milestone audit and update audited timestamp after roadmap/state changes.",
            )

    failure_groups = _ordered_failure_groups(failure_groups)

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

    remediation_steps = {
        "missing_file": [
            "Create the canonical milestone audit artifact in .planning.",
            "Populate frontmatter with milestone, status: passed, and audited timestamp.",
        ],
        "invalid_status": [
            "Set audit frontmatter status exactly to passed.",
            "Confirm no stale or conflicting status values remain in the audit artifact.",
        ],
        "malformed_sections": [
            "Restore required sections: Scope, Checks, Findings, Remediation.",
            "Ensure audited frontmatter is valid ISO-8601 UTC format.",
        ],
        "stale_audit": [
            "Re-run milestone audit after roadmap/state updates.",
            "Update audited timestamp to the latest verification time.",
        ],
    }

    lines = [
        "Milestone governance gate failed.",
        "",
        "Checklist:",
    ]
    for failure_type, issues in failure_groups.items():
        lines.append(f"- Group {failure_type}")
        for issue in issues:
            message = str(issue.get("message", "")).strip() or "Issue detected."
            fix = str(issue.get("fix", "")).strip() or "Apply the remediation checklist."
            lines.append(f"  - {message}")
            lines.append(f"    Fix: {fix}")
    lines.extend(["", "Remediation by failure type:"])
    for failure_type in failure_groups:
        lines.append(f"- Group {failure_type}:")
        for step in remediation_steps.get(
            failure_type,
            ["Resolve all listed checklist issues for this group and retry."],
        ):
            lines.append(f"  - {step}")
    lines.append("")
    effective_retry = retry_command or str(result.get("retry_command", "")).strip()
    lines.append(f"Retry: {effective_retry}")
    return "\n".join(lines)
