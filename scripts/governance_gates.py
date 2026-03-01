from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any


REQUIRED_AUDIT_SECTIONS = (
    "## Scope",
    "## Checks",
    "## Findings",
    "## Remediation",
)
REQUIREMENT_ID_PATTERN = re.compile(r"^[A-Z]+-[0-9]{2,}$")
REQUIREMENTS_ALLOWED_STATUSES = {"Pending", "In Progress", "Complete", "Blocked"}
PHASE_ID_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")
COVERAGE_MATRIX_SCHEMA_VERSION = "coverage_matrix.v1"
COVERAGE_CAUSE_ORDER = (
    "unmapped_requirement",
    "multi_phase_mapping",
    "unknown_mapped_phase",
    "state_mapping_mismatch",
)
COVERAGE_REMEDIATION_BY_CAUSE = {
    "unmapped_requirement": "Add exactly one Traceability row for the requirement.",
    "multi_phase_mapping": "Keep exactly one canonical phase mapping for the requirement.",
    "unknown_mapped_phase": "Map only to normalized phase IDs present in ROADMAP.md.",
    "state_mapping_mismatch": "Align requirement status with mapped phase completion state.",
}
IMPACT_SEVERITY_WEIGHTS = {
    "critical": 4,
    "error": 3,
    "warning": 2,
    "info": 1,
}


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


def _ordered_requirements_failure_groups(
    failure_groups: dict[str, list[dict[str, str]]]
) -> dict[str, list[dict[str, str]]]:
    order = (
        "missing_file",
        "malformed_entry",
        "invalid_id_format",
        "duplicate_id",
        "invalid_status",
        "missing_acceptance_criteria",
    )
    ordered: dict[str, list[dict[str, str]]] = {}
    for key in order:
        if key in failure_groups:
            ordered[key] = failure_groups[key]
    for key in sorted(failure_groups):
        if key not in ordered:
            ordered[key] = failure_groups[key]
    return ordered


def _ordered_traceability_failure_groups(
    failure_groups: dict[str, list[dict[str, str]]]
) -> dict[str, list[dict[str, str]]]:
    order = (
        "missing_file",
        "malformed_traceability_table",
        "missing_touched_requirements",
        "unknown_touched_requirement",
        "unmapped_requirement",
        "multi_phase_mapping",
        "unknown_mapped_phase",
        "state_mapping_mismatch",
    )
    ordered: dict[str, list[dict[str, str]]] = {}
    for key in order:
        if key in failure_groups:
            ordered[key] = failure_groups[key]
    for key in sorted(failure_groups):
        if key not in ordered:
            ordered[key] = failure_groups[key]
    return ordered


def _parse_requirement_entries(content: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    lines = content.splitlines()

    in_allowed_section = False
    current_fields: dict[str, str] | None = None

    def flush_current() -> None:
        if current_fields is not None:
            entries.append(dict(current_fields))

    for raw_line in lines:
        line = raw_line.rstrip("\n")
        stripped = line.strip()
        if stripped in ("## v1 Requirements", "## v2 Requirements", "## Out of Scope"):
            flush_current()
            current_fields = None
            in_allowed_section = True
            continue
        if stripped.startswith("## "):
            flush_current()
            current_fields = None
            in_allowed_section = False
            continue
        if not in_allowed_section:
            continue
        if stripped == "#### Requirement":
            flush_current()
            current_fields = {}
            continue
        if current_fields is None:
            continue
        if not stripped.startswith("- "):
            continue
        payload = stripped[2:]
        if ":" not in payload:
            continue
        key, raw_value = payload.split(":", 1)
        current_fields[key.strip()] = raw_value.strip().strip("'\"")

    flush_current()
    return entries


def _normalize_phase_id(raw_phase: str) -> str | None:
    normalized = raw_phase.strip()
    if not normalized:
        return None
    phase_match = re.fullmatch(r"(?i)phase\s+([0-9]+(?:\.[0-9]+)?)", normalized)
    if phase_match:
        normalized = phase_match.group(1)
    if not PHASE_ID_PATTERN.fullmatch(normalized):
        return None
    if "." in normalized:
        integer_part, decimal_part = normalized.split(".", 1)
        return f"{int(integer_part)}.{int(decimal_part)}"
    return str(int(normalized))


def _parse_roadmap_phase_catalog(roadmap_content: str) -> set[str]:
    phase_ids: set[str] = set()
    for raw_line in roadmap_content.splitlines():
        line = raw_line.strip()
        match = re.search(r"Phase\s+([0-9]+(?:\.[0-9]+)?)", line, flags=re.IGNORECASE)
        if not match:
            continue
        normalized = _normalize_phase_id(match.group(1))
        if normalized:
            phase_ids.add(normalized)
    return phase_ids


def _parse_roadmap_phase_completion(roadmap_content: str) -> dict[str, bool]:
    completion: dict[str, bool] = {}
    for raw_line in roadmap_content.splitlines():
        line = raw_line.strip()
        match = re.search(
            r"^\-\s+\[(?P<marker>[xX ])\].*Phase\s+(?P<phase>[0-9]+(?:\.[0-9]+)?)",
            line,
            flags=re.IGNORECASE,
        )
        if not match:
            continue
        normalized = _normalize_phase_id(match.group("phase"))
        if not normalized:
            continue
        completion[normalized] = match.group("marker").strip().lower() == "x"
    return completion


def _parse_traceability_rows(requirements_content: str) -> tuple[list[dict[str, str]], str | None]:
    lines = requirements_content.splitlines()
    traceability_start = -1

    for index, raw_line in enumerate(lines):
        if raw_line.strip() == "## Traceability":
            traceability_start = index
            break

    if traceability_start < 0:
        return [], "Traceability section `## Traceability` is missing."

    table_lines: list[str] = []
    for raw_line in lines[traceability_start + 1 :]:
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith("## "):
            break
        if stripped.startswith("|"):
            table_lines.append(stripped)

    if len(table_lines) < 2:
        return [], "Traceability table must include header and delimiter rows."

    expected_header = "| Requirement | Phase | Status |"
    if table_lines[0] != expected_header:
        return [], "Traceability table header must be `| Requirement | Phase | Status |`."

    delimiter_cells = [cell.strip() for cell in table_lines[1].strip("|").split("|")]
    if len(delimiter_cells) != 3:
        return [], "Traceability table delimiter row must contain exactly 3 columns."
    if any(not cell or set(cell) != {"-"} for cell in delimiter_cells):
        return [], "Traceability table delimiter row must use hyphen separators."

    rows: list[dict[str, str]] = []
    for row_index, raw_row in enumerate(table_lines[2:], start=1):
        cells = [cell.strip() for cell in raw_row.strip("|").split("|")]
        if len(cells) != 3:
            return [], f"Traceability row #{row_index} must contain Requirement, Phase, and Status cells."
        requirement_id, phase_id, status = cells
        if not requirement_id:
            return [], f"Traceability row #{row_index} has blank Requirement value."
        if not phase_id:
            return [], f"Traceability row #{row_index} has blank Phase value."
        normalized_phase = _normalize_phase_id(phase_id)
        if normalized_phase is None:
            return [], f"Traceability row #{row_index} phase `{phase_id}` is malformed."
        rows.append(
            {
                "requirement_id": requirement_id,
                "phase": normalized_phase,
                "status": status,
            }
        )

    if not rows:
        return [], "Traceability table must include at least one mapping row."

    return rows, None


def _collect_active_requirement_ids(requirements_content: str) -> set[str]:
    active_ids: set[str] = set()
    lines = requirements_content.splitlines()
    in_active_section = False
    current_fields: dict[str, str] | None = None

    def flush_current() -> None:
        if current_fields is None:
            return
        requirement_id = current_fields.get("id", "").strip()
        if requirement_id:
            active_ids.add(requirement_id)

    for raw_line in lines:
        stripped = raw_line.strip()
        if stripped in ("## v1 Requirements", "## v2 Requirements"):
            flush_current()
            current_fields = None
            in_active_section = True
            continue
        if stripped in ("## Out of Scope",):
            flush_current()
            current_fields = None
            in_active_section = False
            continue
        if stripped.startswith("## "):
            flush_current()
            current_fields = None
            in_active_section = False
            continue
        if not in_active_section:
            continue
        if stripped == "#### Requirement":
            flush_current()
            current_fields = {}
            continue
        if current_fields is None:
            continue
        if not stripped.startswith("- "):
            continue
        payload = stripped[2:]
        if ":" not in payload:
            continue
        key, raw_value = payload.split(":", 1)
        current_fields[key.strip()] = raw_value.strip().strip("'\"")

    flush_current()
    return active_ids


def _collect_active_requirement_statuses(requirements_content: str) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for entry in _parse_requirement_entries(requirements_content):
        requirement_id = entry.get("id", "").strip()
        status = entry.get("status", "").strip()
        if not requirement_id or not status:
            continue
        if requirement_id.startswith("OOS-"):
            continue
        statuses[requirement_id] = status
    return statuses


def _collect_coverage_requirement_statuses(requirements_content: str) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for entry in _parse_requirement_entries(requirements_content):
        requirement_id = entry.get("id", "").strip()
        status = entry.get("status", "").strip()
        if not requirement_id or not status:
            continue
        if requirement_id.startswith("OOS-") or status == "Blocked":
            continue
        statuses[requirement_id] = status
    return statuses


def _order_cause_codes(cause_codes: set[str] | list[str]) -> list[str]:
    seen = {code.strip() for code in cause_codes if code and code.strip()}
    ordered: list[str] = []
    for code in COVERAGE_CAUSE_ORDER:
        if code in seen:
            ordered.append(code)
            seen.remove(code)
    ordered.extend(sorted(seen))
    return ordered


def _derive_coverage_state(cause_codes: list[str], *, has_valid_mapping: bool) -> str:
    if "state_mapping_mismatch" in cause_codes:
        return "stale"
    if not cause_codes:
        return "covered"
    if has_valid_mapping:
        return "partial"
    return "uncovered"


def build_requirement_coverage_matrix(
    planning_root: Path,
    *,
    scope: str,
    phase_id: str | None = None,
) -> dict[str, Any]:
    if scope not in {"phase", "milestone"}:
        raise ValueError("scope must be 'phase' or 'milestone'.")

    normalized_phase_id: str | None = None
    if scope == "phase":
        if phase_id is None:
            raise ValueError("phase_id is required when scope='phase'.")
        normalized_phase_id = _normalize_phase_id(phase_id)
        if normalized_phase_id is None:
            raise ValueError(f"phase_id `{phase_id}` is malformed.")

    requirements_path = planning_root / "REQUIREMENTS.md"
    roadmap_path = planning_root / "ROADMAP.md"
    requirements_content = requirements_path.read_text(encoding="utf-8")
    roadmap_content = roadmap_path.read_text(encoding="utf-8")

    active_statuses = _collect_coverage_requirement_statuses(requirements_content)
    traceability_rows, _ = _parse_traceability_rows(requirements_content)
    roadmap_phase_catalog = _parse_roadmap_phase_catalog(roadmap_content)
    roadmap_phase_completion = _parse_roadmap_phase_completion(roadmap_content)

    scoped_requirement_ids = set(active_statuses)
    if normalized_phase_id is not None:
        scoped_requirement_ids = {
            row["requirement_id"]
            for row in traceability_rows
            if row["phase"] == normalized_phase_id and row["requirement_id"] in active_statuses
        }

    phase_mappings: dict[str, set[str]] = {}
    for row in traceability_rows:
        requirement_id = row["requirement_id"]
        if requirement_id not in scoped_requirement_ids:
            continue
        phase_mappings.setdefault(requirement_id, set()).add(row["phase"])

    rows: list[dict[str, Any]] = []
    summary = {
        "total": 0,
        "covered": 0,
        "partial": 0,
        "uncovered": 0,
        "stale": 0,
    }
    retry_command = "node ~/.claude/get-shit-done/bin/gsd-tools.cjs requirements precheck"

    for requirement_id in sorted(scoped_requirement_ids):
        mapped_phases = sorted(phase_mappings.get(requirement_id, set()))
        valid_mapped_phases = [phase for phase in mapped_phases if phase in roadmap_phase_catalog]
        cause_codes: set[str] = set()
        if not mapped_phases:
            cause_codes.add("unmapped_requirement")
        if len(mapped_phases) > 1:
            cause_codes.add("multi_phase_mapping")
        if any(phase not in roadmap_phase_catalog for phase in mapped_phases):
            cause_codes.add("unknown_mapped_phase")

        requirement_complete = active_statuses.get(requirement_id) == "Complete"
        for mapped_phase in valid_mapped_phases:
            mapped_phase_complete = roadmap_phase_completion.get(mapped_phase)
            if mapped_phase_complete is None:
                continue
            if requirement_complete != mapped_phase_complete:
                cause_codes.add("state_mapping_mismatch")
                break

        ordered_causes = _order_cause_codes(cause_codes)
        coverage_state = _derive_coverage_state(
            ordered_causes,
            has_valid_mapping=bool(valid_mapped_phases),
        )
        primary_cause = ordered_causes[0] if ordered_causes else None

        rows.append(
            {
                "requirement_id": requirement_id,
                "requirement_status": active_statuses.get(requirement_id, "Pending"),
                "mapped_phases": mapped_phases,
                "coverage_state": coverage_state,
                "cause_codes": ordered_causes,
                "primary_cause": primary_cause,
                "remediation": COVERAGE_REMEDIATION_BY_CAUSE.get(primary_cause, ""),
                "retry_command": retry_command,
            }
        )
        summary["total"] += 1
        summary[coverage_state] += 1

    return {
        "schema_version": COVERAGE_MATRIX_SCHEMA_VERSION,
        "coverage_matrix": {
            "scope": scope,
            "scope_target": normalized_phase_id if normalized_phase_id is not None else "all-active",
            "rows": rows,
            "summary": summary,
        },
    }


def format_coverage_matrix_summary(coverage_matrix: dict[str, Any]) -> str:
    rows = list(coverage_matrix.get("rows", []) or [])
    summary = dict(coverage_matrix.get("summary", {}) or {})
    scope = str(coverage_matrix.get("scope", "milestone"))
    scope_target = str(coverage_matrix.get("scope_target", "all-active"))
    row_fragments: list[str] = []
    for row in rows:
        requirement_id = str(row.get("requirement_id", "")).strip()
        state = str(row.get("coverage_state", "")).strip() or "unknown"
        causes = ",".join(str(code).strip() for code in row.get("cause_codes", []) if str(code).strip())
        if causes:
            row_fragments.append(f"{requirement_id}:{state}[{causes}]")
        else:
            row_fragments.append(f"{requirement_id}:{state}")
    row_text = "; ".join(row_fragments) if row_fragments else "none"
    return "\n".join(
        [
            "Coverage matrix (compact):",
            f"- scope: {scope} ({scope_target})",
            (
                "- totals: "
                f"total={int(summary.get('total', 0))}, "
                f"covered={int(summary.get('covered', 0))}, "
                f"partial={int(summary.get('partial', 0))}, "
                f"uncovered={int(summary.get('uncovered', 0))}, "
                f"stale={int(summary.get('stale', 0))}"
            ),
            f"- rows: {row_text}",
        ]
    )


def format_coverage_matrix_expanded(coverage_matrix: dict[str, Any]) -> str:
    rows = list(coverage_matrix.get("rows", []) or [])
    scope = str(coverage_matrix.get("scope", "milestone"))
    scope_target = str(coverage_matrix.get("scope_target", "all-active"))
    lines = [
        "Coverage matrix (expanded):",
        f"- scope: {scope} ({scope_target})",
    ]
    if not rows:
        lines.append("- rows: none")
        return "\n".join(lines)
    for row in rows:
        requirement_id = str(row.get("requirement_id", "")).strip() or "UNKNOWN"
        state = str(row.get("coverage_state", "")).strip() or "unknown"
        cause_codes = [str(code).strip() for code in row.get("cause_codes", []) if str(code).strip()]
        causes = ", ".join(cause_codes) if cause_codes else "-"
        remediation = str(row.get("remediation", "")).strip() or "-"
        retry_command = str(row.get("retry_command", "")).strip() or "-"
        lines.append(f"- {requirement_id}: {state}")
        lines.append(f"  cause_codes: {causes}")
        lines.append(f"  remediation: {remediation}")
        lines.append(f"  retry: {retry_command}")
    return "\n".join(lines)


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


def evaluate_requirements_contract_gate(
    planning_root: Path,
    *,
    scope: str = "all",
    touched_requirement_ids: set[str] | None = None,
) -> dict[str, Any]:
    requirements_path = planning_root / "REQUIREMENTS.md"
    retry_command = "node ~/.claude/get-shit-done/bin/gsd-tools.cjs requirements precheck"
    failure_groups: dict[str, list[dict[str, str]]] = {}

    if not requirements_path.exists():
        _add_failure(
            failure_groups,
            "missing_file",
            f"Missing requirements artifact: {requirements_path}",
            f"Create {requirements_path} and add canonical requirement entries.",
        )
        return {
            "passed": False,
            "failure_groups": _ordered_requirements_failure_groups(failure_groups),
            "retry_command": retry_command,
            "requirements_file": str(requirements_path),
        }

    content = requirements_path.read_text(encoding="utf-8")
    entries = _parse_requirement_entries(content)
    seen_ids: set[str] = set()
    validated_entries: list[tuple[int, dict[str, str]]] = []

    for index, entry in enumerate(entries, start=1):
        requirement_id = entry.get("id", "").strip()
        if requirement_id and requirement_id not in seen_ids:
            seen_ids.add(requirement_id)
        validated_entries.append((index, entry))

    touched_ids = {item.strip() for item in (touched_requirement_ids or set()) if item and item.strip()}
    if scope == "touched":
        if not touched_ids:
            _add_failure(
                failure_groups,
                "missing_touched_requirements",
                "Touched requirements scope requires at least one requirement id.",
                "Provide one or more --requirement-id values matching REQUIREMENTS.md ids.",
            )
            validated_entries = []
        else:
            missing_touched = sorted(touched_ids - seen_ids)
            for missing_id in missing_touched:
                _add_failure(
                    failure_groups,
                    "unknown_touched_requirement",
                    f"Touched requirement id `{missing_id}` does not exist in REQUIREMENTS.md.",
                    "Use existing requirement ids or update REQUIREMENTS.md before phase completion.",
                )
            validated_entries = [
                (index, entry)
                for index, entry in validated_entries
                if entry.get("id", "").strip() in touched_ids
            ]

    seen_ids.clear()
    for index, entry in validated_entries:
        requirement_id = entry.get("id", "").strip()
        status = entry.get("status", "").strip()
        has_acceptance_key = "acceptance_criteria" in entry
        acceptance = entry.get("acceptance_criteria", "").strip()

        if not requirement_id or not status:
            _add_failure(
                failure_groups,
                "malformed_entry",
                f"Requirement entry #{index} must include id and status fields.",
                "Ensure every `#### Requirement` block defines id and status bullet fields.",
            )
        if not has_acceptance_key or not acceptance:
            _add_failure(
                failure_groups,
                "missing_acceptance_criteria",
                f"Requirement entry #{index} must include a non-empty acceptance_criteria field.",
                "Add acceptance_criteria with concrete, verifiable behavior for this requirement.",
            )

        if requirement_id and not REQUIREMENT_ID_PATTERN.fullmatch(requirement_id):
            _add_failure(
                failure_groups,
                "invalid_id_format",
                f"Requirement id `{requirement_id}` must match `CAT-NN` format.",
                "Use uppercase category and numeric suffix with at least two digits (example: REQ-01).",
            )
        elif requirement_id:
            if requirement_id in seen_ids:
                _add_failure(
                    failure_groups,
                    "duplicate_id",
                    f"Requirement id `{requirement_id}` is duplicated.",
                    "Ensure each requirement id is globally unique across active sections.",
                )
            else:
                seen_ids.add(requirement_id)

        if status and status not in REQUIREMENTS_ALLOWED_STATUSES:
            _add_failure(
                failure_groups,
                "invalid_status",
                f"Requirement status `{status}` is invalid for entry #{index}.",
                "Use one of: Pending, In Progress, Complete, Blocked.",
            )

    failure_groups = _ordered_requirements_failure_groups(failure_groups)

    return {
        "passed": not failure_groups,
        "failure_groups": failure_groups,
        "retry_command": retry_command,
        "requirements_file": str(requirements_path),
    }


def evaluate_traceability_drift_gate(
    planning_root: Path,
    *,
    scope: str = "all",
    touched_requirement_ids: set[str] | None = None,
) -> dict[str, Any]:
    requirements_path = planning_root / "REQUIREMENTS.md"
    roadmap_path = planning_root / "ROADMAP.md"
    retry_command = "node ~/.claude/get-shit-done/bin/gsd-tools.cjs requirements precheck"
    failure_groups: dict[str, list[dict[str, str]]] = {}

    for artifact in (requirements_path, roadmap_path):
        if artifact.exists():
            continue
        _add_failure(
            failure_groups,
            "missing_file",
            f"Missing traceability artifact: {artifact}",
            "Restore required planning artifacts before running traceability gate.",
        )

    if failure_groups:
        return {
            "passed": False,
            "failure_groups": _ordered_traceability_failure_groups(failure_groups),
            "retry_command": retry_command,
            "scope": scope,
            "touched_requirement_ids": sorted(item.strip() for item in (touched_requirement_ids or set()) if item),
        }

    requirements_content = requirements_path.read_text(encoding="utf-8")
    roadmap_content = roadmap_path.read_text(encoding="utf-8")
    roadmap_phase_catalog = _parse_roadmap_phase_catalog(roadmap_content)
    roadmap_phase_completion = _parse_roadmap_phase_completion(roadmap_content)
    active_ids = _collect_active_requirement_ids(requirements_content)
    active_statuses = _collect_active_requirement_statuses(requirements_content)
    traceability_rows, traceability_error = _parse_traceability_rows(requirements_content)
    if traceability_error:
        _add_failure(
            failure_groups,
            "malformed_traceability_table",
            traceability_error,
            "Define a valid Traceability table with Requirement, Phase, and Status columns.",
        )

    touched_ids = {item.strip() for item in (touched_requirement_ids or set()) if item and item.strip()}
    scoped_ids = set(active_ids)
    if scope == "touched":
        if not touched_ids:
            _add_failure(
                failure_groups,
                "missing_touched_requirements",
                "Touched requirements scope requires at least one requirement id.",
                "Provide one or more --requirement-id values matching active requirements.",
            )
        else:
            for requirement_id in sorted(touched_ids - active_ids):
                _add_failure(
                    failure_groups,
                    "unknown_touched_requirement",
                    f"Touched requirement id `{requirement_id}` does not exist in active requirements.",
                    "Use requirement ids from v1/v2 requirements or update REQUIREMENTS.md.",
                )
        scoped_ids = active_ids & touched_ids

    if not traceability_error:
        phase_mappings: dict[str, set[str]] = {}
        for row in traceability_rows:
            requirement_id = row["requirement_id"]
            if requirement_id not in scoped_ids:
                continue
            phase = row["phase"]
            phase_mappings.setdefault(requirement_id, set()).add(phase)
            if phase not in roadmap_phase_catalog:
                _add_failure(
                    failure_groups,
                    "unknown_mapped_phase",
                    f"Requirement `{requirement_id}` maps to unknown phase `{phase}`.",
                    "Map requirements only to phases that exist in ROADMAP.md.",
                )

        for requirement_id in sorted(scoped_ids):
            mapped_phases = phase_mappings.get(requirement_id, set())
            if not mapped_phases:
                _add_failure(
                    failure_groups,
                    "unmapped_requirement",
                    f"Active requirement `{requirement_id}` is missing a traceability phase mapping.",
                    "Add exactly one Traceability row for every active requirement.",
                )
                continue
            if len(mapped_phases) > 1:
                mapped_list = ", ".join(sorted(mapped_phases))
                _add_failure(
                    failure_groups,
                    "multi_phase_mapping",
                    f"Active requirement `{requirement_id}` maps to multiple phases: {mapped_list}.",
                    "Keep exactly one canonical phase mapping per active requirement.",
                )

            requirement_complete = active_statuses.get(requirement_id) == "Complete"
            for mapped_phase in sorted(mapped_phases):
                mapped_phase_complete = roadmap_phase_completion.get(mapped_phase)
                if mapped_phase_complete is None:
                    continue
                if requirement_complete and not mapped_phase_complete:
                    _add_failure(
                        failure_groups,
                        "state_mapping_mismatch",
                        (
                            f"Requirement `{requirement_id}` is Complete while mapped phase "
                            f"`{mapped_phase}` is not complete in ROADMAP.md."
                        ),
                        "Align requirement status with mapped phase completion state before retrying.",
                    )
                    break
                if mapped_phase_complete and not requirement_complete:
                    _add_failure(
                        failure_groups,
                        "state_mapping_mismatch",
                        (
                            f"Requirement `{requirement_id}` is not Complete while mapped phase "
                            f"`{mapped_phase}` is complete in ROADMAP.md."
                        ),
                        "Mark requirement Complete or move mapping to the correct incomplete phase.",
                    )
                    break

    failure_groups = _ordered_traceability_failure_groups(failure_groups)
    return {
        "passed": not failure_groups,
        "failure_groups": failure_groups,
        "retry_command": retry_command,
        "scope": scope,
        "touched_requirement_ids": sorted(touched_ids),
    }


def _canonical_check_key(failure_type: str, issue: dict[str, Any], issue_index: int) -> str:
    raw_code = str(issue.get("code", "")).strip()
    if raw_code:
        return raw_code
    message = " ".join(str(issue.get("message", "")).strip().split())
    fix = " ".join(str(issue.get("fix", "")).strip().split())
    return f"{failure_type}:{message}|{fix}|{issue_index:04d}"


def _coverage_rows_from_payload(coverage_matrix: dict[str, Any]) -> list[dict[str, Any]]:
    rows = coverage_matrix.get("rows")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    nested = coverage_matrix.get("coverage_matrix", {})
    if isinstance(nested, dict):
        nested_rows = nested.get("rows")
        if isinstance(nested_rows, list):
            return [row for row in nested_rows if isinstance(row, dict)]
    return []


def _cause_blast_radius_map(coverage_matrix: dict[str, Any]) -> dict[str, int]:
    rows = _coverage_rows_from_payload(coverage_matrix)
    radius: dict[str, set[str]] = {}
    for row in rows:
        requirement_id = str(row.get("requirement_id", "")).strip()
        if not requirement_id:
            continue
        for code in row.get("cause_codes", []) or []:
            cause_code = str(code).strip()
            if not cause_code:
                continue
            radius.setdefault(cause_code, set()).add(requirement_id)
        primary_cause = str(row.get("primary_cause", "")).strip()
        if primary_cause:
            radius.setdefault(primary_cause, set()).add(requirement_id)
    return {code: len(requirements) for code, requirements in radius.items()}


def build_impact_ranked_remediation_hints(
    result: dict[str, Any],
    coverage_matrix: dict[str, Any],
    *,
    retry_command: str,
) -> list[dict[str, Any]]:
    failure_groups = result.get("failure_groups", {})
    if not isinstance(failure_groups, dict):
        return []

    cause_blast_radius = _cause_blast_radius_map(coverage_matrix)
    ranked_records: list[dict[str, Any]] = []
    for failure_type, issues in failure_groups.items():
        if not isinstance(issues, list):
            continue
        failure_type_key = str(failure_type).strip()
        for issue_index, issue in enumerate(issues):
            if not isinstance(issue, dict):
                continue
            severity = str(issue.get("severity", "error")).strip().lower() or "error"
            severity_weight = IMPACT_SEVERITY_WEIGHTS.get(severity, IMPACT_SEVERITY_WEIGHTS["error"])
            check_key = _canonical_check_key(failure_type_key, issue, issue_index)
            blast_radius = max(cause_blast_radius.get(failure_type_key, 0), 1)
            rank_sort_key = (-severity_weight, -blast_radius, check_key)
            message = str(issue.get("message", "")).strip() or "Traceability check failed."
            fix = str(issue.get("fix", "")).strip() or "Apply the smallest corrective update and rerun."
            rationale = (
                f"severity {severity} (w={severity_weight}) and blast radius {blast_radius}; "
                f"tie-break by check key `{check_key}`."
            )
            ranked_records.append(
                {
                    "_sort_key": rank_sort_key,
                    "failure_type": failure_type_key,
                    "severity": severity,
                    "severity_weight": severity_weight,
                    "blast_radius": blast_radius,
                    "check_key": check_key,
                    "blocking_reason": message,
                    "minimal_fix": fix,
                    "retry_command": retry_command,
                    "rationale": rationale,
                }
            )

    ranked_records.sort(key=lambda record: record["_sort_key"])
    ranked_hints: list[dict[str, Any]] = []
    for index, record in enumerate(ranked_records, start=1):
        record.pop("_sort_key", None)
        record["rank"] = index
        record["rank_key"] = f"{index:04d}:{record['check_key']}"
        ranked_hints.append(record)
    return ranked_hints


def format_impact_ranked_remediation_hints(ranked_hints: list[dict[str, Any]]) -> str:
    if not ranked_hints:
        return "No impact-ranked remediation hints."

    blocks: list[str] = []
    for hint in ranked_hints:
        rank = int(hint.get("rank", 0))
        rationale = str(hint.get("rationale", "")).strip() or "deterministic impact order."
        blocking_reason = str(hint.get("blocking_reason", "")).strip() or "Traceability check failed."
        minimal_fix = str(hint.get("minimal_fix", "")).strip() or "Apply the smallest corrective change."
        retry_command = str(hint.get("retry_command", "")).strip() or "node ~/.claude/get-shit-done/bin/gsd-tools.cjs requirements precheck"
        blocks.append(
            "\n".join(
                [
                    f"Rank {rank}: {rationale}",
                    f"Blocking reason: {blocking_reason}",
                    f"Minimal fix: {minimal_fix}",
                    f"Retry: {retry_command}",
                ]
            )
        )
    return "\n\n".join(blocks)


def format_traceability_drift_failures(result: dict[str, Any], retry_command: str) -> str:
    failure_groups = result.get("failure_groups", {})
    if not failure_groups:
        return "Traceability drift gate passed."

    remediation_steps = {
        "missing_file": [
            "Restore missing planning artifacts (REQUIREMENTS.md and ROADMAP.md).",
            "Re-run traceability precheck after restoring files.",
        ],
        "malformed_traceability_table": [
            "Fix Traceability section header and table schema.",
            "Ensure Requirement, Phase, and Status columns are present for each row.",
        ],
        "missing_touched_requirements": [
            "Provide one or more --requirement-id values for touched scope checks.",
            "Use IDs from active v1/v2 requirement blocks.",
        ],
        "unknown_touched_requirement": [
            "Remove unknown requirement IDs from touched scope commands.",
            "Add requirement entry first if the ID is new.",
        ],
        "unmapped_requirement": [
            "Add exactly one Traceability row for each active requirement in scope.",
            "Keep requirement IDs aligned with REQUIREMENTS.md entries.",
        ],
        "multi_phase_mapping": [
            "Consolidate each requirement to one canonical phase mapping.",
            "Remove duplicate Traceability rows for the same requirement.",
        ],
        "unknown_mapped_phase": [
            "Update Traceability rows to only reference phases present in ROADMAP.md.",
            "Normalize aliases (for example, `Phase 4`) to canonical phase IDs.",
        ],
        "state_mapping_mismatch": [
            "Synchronize STATE/traceability evidence with canonical requirement IDs.",
            "Re-run precheck after correcting state and traceability mappings.",
        ],
    }

    lines = [
        "Traceability drift gate failed.",
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


def format_requirements_contract_failures(result: dict[str, Any], retry_command: str) -> str:
    failure_groups = result.get("failure_groups", {})
    if not failure_groups:
        return "Requirements contract gate passed."

    remediation_steps = {
        "missing_file": [
            "Create .planning/REQUIREMENTS.md with canonical requirement blocks.",
            "Define id, status, and acceptance_criteria for each entry.",
        ],
        "malformed_entry": [
            "Ensure each `#### Requirement` block includes id and status fields.",
            "Use canonical bullet format: `- key: value`.",
        ],
        "invalid_id_format": [
            "Rename IDs to `CAT-NN` format (uppercase category + two or more digits).",
            "Avoid lowercase IDs or one-digit numeric suffixes.",
        ],
        "duplicate_id": [
            "Make each requirement ID globally unique across active sections.",
            "Update traceability rows if IDs changed.",
        ],
        "invalid_status": [
            "Set status to one of: Pending, In Progress, Complete, Blocked.",
            "Remove ad-hoc status labels like Done or WIP.",
        ],
        "missing_acceptance_criteria": [
            "Add non-empty acceptance_criteria for every requirement entry.",
            "Use concrete, verifiable criteria text.",
        ],
    }

    lines = [
        "Requirements contract gate failed.",
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
