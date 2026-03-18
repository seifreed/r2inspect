from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


DEFAULT_GSD_TOOLS_PATH = str(Path.home() / ".codex/get-shit-done/bin/gsd-tools.cjs")
DEFAULT_TEMPLATE_DIR = Path(__file__).resolve().parent / "quick_templates"
DEFAULT_STATE_PATH = Path(".planning/STATE.md")
TRACEABILITY_TOP_RANK_MARKER = "<!-- traceability_top_rank_key:"
TRACEABILITY_DELTA_FILE_NAME = "traceability-delta.json"
TRACEABILITY_DELTA_SCHEMA_VERSION = "traceability_delta.v1"
MIN_CHECKS = 2
MAX_CHECKS = 3


class BootstrapError(RuntimeError):
    """Raised when bootstrap execution cannot complete."""


class PreflightError(BootstrapError):
    """Raised when init quick preflight requirements are not satisfied."""


@dataclass(frozen=True)
class BootstrapResult:
    number: int
    slug: str
    task_dir: Path
    checks: list[str]
    retries: int
    plan_path: Path
    summary_path: Path


def _load_governance_functions() -> tuple[
    Callable[[Path, str], dict[str, object]],
    Callable[[dict[str, object], str], str],
    Callable[..., dict[str, object]],
    Callable[[dict[str, object], str], str],
    Callable[..., dict[str, object]],
    Callable[[dict[str, object], str], str],
    Callable[..., dict[str, object]],
    Callable[[dict[str, object]], str],
    Callable[[dict[str, object]], str],
    Callable[..., list[dict[str, object]]],
    Callable[[list[dict[str, object]]], str],
    Callable[[str | None, str | None], str],
]:
    module_path = Path(__file__).resolve().parent / "governance_gates.py"
    module_name = "governance_gates"
    if module_name in sys.modules:
        module = sys.modules[module_name]
    else:
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec is None or spec.loader is None:
            raise BootstrapError(f"Unable to load governance module from {module_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
    return (
        module.evaluate_milestone_governance_gate,
        module.format_gate_failures,
        module.evaluate_requirements_contract_gate,
        module.format_requirements_contract_failures,
        module.evaluate_traceability_drift_gate,
        module.format_traceability_drift_failures,
        module.build_requirement_coverage_matrix,
        module.format_coverage_matrix_summary,
        module.format_coverage_matrix_expanded,
        module.build_impact_ranked_remediation_hints,
        module.format_impact_ranked_remediation_hints,
        module.build_top_rank_change_note,
    )


(
    evaluate_milestone_governance_gate,
    format_gate_failures,
    evaluate_requirements_contract_gate,
    format_requirements_contract_failures,
    evaluate_traceability_drift_gate,
    format_traceability_drift_failures,
    build_requirement_coverage_matrix,
    format_coverage_matrix_summary,
    format_coverage_matrix_expanded,
    build_impact_ranked_remediation_hints,
    format_impact_ranked_remediation_hints,
    build_top_rank_change_note,
) = _load_governance_functions()


def _build_traceability_retry_command(scope: str, phase_id: str | None) -> str:
    parts = ["python scripts/quick_bootstrap.py traceability precheck"]
    normalized_scope = str(scope).strip().lower()
    if normalized_scope == "phase":
        normalized_phase_id = str(phase_id or "").strip()
        parts.extend(["--scope", "phase", "--phase-id", normalized_phase_id])
    return " ".join(parts)


def _read_traceability_top_rank_key(state_path: Path) -> str | None:
    if not state_path.exists():
        return None
    text = state_path.read_text(encoding="utf-8")
    match = re.search(
        r"^<!-- traceability_top_rank_key:\s*(?P<key>.*?)\s*-->$",
        text,
        flags=re.MULTILINE,
    )
    if not match:
        return None
    value = match.group("key").strip()
    return value or None


def _write_traceability_top_rank_key(state_path: Path, top_rank_key: str | None) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    marker_line = f"{TRACEABILITY_TOP_RANK_MARKER} {str(top_rank_key or '').strip()} -->"
    if state_path.exists():
        text = state_path.read_text(encoding="utf-8")
    else:
        text = "# Project State\n"
    if re.search(r"^<!-- traceability_top_rank_key:.*-->$", text, flags=re.MULTILINE):
        updated = re.sub(
            r"^<!-- traceability_top_rank_key:.*-->$",
            marker_line,
            text,
            flags=re.MULTILINE,
        )
    else:
        updated = text.rstrip() + f"\n\n{marker_line}\n"
    state_path.write_text(updated if updated.endswith("\n") else f"{updated}\n", encoding="utf-8")


def _parse_iso_utc(value: str) -> datetime | None:
    normalized = str(value).strip()
    if not normalized:
        return None
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_governance_exception_payload(args: argparse.Namespace) -> dict[str, str] | None:
    owner = str(getattr(args, "governance_exception_owner", "")).strip()
    task = str(getattr(args, "governance_exception_task", "")).strip()
    rationale = str(getattr(args, "governance_exception_rationale", "")).strip()
    until_raw = str(getattr(args, "governance_exception_until", "")).strip()

    if not any((owner, task, rationale, until_raw)):
        return None

    if not (owner and task and rationale and until_raw):
        return None

    until = _parse_iso_utc(until_raw)
    if until is None:
        return None

    now = datetime.now(timezone.utc)
    if until <= now:
        return None

    return {
        "owner": owner,
        "task": task,
        "rationale": rationale,
        "until": _format_iso_utc(until),
    }


def _normalize_traceability_delta_key(scope: str, scope_target: str) -> str:
    normalized_scope = str(scope or "milestone").strip().lower()
    normalized_target = str(scope_target or "all-active").strip() or "all-active"
    return f"{normalized_scope}:{normalized_target}"


def _normalize_phase_snapshot_target(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.lower().startswith("phase "):
        text = text[6:].strip()
    if not text:
        return ""
    if "." in text:
        integer_part, decimal_part = text.split(".", 1)
        return f"{int(integer_part)}.{int(decimal_part)}"
    return str(int(text))


def _normalize_delta_row(row: dict[str, object]) -> dict[str, object]:
    requirement_id = str(row.get("requirement_id", "")).strip()
    requirement_status = str(row.get("requirement_status", "")).strip()
    coverage_state = str(row.get("coverage_state", "")).strip()
    mapped_phases = sorted(
        item.strip() for item in (row.get("mapped_phases", []) or []) if str(item).strip()
    )
    primary_cause = str(row.get("primary_cause", "")).strip()
    cause_codes = sorted(
        item.strip() for item in (row.get("cause_codes", []) or []) if str(item).strip()
    )
    return {
        "requirement_id": requirement_id,
        "requirement_status": requirement_status,
        "mapped_phases": mapped_phases,
        "coverage_state": coverage_state,
        "primary_cause": primary_cause,
        "cause_codes": cause_codes,
    }


def _snapshot_rows_from_coverage_matrix(
    matrix_payload: dict[str, object],
) -> list[dict[str, object]]:
    matrix_payload_root = matrix_payload.get("coverage_matrix", {})
    if not isinstance(matrix_payload_root, dict):
        return []
    rows = matrix_payload_root.get("rows", [])
    if not isinstance(rows, list):
        return []
    normalized: list[dict[str, object]] = []
    for raw_row in rows:
        if not isinstance(raw_row, dict):
            continue
        normalized_row = _normalize_delta_row(raw_row)
        if not normalized_row.get("requirement_id"):
            continue
        normalized.append(normalized_row)
    return sorted(normalized, key=lambda row: str(row.get("requirement_id", "")))


def _compare_traceability_rows(
    previous_rows: list[dict[str, object]],
    current_rows: list[dict[str, object]],
) -> tuple[list[str], list[str], list[str]]:
    previous_by_id = {str(item.get("requirement_id", "")).strip(): item for item in previous_rows}
    current_by_id = {str(item.get("requirement_id", "")).strip(): item for item in current_rows}
    previous_ids = sorted(previous_by_id)
    current_ids = sorted(current_by_id)

    added = [rid for rid in current_ids if rid not in previous_by_id]
    removed = [rid for rid in previous_ids if rid not in current_by_id]
    changed: list[str] = []
    for rid in sorted(set(previous_ids) & set(current_ids)):
        if previous_by_id[rid] != current_by_id[rid]:
            changed.append(rid)
    return added, removed, changed


def _summary_from_coverage_matrix(matrix_payload: dict[str, object]) -> dict[str, int]:
    matrix_payload_root = matrix_payload.get("coverage_matrix", {})
    if not isinstance(matrix_payload_root, dict):
        return {}
    summary = matrix_payload_root.get("summary", {})
    if not isinstance(summary, dict) or not summary:
        return {}
    return {
        "total": int(summary.get("total", 0) or 0),
        "covered": int(summary.get("covered", 0) or 0),
        "partial": int(summary.get("partial", 0) or 0),
        "uncovered": int(summary.get("uncovered", 0) or 0),
        "stale": int(summary.get("stale", 0) or 0),
    }


def _format_traceability_delta_report(
    scope: str,
    scope_target: str,
    current_rows: list[dict[str, object]],
    previous_rows: list[dict[str, object]],
    current_summary: dict[str, int],
    previous_summary: dict[str, int],
) -> str:
    added, removed, changed = _compare_traceability_rows(previous_rows, current_rows)
    lines = [
        "Traceability delta report:",
        f"- scope: {scope} ({scope_target})",
    ]

    if not previous_rows and not previous_summary:
        lines.append("- baseline: none (first successful traceability precheck).")
        return "\n".join(lines + ["- added: 0", "- removed: 0", "- changed: 0"])

    lines.append(f"- added: {len(added)}")
    if added:
        lines.append("  - added requirements:")
        for requirement_id in added:
            row = next(
                (item for item in current_rows if item.get("requirement_id") == requirement_id),
                None,
            )
            if row is None:
                continue
            state_value = str(row.get("coverage_state", "")).strip() or "unknown"
            lines.append(f"    - {requirement_id}: {state_value}")

    lines.append(f"- removed: {len(removed)}")
    if removed:
        lines.append("  - removed requirements:")
        for requirement_id in removed:
            row = next(
                (item for item in previous_rows if item.get("requirement_id") == requirement_id),
                None,
            )
            if row is None:
                continue
            state_value = str(row.get("coverage_state", "")).strip() or "unknown"
            lines.append(f"    - {requirement_id}: {state_value}")

    lines.append(f"- changed: {len(changed)}")
    if changed:
        lines.append("  - changed requirements:")
        for requirement_id in changed:
            current = next(
                (item for item in current_rows if item.get("requirement_id") == requirement_id),
                None,
            )
            previous = next(
                (item for item in previous_rows if item.get("requirement_id") == requirement_id),
                None,
            )
            if current is None or previous is None:
                continue
            current_state = str(current.get("coverage_state", "")).strip() or "unknown"
            previous_state = str(previous.get("coverage_state", "")).strip() or "unknown"
            if current_state == previous_state:
                lines.append(f"    - {requirement_id}: metadata changed")
            else:
                lines.append(f"    - {requirement_id}: {previous_state} -> {current_state}")

    stale_delta = int(current_summary.get("stale", 0)) - int(previous_summary.get("stale", 0))
    uncovered_delta = int(current_summary.get("uncovered", 0)) - int(
        previous_summary.get("uncovered", 0)
    )
    regressions: list[str] = []
    if stale_delta > 0:
        regressions.append(f"stale increased by {stale_delta}")
    if uncovered_delta > 0:
        regressions.append(f"uncovered increased by {uncovered_delta}")

    if regressions:
        lines.append("- regressions:")
        for regression in regressions:
            lines.append(f"  - {regression}")
    else:
        lines.append("- regressions: none")

    return "\n".join(lines)


def _read_traceability_delta_payload(planning_root: Path) -> dict[str, object]:
    path = planning_root / TRACEABILITY_DELTA_FILE_NAME
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return payload


def _write_traceability_delta_payload(planning_root: Path, payload: dict[str, object]) -> None:
    path = planning_root / TRACEABILITY_DELTA_FILE_NAME
    planning_root.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=2), encoding="utf-8"
    )


def _build_traceability_delta_snapshot(
    scope: str,
    scope_target: str,
    matrix_payload: dict[str, object],
) -> dict[str, object]:
    return {
        "scope": str(scope).strip() or "milestone",
        "scope_target": str(scope_target).strip() or "all-active",
        "schema_version": TRACEABILITY_DELTA_SCHEMA_VERSION,
        "generated_at": _format_iso_utc(datetime.now(timezone.utc)),
        "summary": _summary_from_coverage_matrix(matrix_payload),
        "rows": _snapshot_rows_from_coverage_matrix(matrix_payload),
    }


def slugify(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().lower())
    normalized = normalized.strip("-")
    return normalized[:48] or "quick-task"


def build_measurable_checks(objective: str) -> list[str]:
    subject = objective.strip() or "quick task"
    checks = [
        "Bootstrap validate preflight and creates a deterministic task directory.",
        f"PLAN scaffold includes objective-derived verification for: {subject}.",
        "Bootstrap retries exactly once after minimal auto-fix when init fails.",
    ]
    return checks[:MAX_CHECKS]


def run_preflight(payload: dict[str, object]) -> None:
    if not payload.get("roadmap_exists", False):
        raise PreflightError("Missing .planning/ROADMAP.md. Run project initialization first.")
    if not payload.get("planning_exists", False):
        raise PreflightError("Missing .planning directory. Run project initialization first.")
    task_dir = str(payload.get("task_dir", "")).strip()
    if not task_dir:
        raise PreflightError("init quick did not return task_dir.")


def run_init_quick(objective: str, gsd_tools_path: str) -> dict[str, object]:
    cmd = [
        "node",
        gsd_tools_path,
        "init",
        "quick",
        objective,
        "--raw",
    ]
    completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown error"
        raise BootstrapError(f"init quick failed: {detail}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise BootstrapError("init quick returned non-JSON output.") from exc
    return payload


def apply_minimal_autofix(repo_root: Path) -> list[str]:
    quick_root = repo_root / ".planning" / "quick"
    quick_root.mkdir(parents=True, exist_ok=True)
    return [f"mkdir -p {quick_root}"]


def normalize_task_identity(payload: dict[str, object], objective: str) -> tuple[int, str, Path]:
    task_dir_from_init = Path(str(payload.get("task_dir", "")).strip())
    number_raw = payload.get("next_num")
    if isinstance(number_raw, int):
        number = number_raw
    else:
        prefix = task_dir_from_init.name.split("-", 1)[0]
        number = int(prefix) if prefix.isdigit() else 0
    if number <= 0:
        raise PreflightError("Could not resolve quick task number from init quick payload.")

    raw_slug = str(payload.get("slug", "")).strip()
    slug = slugify(raw_slug or objective)
    parent = (
        task_dir_from_init.parent
        if task_dir_from_init.parent != Path(".")
        else Path(".planning/quick")
    )
    normalized_task_dir = parent / f"{number}-{slug}"
    return number, slug, normalized_task_dir


def _render_template(template: str, context: dict[str, str]) -> str:
    rendered = template
    for key, value in context.items():
        rendered = rendered.replace("{" + key + "}", value)
    return rendered


def create_quick_task(
    payload: dict[str, object],
    objective: str,
    checks: list[str],
    template_dir: Path = DEFAULT_TEMPLATE_DIR,
) -> dict[str, Path]:
    number, slug, task_dir = normalize_task_identity(payload, objective)
    task_dir.mkdir(parents=True, exist_ok=True)

    plan_template = (template_dir / "PLAN.template.md").read_text(encoding="utf-8")
    summary_template = (template_dir / "SUMMARY.template.md").read_text(encoding="utf-8")
    checks_block = "\n".join(f"- {check}" for check in checks)

    context = {
        "number": str(number),
        "slug": slug,
        "objective": objective.strip(),
        "checks": checks_block,
        "status": "scaffolded",
        "blocker": "None",
        "attempted_commands": "- pending",
        "continuation_command": f'python scripts/quick_bootstrap.py "{objective.strip()}"',
    }

    plan_path = task_dir / f"{number}-PLAN.md"
    summary_path = task_dir / f"{number}-SUMMARY.md"
    plan_path.write_text(_render_template(plan_template, context), encoding="utf-8")
    summary_path.write_text(_render_template(summary_template, context), encoding="utf-8")
    return {"task_dir": task_dir, "plan_path": plan_path, "summary_path": summary_path}


def _today_iso() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def update_global_state(state_path: Path, number: int, description: str, status: str) -> None:
    date = _today_iso()
    row = f"| {number} | {date} | {description} | {status} |"
    if state_path.exists():
        text = state_path.read_text(encoding="utf-8")
    else:
        text = (
            "# Project State\n\n## Quick Tasks Completed\n\n| # | Date | Description | Status |\n"
            "|---|------|-------------|--------|\n"
        )

    if row in text:
        updated = text
    else:
        lines = text.splitlines()
        inserted = False
        for idx, line in enumerate(lines):
            if line.strip() == "|---|------|-------------|--------|":
                lines.insert(idx + 1, row)
                inserted = True
                break
        if not inserted:
            lines.extend(
                [
                    "",
                    "## Quick Tasks Completed",
                    "",
                    "| # | Date | Description | Status |",
                    "|---|------|-------------|--------|",
                    row,
                ]
            )
        updated = "\n".join(lines)

    last_activity = f"Last activity: {date} — quick task {number} {status}"
    if re.search(r"^Last activity:.*$", updated, flags=re.MULTILINE):
        updated = re.sub(r"^Last activity:.*$", last_activity, updated, flags=re.MULTILINE)
    else:
        updated = updated.rstrip() + f"\n\n{last_activity}\n"
    state_path.write_text(updated if updated.endswith("\n") else f"{updated}\n", encoding="utf-8")


def close_quick_task(
    task_dir: Path,
    status: str,
    description: str,
    blocker: str = "None",
    attempted_commands: list[str] | None = None,
    continuation_command: str = 'python scripts/quick_bootstrap.py "<objective>"',
    state_path: Path = DEFAULT_STATE_PATH,
) -> Path:
    number_prefix = task_dir.name.split("-", 1)[0]
    if not number_prefix.isdigit():
        raise BootstrapError(f"Invalid task directory name: {task_dir.name}")
    number = int(number_prefix)
    summary_path = task_dir / f"{number}-SUMMARY.md"
    if not summary_path.exists():
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(
            f"# Quick Task {number} Summary\n\n## Verification\n- pending\n", encoding="utf-8"
        )

    attempts = attempted_commands or ["- pending"]
    block = [
        "",
        "## Closure Evidence",
        f"- status: {status}",
        f"- blocker: {blocker}",
        "- attempted commands:",
    ]
    block.extend(f"  - {cmd}" for cmd in attempts)
    block.append(f"- continuation command: {continuation_command}")
    with summary_path.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(block) + "\n")

    update_global_state(state_path, number=number, description=description, status=status)
    return summary_path


def record_milestone_gate_activity(
    state_path: Path,
    milestone_version: str,
    gate_command: str,
    passed: bool,
) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    status = "passed" if passed else "blocked"
    line = f"Last activity: {_today_iso()} - milestone {gate_command} {milestone_version} gate {status}"
    if state_path.exists():
        text = state_path.read_text(encoding="utf-8")
    else:
        text = "# Project State\n"
    if re.search(r"^Last activity:.*$", text, flags=re.MULTILINE):
        text = re.sub(r"^Last activity:.*$", line, text, flags=re.MULTILINE)
    else:
        text = text.rstrip() + f"\n\n{line}\n"

    row = f"| {_today_iso()} | {gate_command} | {milestone_version} | {status} |"
    if "## Milestone Gate Activity" not in text:
        text = text.rstrip() + (
            "\n\n## Milestone Gate Activity\n\n"
            "| Date | Command | Milestone | Result |\n"
            "|------|---------|-----------|--------|\n"
            f"{row}\n"
        )
    elif row not in text:
        lines = text.splitlines()
        inserted = False
        for idx, current in enumerate(lines):
            if current.strip() == "|------|---------|-----------|--------|":
                lines.insert(idx + 1, row)
                inserted = True
                break
        if not inserted:
            lines.extend(
                [
                    "",
                    "## Milestone Gate Activity",
                    "",
                    "| Date | Command | Milestone | Result |",
                    "|------|---------|-----------|--------|",
                    row,
                ]
            )
        text = "\n".join(lines)
    state_path.write_text(text if text.endswith("\n") else f"{text}\n", encoding="utf-8")


def record_requirements_gate_activity(
    state_path: Path,
    gate_command: str,
    passed: bool,
    *,
    scope: str = "all",
) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    status = "passed" if passed else "blocked"
    line = f"Last activity: {_today_iso()} - requirements {gate_command} gate {status}"
    if state_path.exists():
        text = state_path.read_text(encoding="utf-8")
    else:
        text = "# Project State\n"

    if re.search(r"^Last activity:.*$", text, flags=re.MULTILINE):
        text = re.sub(r"^Last activity:.*$", line, text, flags=re.MULTILINE)
    else:
        text = text.rstrip() + f"\n\n{line}\n"

    row = f"| {_today_iso()} | {gate_command} | {scope} | {status} |"
    if "## Requirements Gate Activity" not in text:
        text = text.rstrip() + (
            "\n\n## Requirements Gate Activity\n\n"
            "| Date | Command | Scope | Result |\n"
            "|------|---------|-------|--------|\n"
            f"{row}\n"
        )
    elif row not in text:
        lines = text.splitlines()
        inserted = False
        for idx, current in enumerate(lines):
            if current.strip() == "|------|---------|-------|--------|":
                lines.insert(idx + 1, row)
                inserted = True
                break
        if not inserted:
            lines.extend(
                [
                    "",
                    "## Requirements Gate Activity",
                    "",
                    "| Date | Command | Scope | Result |",
                    "|------|---------|-------|--------|",
                    row,
                ]
            )
        text = "\n".join(lines)
    state_path.write_text(text if text.endswith("\n") else f"{text}\n", encoding="utf-8")


def _format_touched_requirement_ids(touched_requirement_ids: set[str] | list[str] | None) -> str:
    touched = sorted(item.strip() for item in (touched_requirement_ids or []) if str(item).strip())
    return ", ".join(touched) if touched else "-"


def record_traceability_gate_activity(
    state_path: Path,
    gate_command: str,
    passed: bool,
    *,
    scope: str = "all",
    touched_requirement_ids: set[str] | list[str] | None = None,
    top_rank_key: str | None = None,
) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    status = "passed" if passed else "blocked"
    touched_ids = _format_touched_requirement_ids(touched_requirement_ids)
    line = f"Last activity: {_today_iso()} - traceability {gate_command} gate {status}"
    if state_path.exists():
        text = state_path.read_text(encoding="utf-8")
    else:
        text = "# Project State\n"

    if re.search(r"^Last activity:.*$", text, flags=re.MULTILINE):
        text = re.sub(r"^Last activity:.*$", line, text, flags=re.MULTILINE)
    else:
        text = text.rstrip() + f"\n\n{line}\n"

    row = f"| {_today_iso()} | {gate_command} | {scope} | {touched_ids} | {status} |"
    if "## Traceability Gate Activity" not in text:
        text = text.rstrip() + (
            "\n\n## Traceability Gate Activity\n\n"
            "| Date | Command | Scope | Touched Requirement IDs | Result |\n"
            "|------|---------|-------|--------------------------|--------|\n"
            f"{row}\n"
        )
    elif row not in text:
        lines = text.splitlines()
        inserted = False
        for idx, current in enumerate(lines):
            if current.strip() == "|------|---------|-------|--------------------------|--------|":
                lines.insert(idx + 1, row)
                inserted = True
                break
        if not inserted:
            lines.extend(
                [
                    "",
                    "## Traceability Gate Activity",
                    "",
                    "| Date | Command | Scope | Touched Requirement IDs | Result |",
                    "|------|---------|-------|--------------------------|--------|",
                    row,
                ]
            )
        text = "\n".join(lines)
    state_path.write_text(text if text.endswith("\n") else f"{text}\n", encoding="utf-8")
    if top_rank_key is not None:
        _write_traceability_top_rank_key(state_path, top_rank_key)


def record_governance_exception_activity(
    state_path: Path,
    command: str,
    *,
    scope: str,
    owner: str,
    task: str,
    rationale: str,
    until: str,
    result: str = "active",
) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    line = f"Last activity: {_today_iso()} - governance exception {result}: {command}"
    if state_path.exists():
        text = state_path.read_text(encoding="utf-8")
    else:
        text = "# Project State\n"

    if re.search(r"^Last activity:.*$", text, flags=re.MULTILINE):
        text = re.sub(r"^Last activity:.*$", line, text, flags=re.MULTILINE)
    else:
        text = text.rstrip() + f"\n\n{line}\n"

    row = f"| {_today_iso()} | {command} | {scope} | {owner} | {task} | {until} | {result} | {rationale} |"
    if "## Governance Exception Activity" not in text:
        text = text.rstrip() + (
            "\n\n## Governance Exception Activity\n\n"
            "| Date | Command | Scope | Owner | Task | Until | Result | Rationale |\n"
            "|------|---------|-------|-------|------|-------|--------|-----------|\n"
            f"{row}\n"
        )
    elif row not in text:
        lines = text.splitlines()
        inserted = False
        for idx, current in enumerate(lines):
            if (
                current.strip()
                == "|------|---------|-------|-------|------|-------|--------|-----------|"
            ):
                lines.insert(idx + 1, row)
                inserted = True
                break
        if not inserted:
            lines.extend(
                [
                    "",
                    "## Governance Exception Activity",
                    "",
                    "| Date | Command | Scope | Owner | Task | Until | Result | Rationale |",
                    "|------|---------|-------|-------|------|-------|--------|-----------|",
                    row,
                ]
            )
        text = "\n".join(lines)
    state_path.write_text(text if text.endswith("\n") else f"{text}\n", encoding="utf-8")


def run_transition_delegate(subcommand: str, delegate_args: list[str]):
    command_parts = subcommand.split()
    if len(command_parts) != 2:
        raise BootstrapError(f"Invalid transition subcommand: {subcommand}")
    cmd = ["node", DEFAULT_GSD_TOOLS_PATH, command_parts[0], command_parts[1], *delegate_args]
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def execute_bootstrap(
    objective: str,
    gsd_tools_path: str = DEFAULT_GSD_TOOLS_PATH,
    runner: Callable[[str, str], dict[str, object]] = run_init_quick,
    autofix: Callable[[Path], list[str]] = apply_minimal_autofix,
    repo_root: Path | None = None,
    template_dir: Path = DEFAULT_TEMPLATE_DIR,
) -> BootstrapResult:
    clean_objective = objective.strip()
    if not clean_objective:
        raise BootstrapError("Objective is required.")

    repo = (repo_root or Path.cwd()).resolve()
    attempts = 0
    last_error: Exception | None = None
    while attempts < 2:
        try:
            payload = runner(clean_objective, gsd_tools_path)
            run_preflight(payload)
            number, slug, task_dir = normalize_task_identity(payload, clean_objective)
            checks = build_measurable_checks(clean_objective)
            if not (MIN_CHECKS <= len(checks) <= MAX_CHECKS):
                raise BootstrapError("Quick intake must include 2-3 measurable checks.")
            artifacts = create_quick_task(
                payload, clean_objective, checks, template_dir=template_dir
            )
            return BootstrapResult(
                number=number,
                slug=slug,
                task_dir=task_dir,
                checks=checks,
                retries=attempts,
                plan_path=artifacts["plan_path"],
                summary_path=artifacts["summary_path"],
            )
        except BootstrapError as exc:
            last_error = exc
            if attempts >= 1:
                break
            autofix(repo)
            attempts += 1
            continue
    raise_error = BootstrapError(
        f"Bootstrap failed after auto-fix retry. Guidance: {last_error}. "
        "Fix prerequisites and retry the command."
    )
    raise raise_error


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bootstrap quick planning task with preflight and retry."
    )
    subparsers = parser.add_subparsers(dest="command")

    bootstrap_parser = subparsers.add_parser("bootstrap")
    bootstrap_parser.add_argument("objective", help="Quick task objective.")
    bootstrap_parser.add_argument(
        "--gsd-tools-path",
        default=DEFAULT_GSD_TOOLS_PATH,
        help="Path to gsd-tools.cjs.",
    )
    bootstrap_parser.add_argument("--state-path", default=str(DEFAULT_STATE_PATH))

    close_parser = subparsers.add_parser("close")
    close_parser.add_argument("--task-dir", required=True, help="Quick task directory path.")
    close_parser.add_argument(
        "--status", required=True, choices=["completed", "failed", "scaffolded"]
    )
    close_parser.add_argument("--description", required=True)
    close_parser.add_argument("--blocker", default="None")
    close_parser.add_argument("--attempted-command", action="append", default=[])
    close_parser.add_argument(
        "--continuation-command",
        default='python scripts/quick_bootstrap.py bootstrap "<objective>"',
    )
    close_parser.add_argument("--state-path", default=str(DEFAULT_STATE_PATH))

    milestone_parser = subparsers.add_parser("milestone")
    milestone_subparsers = milestone_parser.add_subparsers(dest="milestone_command")

    precheck_parser = milestone_subparsers.add_parser("precheck")
    precheck_parser.add_argument("version", help="Milestone version, e.g., v1.1.")
    precheck_parser.add_argument("--planning-root", default=".planning")
    precheck_parser.add_argument("--state-path", default=str(DEFAULT_STATE_PATH))

    complete_parser = milestone_subparsers.add_parser("complete")
    complete_parser.add_argument("version", help="Milestone version, e.g., v1.1.")
    complete_parser.add_argument("--planning-root", default=".planning")
    complete_parser.add_argument("--state-path", default=str(DEFAULT_STATE_PATH))
    complete_parser.add_argument(
        "--governance-exception-owner", help="Exception owner (required with all exception fields)."
    )
    complete_parser.add_argument("--governance-exception-task", help="Exception task ID.")
    complete_parser.add_argument("--governance-exception-rationale", help="Exception rationale.")
    complete_parser.add_argument(
        "--governance-exception-until", help="Exception expiry in ISO-8601 UTC."
    )

    roadmap_parser = subparsers.add_parser("roadmap")
    roadmap_subparsers = roadmap_parser.add_subparsers(dest="roadmap_command")
    roadmap_create = roadmap_subparsers.add_parser("create")
    roadmap_create.add_argument("--planning-root", default=".planning")
    roadmap_create.add_argument("--state-path", default=str(DEFAULT_STATE_PATH))
    roadmap_create.add_argument("delegate_args", nargs=argparse.REMAINDER)
    roadmap_revise = roadmap_subparsers.add_parser("revise")
    roadmap_revise.add_argument("--planning-root", default=".planning")
    roadmap_revise.add_argument("--state-path", default=str(DEFAULT_STATE_PATH))
    roadmap_revise.add_argument("delegate_args", nargs=argparse.REMAINDER)

    phase_parser = subparsers.add_parser("phase")
    phase_subparsers = phase_parser.add_subparsers(dest="phase_command")
    phase_complete = phase_subparsers.add_parser("complete")
    phase_complete.add_argument("--planning-root", default=".planning")
    phase_complete.add_argument("--state-path", default=str(DEFAULT_STATE_PATH))
    phase_complete.add_argument(
        "--requirement-id",
        action="append",
        default=[],
        help="Touched requirement ID; repeat flag for multiple IDs.",
    )
    phase_complete.add_argument(
        "--governance-exception-owner", help="Exception owner (required with all exception fields)."
    )
    phase_complete.add_argument("--governance-exception-task", help="Exception task ID.")
    phase_complete.add_argument("--governance-exception-rationale", help="Exception rationale.")
    phase_complete.add_argument(
        "--governance-exception-until", help="Exception expiry in ISO-8601 UTC."
    )
    phase_complete.add_argument("delegate_args", nargs=argparse.REMAINDER)

    requirements_parser = subparsers.add_parser("requirements")
    requirements_subparsers = requirements_parser.add_subparsers(dest="requirements_command")

    requirements_precheck = requirements_subparsers.add_parser("precheck")
    requirements_precheck.add_argument("--planning-root", default=".planning")
    requirements_precheck.add_argument("--state-path", default=str(DEFAULT_STATE_PATH))

    traceability_parser = subparsers.add_parser("traceability")
    traceability_subparsers = traceability_parser.add_subparsers(dest="traceability_command")

    traceability_precheck = traceability_subparsers.add_parser("precheck")
    traceability_precheck.add_argument("--planning-root", default=".planning")
    traceability_precheck.add_argument("--state-path", default=str(DEFAULT_STATE_PATH))
    traceability_precheck.add_argument(
        "--scope",
        choices=("phase", "milestone"),
        default="milestone",
    )
    traceability_precheck.add_argument(
        "--phase-id",
        help="Required when --scope phase. Accepts canonical numeric IDs like 5 or 05.",
    )
    traceability_precheck.add_argument(
        "--matrix-detail",
        choices=("compact", "expanded"),
        default="compact",
        help="Human-readable matrix detail mode.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    command = args.command
    if command is None:
        raise BootstrapError("Missing command. Use `bootstrap`, `close`, or `milestone`.")
    if command == "close":
        summary_path = close_quick_task(
            task_dir=Path(args.task_dir),
            status=args.status,
            description=args.description,
            blocker=args.blocker,
            attempted_commands=args.attempted_command,
            continuation_command=args.continuation_command,
            state_path=Path(args.state_path),
        )
        print(
            json.dumps(
                {"summary_path": str(summary_path), "status": args.status}, ensure_ascii=True
            )
        )
        return 0
    if command == "milestone":
        milestone_command = getattr(args, "milestone_command", None)
        if milestone_command not in {"precheck", "complete"}:
            raise BootstrapError("Missing milestone subcommand. Use `precheck` or `complete`.")
        planning_root = Path(args.planning_root)
        state_path = Path(args.state_path)
        milestone_version = args.version
        governance_exception = _parse_governance_exception_payload(args)

        if milestone_command == "precheck":
            result = evaluate_milestone_governance_gate(planning_root, milestone_version)
            passed = bool(result.get("passed", False))
            precheck_retry = (
                f"python scripts/quick_bootstrap.py milestone precheck {milestone_version}"
            )
            record_milestone_gate_activity(state_path, milestone_version, "precheck", passed)
            output = {
                "command": "milestone precheck",
                "version": milestone_version,
                "passed": passed,
                "failure_groups": result.get("failure_groups", {}),
                "retry_command": precheck_retry,
                "checklist": format_gate_failures(result, precheck_retry),
            }
            print(json.dumps(output, ensure_ascii=True))
            return 0

        if governance_exception is not None:
            record_governance_exception_activity(
                state_path,
                f"milestone complete {milestone_version}",
                scope="milestone",
                owner=governance_exception["owner"],
                task=governance_exception["task"],
                rationale=governance_exception["rationale"],
                until=governance_exception["until"],
            )
            print(
                json.dumps(
                    {
                        "command": "milestone complete",
                        "version": milestone_version,
                        "passed": True,
                        "governance_exception": governance_exception,
                    },
                    ensure_ascii=True,
                )
            )
            return 0

        requirements_result = evaluate_requirements_contract_gate(planning_root)
        if not bool(requirements_result.get("passed", False)):
            retry_command = (
                f"python scripts/quick_bootstrap.py milestone complete {milestone_version}"
            )
            record_requirements_gate_activity(
                state_path,
                "complete",
                False,
                scope="all",
            )
            print(format_requirements_contract_failures(requirements_result, retry_command))
            return 1

        record_requirements_gate_activity(
            state_path,
            "complete",
            True,
            scope="all",
        )

        traceability_result = evaluate_traceability_drift_gate(
            planning_root,
            scope="all",
        )
        traceability_retry = (
            f"python scripts/quick_bootstrap.py milestone complete {milestone_version}"
        )
        traceability_touched_ids = sorted(
            item.strip()
            for item in traceability_result.get("touched_requirement_ids", [])
            if str(item).strip()
        )
        if not bool(traceability_result.get("passed", False)):
            record_traceability_gate_activity(
                state_path,
                "complete",
                False,
                scope="all",
                touched_requirement_ids=traceability_touched_ids,
            )
            print(format_traceability_drift_failures(traceability_result, traceability_retry))
            return 1

        record_traceability_gate_activity(
            state_path,
            "complete",
            True,
            scope="all",
            touched_requirement_ids=traceability_touched_ids,
        )

        result = evaluate_milestone_governance_gate(planning_root, milestone_version)
        if not bool(result.get("passed", False)):
            retry_command = (
                f"python scripts/quick_bootstrap.py milestone complete {milestone_version}"
            )
            record_milestone_gate_activity(state_path, milestone_version, "complete", False)
            print(format_gate_failures(result, retry_command))
            return 1

        record_milestone_gate_activity(state_path, milestone_version, "complete", True)
        print(
            json.dumps(
                {
                    "command": "milestone complete",
                    "version": milestone_version,
                    "passed": True,
                },
                ensure_ascii=True,
            )
        )
        return 0
    if command == "roadmap":
        roadmap_command = getattr(args, "roadmap_command", None)
        if roadmap_command not in {"create", "revise"}:
            raise BootstrapError("Missing roadmap subcommand. Use `create` or `revise`.")
        planning_root = Path(args.planning_root)
        state_path = Path(args.state_path)
        requirements_result = evaluate_requirements_contract_gate(planning_root)
        retry_command = f"python scripts/quick_bootstrap.py roadmap {roadmap_command}"
        if not bool(requirements_result.get("passed", False)):
            record_requirements_gate_activity(
                state_path,
                roadmap_command,
                False,
                scope="all",
            )
            print(format_requirements_contract_failures(requirements_result, retry_command))
            return 1

        record_requirements_gate_activity(
            state_path,
            roadmap_command,
            True,
            scope="all",
        )
        delegate = run_transition_delegate(
            f"roadmap {roadmap_command}",
            list(getattr(args, "delegate_args", []) or []),
        )
        if delegate.returncode != 0:
            detail = (
                (delegate.stderr or "").strip()
                or (delegate.stdout or "").strip()
                or "roadmap transition failed"
            )
            print(detail)
            return int(delegate.returncode) if int(delegate.returncode) > 0 else 1
        output = {
            "command": f"roadmap {roadmap_command}",
            "passed": True,
        }
        print(json.dumps(output, ensure_ascii=True))
        return 0
    if command == "phase":
        phase_command = getattr(args, "phase_command", None)
        if phase_command != "complete":
            raise BootstrapError("Missing phase subcommand. Use `complete`.")
        planning_root = Path(args.planning_root)
        state_path = Path(args.state_path)
        governance_exception = _parse_governance_exception_payload(args)
        touched_ids = {
            requirement_id.strip()
            for requirement_id in list(getattr(args, "requirement_id", []) or [])
            if str(requirement_id).strip()
        }

        if governance_exception is not None:
            record_governance_exception_activity(
                state_path,
                "phase complete",
                scope="phase",
                owner=governance_exception["owner"],
                task=governance_exception["task"],
                rationale=governance_exception["rationale"],
                until=governance_exception["until"],
            )
            delegate = run_transition_delegate(
                "phase complete",
                list(getattr(args, "delegate_args", []) or []),
            )
            if delegate.returncode != 0:
                detail = (
                    (delegate.stderr or "").strip()
                    or (delegate.stdout or "").strip()
                    or "phase transition failed"
                )
                print(detail)
                return int(delegate.returncode) if int(delegate.returncode) > 0 else 1

            output = {
                "command": "phase complete",
                "passed": True,
                "governance_exception": governance_exception,
                "touched_requirement_ids": sorted(touched_ids),
            }
            print(json.dumps(output, ensure_ascii=True))
            return 0

        requirements_result = evaluate_requirements_contract_gate(
            planning_root,
            scope="touched",
            touched_requirement_ids=touched_ids,
        )
        retry_command_parts = ["python scripts/quick_bootstrap.py phase complete"]
        retry_command_parts.extend(
            f"--requirement-id {requirement_id}" for requirement_id in sorted(touched_ids)
        )
        retry_command = " ".join(retry_command_parts)

        if not bool(requirements_result.get("passed", False)):
            record_requirements_gate_activity(
                state_path,
                "phase complete",
                False,
                scope="touched",
            )
            print(format_requirements_contract_failures(requirements_result, retry_command))
            return 1

        record_requirements_gate_activity(
            state_path,
            "phase complete",
            True,
            scope="touched",
        )
        traceability_result = evaluate_traceability_drift_gate(
            planning_root,
            scope="touched",
            touched_requirement_ids=touched_ids,
        )
        if not bool(traceability_result.get("passed", False)):
            record_traceability_gate_activity(
                state_path,
                "phase complete",
                False,
                scope="touched",
                touched_requirement_ids=touched_ids,
            )
            print(format_traceability_drift_failures(traceability_result, retry_command))
            return 1

        record_traceability_gate_activity(
            state_path,
            "phase complete",
            True,
            scope="touched",
            touched_requirement_ids=touched_ids,
        )
        delegate = run_transition_delegate(
            "phase complete",
            list(getattr(args, "delegate_args", []) or []),
        )
        if delegate.returncode != 0:
            detail = (
                (delegate.stderr or "").strip()
                or (delegate.stdout or "").strip()
                or "phase transition failed"
            )
            print(detail)
            return int(delegate.returncode) if int(delegate.returncode) > 0 else 1
        output = {
            "command": "phase complete",
            "passed": True,
            "touched_requirement_ids": sorted(touched_ids),
        }
        print(json.dumps(output, ensure_ascii=True))
        return 0
    if command == "requirements":
        requirements_command = getattr(args, "requirements_command", None)
        if requirements_command != "precheck":
            raise BootstrapError("Missing requirements subcommand. Use `precheck`.")
        planning_root = Path(args.planning_root)
        state_path = Path(args.state_path)
        result = evaluate_requirements_contract_gate(planning_root)
        passed = bool(result.get("passed", False))
        retry_command = "python scripts/quick_bootstrap.py requirements precheck"
        checklist = format_requirements_contract_failures(result, retry_command)
        record_requirements_gate_activity(
            state_path,
            "precheck",
            passed,
            scope="all",
        )
        output = {
            "command": "requirements precheck",
            "passed": passed,
            "failure_groups": result.get("failure_groups", {}),
            "retry_command": retry_command,
            "checklist": checklist,
        }
        print(json.dumps(output, ensure_ascii=True))
        return 0
    if command == "traceability":
        traceability_command = getattr(args, "traceability_command", None)
        if traceability_command != "precheck":
            raise BootstrapError("Missing traceability subcommand. Use `precheck`.")
        planning_root = Path(args.planning_root)
        state_path = Path(args.state_path)
        traceability_scope = getattr(args, "scope", "milestone")
        traceability_phase_id = getattr(args, "phase_id", None)
        matrix_detail = getattr(args, "matrix_detail", "compact")
        if traceability_scope == "phase" and not str(traceability_phase_id or "").strip():
            raise BootstrapError("--phase-id is required when --scope phase.")
        result = evaluate_traceability_drift_gate(planning_root, scope="all")
        try:
            matrix_payload = build_requirement_coverage_matrix(
                planning_root,
                scope=traceability_scope,
                phase_id=traceability_phase_id,
            )
        except (FileNotFoundError, ValueError):
            scope_target = (
                str(traceability_phase_id).strip()
                if traceability_scope == "phase"
                else "all-active"
            )
            matrix_payload = {
                "schema_version": "coverage_matrix.v1",
                "coverage_matrix": {
                    "scope": traceability_scope,
                    "scope_target": scope_target,
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
        passed = bool(result.get("passed", False))
        retry_command = _build_traceability_retry_command(traceability_scope, traceability_phase_id)
        previous_top_rank_key = _read_traceability_top_rank_key(state_path)
        matrix_payload_coverage = matrix_payload.get("coverage_matrix", {})
        current_scope_target = str(matrix_payload_coverage.get("scope_target", "")).strip() or (
            _normalize_phase_snapshot_target(traceability_phase_id)
            if traceability_scope == "phase"
            else "all-active"
        )
        scope_key = _normalize_traceability_delta_key(traceability_scope, current_scope_target)
        current_rows = _snapshot_rows_from_coverage_matrix(matrix_payload)
        try:
            delta_baseline_payload = _read_traceability_delta_payload(planning_root)
        except Exception:
            delta_baseline_payload = {}
        scope_payload = (
            delta_baseline_payload.get("snapshots", {})
            if isinstance(delta_baseline_payload.get("snapshots", {}), dict)
            else {}
        )
        previous_scope_payload = (
            scope_payload.get(scope_key, {}) if isinstance(scope_payload, dict) else {}
        )
        if not isinstance(previous_scope_payload, dict):
            previous_scope_payload = {}
        previous_rows = [
            item
            for item in list(previous_scope_payload.get("rows", []) or [])
            if isinstance(item, dict) and str(item.get("requirement_id", "")).strip()
        ]
        previous_summary = _summary_from_coverage_matrix(
            {
                "coverage_matrix": {
                    "summary": previous_scope_payload.get("summary", {}),
                }
            }
        )
        current_summary = _summary_from_coverage_matrix(matrix_payload)
        delta_report = _format_traceability_delta_report(
            traceability_scope,
            current_scope_target,
            current_rows,
            previous_rows,
            current_summary,
            previous_summary,
        )
        try:
            current_snapshots = dict(scope_payload or {})
            current_snapshots[scope_key] = _build_traceability_delta_snapshot(
                traceability_scope,
                current_scope_target,
                matrix_payload,
            )
            payload_to_store = {
                "schema_version": TRACEABILITY_DELTA_SCHEMA_VERSION,
                "generated_at": _format_iso_utc(datetime.now(timezone.utc)),
                "snapshots": current_snapshots,
            }
            _write_traceability_delta_payload(planning_root, payload_to_store)
        except Exception:
            if delta_report:
                delta_report = (
                    delta_report
                    + "\n- baseline persistence unavailable: not persisted for this run."
                )
        ranked_hints = build_impact_ranked_remediation_hints(
            result,
            matrix_payload,
            retry_command=retry_command,
        )
        current_top_rank_key = (
            str(ranked_hints[0].get("check_key", "")).strip() if ranked_hints else None
        )
        top_rank_note = build_top_rank_change_note(previous_top_rank_key, current_top_rank_key)
        ranked_hint_text = format_impact_ranked_remediation_hints(ranked_hints)
        grouped_checklist = format_traceability_drift_failures(result, retry_command)
        coverage_matrix = matrix_payload.get("coverage_matrix", {})
        matrix_text = (
            format_coverage_matrix_expanded(coverage_matrix)
            if matrix_detail == "expanded"
            else format_coverage_matrix_summary(coverage_matrix)
        )
        checklist_parts = [
            part
            for part in (
                ranked_hint_text,
                delta_report,
                top_rank_note,
                grouped_checklist,
                matrix_text,
            )
            if part
        ]
        checklist = "\n\n".join(checklist_parts)
        touched_ids = sorted(
            item.strip() for item in result.get("touched_requirement_ids", []) if str(item).strip()
        )
        record_traceability_gate_activity(
            state_path,
            "precheck",
            passed,
            scope="all",
            touched_requirement_ids=touched_ids,
            top_rank_key=current_top_rank_key,
        )
        output = {
            "command": "traceability precheck",
            "passed": passed,
            "failure_groups": result.get("failure_groups", {}),
            "retry_command": retry_command,
            "scope": "all",
            "touched_requirement_ids": touched_ids,
            "checklist": checklist,
        }
        if "schema_version" in matrix_payload:
            output["schema_version"] = matrix_payload["schema_version"]
        if "coverage_matrix" in matrix_payload:
            output["coverage_matrix"] = matrix_payload["coverage_matrix"]
        print(json.dumps(output, ensure_ascii=True))
        return 0

    objective = args.objective
    if not objective:
        raise BootstrapError("Objective is required.")
    result = execute_bootstrap(
        objective,
        gsd_tools_path=args.gsd_tools_path,
    )
    close_quick_task(
        task_dir=result.task_dir,
        status="scaffolded",
        description=objective,
        attempted_commands=["node ... init quick ... --raw"],
        continuation_command=f'python scripts/quick_bootstrap.py bootstrap "{objective}"',
        state_path=Path(args.state_path),
    )
    print(
        json.dumps(
            {
                "number": result.number,
                "slug": result.slug,
                "task_dir": str(result.task_dir),
                "checks": result.checks,
                "retries": result.retries,
                "plan_path": str(result.plan_path),
                "summary_path": str(result.summary_path),
            },
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
