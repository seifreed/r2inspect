from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


DEFAULT_GSD_TOOLS_PATH = str(Path.home() / ".codex/get-shit-done/bin/gsd-tools.cjs")
DEFAULT_TEMPLATE_DIR = Path(__file__).resolve().parent / "quick_templates"
DEFAULT_STATE_PATH = Path(".planning/STATE.md")
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
    parent = task_dir_from_init.parent if task_dir_from_init.parent != Path(".") else Path(".planning/quick")
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
        "continuation_command": f"python scripts/quick_bootstrap.py \"{objective.strip()}\"",
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
    continuation_command: str = "python scripts/quick_bootstrap.py \"<objective>\"",
    state_path: Path = DEFAULT_STATE_PATH,
) -> Path:
    number_prefix = task_dir.name.split("-", 1)[0]
    if not number_prefix.isdigit():
        raise BootstrapError(f"Invalid task directory name: {task_dir.name}")
    number = int(number_prefix)
    summary_path = task_dir / f"{number}-SUMMARY.md"
    if not summary_path.exists():
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(f"# Quick Task {number} Summary\n\n## Verification\n- pending\n", encoding="utf-8")

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
            artifacts = create_quick_task(payload, clean_objective, checks, template_dir=template_dir)
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
    parser = argparse.ArgumentParser(description="Bootstrap quick planning task with preflight and retry.")
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
    close_parser.add_argument("--status", required=True, choices=["completed", "failed", "scaffolded"])
    close_parser.add_argument("--description", required=True)
    close_parser.add_argument("--blocker", default="None")
    close_parser.add_argument("--attempted-command", action="append", default=[])
    close_parser.add_argument(
        "--continuation-command",
        default="python scripts/quick_bootstrap.py bootstrap \"<objective>\"",
    )
    close_parser.add_argument("--state-path", default=str(DEFAULT_STATE_PATH))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    command = args.command
    if command is None:
        raise BootstrapError("Missing command. Use `bootstrap` or `close`.")
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
        print(json.dumps({"summary_path": str(summary_path), "status": args.status}, ensure_ascii=True))
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
        continuation_command=f"python scripts/quick_bootstrap.py bootstrap \"{objective}\"",
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
