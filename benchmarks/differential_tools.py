"""Run optional specialist tools and compare their observations with report/v1."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from r2inspect.schemas.report_v1 import ReportV1

TOOL_COMMANDS = {
    "capa": ("capa", "-j"),
    "floss": ("floss", "-j"),
    "yara": ("yara",),
}


def _tool_findings(tool: str, payload: Any) -> set[str]:
    if tool == "capa" and isinstance(payload, dict):
        rules = payload.get("rules")
        return set(rules) if isinstance(rules, dict) else set()
    if tool == "floss" and isinstance(payload, dict):
        return {
            str(value)
            for key in ("strings", "decoded_strings", "stack_strings", "tight_strings")
            for value in payload.get(key, [])
            if isinstance(payload.get(key), list)
        }
    if tool == "yara" and isinstance(payload, str):
        return {line.split(maxsplit=1)[0] for line in payload.splitlines() if line.strip()}
    return set()


def run_specialist(tool: str, sample: Path, *, timeout: int = 120) -> set[str]:
    command = TOOL_COMMANDS.get(tool)
    if command is None:
        raise ValueError(f"unsupported differential tool: {tool}")
    if shutil.which(command[0]) is None:
        raise FileNotFoundError(command[0])
    completed = subprocess.run(
        [*command, str(sample)],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"{tool} failed for {sample}: {completed.stderr.strip()}")
    payload: Any = completed.stdout
    if command[-1] == "-j":
        payload = json.loads(completed.stdout)
    return _tool_findings(tool, payload)


def run_specialist_safe(tool: str, sample: Path, *, timeout: int = 120) -> dict[str, Any]:
    """Run a specialist without hiding timeout or dependency failures."""
    try:
        return {
            "status": "completed",
            "findings": sorted(run_specialist(tool, sample, timeout=timeout)),
        }
    except FileNotFoundError as exc:
        return {"status": "dependency_unavailable", "findings": [], "error": str(exc)}
    except subprocess.TimeoutExpired as exc:
        return {"status": "timed_out", "findings": [], "error": f"timeout after {exc.timeout}s"}
    except Exception as exc:
        return {"status": "failed", "findings": [], "error": str(exc)}


def compare_report(report: ReportV1, specialist_findings: set[str]) -> dict[str, Any]:
    report_findings = {finding.rule_id for finding in report.findings}
    return {
        "r2inspect_findings": sorted(report_findings),
        "specialist_findings": sorted(specialist_findings),
        "agreement": sorted(report_findings & specialist_findings),
        "r2inspect_only": sorted(report_findings - specialist_findings),
        "specialist_only": sorted(specialist_findings - report_findings),
    }


__all__ = ["compare_report", "run_specialist", "run_specialist_safe"]
