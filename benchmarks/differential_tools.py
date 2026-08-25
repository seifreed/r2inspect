"""Run optional specialist tools and compare their observations with report/v1."""

from __future__ import annotations

import json
import os
import re
import signal
import shutil
import subprocess
import unicodedata
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
        values: set[str] = set()
        for key in ("strings", "decoded_strings", "stack_strings", "tight_strings"):
            entries = payload.get(key, [])
            if isinstance(entries, dict):
                entries = [
                    value
                    for values_list in entries.values()
                    if isinstance(values_list, list)
                    for value in values_list
                ]
            if isinstance(entries, list):
                values.update(str(value) for value in entries if isinstance(value, (str, bytes)))
        return values
    if tool == "yara" and isinstance(payload, str):
        return {line.split(maxsplit=1)[0] for line in payload.splitlines() if line.strip()}
    return set()


def run_specialist(tool: str, sample: Path, *, timeout: int = 120) -> set[str]:
    command = TOOL_COMMANDS.get(tool)
    if command is None:
        raise ValueError(f"unsupported differential tool: {tool}")
    if shutil.which(command[0]) is None:
        raise FileNotFoundError(command[0])
    kwargs: dict[str, Any] = {"capture_output": True, "text": True}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    process = subprocess.Popen([*command, str(sample)], **kwargs)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise exc
    completed = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
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


def _normalize(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value)).casefold()
    return re.sub(r"[^a-z0-9]+", "_", text).strip("_")


def _string_values(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {item for child in value for item in _string_values(child)}
    if isinstance(value, dict):
        return {item for child in value.values() for item in _string_values(child)}
    return set()


def compare_report(
    report: ReportV1, specialist_findings: set[str], *, tool: str | None = None
) -> dict[str, Any]:
    tool = tool or "generic"
    if tool == "capa":
        report_findings = {
            str(item.get("name"))
            for item in report.capabilities
            if isinstance(item.get("name"), str)
        }
        report_findings.update(finding.rule_id for finding in report.findings)
        report_findings.update(finding.title for finding in report.findings)
    elif tool == "floss":
        report_findings = {
            str(item.get("value"))
            for item in report.artifacts
            if isinstance(item, dict) and isinstance(item.get("value"), str)
        }
        for key in ("strings", "decoded_strings", "stack_strings", "tight_strings"):
            report_findings.update(_string_values(report.extras.get(key)))
        file_info = report.extras.get("file_info")
        if isinstance(file_info, dict):
            report_findings.update(_string_values(file_info.get("strings")))
    else:
        report_findings = {finding.rule_id for finding in report.findings}
    normalized_report = {_normalize(item): item for item in report_findings if _normalize(item)}
    normalized_specialist = {_normalize(item): item for item in specialist_findings if _normalize(item)}
    matched = sorted(
        normalized_report[key]
        for key in normalized_report.keys() & normalized_specialist.keys()
    )
    return {
        "r2inspect_findings": sorted(report_findings),
        "specialist_findings": sorted(specialist_findings),
        "agreement": matched,
        "r2inspect_only": sorted(
            value for key, value in normalized_report.items() if key not in normalized_specialist
        ),
        "specialist_only": sorted(
            value for key, value in normalized_specialist.items() if key not in normalized_report
        ),
        "comparison_basis": tool,
    }


__all__ = ["compare_report", "run_specialist", "run_specialist_safe"]
