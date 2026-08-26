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
    "floss": ("floss", "--only", "static", "-j"),
    "yara": ("yara",),
}

# capa's static backend walks every function and can spend several minutes on
# system DLLs. Keep the differential benchmark bounded and report this policy
# explicitly instead of turning resource exhaustion into a timeout failure.
CAPA_MAX_STATIC_SAMPLE_BYTES = 512 * 1024

_CAPA_STOPWORDS = {
    "a",
    "an",
    "and",
    "as",
    "at",
    "by",
    "for",
    "from",
    "in",
    "of",
    "on",
    "or",
    "the",
    "to",
    "via",
    "with",
}


def _string_leaves(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, bytes):
        return {value.decode("utf-8", errors="replace")}
    if isinstance(value, list):
        return {item for child in value for item in _string_leaves(child)}
    if isinstance(value, dict):
        return {item for child in value.values() for item in _string_leaves(child)}
    return set()


def _floss_string_leaves(value: Any) -> set[str]:
    """Extract string values without treating FLOSS metadata as findings."""
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {item for child in value for item in _floss_string_leaves(child)}
    if isinstance(value, dict):
        result: set[str] = set()
        string_value = value.get("string")
        if isinstance(string_value, str):
            result.add(string_value)
        for key, child in value.items():
            if key != "string" and isinstance(child, (dict, list)):
                result.update(_floss_string_leaves(child))
        return result
    return set()


def _tool_findings(tool: str, payload: Any) -> set[str]:
    if tool == "capa" and isinstance(payload, dict):
        rules = payload.get("rules")
        return set(rules) if isinstance(rules, dict) else set()
    if tool == "floss" and isinstance(payload, dict):
        findings = _floss_string_leaves(payload.get("strings", payload))
        for key in ("static_strings", "decoded_strings", "stack_strings", "tight_strings"):
            findings.update(_floss_string_leaves(payload.get(key, [])))
        return findings
    if tool == "yara" and isinstance(payload, str):
        return {line.split(maxsplit=1)[0] for line in payload.splitlines() if line.strip()}
    return set()


def run_specialist(tool: str, sample: Path, *, timeout: int = 120) -> set[str]:
    command = TOOL_COMMANDS.get(tool)
    if command is None:
        raise ValueError(f"unsupported differential tool: {tool}")
    resolved = shutil.which(command[0])
    if resolved is None:
        raise FileNotFoundError(command[0])
    executable = resolved if os.name == "nt" else command[0]
    kwargs: dict[str, Any] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    process = subprocess.Popen([executable, *command[1:], str(sample)], **kwargs)
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
    if tool == "capa":
        try:
            if sample.stat().st_size > CAPA_MAX_STATIC_SAMPLE_BYTES:
                return {
                    "status": "skipped_by_profile",
                    "findings": [],
                    "error": (
                        "capa static analysis skipped for samples larger than "
                        f"{CAPA_MAX_STATIC_SAMPLE_BYTES} bytes"
                    ),
                }
        except OSError:
            pass
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


def _tokens(value: str) -> set[str]:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(value))
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text)
    tokens = set(re.findall(r"[a-z0-9]+", text.casefold()))
    normalized: set[str] = set()
    for token in tokens - _CAPA_STOPWORDS:
        if token in {"ex", "n", "w"}:
            continue
        if token.endswith("s") and not token.endswith("ss") and len(token) > 4:
            token = token[:-1]
        if len(token) > 1:
            normalized.add(token)
    return normalized


def _string_values(value: Any) -> set[str]:
    return _floss_string_leaves(value)


def _capa_report_values(report: ReportV1) -> set[str]:
    values = {
        str(item.get("name")) for item in report.capabilities if isinstance(item.get("name"), str)
    }
    values.update(finding.rule_id for finding in report.findings)
    values.update(finding.title for finding in report.findings)
    for item in report.extras.get("imports", []):
        if not isinstance(item, dict):
            continue
        for key in ("name", "description", "category"):
            if isinstance(item.get(key), str) and item[key]:
                values.add(item[key])
        tags = item.get("risk_tags")
        if isinstance(tags, list):
            values.update(tag for tag in tags if isinstance(tag, str))
    for item in report.extras.get("indicators", []):
        if isinstance(item, dict) and isinstance(item.get("description"), str):
            values.add(item["description"])
    return values


def _semantic_capa_matches(
    report_values: set[str], specialist_values: set[str]
) -> list[dict[str, Any]]:
    candidates = [(value, _tokens(value)) for value in report_values]
    matches: list[dict[str, Any]] = []
    for specialist in sorted(specialist_values):
        specialist_tokens = _tokens(specialist)
        if len(specialist_tokens) < 2:
            continue
        best: tuple[int, float, str] | None = None
        for report_value, report_tokens in sorted(candidates):
            overlap = len(specialist_tokens & report_tokens)
            required = max(2, (len(specialist_tokens) + 1) // 2)
            ratio = overlap / len(specialist_tokens)
            if overlap < required or ratio < 0.5:
                continue
            candidate = (overlap, ratio, report_value)
            if best is None or candidate[:2] > best[:2]:
                best = candidate
        if best is not None:
            matches.append(
                {
                    "specialist": specialist,
                    "r2inspect": best[2],
                    "match_type": "semantic",
                    "token_overlap": best[0],
                }
            )
    return matches


def compare_report(
    report: ReportV1, specialist_findings: set[str], *, tool: str | None = None
) -> dict[str, Any]:
    tool = tool or "generic"
    if tool == "capa":
        report_findings = _capa_report_values(report)
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
    normalized_specialist = {
        _normalize(item): item for item in specialist_findings if _normalize(item)
    }
    exact_details = [
        {
            "specialist": normalized_specialist[key],
            "r2inspect": normalized_report[key],
            "match_type": "exact",
            "token_overlap": None,
        }
        for key in normalized_report.keys() & normalized_specialist.keys()
    ]
    semantic_details = (
        _semantic_capa_matches(report_findings, specialist_findings) if tool == "capa" else []
    )
    details = exact_details + semantic_details
    matched_report = {item["r2inspect"] for item in details}
    matched_specialist = {item["specialist"] for item in details}
    return {
        "r2inspect_findings": sorted(report_findings),
        "specialist_findings": sorted(specialist_findings),
        "agreement": sorted(matched_report),
        "agreement_details": sorted(
            details, key=lambda item: (item["specialist"], item["r2inspect"])
        ),
        "r2inspect_only": sorted(value for value in report_findings if value not in matched_report),
        "specialist_only": sorted(
            value for value in specialist_findings if value not in matched_specialist
        ),
        "comparison_basis": tool,
    }


__all__ = ["compare_report", "run_specialist", "run_specialist_safe"]
