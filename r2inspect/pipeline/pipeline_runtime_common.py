"""Shared helpers for pipeline execution internals."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, cast

from .stage_models import ThreadSafeContext


def build_context(options: dict[str, Any] | None, execution_id: int) -> dict[str, Any]:
    return {
        "options": options or {},
        "results": {},
        "execution_id": execution_id,
        "metadata": {},
    }


def build_threadsafe_context(
    options: dict[str, Any] | None, execution_id: int
) -> ThreadSafeContext:
    return ThreadSafeContext(build_context(options, execution_id))


def merge_stage_results(ts_context: ThreadSafeContext, stage_result: dict[str, Any]) -> None:
    ts_context.merge_results(stage_result)


def stage_success(result: dict[str, Any], stage_name: str) -> bool:
    entry = result.get(stage_name)
    return not (isinstance(entry, dict) and entry.get("success") is False)


def error_result(stage_name: str, message: str) -> dict[str, Any]:
    return {stage_name: {"error": message, "success": False}}


def merge_into_plain_context(context: dict[str, Any], stage_result: dict[str, Any]) -> None:
    if not stage_result:
        return
    context_results = cast(dict[str, Any], context.get("results", {}))
    context_results.update(stage_result)
    context["results"] = context_results


def detect_via_header_bytes(filename: str) -> str | None:
    try:
        header = Path(filename).read_bytes()[:8]
    except Exception:
        return None

    if header.startswith(b"MZ"):
        return "PE"
    if header.startswith(b"\x7fELF"):
        return "ELF"
    if header[:4] in {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
    }:
        return "Mach-O"
    return None


def default_hash_calculator(filename: str) -> dict[str, str]:
    data = Path(filename).read_bytes()
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def default_file_type_detector(filename: str) -> dict[str, Any]:
    header_type = detect_via_header_bytes(filename)
    suffix = Path(filename).suffix.lower()
    if header_type == "PE":
        file_format = "PE"
    elif header_type == "ELF":
        file_format = "ELF"
    elif header_type == "Mach-O":
        file_format = "MACHO"
    elif suffix == ".zip":
        file_format = "ZIP"
    elif suffix == ".rar":
        file_format = "RAR"
    elif suffix == ".7z":
        file_format = "7ZIP"
    elif suffix in {".pdf", ".doc", ".docx", ".rtf"}:
        file_format = suffix[1:].upper()
    else:
        file_format = "UNKNOWN"
    return {
        "file_format": file_format,
        "format_category": "Executable" if header_type else "Unknown",
        "architecture": "Unknown",
        "bits": "Unknown",
        "endianness": "Unknown",
        "confidence": 0.95 if file_format != "UNKNOWN" else 0.0,
        "potential_threat": header_type == "PE",
    }
