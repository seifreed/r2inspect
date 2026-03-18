"""Helper operations for AnalysisResult loading."""

from __future__ import annotations

from datetime import datetime
from typing import Any

IMPORT_FIELDS = [
    ("name", "name", ""),
    ("library", "library", ""),
    ("address", "address", ""),
    ("ordinal", "ordinal", 0),
    ("category", "category", ""),
    ("risk_score", "risk_score", 0),
    ("risk_level", "risk_level", "Low"),
    ("risk_tags", "risk_tags", []),
]
EXPORT_FIELDS = [
    ("name", "name", ""),
    ("address", "address", ""),
    ("ordinal", "ordinal", 0),
    ("size", "size", 0),
]
SECTION_FIELDS = [
    ("name", "name", ""),
    ("virtual_address", "virtual_address", 0),
    ("virtual_size", "virtual_size", 0),
    ("raw_size", "raw_size", 0),
    ("entropy", "entropy", 0.0),
    ("permissions", "permissions", ""),
    ("is_executable", "is_executable", False),
    ("is_writable", "is_writable", False),
    ("is_readable", "is_readable", False),
    ("flags", "flags", None),
    ("suspicious_indicators", "suspicious_indicators", []),
]
YARA_FIELDS = [
    ("rule", "rule", ""),
    ("namespace", "namespace", ""),
    ("tags", "tags", []),
    ("meta", "meta", {}),
    ("strings", "strings", []),
]
FUNCTION_FIELDS = [
    ("name", "name", ""),
    ("address", "address", 0),
    ("size", "size", 0),
    ("complexity", "complexity", 0),
    ("basic_blocks", "basic_blocks", 0),
    ("call_refs", "call_refs", 0),
    ("data_refs", "data_refs", 0),
]
INDICATOR_FIELDS = [
    ("type", "type", ""),
    ("description", "description", ""),
    ("severity", "severity", "Low"),
]


def load_file_info(result: Any, data: dict[str, Any], file_info_cls: Any) -> None:
    fi = data.get("file_info")
    if not fi:
        return
    result.file_info = file_info_cls(
        name=fi.get("name", ""),
        path=fi.get("path", ""),
        size=fi.get("size", 0),
        md5=fi.get("md5", ""),
        sha1=fi.get("sha1", ""),
        sha256=fi.get("sha256", ""),
        file_type=fi.get("file_type", ""),
        architecture=fi.get("architecture", ""),
        bits=fi.get("bits", 0),
        endian=fi.get("endian", ""),
        mime_type=fi.get("mime_type", ""),
    )


def load_hashing(result: Any, data: dict[str, Any], hashing_cls: Any) -> None:
    h = data.get("hashing")
    if not h:
        return
    result.hashing = hashing_cls(
        ssdeep=h.get("ssdeep", ""),
        tlsh=h.get("tlsh", ""),
        imphash=h.get("imphash", ""),
        impfuzzy=h.get("impfuzzy", ""),
        ccbhash=h.get("ccbhash", ""),
        simhash=h.get("simhash", ""),
        telfhash=h.get("telfhash", ""),
        rich_hash=h.get("rich_hash", ""),
        machoc_hash=h.get("machoc_hash", ""),
    )


def load_security(result: Any, data: dict[str, Any], security_cls: Any) -> None:
    s = data.get("security")
    if not s:
        return
    result.security = security_cls(
        nx=s.get("nx", False),
        pie=s.get("pie", False),
        canary=s.get("canary", False),
        dep=s.get("dep", False),
        stack_canary=s.get("stack_canary", False),
        relro=s.get("relro", ""),
        aslr=s.get("aslr", False),
        seh=s.get("seh", False),
        guard_cf=s.get("guard_cf", False),
        authenticode=s.get("authenticode", False),
        fortify=s.get("fortify", False),
        rpath=s.get("rpath", False),
        runpath=s.get("runpath", False),
        high_entropy_va=s.get("high_entropy_va", False),
    )


def load_collection(
    result: Any, data: dict[str, Any], key: str, cls: Any, field_map: list[tuple[str, str, Any]]
) -> None:
    items = data.get(key)
    if not items:
        return
    setattr(
        result,
        key,
        [
            cls(**{target: item.get(source, default) for source, target, default in field_map})
            for item in items
        ],
    )


def load_timestamp(result: Any, data: dict[str, Any]) -> None:
    ts = data.get("timestamp")
    if ts is None:
        return
    if isinstance(ts, str):
        try:
            result.timestamp = datetime.fromisoformat(ts)
        except ValueError:
            return
    elif isinstance(ts, datetime):
        result.timestamp = ts


def load_simple(
    result: Any, data: dict[str, Any], key: str, cls: Any, fields: dict[str, Any]
) -> None:
    value = data.get(key)
    if value:
        setattr(
            result,
            key,
            cls(
                **{
                    target: value.get(source, default)
                    for target, (source, default) in fields.items()
                }
            ),
        )


def set_if_present(result: Any, data: dict[str, Any], key: str) -> None:
    if key in data:
        setattr(result, key, data[key])
