"""Small helpers for analyzer-owned report findings."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from typing import Any


def finding_slug(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", ".", str(value).casefold()).strip(".") or "unknown"


def native_finding(
    *,
    rule_id: str,
    title: str,
    category: str,
    severity: str,
    confidence: float,
    source_analyzer: str,
    method: str,
    evidence: list[dict[str, Any]],
    locations: list[dict[str, Any]] | None = None,
    attack: Iterable[str] = (),
    mbc: Iterable[str] = (),
) -> dict[str, Any]:
    locations = locations or []
    identity = json.dumps(
        [rule_id, evidence, locations], sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    return {
        "finding_id": f"finding-{hashlib.sha256(identity).hexdigest()[:16]}",
        "rule_id": rule_id,
        "title": title,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "source_analyzer": source_analyzer,
        "method": method,
        "evidence": evidence,
        "locations": locations,
        "attack": list(attack),
        "mbc": list(mbc),
    }


def parse_address(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value if value > 0 else None
    if not isinstance(value, str):
        return None
    match = re.search(r"\b0x[0-9a-fA-F]+\b", value)
    if match:
        return int(match.group(), 16)
    try:
        address = int(value, 0)
    except ValueError:
        return None
    return address if address > 0 else None


def evidence_locations(evidence: Iterable[Any]) -> list[dict[str, int]]:
    """Extract explicit address fields from analyzer evidence."""
    addresses: set[int] = set()

    def visit(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                visit(child, str(child_key))
        elif isinstance(value, list):
            for child in value:
                visit(child, key)
        elif (
            key in {"address", "addresses", "vaddr", "virtual_address"}
            and (address := parse_address(value)) is not None
        ):
            addresses.add(address)

    visit(list(evidence))
    return [{"virtual_address": address} for address in sorted(addresses)]


__all__ = ["evidence_locations", "finding_slug", "native_finding", "parse_address"]
