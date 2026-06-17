"""Regression test for loop iteration 12.

``find_suspicious`` matched its crypto-algorithm keywords case-insensitively
with no word boundary, so "DES" hit ordinary words like "modes"/"nodes" and
flagged them as crypto. Its IP regex also accepted out-of-range octets, so
dotted-decimal version strings (e.g. 4.0.30319.1) were reported as IPs. Both
now use tighter patterns.
"""

from __future__ import annotations

from r2inspect.domain.formats.string import find_suspicious


def _types(strings: list[str], kind: str) -> list[dict]:
    return [s for s in find_suspicious(strings) if s["type"] == kind]


def test_crypto_does_not_match_substrings_of_ordinary_words() -> None:
    assert _types(["decode the modes and nodes"], "crypto") == []
    assert _types(["update the description"], "crypto") == []


def test_crypto_still_matches_real_algorithm_names() -> None:
    assert _types(["AES-256-CBC cipher"], "crypto")
    assert _types(["SHA256 digest"], "crypto")


def test_ips_reject_out_of_range_octets_and_versions() -> None:
    assert _types(["999.999.999.999"], "ips") == []
    assert _types(["runtime build 4.0.30319.1"], "ips") == []


def test_ips_still_match_real_addresses() -> None:
    assert _types(["192.168.1.1"], "ips")
    assert _types(["10.0.0.1"], "ips")
