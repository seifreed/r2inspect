"""Regression test for loop iteration 10.

Suspicious-import detection used exact set membership, so the cross-process
``*Ex`` variants (e.g. ``VirtualAllocEx`` — the more suspicious form) were
silently missed in both the threat-indicator list and the executive-summary
count. Matching is now a substring, consistent with ``categorize_apis``.
"""

from __future__ import annotations

from r2inspect.core.result_aggregator_indicator_support import generate_indicators
from r2inspect.core.result_aggregator_summary_support import _count_suspicious_imports


def test_virtualallocex_flagged_as_suspicious_indicator() -> None:
    results = {
        "imports": [{"name": "VirtualAllocEx"}, {"name": "WriteProcessMemory"}],
        "yara_matches": [],
    }
    indicators = generate_indicators(results, [])
    descriptions = [i["description"] for i in indicators if i["type"] == "Suspicious API"]
    assert any("VirtualAllocEx" in d for d in descriptions)
    assert any("WriteProcessMemory" in d for d in descriptions)


def test_count_suspicious_imports_includes_ex_variants() -> None:
    imports = [
        {"name": "VirtualAllocEx"},  # matches "VirtualAlloc"
        {"name": "SetThreadContext"},  # exact
        {"name": "printf"},  # not suspicious
    ]
    assert _count_suspicious_imports(imports) == 2


def test_count_suspicious_imports_handles_missing_name() -> None:
    assert _count_suspicious_imports([{"ordinal": 3}, {"name": None}]) == 0


def test_generate_indicators_skips_none_buckets() -> None:
    indicators = generate_indicators(
        {"packer": None, "anti_analysis": None, "imports": None, "yara_matches": None}, []
    )
    assert indicators == []
