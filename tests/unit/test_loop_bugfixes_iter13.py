"""Regression test for loop iteration 13.

``assess_api_risk`` checked ``categories.get("DLL Injection")``, but the
production ``API_CATEGORIES`` had no such category, so ``categorize_apis`` never
produced that key and the branch was dead on real input — a textbook process
injector scored nothing from it and never surfaced the indicator (only synthetic
tests that hand-built a "DLL Injection" category exercised the branch). The
category now exists, so the detection actually fires on real imports.
"""

from __future__ import annotations

from r2inspect.domain.formats.import_analysis import assess_api_risk, categorize_apis
from r2inspect.modules.import_categories import API_CATEGORIES


def test_dll_injection_detected_from_production_categories() -> None:
    imports = [
        {"name": api}
        for api in (
            "OpenProcess",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        )
    ]
    categories = categorize_apis(imports, API_CATEGORIES)

    assert categories.get("DLL Injection", {}).get("count", 0) >= 3

    suspicious_apis, risk_score = assess_api_risk(categories)
    assert any("DLL injection" in api for api in suspicious_apis)
    assert risk_score >= 30


def test_benign_single_injection_api_does_not_trigger() -> None:
    categories = categorize_apis([{"name": "OpenProcess"}], API_CATEGORIES)
    suspicious_apis, _ = assess_api_risk(categories)
    assert not any("DLL injection" in api for api in suspicious_apis)
