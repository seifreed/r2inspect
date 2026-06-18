"""Branch-path tests for r2inspect/modules/import_domain.py."""

from __future__ import annotations

from r2inspect.domain.formats.import_analysis import (
    NETWORK_CATEGORY,
    assess_api_risk,
    find_max_risk_score,
    risk_level_from_score,
    build_api_categories,
)

# ---------------------------------------------------------------------------
# assess_api_risk - individual branches (lines 120-135)
# ---------------------------------------------------------------------------


def test_assess_api_risk_anti_analysis_below_threshold_no_flag():
    categories = {"Anti-Analysis": {"count": 1, "apis": ["IsDebuggerPresent"]}}
    suspicious, risk = assess_api_risk(categories)
    assert not any("anti-debug" in s.lower() for s in suspicious)


def test_assess_api_risk_anti_analysis_at_threshold_adds_flag():
    categories = {
        "Anti-Analysis": {"count": 2, "apis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]}
    }
    suspicious, risk = assess_api_risk(categories)
    assert any("anti-debug" in s.lower() for s in suspicious)
    assert risk >= 20


def test_assess_api_risk_dll_injection_at_threshold_adds_flag():
    categories = {
        "DLL Injection": {
            "count": 3,
            "apis": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx"],
        }
    }
    suspicious, risk = assess_api_risk(categories)
    assert any("dll injection" in s.lower() for s in suspicious)
    assert risk >= 30


def test_assess_api_risk_dll_injection_below_threshold_no_flag():
    categories = {
        "DLL Injection": {"count": 2, "apis": ["CreateRemoteThread", "WriteProcessMemory"]}
    }
    suspicious, risk = assess_api_risk(categories)
    assert not any("dll injection" in s.lower() for s in suspicious)


def test_assess_api_risk_process_manipulation_adds_flag():
    categories = {
        "Process/Thread Management": {
            "count": 3,
            "apis": ["CreateProcess", "OpenProcess", "TerminateProcess"],
        },
        "Memory Management": {
            "count": 3,
            "apis": ["VirtualAlloc", "VirtualProtect", "WriteProcessMemory"],
        },
    }
    suspicious, risk = assess_api_risk(categories)
    assert any("process" in s.lower() for s in suspicious)
    assert risk >= 25


def test_assess_api_risk_process_manipulation_below_threshold_no_flag():
    categories = {
        "Process/Thread Management": {"count": 2, "apis": []},
        "Memory Management": {"count": 3, "apis": []},
    }
    suspicious, risk = assess_api_risk(categories)
    assert not any("process manipulation" in s.lower() for s in suspicious)


def test_assess_api_risk_registry_adds_flag():
    categories = {
        "Registry": {
            "count": 4,
            "apis": ["RegSetValue", "RegCreateKey", "RegDeleteKey", "RegOpenKey"],
        }
    }
    suspicious, risk = assess_api_risk(categories)
    assert any("registry" in s.lower() for s in suspicious)
    assert risk >= 15


def test_assess_api_risk_registry_below_threshold_no_flag():
    categories = {"Registry": {"count": 3, "apis": []}}
    suspicious, risk = assess_api_risk(categories)
    assert not any("registry" in s.lower() for s in suspicious)


def test_assess_api_risk_network_adds_flag():
    categories = {NETWORK_CATEGORY: {"count": 3, "apis": ["socket", "connect", "send"]}}
    suspicious, risk = assess_api_risk(categories)
    assert any("network" in s.lower() for s in suspicious)
    assert risk >= 10


def test_assess_api_risk_network_below_threshold_no_flag():
    categories = {NETWORK_CATEGORY: {"count": 2, "apis": []}}
    suspicious, risk = assess_api_risk(categories)
    assert not any("network communication" in s.lower() for s in suspicious)


# ---------------------------------------------------------------------------
# find_max_risk_score - tied scores append tag (lines 245-246)
# ---------------------------------------------------------------------------


def test_find_max_risk_score_equal_scores_collect_both_tags():
    categories = {
        "Cat1": {"SomeAPI": (50, "TagA")},
        "Cat2": {"SomeAPI": (50, "TagB")},
    }
    score, tags = find_max_risk_score("SomeAPI", categories)
    assert score == 50
    assert "TagA" in tags
    assert "TagB" in tags


def test_find_max_risk_score_highest_wins():
    categories = {
        "Cat1": {"LowAPI": (20, "Low")},
        "Cat2": {"HighAPI": (90, "High")},
    }
    score, tags = find_max_risk_score("HighAPI", categories)
    assert score == 90
    assert "High" in tags


def test_find_max_risk_score_no_match_returns_zero():
    categories = build_api_categories()
    score, tags = find_max_risk_score("CompletelyUnknownFunction", categories)
    assert score == 0
    assert tags == []


def test_find_max_risk_score_skips_malformed_category_entries():
    score, tags = find_max_risk_score(
        "CreateRemoteThread",
        {
            "Cat1": "bad",
            "Cat2": {"CreateRemoteThread": "bad"},
            "Cat3": {"CreateRemoteThread": (95, "TagA")},
        },
    )
    assert score == 95
    assert tags == ["TagA"]


# ---------------------------------------------------------------------------
# risk_level_from_score - all branches (lines 252, 256, 258)
# ---------------------------------------------------------------------------


def test_risk_level_critical():
    assert risk_level_from_score(80) == "Critical"
    assert risk_level_from_score(100) == "Critical"


def test_risk_level_high():
    assert risk_level_from_score(65) == "High"
    assert risk_level_from_score(79) == "High"


def test_risk_level_medium():
    assert risk_level_from_score(45) == "Medium"
    assert risk_level_from_score(64) == "Medium"


def test_risk_level_low():
    assert risk_level_from_score(25) == "Low"
    assert risk_level_from_score(44) == "Low"


def test_risk_level_minimal():
    assert risk_level_from_score(0) == "Minimal"
    assert risk_level_from_score(24) == "Minimal"


def test_risk_level_non_numeric_inputs_fall_back_to_minimal():
    assert risk_level_from_score(None) == "Minimal"
    assert risk_level_from_score("65") == "High"
