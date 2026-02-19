"""Branch-path tests for r2inspect/modules/import_domain.py."""

from __future__ import annotations

from r2inspect.modules.import_domain import (
    NETWORK_CATEGORY,
    assess_api_risk,
    count_import_categories,
    find_max_risk_score,
    find_suspicious_patterns,
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
    categories = {"Anti-Analysis": {"count": 2, "apis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]}}
    suspicious, risk = assess_api_risk(categories)
    assert any("anti-debug" in s.lower() for s in suspicious)
    assert risk >= 20


def test_assess_api_risk_dll_injection_at_threshold_adds_flag():
    categories = {"DLL Injection": {"count": 3, "apis": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx"]}}
    suspicious, risk = assess_api_risk(categories)
    assert any("dll injection" in s.lower() for s in suspicious)
    assert risk >= 30


def test_assess_api_risk_dll_injection_below_threshold_no_flag():
    categories = {"DLL Injection": {"count": 2, "apis": ["CreateRemoteThread", "WriteProcessMemory"]}}
    suspicious, risk = assess_api_risk(categories)
    assert not any("dll injection" in s.lower() for s in suspicious)


def test_assess_api_risk_process_manipulation_adds_flag():
    categories = {
        "Process/Thread Management": {"count": 3, "apis": ["CreateProcess", "OpenProcess", "TerminateProcess"]},
        "Memory Management": {"count": 3, "apis": ["VirtualAlloc", "VirtualProtect", "WriteProcessMemory"]},
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
    categories = {"Registry": {"count": 4, "apis": ["RegSetValue", "RegCreateKey", "RegDeleteKey", "RegOpenKey"]}}
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
# find_suspicious_patterns - individual branches (lines 151, 169, 181, 192, 203, 214)
# ---------------------------------------------------------------------------


def test_find_suspicious_patterns_dll_injection_at_threshold():
    imports = [
        {"name": "VirtualAllocEx", "category": "Memory"},
        {"name": "WriteProcessMemory", "category": "Memory"},
    ]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "DLL Injection" in patterns


def test_find_suspicious_patterns_dll_injection_below_threshold():
    imports = [{"name": "VirtualAllocEx", "category": "Memory"}]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "DLL Injection" not in patterns


def test_find_suspicious_patterns_process_hollowing_at_threshold():
    imports = [
        {"name": "CreateProcess", "category": "Process"},
        {"name": "VirtualAllocEx", "category": "Memory"},
        {"name": "WriteProcessMemory", "category": "Memory"},
    ]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "Process Hollowing" in patterns


def test_find_suspicious_patterns_process_hollowing_below_threshold():
    imports = [
        {"name": "CreateProcess", "category": "Process"},
        {"name": "VirtualAllocEx", "category": "Memory"},
    ]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "Process Hollowing" not in patterns


def test_find_suspicious_patterns_keylogging_single_api():
    imports = [{"name": "SetWindowsHookEx", "category": "Hooks"}]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "Keylogging" in patterns


def test_find_suspicious_patterns_keylogging_no_match():
    imports = [{"name": "SomeOtherAPI", "category": "Other"}]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "Keylogging" not in patterns


def test_find_suspicious_patterns_heavy_network_above_threshold():
    imports = [{"name": f"NetAPI{i}", "category": NETWORK_CATEGORY} for i in range(6)]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "Heavy Network Usage" in patterns


def test_find_suspicious_patterns_heavy_network_at_or_below_threshold():
    imports = [{"name": f"NetAPI{i}", "category": NETWORK_CATEGORY} for i in range(5)]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "Heavy Network Usage" not in patterns


def test_find_suspicious_patterns_anti_analysis_detected():
    imports = [{"name": "IsDebuggerPresent", "category": "Anti-Analysis"}]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "Anti-Analysis" in patterns


def test_find_suspicious_patterns_anti_analysis_not_present():
    imports = [{"name": "CreateFile", "category": "FileIO"}]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "Anti-Analysis" not in patterns


def test_find_suspicious_patterns_heavy_crypto_above_threshold():
    imports = [{"name": f"CryptAPI{i}", "category": "Cryptography"} for i in range(4)]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "Heavy Cryptography" in patterns


def test_find_suspicious_patterns_heavy_crypto_at_or_below_threshold():
    imports = [{"name": f"CryptAPI{i}", "category": "Cryptography"} for i in range(3)]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "Heavy Cryptography" not in patterns


# ---------------------------------------------------------------------------
# count_import_categories (lines 226-231)
# ---------------------------------------------------------------------------


def test_count_import_categories_with_valid_categories():
    imports = [
        {"category": "Process"},
        {"category": "Memory"},
        {"category": "Process"},
    ]
    result = count_import_categories(imports)
    assert result["Process"] == 2
    assert result["Memory"] == 1


def test_count_import_categories_skips_none_category():
    imports = [
        {"category": "Process"},
        {"category": None},
        {"name": "NoCategory"},
    ]
    result = count_import_categories(imports)
    assert result["Process"] == 1
    assert None not in result


def test_count_import_categories_empty_list():
    result = count_import_categories([])
    assert result == {}


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
