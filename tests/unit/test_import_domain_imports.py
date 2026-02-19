#!/usr/bin/env python3
"""Comprehensive tests for import_domain.py module."""

from r2inspect.modules.import_domain import (
    NETWORK_CATEGORY,
    INJECTION_APIS,
    ANTI_ANALYSIS_APIS,
    CRYPTO_APIS,
    PERSISTENCE_APIS,
    NETWORK_APIS,
    PROCESS_APIS,
    MEMORY_APIS,
    LOADING_APIS,
    build_api_categories,
    categorize_apis,
    assess_api_risk,
    find_suspicious_patterns,
    count_import_categories,
    find_max_risk_score,
    risk_level_from_score,
)


def test_network_category_constant():
    """Test NETWORK_CATEGORY constant value."""
    assert NETWORK_CATEGORY == "Network/Internet"


def test_injection_apis_structure():
    """Test INJECTION_APIS has correct structure."""
    assert isinstance(INJECTION_APIS, dict)
    assert "CreateRemoteThread" in INJECTION_APIS
    assert "WriteProcessMemory" in INJECTION_APIS
    score, tag = INJECTION_APIS["CreateRemoteThread"]
    assert isinstance(score, int)
    assert isinstance(tag, str)
    assert score == 95


def test_anti_analysis_apis_structure():
    """Test ANTI_ANALYSIS_APIS has correct structure."""
    assert isinstance(ANTI_ANALYSIS_APIS, dict)
    assert "IsDebuggerPresent" in ANTI_ANALYSIS_APIS
    score, tag = ANTI_ANALYSIS_APIS["IsDebuggerPresent"]
    assert score == 75
    assert tag == "Anti-Debug"


def test_crypto_apis_structure():
    """Test CRYPTO_APIS has correct structure."""
    assert isinstance(CRYPTO_APIS, dict)
    assert "CryptEncrypt" in CRYPTO_APIS
    score, tag = CRYPTO_APIS["CryptEncrypt"]
    assert score == 70


def test_persistence_apis_structure():
    """Test PERSISTENCE_APIS has correct structure."""
    assert isinstance(PERSISTENCE_APIS, dict)
    assert "CreateService" in PERSISTENCE_APIS
    score, tag = PERSISTENCE_APIS["CreateService"]
    assert score == 80


def test_network_apis_structure():
    """Test NETWORK_APIS has correct structure."""
    assert isinstance(NETWORK_APIS, dict)
    assert "URLDownloadToFile" in NETWORK_APIS
    assert "InternetOpen" in NETWORK_APIS


def test_process_apis_structure():
    """Test PROCESS_APIS has correct structure."""
    assert isinstance(PROCESS_APIS, dict)
    assert "CreateProcess" in PROCESS_APIS
    assert "TerminateProcess" in PROCESS_APIS


def test_memory_apis_structure():
    """Test MEMORY_APIS has correct structure."""
    assert isinstance(MEMORY_APIS, dict)
    assert "VirtualAlloc" in MEMORY_APIS
    assert "VirtualProtect" in MEMORY_APIS


def test_loading_apis_structure():
    """Test LOADING_APIS has correct structure."""
    assert isinstance(LOADING_APIS, dict)
    assert "LoadLibrary" in LOADING_APIS
    assert "GetProcAddress" in LOADING_APIS


def test_build_api_categories():
    """Test building API categories dictionary."""
    categories = build_api_categories()
    assert isinstance(categories, dict)
    assert "Injection" in categories
    assert "Anti-Analysis" in categories
    assert "Crypto" in categories
    assert "Persistence" in categories
    assert "Network" in categories
    assert "Process" in categories
    assert "Memory" in categories
    assert "Loading" in categories


def test_build_api_categories_content():
    """Test built API categories contain correct content."""
    categories = build_api_categories()
    assert categories["Injection"] is INJECTION_APIS
    assert categories["Anti-Analysis"] is ANTI_ANALYSIS_APIS
    assert categories["Crypto"] is CRYPTO_APIS


def test_categorize_apis_empty():
    """Test categorizing empty imports list."""
    api_categories = {"Test": ["TestAPI"]}
    result = categorize_apis([], api_categories)
    assert isinstance(result, dict)
    assert len(result) == 0


def test_categorize_apis_basic():
    """Test categorizing basic imports."""
    imports = [
        {"name": "CreateProcess"},
        {"name": "VirtualAlloc"},
        {"name": "Unknown"},
    ]
    api_categories = {
        "Process": ["CreateProcess"],
        "Memory": ["VirtualAlloc"],
    }
    result = categorize_apis(imports, api_categories)
    assert "Process" in result
    assert "Memory" in result
    assert result["Process"]["count"] == 1
    assert result["Memory"]["count"] == 1


def test_categorize_apis_multiple_matches():
    """Test categorizing imports with multiple matches."""
    imports = [
        {"name": "CreateProcess"},
        {"name": "CreateProcessW"},
        {"name": "CreateProcessA"},
    ]
    api_categories = {
        "Process": ["CreateProcess"],
    }
    result = categorize_apis(imports, api_categories)
    assert result["Process"]["count"] == 3
    assert len(result["Process"]["apis"]) == 3


def test_categorize_apis_case_insensitive():
    """Test categorizing APIs is case insensitive."""
    imports = [
        {"name": "createprocess"},
        {"name": "CREATEPROCESS"},
    ]
    api_categories = {
        "Process": ["CreateProcess"],
    }
    result = categorize_apis(imports, api_categories)
    assert result["Process"]["count"] == 2


def test_categorize_apis_partial_match():
    """Test categorizing APIs with partial matches."""
    imports = [
        {"name": "NtCreateProcessEx"},
        {"name": "ZwCreateProcess"},
    ]
    api_categories = {
        "Process": ["CreateProcess"],
    }
    result = categorize_apis(imports, api_categories)
    assert result["Process"]["count"] == 2


def test_categorize_apis_no_match():
    """Test categorizing imports with no matches."""
    imports = [
        {"name": "UnknownAPI1"},
        {"name": "UnknownAPI2"},
    ]
    api_categories = {
        "Process": ["CreateProcess"],
    }
    result = categorize_apis(imports, api_categories)
    assert len(result) == 0


def test_assess_api_risk_empty():
    """Test assessing risk with empty categories."""
    suspicious, risk = assess_api_risk({})
    assert isinstance(suspicious, list)
    assert isinstance(risk, int)
    assert len(suspicious) == 0
    assert risk == 0


def test_assess_api_risk_anti_analysis():
    """Test assessing risk with anti-analysis APIs."""
    categories = {
        "Anti-Analysis": {"count": 2, "apis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]}
    }
    suspicious, risk = assess_api_risk(categories)
    assert len(suspicious) >= 1
    assert risk >= 20
    assert any("anti-debug" in s.lower() for s in suspicious)


def test_assess_api_risk_dll_injection():
    """Test assessing risk with DLL injection pattern."""
    categories = {
        "DLL Injection": {"count": 3, "apis": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx"]}
    }
    suspicious, risk = assess_api_risk(categories)
    assert len(suspicious) >= 1
    assert risk >= 30


def test_assess_api_risk_process_manipulation():
    """Test assessing risk with process manipulation."""
    categories = {
        "Process/Thread Management": {"count": 3, "apis": ["CreateProcess", "OpenProcess", "TerminateProcess"]},
        "Memory Management": {"count": 3, "apis": ["VirtualAlloc", "VirtualProtect", "WriteProcessMemory"]}
    }
    suspicious, risk = assess_api_risk(categories)
    assert len(suspicious) >= 1
    assert risk >= 25


def test_assess_api_risk_registry():
    """Test assessing risk with registry manipulation."""
    categories = {
        "Registry": {"count": 4, "apis": ["RegSetValue", "RegCreateKey", "RegDeleteKey", "RegOpenKey"]}
    }
    suspicious, risk = assess_api_risk(categories)
    assert len(suspicious) >= 1
    assert risk >= 15


def test_assess_api_risk_network():
    """Test assessing risk with network capabilities."""
    categories = {
        NETWORK_CATEGORY: {"count": 3, "apis": ["InternetOpen", "URLDownloadToFile", "WinHttpSendRequest"]}
    }
    suspicious, risk = assess_api_risk(categories)
    assert len(suspicious) >= 1
    assert risk >= 10


def test_assess_api_risk_combined():
    """Test assessing risk with combined categories."""
    categories = {
        "Anti-Analysis": {"count": 2, "apis": []},
        "DLL Injection": {"count": 3, "apis": []},
        NETWORK_CATEGORY: {"count": 3, "apis": []},
    }
    suspicious, risk = assess_api_risk(categories)
    assert len(suspicious) >= 3
    assert risk >= 60


def test_find_suspicious_patterns_empty():
    """Test finding suspicious patterns in empty list."""
    result = find_suspicious_patterns([])
    assert isinstance(result, list)
    assert len(result) == 0


def test_find_suspicious_patterns_dll_injection():
    """Test finding DLL injection pattern."""
    imports = [
        {"name": "VirtualAllocEx", "category": "Memory"},
        {"name": "WriteProcessMemory", "category": "Memory"},
        {"name": "CreateRemoteThread", "category": "Process"},
    ]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "DLL Injection" in patterns
    dll_pattern = next(p for p in result if p["pattern"] == "DLL Injection")
    assert dll_pattern["severity"] == "High"
    assert dll_pattern["count"] >= 2


def test_find_suspicious_patterns_process_hollowing():
    """Test finding process hollowing pattern."""
    imports = [
        {"name": "CreateProcess", "category": "Process"},
        {"name": "VirtualAllocEx", "category": "Memory"},
        {"name": "WriteProcessMemory", "category": "Memory"},
        {"name": "SetThreadContext", "category": "Process"},
    ]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "Process Hollowing" in patterns


def test_find_suspicious_patterns_keylogging():
    """Test finding keylogging pattern."""
    imports = [
        {"name": "SetWindowsHookEx", "category": "Hooks"},
    ]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "Keylogging" in patterns


def test_find_suspicious_patterns_network():
    """Test finding heavy network usage pattern."""
    imports = [
        {"name": f"NetworkAPI{i}", "category": NETWORK_CATEGORY}
        for i in range(6)
    ]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "Heavy Network Usage" in patterns


def test_find_suspicious_patterns_anti_analysis():
    """Test finding anti-analysis pattern."""
    imports = [
        {"name": "IsDebuggerPresent", "category": "Anti-Analysis"},
    ]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "Anti-Analysis" in patterns


def test_find_suspicious_patterns_crypto():
    """Test finding heavy cryptography pattern."""
    imports = [
        {"name": f"CryptAPI{i}", "category": "Cryptography"}
        for i in range(4)
    ]
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    assert "Heavy Cryptography" in patterns


def test_count_import_categories_empty():
    """Test counting categories in empty list."""
    result = count_import_categories([])
    assert isinstance(result, dict)
    assert len(result) == 0


def test_count_import_categories_basic():
    """Test counting categories."""
    imports = [
        {"category": "Process"},
        {"category": "Memory"},
        {"category": "Process"},
        {"category": "Network"},
    ]
    result = count_import_categories(imports)
    assert result["Process"] == 2
    assert result["Memory"] == 1
    assert result["Network"] == 1


def test_count_import_categories_missing_category():
    """Test counting with missing category field."""
    imports = [
        {"category": "Process"},
        {"name": "NoCategory"},
        {"category": "Memory"},
    ]
    result = count_import_categories(imports)
    assert result["Process"] == 1
    assert result["Memory"] == 1


def test_count_import_categories_none_category():
    """Test counting with None category."""
    imports = [
        {"category": "Process"},
        {"category": None},
        {"category": "Process"},
    ]
    result = count_import_categories(imports)
    assert result["Process"] == 2
    assert None not in result


def test_find_max_risk_score_empty():
    """Test finding max risk score with no match."""
    categories = build_api_categories()
    score, tags = find_max_risk_score("UnknownAPI", categories)
    assert score == 0
    assert tags == []


def test_find_max_risk_score_single_match():
    """Test finding max risk score with single match."""
    categories = build_api_categories()
    score, tags = find_max_risk_score("CreateRemoteThread", categories)
    assert score == 95
    assert len(tags) == 1
    assert tags[0] == "Remote Thread Injection"


def test_find_max_risk_score_multiple_categories():
    """Test finding max risk score across categories."""
    categories = build_api_categories()
    score, tags = find_max_risk_score("LoadLibrary", categories)
    assert score > 0
    assert len(tags) > 0


def test_find_max_risk_score_highest():
    """Test finding highest risk score when multiple matches."""
    categories = {
        "Cat1": {"LowAPI": (10, "Low"), "HighAPI": (90, "High")},
        "Cat2": {"MedAPI": (50, "Medium")},
    }
    score, tags = find_max_risk_score("HighAPI", categories)
    assert score == 90
    assert "High" in tags


def test_find_max_risk_score_equal_scores():
    """Test finding max risk score with equal scores."""
    categories = {
        "Cat1": {"API": (50, "Tag1")},
        "Cat2": {"API": (50, "Tag2")},
    }
    score, tags = find_max_risk_score("API", categories)
    assert score == 50
    assert len(tags) == 2


def test_risk_level_from_score_critical():
    """Test risk level for critical score."""
    assert risk_level_from_score(80) == "Critical"
    assert risk_level_from_score(95) == "Critical"
    assert risk_level_from_score(100) == "Critical"


def test_risk_level_from_score_high():
    """Test risk level for high score."""
    assert risk_level_from_score(65) == "High"
    assert risk_level_from_score(70) == "High"
    assert risk_level_from_score(79) == "High"


def test_risk_level_from_score_medium():
    """Test risk level for medium score."""
    assert risk_level_from_score(45) == "Medium"
    assert risk_level_from_score(50) == "Medium"
    assert risk_level_from_score(64) == "Medium"


def test_risk_level_from_score_low():
    """Test risk level for low score."""
    assert risk_level_from_score(25) == "Low"
    assert risk_level_from_score(30) == "Low"
    assert risk_level_from_score(44) == "Low"


def test_risk_level_from_score_minimal():
    """Test risk level for minimal score."""
    assert risk_level_from_score(0) == "Minimal"
    assert risk_level_from_score(10) == "Minimal"
    assert risk_level_from_score(24) == "Minimal"


def test_risk_level_from_score_boundaries():
    """Test risk level at boundary values."""
    assert risk_level_from_score(79) == "High"
    assert risk_level_from_score(80) == "Critical"
    assert risk_level_from_score(64) == "Medium"
    assert risk_level_from_score(65) == "High"
    assert risk_level_from_score(44) == "Low"
    assert risk_level_from_score(45) == "Medium"
    assert risk_level_from_score(24) == "Minimal"
    assert risk_level_from_score(25) == "Low"


def test_categorize_apis_with_apis_list():
    """Test that categorize_apis returns APIs list."""
    imports = [
        {"name": "CreateProcess"},
        {"name": "CreateProcessW"},
    ]
    api_categories = {
        "Process": ["CreateProcess"],
    }
    result = categorize_apis(imports, api_categories)
    assert "Process" in result
    assert "apis" in result["Process"]
    assert len(result["Process"]["apis"]) == 2
    assert "CreateProcess" in result["Process"]["apis"]


def test_find_suspicious_patterns_all_patterns():
    """Test finding all patterns at once."""
    imports = [
        {"name": "VirtualAllocEx", "category": "Memory"},
        {"name": "WriteProcessMemory", "category": "Memory"},
        {"name": "CreateRemoteThread", "category": "Process"},
        {"name": "SetThreadContext", "category": "Process"},
        {"name": "SetWindowsHookEx", "category": "Hooks"},
        {"name": "IsDebuggerPresent", "category": "Anti-Analysis"},
    ]
    imports.extend([{"name": f"NetAPI{i}", "category": NETWORK_CATEGORY} for i in range(6)])
    imports.extend([{"name": f"CryptAPI{i}", "category": "Cryptography"} for i in range(4)])
    
    result = find_suspicious_patterns(imports)
    patterns = [p["pattern"] for p in result]
    
    assert len(patterns) >= 4
    assert "DLL Injection" in patterns or "Process Hollowing" in patterns


def test_api_categories_complete():
    """Test that build_api_categories returns all expected categories."""
    categories = build_api_categories()
    expected_keys = ["Injection", "Anti-Analysis", "Crypto", "Persistence", 
                     "Network", "Process", "Memory", "Loading"]
    for key in expected_keys:
        assert key in categories


def test_injection_apis_all_present():
    """Test all documented injection APIs are present."""
    expected_apis = ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", 
                     "SetThreadContext", "QueueUserAPC", "NtMapViewOfSection"]
    for api in expected_apis:
        assert api in INJECTION_APIS


def test_anti_analysis_apis_all_present():
    """Test all documented anti-analysis APIs are present."""
    expected_apis = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", 
                     "NtQueryInformationProcess", "QueryPerformanceCounter",
                     "GetTickCount", "OutputDebugString"]
    for api in expected_apis:
        assert api in ANTI_ANALYSIS_APIS
