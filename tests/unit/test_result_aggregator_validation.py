#!/usr/bin/env python3
"""Comprehensive tests for result_aggregator.py aggregation logic."""

from r2inspect.core.result_aggregator import (
    ResultAggregator,
    _normalize_results,
    _build_file_overview,
    _build_security_assessment,
    _build_threat_indicators,
    _build_technical_details,
    _generate_recommendations,
    _count_suspicious_imports,
    _count_high_entropy_sections,
    _count_suspicious_sections,
    _count_crypto_indicators,
)


def test_normalize_results_with_full_data():
    results = {
        "file_info": {"name": "test"},
        "pe_info": {"timestamp": 123},
        "security": {"aslr": True},
        "packer": {"is_packed": False},
        "anti_analysis": {"anti_debug": False},
        "imports": [{"name": "kernel32"}],
        "yara_matches": [],
        "sections": [],
        "functions": {"count": 10},
        "crypto": {"matches": []},
        "rich_header": {},
    }
    
    normalized = _normalize_results(results)
    assert normalized["file_info"] == {"name": "test"}
    assert normalized["pe_info"] == {"timestamp": 123}


def test_normalize_results_with_missing_keys():
    results = {"file_info": {"name": "test"}}
    normalized = _normalize_results(results)
    
    assert normalized["file_info"] == {"name": "test"}
    assert normalized["pe_info"] == {}
    assert normalized["security"] == {}
    assert normalized["packer"] == {}
    assert normalized["imports"] == []
    assert normalized["sections"] == []


def test_normalize_results_empty_input():
    results = {}
    normalized = _normalize_results(results)
    
    assert normalized["file_info"] == {}
    assert normalized["pe_info"] == {}
    assert normalized["security"] == {}
    assert normalized["packer"] == {}
    assert normalized["anti_analysis"] == {}
    assert normalized["imports"] == []
    assert normalized["yara_matches"] == []
    assert normalized["sections"] == []
    assert normalized["functions"] == {}
    assert normalized["crypto"] == {}
    assert normalized["rich_header"] == {}


def test_build_file_overview_minimal():
    results = {
        "file_info": {
            "name": "sample.exe",
            "file_type": "PE32",
            "size": 102400,
            "architecture": "x86",
            "md5": "abc123",
            "sha256": "def456",
        },
        "pe_info": {},
        "rich_header": {},
    }
    
    overview = _build_file_overview(results)
    assert overview["filename"] == "sample.exe"
    assert overview["file_type"] == "PE32"
    assert overview["size"] == 102400
    assert overview["architecture"] == "x86"
    assert overview["md5"] == "abc123"
    assert overview["sha256"] == "def456"


def test_build_file_overview_with_timestamp():
    results = {
        "file_info": {
            "name": "sample.exe",
            "file_type": "PE32",
            "size": 102400,
            "architecture": "x86",
            "md5": "abc",
            "sha256": "def",
        },
        "pe_info": {"compilation_timestamp": "2024-01-01 12:00:00"},
        "rich_header": {},
    }
    
    overview = _build_file_overview(results)
    assert overview["compiled"] == "2024-01-01 12:00:00"


def test_build_file_overview_with_rich_header():
    results = {
        "file_info": {
            "name": "test.exe",
            "file_type": "PE",
            "size": 100,
            "architecture": "x64",
            "md5": "m",
            "sha256": "s",
        },
        "pe_info": {},
        "rich_header": {
            "available": True,
            "compilers": [
                {"compiler_name": "MSVC", "build_number": 12345},
                {"compiler_name": "Link", "build_number": 54321},
                {"compiler_name": "MASM", "build_number": 11111},
                {"compiler_name": "Extra", "build_number": 99999},
            ],
        },
    }
    
    overview = _build_file_overview(results)
    assert "toolset" in overview
    assert len(overview["toolset"]) == 3
    assert "MSVC (Build 12345)" in overview["toolset"]
    assert "Link (Build 54321)" in overview["toolset"]
    assert "MASM (Build 11111)" in overview["toolset"]


def test_build_file_overview_rich_header_not_available():
    results = {
        "file_info": {
            "name": "test.exe",
            "file_type": "PE",
            "size": 100,
            "architecture": "x64",
            "md5": "m",
            "sha256": "s",
        },
        "pe_info": {},
        "rich_header": {"available": False},
    }
    
    overview = _build_file_overview(results)
    assert "toolset" not in overview


def test_build_file_overview_missing_fields():
    results = {
        "file_info": {},
        "pe_info": {},
        "rich_header": {},
    }
    
    overview = _build_file_overview(results)
    assert overview["filename"] == "Unknown"
    assert overview["file_type"] == "Unknown"
    assert overview["size"] == 0
    assert overview["architecture"] == "Unknown"
    assert overview["md5"] == "Unknown"
    assert overview["sha256"] == "Unknown"


def test_build_security_assessment_all_features():
    results = {
        "security": {
            "authenticode": True,
            "aslr": True,
            "dep": True,
            "cfg": True,
            "stack_canary": True,
            "safe_seh": True,
        },
        "packer": {"is_packed": False},
    }
    
    assessment = _build_security_assessment(results)
    assert assessment["is_signed"] is True
    assert assessment["is_packed"] is False
    assert assessment["packer_type"] is None
    assert assessment["security_features"]["aslr"] is True
    assert assessment["security_features"]["dep"] is True
    assert assessment["security_features"]["cfg"] is True
    assert assessment["security_features"]["stack_canary"] is True
    assert assessment["security_features"]["safe_seh"] is True


def test_build_security_assessment_packed():
    results = {
        "security": {"authenticode": False},
        "packer": {"is_packed": True, "packer_type": "UPX"},
    }
    
    assessment = _build_security_assessment(results)
    assert assessment["is_signed"] is False
    assert assessment["is_packed"] is True
    assert assessment["packer_type"] == "UPX"


def test_build_security_assessment_no_security():
    results = {
        "security": {},
        "packer": {},
    }
    
    assessment = _build_security_assessment(results)
    assert assessment["is_signed"] is False
    assert assessment["is_packed"] is False
    assert assessment["security_features"]["aslr"] is False
    assert assessment["security_features"]["dep"] is False


def test_build_threat_indicators_clean():
    results = {
        "imports": [],
        "yara_matches": [],
        "sections": [],
        "crypto": {},
    }
    
    indicators = _build_threat_indicators(results)
    assert indicators["suspicious_imports"] == 0
    assert indicators["yara_matches"] == 0
    assert indicators["entropy_warnings"] == 0
    assert indicators["suspicious_sections"] == 0
    assert indicators["crypto_indicators"] == 0


def test_build_threat_indicators_suspicious():
    results = {
        "imports": [
            {"name": "VirtualAlloc"},
            {"name": "WriteProcessMemory"},
        ],
        "yara_matches": [{"rule": "malware"}, {"rule": "trojan"}],
        "sections": [
            {"entropy": 7.5},
            {"entropy": 6.0},
        ],
        "crypto": {"matches": ["AES", "RC4"]},
    }
    
    indicators = _build_threat_indicators(results)
    assert indicators["suspicious_imports"] == 2
    assert indicators["yara_matches"] == 2
    assert indicators["entropy_warnings"] == 1
    assert indicators["crypto_indicators"] == 2


def test_build_technical_details():
    results = {
        "imports": [{"name": "a"}, {"name": "b"}],
        "sections": [{"name": ".text"}, {"name": ".data"}],
        "functions": {"count": 42},
        "crypto": {"matches": ["AES"]},
    }
    
    details = _build_technical_details(results)
    assert details["imports"] == 2
    assert details["sections"] == 2
    assert details["functions"] == 42
    assert details["crypto_matches"] == 1


def test_build_technical_details_empty():
    results = {
        "imports": [],
        "sections": [],
        "functions": {},
        "crypto": {},
    }
    
    details = _build_technical_details(results)
    assert details["imports"] == 0
    assert details["sections"] == 0
    assert details["functions"] == 0
    assert details["crypto_matches"] == 0


def test_count_suspicious_imports():
    imports = [
        {"name": "VirtualAlloc"},
        {"name": "GetProcAddress"},
        {"name": "WriteProcessMemory"},
        {"name": "CreateRemoteThread"},
        {"name": "SetThreadContext"},
    ]
    
    count = _count_suspicious_imports(imports)
    assert count == 4


def test_count_suspicious_imports_none():
    imports = [{"name": "MessageBoxA"}, {"name": "GetModuleHandleA"}]
    count = _count_suspicious_imports(imports)
    assert count == 0


def test_count_suspicious_imports_empty():
    assert _count_suspicious_imports([]) == 0


def test_count_high_entropy_sections():
    sections = [
        {"entropy": 7.5},
        {"entropy": 8.0},
        {"entropy": 6.5},
        {"entropy": 7.2},
    ]
    
    count = _count_high_entropy_sections(sections)
    assert count == 3


def test_count_high_entropy_sections_none():
    sections = [{"entropy": 6.0}, {"entropy": 5.5}]
    count = _count_high_entropy_sections(sections)
    assert count == 0


def test_count_high_entropy_sections_missing_entropy():
    sections = [{"name": ".text"}, {"entropy": 7.5}]
    count = _count_high_entropy_sections(sections)
    assert count == 1


def test_count_suspicious_sections_by_name():
    sections = [
        {"name": ".textbss"},
        {"name": "UPX0"},
        {"name": ".text"},
    ]
    
    count = _count_suspicious_sections(sections)
    assert count == 2


def test_count_suspicious_sections_by_indicator():
    sections = [
        {"name": ".text", "suspicious_indicators": ["unusual_size"]},
        {"name": ".data"},
    ]
    
    count = _count_suspicious_sections(sections)
    assert count == 1


def test_count_suspicious_sections_both():
    sections = [
        {"name": "UPX1", "suspicious_indicators": ["packed"]},
        {"name": ".rsrc", "suspicious_indicators": []},
        {"name": ".text"},
    ]
    
    count = _count_suspicious_sections(sections)
    assert count == 2


def test_count_crypto_indicators():
    crypto = {"matches": ["AES", "RC4", "SHA256"]}
    count = _count_crypto_indicators(crypto)
    assert count == 3


def test_count_crypto_indicators_empty():
    crypto = {}
    count = _count_crypto_indicators(crypto)
    assert count == 0


def test_count_crypto_indicators_no_matches():
    crypto = {"matches": []}
    count = _count_crypto_indicators(crypto)
    assert count == 0


def test_generate_recommendations_packed():
    results = {
        "packer": {"is_packed": True},
        "security": {},
        "crypto": {},
        "anti_analysis": {},
    }
    
    recommendations = _generate_recommendations(results)
    assert any("packed" in r.lower() for r in recommendations)


def test_generate_recommendations_unsigned():
    results = {
        "packer": {},
        "security": {"authenticode": False},
        "crypto": {},
        "anti_analysis": {},
    }
    
    recommendations = _generate_recommendations(results)
    assert any("unsigned" in r.lower() for r in recommendations)


def test_generate_recommendations_crypto():
    results = {
        "packer": {},
        "security": {},
        "crypto": {"matches": ["AES"]},
        "anti_analysis": {},
    }
    
    recommendations = _generate_recommendations(results)
    assert any("crypto" in r.lower() for r in recommendations)


def test_generate_recommendations_anti_debug():
    results = {
        "packer": {},
        "security": {},
        "crypto": {},
        "anti_analysis": {"anti_debug": True},
    }
    
    recommendations = _generate_recommendations(results)
    assert any("anti-debug" in r.lower() for r in recommendations)


def test_generate_recommendations_clean():
    results = {
        "packer": {},
        "security": {},
        "crypto": {},
        "anti_analysis": {},
    }
    
    recommendations = _generate_recommendations(results)
    assert len(recommendations) == 1
    assert "no immediate concerns" in recommendations[0].lower()


def test_generate_recommendations_multiple():
    results = {
        "packer": {"is_packed": True},
        "security": {"authenticode": False},
        "crypto": {"matches": ["AES"]},
        "anti_analysis": {"anti_debug": True},
    }
    
    recommendations = _generate_recommendations(results)
    assert len(recommendations) == 4


def test_result_aggregator_generate_indicators_packer():
    agg = ResultAggregator()
    results = {
        "packer": {"is_packed": True, "packer_type": "UPX"},
    }
    
    indicators = agg.generate_indicators(results)
    assert len(indicators) >= 1
    assert any(i["type"] == "Packer" for i in indicators)


def test_result_aggregator_generate_indicators_anti_debug():
    agg = ResultAggregator()
    results = {
        "anti_analysis": {"anti_debug": True},
    }
    
    indicators = agg.generate_indicators(results)
    assert any(i["type"] == "Anti-Debug" for i in indicators)


def test_result_aggregator_generate_indicators_anti_vm():
    agg = ResultAggregator()
    results = {
        "anti_analysis": {"anti_vm": True},
    }
    
    indicators = agg.generate_indicators(results)
    assert any(i["type"] == "Anti-VM" for i in indicators)


def test_result_aggregator_generate_indicators_suspicious_api():
    agg = ResultAggregator()
    results = {
        "imports": [
            {"name": "VirtualAlloc"},
            {"name": "CreateRemoteThread"},
        ],
    }
    
    indicators = agg.generate_indicators(results)
    suspicious_apis = [i for i in indicators if i["type"] == "Suspicious API"]
    assert len(suspicious_apis) == 2


def test_result_aggregator_generate_indicators_yara():
    agg = ResultAggregator()
    results = {
        "yara_matches": [
            {"rule": "malware_rule"},
            {"rule": "trojan_rule"},
        ],
    }
    
    indicators = agg.generate_indicators(results)
    yara_indicators = [i for i in indicators if i["type"] == "YARA Match"]
    assert len(yara_indicators) == 2


def test_result_aggregator_generate_indicators_combined():
    agg = ResultAggregator()
    results = {
        "packer": {"is_packed": True, "packer_type": "Themida"},
        "anti_analysis": {"anti_debug": True, "anti_vm": True},
        "imports": [{"name": "VirtualAlloc"}],
        "yara_matches": [{"rule": "malware"}],
    }
    
    indicators = agg.generate_indicators(results)
    assert len(indicators) >= 5


def test_result_aggregator_generate_indicators_empty():
    agg = ResultAggregator()
    results = {}
    
    indicators = agg.generate_indicators(results)
    assert indicators == []


def test_result_aggregator_generate_executive_summary():
    agg = ResultAggregator()
    results = {
        "file_info": {
            "name": "sample.exe",
            "file_type": "PE",
            "size": 1024,
            "architecture": "x86",
            "md5": "abc",
            "sha256": "def",
        },
        "security": {"aslr": True, "authenticode": False},
        "packer": {"is_packed": False},
        "imports": [],
        "sections": [],
        "functions": {"count": 10},
        "crypto": {},
    }
    
    summary = agg.generate_executive_summary(results)
    assert "file_overview" in summary
    assert "security_assessment" in summary
    assert "threat_indicators" in summary
    assert "technical_details" in summary
    assert "recommendations" in summary


def test_result_aggregator_generate_executive_summary_complete():
    agg = ResultAggregator()
    results = {
        "file_info": {
            "name": "test.exe",
            "file_type": "PE32",
            "size": 2048,
            "architecture": "x64",
            "md5": "123",
            "sha256": "456",
        },
        "pe_info": {"compilation_timestamp": "2024-01-01"},
        "security": {
            "authenticode": True,
            "aslr": True,
            "dep": True,
            "cfg": False,
            "stack_canary": True,
            "safe_seh": False,
        },
        "packer": {"is_packed": True, "packer_type": "UPX"},
        "anti_analysis": {"anti_debug": False, "anti_vm": False},
        "imports": [{"name": "VirtualAlloc"}],
        "yara_matches": [{"rule": "test"}],
        "sections": [{"entropy": 7.5}],
        "functions": {"count": 50},
        "crypto": {"matches": ["AES"]},
        "rich_header": {"available": False},
    }
    
    summary = agg.generate_executive_summary(results)
    
    assert summary["file_overview"]["filename"] == "test.exe"
    assert summary["security_assessment"]["is_signed"] is True
    assert summary["security_assessment"]["is_packed"] is True
    assert summary["threat_indicators"]["suspicious_imports"] == 1
    assert summary["technical_details"]["functions"] == 50


def test_result_aggregator_generate_executive_summary_error_handling():
    agg = ResultAggregator()
    
    summary = agg.generate_executive_summary(None)
    assert "error" in summary


def test_result_aggregator_indicator_severity():
    agg = ResultAggregator()
    results = {
        "packer": {"is_packed": True, "packer_type": "UPX"},
        "anti_analysis": {"anti_debug": True},
        "imports": [{"name": "VirtualAlloc"}],
        "yara_matches": [{"rule": "malware"}],
    }
    
    indicators = agg.generate_indicators(results)
    
    packer_ind = next(i for i in indicators if i["type"] == "Packer")
    assert packer_ind["severity"] == "Medium"
    
    anti_debug_ind = next(i for i in indicators if i["type"] == "Anti-Debug")
    assert anti_debug_ind["severity"] == "High"
    
    yara_ind = next(i for i in indicators if i["type"] == "YARA Match")
    assert yara_ind["severity"] == "High"


def test_result_aggregator_indicator_descriptions():
    agg = ResultAggregator()
    results = {
        "packer": {"is_packed": True, "packer_type": "Themida"},
        "anti_analysis": {"anti_debug": True, "anti_vm": True},
    }
    
    indicators = agg.generate_indicators(results)
    
    packer_ind = next(i for i in indicators if i["type"] == "Packer")
    assert "Themida" in packer_ind["description"]
    
    anti_debug_ind = next(i for i in indicators if i["type"] == "Anti-Debug")
    assert "debug" in anti_debug_ind["description"].lower()


def test_normalize_results_preserves_original():
    original = {"file_info": {"name": "test"}}
    normalized = _normalize_results(original)
    
    assert normalized["file_info"]["name"] == "test"
    assert "pe_info" in normalized
    assert "security" in normalized
