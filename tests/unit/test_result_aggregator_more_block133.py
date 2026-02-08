from __future__ import annotations

from r2inspect.core.result_aggregator import ResultAggregator


def test_result_aggregator_indicators_and_summary():
    results = {
        "file_info": {
            "name": "sample.exe",
            "file_type": "PE",
            "size": 1234,
            "architecture": "x86",
            "md5": "aa",
            "sha256": "bb",
        },
        "pe_info": {"compilation_timestamp": "2025-01-01"},
        "rich_header": {
            "available": True,
            "compilers": [
                {"compiler_name": "MSVC", "build_number": 123},
                {"compiler_name": "MSVC", "build_number": 124},
            ],
        },
        "packer": {"is_packed": True, "packer_type": "UPX"},
        "anti_analysis": {"anti_debug": True, "anti_vm": True},
        "imports": [{"name": "VirtualAlloc"}],
        "yara_matches": [{"rule": "TestRule"}],
        "security": {"authenticode": True},
    }

    aggregator = ResultAggregator()
    indicators = aggregator.generate_indicators(results)
    assert any(ind["type"] == "Packer" for ind in indicators)
    assert any(ind["type"] == "Anti-Debug" for ind in indicators)
    assert any(ind["type"] == "YARA Match" for ind in indicators)

    summary = aggregator.generate_executive_summary(results)
    assert summary["file_overview"]["filename"] == "sample.exe"
    assert summary["security_assessment"]["is_signed"] is True
    assert summary["security_assessment"]["is_packed"] is True
