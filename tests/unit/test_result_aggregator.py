from r2inspect.core.result_aggregator import ResultAggregator


def test_generate_indicators():
    results = {
        "packer": {"is_packed": True, "packer_type": "UPX"},
        "anti_analysis": {"anti_debug": True, "anti_vm": True},
        "imports": [{"name": "VirtualAlloc"}, {"name": "WriteProcessMemory"}],
        "yara_matches": [{"rule": "rule1"}],
    }
    agg = ResultAggregator()
    indicators = agg.generate_indicators(results)
    types = {i["type"] for i in indicators}
    assert "Packer" in types
    assert "Anti-Debug" in types
    assert "Anti-VM" in types
    assert "Suspicious API" in types
    assert "YARA Match" in types


def test_generate_executive_summary():
    results = {
        "file_info": {
            "name": "sample",
            "file_type": "PE",
            "size": 123,
            "architecture": "x86",
            "md5": "m",
            "sha256": "s",
        },
        "security": {"aslr": True, "dep": False, "authenticode": False},
        "packer": {"is_packed": False},
        "imports": [],
        "sections": [{"suspicious_indicators": ["x"]}],
    }
    agg = ResultAggregator()
    summary = agg.generate_executive_summary(results)
    assert summary["file_overview"]["filename"] == "sample"
    assert summary["security_assessment"]["is_signed"] is False
    assert summary["threat_indicators"]["suspicious_sections"] == 1
