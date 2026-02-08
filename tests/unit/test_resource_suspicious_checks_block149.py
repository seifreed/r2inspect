from __future__ import annotations

from r2inspect.modules.resource_analyzer import ResourceAnalyzer


def test_resource_suspicious_checks():
    analyzer = ResourceAnalyzer(adapter=None)

    res_entropy = {"name": "res", "type_name": "RT_RCDATA", "entropy": 8.0, "size": 2000}
    res_large = {"name": "big", "type_name": "RT_ICON", "entropy": 1.0, "size": 2 * 1024 * 1024}
    res_rcdata = {"name": "rc", "type_name": "RT_RCDATA", "entropy": 1.0, "size": 20000}

    assert analyzer._check_resource_entropy(res_entropy)
    assert analyzer._check_resource_size(res_large)
    assert analyzer._check_resource_rcdata(res_rcdata)

    res_normal = {"name": "n", "type_name": "RT_ICON", "entropy": 1.0, "size": 100}
    assert analyzer._check_resource_entropy(res_normal) == []
    assert analyzer._check_resource_size(res_normal) == []
    assert analyzer._check_resource_rcdata(res_normal) == []
