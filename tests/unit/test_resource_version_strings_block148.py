from __future__ import annotations

from r2inspect.modules.resource_analyzer import ResourceAnalyzer


def test_resource_version_string_value_extraction():
    analyzer = ResourceAnalyzer(adapter=None)

    key = "ProductName"
    value = "TestApp"

    key_bytes = list(key.encode("utf-16le"))
    value_bytes = list(value.encode("utf-16le"))

    data = key_bytes + [0, 0, 0, 0] + value_bytes + [0, 0]

    extracted = analyzer._read_version_string_value(data, key)
    assert extracted == value

    assert analyzer._read_version_string_value(data, "MissingKey") == ""
    assert "ProductName" in analyzer._version_string_keys()
