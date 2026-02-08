from __future__ import annotations

from r2inspect.utils.output import OutputFormatter


def test_output_extract_names_from_list():
    formatter = OutputFormatter({"items": [{"name": "a"}, {"name": "b"}]})
    result = formatter._extract_names_from_list(formatter.results, "items")
    assert result == "a, b"

    formatter = OutputFormatter({"items": [{"rule": "r1"}, {"rule": "r2"}]})
    result = formatter._extract_names_from_list(formatter.results, "items", name_field="rule")
    assert result == "r1, r2"

    formatter = OutputFormatter({"items": "notalist"})
    assert formatter._extract_names_from_list(formatter.results, "items") == ""
