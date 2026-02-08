from __future__ import annotations

from r2inspect.utils.output import OutputFormatter


def test_output_table_helpers() -> None:
    formatter = OutputFormatter({"name": "x"})

    table = formatter.format_table({"alpha": 1, "beta": {"x": 2}})
    assert table.columns[0].header == "Property"

    sections = [
        {
            "name": ".text",
            "raw_size": 10,
            "flags": "r-x",
            "entropy": 5.0,
            "suspicious_indicators": [],
        },
        {
            "name": ".bad",
            "raw_size": 1,
            "flags": "rw-",
            "entropy": 7.5,
            "suspicious_indicators": ["x"],
        },
    ]
    table_sections = formatter.format_sections(sections)
    assert table_sections.columns[0].header == "Name"
