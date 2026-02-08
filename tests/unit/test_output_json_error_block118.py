from __future__ import annotations

import json

from r2inspect.utils.output import OutputFormatter


class _BadStr:
    def __str__(self) -> str:
        raise RuntimeError("boom")


def test_output_formatter_json_error_path():
    formatter = OutputFormatter({"bad": _BadStr()})
    payload = formatter.to_json()
    data = json.loads(payload)
    assert "error" in data
    assert "partial_results" in data
