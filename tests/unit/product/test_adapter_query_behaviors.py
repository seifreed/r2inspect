from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from r2inspect.adapters.r2pipe_queries import R2PipeQueryMixin
from r2inspect.adapters.validation import (
    is_valid_r2_response,
    sanitize_r2_output,
    validate_address,
    validate_r2_data,
    validate_size,
)


class StubR2:
    def __init__(self, cmdj_responses: dict[str, Any] | None = None) -> None:
        self._cmdj_responses = cmdj_responses or {}

    def cmd(self, _command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return self._cmdj_responses.get(command)


class QueryAdapter(R2PipeQueryMixin):
    def __init__(self, stub: StubR2) -> None:
        self._stub = stub
        self._cache: dict[str, Any] = {}

    def cmd(self, command: str) -> str:
        return self._stub.cmd(command)

    def cmdj(self, command: str) -> Any:
        return self._stub.cmdj(command)

    def _maybe_force_error(self, _method: str) -> None:
        return None

    def _cached_query(
        self,
        cmd: str,
        data_type: str = "list",
        default: list | dict | None = None,
        error_msg: str = "",
        *,
        cache: bool = True,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        if cache and cmd in self._cache:
            return self._cache[cmd]

        result_raw = self._stub.cmdj(cmd)
        if result_raw is None:
            result_raw = default if default is not None else ([] if data_type == "list" else {})

        validated = validate_r2_data(result_raw, data_type)
        if cache:
            self._cache[cmd] = validated
        return validated


def test_validation_helpers_normalize_r2_data_and_numeric_inputs() -> None:
    cleaned = validate_r2_data({"name": "foo&nbsp;bar"}, "dict")
    listing = validate_r2_data([{"ok": 1}, "bad"], "list")

    assert cleaned["name"] == "foo bar"
    assert listing == [{"ok": 1}]
    assert sanitize_r2_output("  before \x1b[0m after  ").strip() == "before  after"
    assert is_valid_r2_response({"ok": True}) is True
    assert validate_address("0x20") == 32
    assert validate_size("0x40") == 64


def test_query_mixin_safe_cached_query_returns_validated_cached_results() -> None:
    adapter = QueryAdapter(StubR2({"ijj": [{"name": "alpha"}, "bad"]}))

    first = adapter._safe_cached_query("ijj", "list", [], error_label="demo query")
    adapter._stub._cmdj_responses["ijj"] = [{"name": "mutated"}]
    second = adapter._safe_cached_query("ijj", "list", [], error_label="demo query")

    assert first == [{"name": "alpha"}]
    assert second == [{"name": "alpha"}]


def test_query_mixin_safe_cached_query_falls_back_to_default_on_errors() -> None:
    class BrokenAdapter(QueryAdapter):
        def _cached_query(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]] | dict[str, Any]:
            raise RuntimeError("boom")

    adapter = BrokenAdapter(StubR2())
    result = adapter._safe_cached_query("ijj", "list", [], error_label="broken query")
    assert result == []
