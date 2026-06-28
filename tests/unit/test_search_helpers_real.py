from __future__ import annotations

from r2inspect.modules.search_helpers import (
    search_executable_hex,
    search_hex,
    search_text,
)


class DummyAdapter:
    def __init__(self) -> None:
        self.text_calls: list[str] = []
        self.hex_calls: list[str] = []

    def search_text(self, pattern: str) -> str:
        self.text_calls.append(pattern)
        return f"text:{pattern}"

    def search_hex(self, pattern: str) -> str:
        self.hex_calls.append(pattern)
        return f"hex:{pattern}"


def test_search_helpers_normalize_pattern():
    adapter = DummyAdapter()
    assert search_text(adapter, "  nop  ") == "text:nop"
    assert adapter.text_calls == ["nop"]

    assert search_hex(adapter, " 90  ") == "hex:90"
    assert adapter.hex_calls == ["90"]


def test_search_executable_hex_normalizes_and_passes_through():
    class ExecAdapter:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def search_executable_hex(self, pattern: str) -> str:
            self.calls.append(pattern)
            return f"exec:{pattern}"

    adapter = ExecAdapter()
    assert search_executable_hex(adapter, "  0f31 ") == "exec:0f31"
    assert adapter.calls == ["0f31"]


def test_search_executable_hex_returns_none_on_bad_inputs():
    class NonStr:
        def search_executable_hex(self, pattern: str) -> int:
            return 123

    assert search_executable_hex(DummyAdapter(), "0f31") is None  # adapter lacks method
    assert search_executable_hex(None, "0f31") is None  # no adapter
    assert search_executable_hex(DummyAdapter(), "   ") is None  # empty pattern
    assert search_executable_hex(NonStr(), "0f31") is None  # non-str result
