from __future__ import annotations

from r2inspect.modules.search_helpers import search_hex, search_text


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
    assert search_text(adapter, None, "  nop  ") == "text:nop"
    assert adapter.text_calls == ["nop"]

    assert search_hex(adapter, None, " 90  ") == "hex:90"
    assert adapter.hex_calls == ["90"]
