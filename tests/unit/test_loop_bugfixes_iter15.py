"""Regression tests for loop iteration 15.

1. ``R2PipeAdapter.execute_command`` decided JSON-vs-text from the full command
   string, so an addressed JSON command like ``aflj @ 0x401000`` (which ends in
   a digit) took the text path and returned a raw string instead of the parsed
   list. JSON-ness is now decided by the base command token.
2. ``validate_extensions_input`` rejected empty segments from a trailing/double
   comma ("exe,") as invalid extensions; such segments are now skipped.
"""

from __future__ import annotations

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.cli.validator_rules import validate_extensions_input
from r2inspect.testing.fake_r2 import FakeR2


def test_execute_command_addressed_json_returns_parsed_list():
    r2 = FakeR2(cmdj_map={"aflj @ 0x401000": [{"name": "main"}]})
    adapter = R2PipeAdapter(r2)
    result = adapter.execute_command("aflj @ 0x401000")
    assert result == [{"name": "main"}]


def test_execute_command_addressed_text_still_text():
    r2 = FakeR2(cmd_map={"pd 1 @ 0x401000": "nop"})
    adapter = R2PipeAdapter(r2)
    assert adapter.execute_command("pd 1 @ 0x401000") == "nop"


def test_validate_extensions_tolerates_trailing_comma():
    assert validate_extensions_input("exe,") == []
    assert validate_extensions_input("exe,,dll") == []
    assert validate_extensions_input("exe, ,dll") == []


def test_validate_extensions_still_flags_real_invalid():
    assert validate_extensions_input("exe,@bad") != []
