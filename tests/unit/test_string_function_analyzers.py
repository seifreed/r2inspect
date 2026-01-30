from r2inspect.modules.function_analyzer import FunctionAnalyzer
from r2inspect.modules.string_analyzer import StringAnalyzer


class FakeR2:
    def __init__(self, cmd_map=None, cmdj_map=None):
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command):
        return self._cmd_map.get(command, "")

    def cmdj(self, command):
        return self._cmdj_map.get(command)


class ConfigStub:
    def __init__(self):
        self._values = {
            ("strings", "min_length"): 4,
            ("strings", "max_length"): 100,
            ("strings", "extract_ascii"): True,
            ("strings", "extract_unicode"): True,
            ("general", "max_strings"): 1000,
        }

    def get(self, section, key, default=None):
        return self._values.get((section, key), default)


def test_string_filters_and_decoders():
    analyzer = StringAnalyzer(FakeR2(), ConfigStub())

    filtered = analyzer._filter_strings(["ok", "hello", "\x00bad", "a" * 200])
    assert "hello" in filtered
    assert "ok" not in filtered

    base64_str = "aGVsbG8="
    decoded = analyzer._decode_base64(base64_str)
    assert decoded["decoded"] == "hello"

    hex_str = "68656c6c6f"
    decoded_hex = analyzer._decode_hex(hex_str)
    assert decoded_hex["decoded"] == "hello"


def test_function_analyzer_mnemonics_and_stats():
    analyzer = FunctionAnalyzer(FakeR2())

    ops = [{"opcode": "mov eax, ebx"}, {"opcode": "ret"}, {"opcode": ""}]
    assert analyzer._extract_mnemonics_from_ops(ops) == ["mov", "ret"]

    stats = analyzer._generate_function_stats(
        [
            {"name": "f1", "size": 10},
            {"name": "f2", "size": 30},
        ]
    )
    assert stats["total_functions"] == 2
    assert stats["min_function_size"] == 10
    assert stats["max_function_size"] == 30
