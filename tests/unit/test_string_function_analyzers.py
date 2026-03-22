from r2inspect.modules.function_analyzer import FunctionAnalyzer
from r2inspect.domain.formats.string import decode_base64, decode_hex, filter_strings
from r2inspect.testing.fake_r2 import FakeR2


class _Strings:
    min_length = 4
    max_length = 100
    extract_ascii = True
    extract_unicode = True


class _General:
    max_strings = 1000


class ConfigStub:
    class typed_config:
        strings = _Strings()
        general = _General()


def test_string_filters_and_decoders():
    filtered = filter_strings(["ok", "hello", "\x00bad", "a" * 200], 4, 100)
    assert "hello" in filtered
    assert "ok" not in filtered

    base64_str = "aGVsbG8="
    decoded = decode_base64(base64_str)
    assert decoded["decoded"] == "hello"

    hex_str = "68656c6c6f"
    decoded_hex = decode_hex(hex_str)
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
