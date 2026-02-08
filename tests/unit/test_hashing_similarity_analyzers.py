import hashlib

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.binbloom_analyzer import BLOOM_AVAILABLE, BinbloomAnalyzer, BloomFilter
from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer
from r2inspect.modules.binlex_analyzer import BinlexAnalyzer
from r2inspect.modules.ccbhash_analyzer import CCBHashAnalyzer
from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer
from r2inspect.modules.simhash_analyzer import SimHashAnalyzer
from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer
from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer
from r2inspect.modules.tlsh_analyzer import TLSH_AVAILABLE, TLSHAnalyzer


class FakeR2:
    def __init__(self, cmd_map=None, cmdj_map=None):
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command):
        return self._cmd_map.get(command, "")

    def cmdj(self, command):
        return self._cmdj_map.get(command)


def test_ssdeep_parse_output():
    output = "ssdeep: 1 matches (42)"
    assert SSDeepAnalyzer._parse_ssdeep_output(output) == 42
    assert SSDeepAnalyzer._parse_ssdeep_output("no matches") is None


def test_telfhash_symbol_filtering_and_names():
    analyzer = TelfhashAnalyzer(R2PipeAdapter(FakeR2()), filepath="/tmp/sample.elf")
    symbols = [
        {"type": "FUNC", "bind": "GLOBAL", "name": "printf"},
        {"type": "OBJECT", "bind": "WEAK", "name": "data"},
        {"type": "FUNC", "bind": "LOCAL", "name": "local"},
        {"type": "SECTION", "bind": "GLOBAL", "name": "skip"},
        {"type": "FUNC", "bind": "GLOBAL", "name": "_start"},
    ]
    filtered = analyzer._filter_symbols_for_telfhash(symbols)
    assert len(filtered) == 2
    names = analyzer._extract_symbol_names(filtered)
    assert names == ["data", "printf"]


def test_impfuzzy_process_imports(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 10)
    analyzer = ImpfuzzyAnalyzer(R2PipeAdapter(FakeR2()), filepath=str(sample))

    imports = [
        {"libname": "KERNEL32.dll", "name": "CreateFileA"},
        {"libname": "USER32.dll", "name": "ord_12"},
        {"lib": "ADVAPI32.dll", "function": "RegSetValue"},
    ]
    processed = analyzer._process_imports(imports)
    assert processed == ["advapi32.regsetvalue", "kernel32.createfilea"]
    assert analyzer._is_pe_file() is True


def test_simhash_helpers():
    analyzer = SimHashAnalyzer(R2PipeAdapter(FakeR2()), filepath="/tmp/sample.bin")
    assert analyzer._get_length_category(4) == "short"
    assert analyzer._get_length_category(10) == "medium"
    assert analyzer._get_length_category(40) == "long"
    assert analyzer._get_length_category(200) == "very_long"

    assert analyzer._classify_string_type("http://example.com") == "url"
    assert analyzer._classify_string_type("C:\\Windows") == "path"
    assert analyzer._classify_string_type("HKEY_LOCAL_MACHINE\\Software") == "registry"
    assert analyzer._classify_string_type("CreateFileW") == "api"
    assert analyzer._classify_string_type("error: failed") == "error"

    assert analyzer._is_useful_string("deadbeef") is False
    assert analyzer._is_useful_string("hello world") is True


def test_binlex_similarity_score():
    analyzer = BinlexAnalyzer(R2PipeAdapter(FakeR2()), filepath="/tmp/sample.bin")
    score = analyzer.get_function_similarity_score(["a", "b"], ["b", "c"])
    assert score == 1 / 3
    assert analyzer.compare_functions("sig", "sig") is True


def test_ccbhash_function_and_binary_hash():
    cfg = [{"edges": [{"src": 1, "dst": 2}, {"src": 2, "dst": 3}], "blocks": []}]
    r2 = FakeR2(cmdj_map={"agj": cfg})
    analyzer = CCBHashAnalyzer(R2PipeAdapter(r2), filepath="/tmp/sample.bin")

    expected_canonical = "1->2|2->3"
    expected = hashlib.sha256(expected_canonical.encode("utf-8")).hexdigest()
    assert analyzer._calculate_function_ccbhash(4096, "func") == expected

    function_hashes = {
        "f1": {"ccbhash": "a" * 64},
        "f2": {"ccbhash": "b" * 64},
    }
    combined = hashlib.sha256(("a" * 64 + "|" + "b" * 64).encode("utf-8")).hexdigest()
    assert analyzer._calculate_binary_ccbhash(function_hashes) == combined


def test_bindiff_helpers():
    analyzer = BinDiffAnalyzer(R2PipeAdapter(FakeR2()), filepath="/tmp/sample.bin")
    cfg = {"edges": [1, 2, 3], "blocks": [1, 2]}
    assert analyzer._calculate_cyclomatic_complexity(cfg) == 3

    data = b"a" * 100
    hashes = analyzer._calculate_rolling_hash(data, window_size=10)
    assert len(hashes) == 91

    assert analyzer._is_api_string("CreateProcessA") is True
    assert analyzer._is_url_string("https://example.com") is True
    assert analyzer._is_path_string("C:\\temp\\a.txt") is True


def test_binbloom_serialize_deserialize_roundtrip():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")

    analyzer = BinbloomAnalyzer(FakeR2(), filepath="/tmp/sample.bin")
    bloom = BloomFilter(capacity=10, error_rate=0.01)
    bloom.add("alpha")
    bloom.add("beta")

    blob = analyzer._serialize_bloom(bloom)
    restored = BinbloomAnalyzer.deserialize_bloom(blob)

    assert restored is not None
    assert restored.capacity == bloom.capacity
    assert restored.count == bloom.count
    assert "alpha" in restored


def test_tlsh_binary_hash(tmp_path):
    if not TLSH_AVAILABLE:
        pytest.skip("tlsh library not available")

    sample = tmp_path / "sample.bin"
    sample.write_bytes(bytes(range(256)) * 2)
    analyzer = TLSHAnalyzer(R2PipeAdapter(FakeR2()), filename=str(sample))
    value = analyzer._calculate_binary_tlsh()
    assert isinstance(value, str) and value
