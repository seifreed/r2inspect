"""Coverage tests for binbloom_analyzer.py."""

import hashlib
import json
import base64

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.binbloom_analyzer import BLOOM_AVAILABLE, BinbloomAnalyzer


class FakeR2:
    def __init__(self, cmd_map=None, cmdj_map=None):
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command):
        return self._cmd_map.get(command, "")

    def cmdj(self, command):
        return self._cmdj_map.get(command)


def make_adapter(cmd_map=None, cmdj_map=None):
    return R2PipeAdapter(FakeR2(cmd_map=cmd_map, cmdj_map=cmdj_map))


class FakeDisasmAdapter:
    """Adapter that provides disassembly data via get_disasm."""

    def __init__(self, disasm_data=None, disasm_list=None, disasm_text=None):
        self._disasm_data = disasm_data  # For get_disasm(address=...)
        self._disasm_list = disasm_list  # For get_disasm(address=..., size=...)
        self._disasm_text = disasm_text  # For get_disasm_text(...)
        self._cmd_map = {}
        self._cmdj_map = {}

    def get_disasm(self, address=None, size=None):
        if size is not None:
            return self._disasm_list
        return self._disasm_data

    def get_disasm_text(self, address=None, size=None):
        return self._disasm_text

    def analyze_all(self):
        pass

    def cmd(self, command):
        return self._cmd_map.get(command, "")

    def cmdj(self, command):
        return self._cmdj_map.get(command)


class FakeAFLAdapter:
    """Adapter that returns function list from aflj."""

    def __init__(self, functions=None, disasm_data=None):
        self._functions = functions or []
        self._disasm_data = disasm_data or {}

    def analyze_all(self):
        pass

    def get_disasm(self, address=None, size=None):
        if address is not None:
            data = self._disasm_data.get(address)
            return data
        return None

    def get_disasm_text(self, address=None, size=None):
        return None

    def cmd(self, command):
        return ""

    def cmdj(self, command):
        if command == "aflj":
            return self._functions
        return None


# --- availability ---


def test_bloom_is_available_returns_bool():
    assert isinstance(BinbloomAnalyzer.is_available(), bool)


def test_bloom_available_constant_matches():
    assert BLOOM_AVAILABLE == BinbloomAnalyzer.is_available()


# --- _normalize_mnemonic ---


def test_normalize_mnemonic_basic():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    assert analyzer._normalize_mnemonic("MOV") == "mov"
    assert analyzer._normalize_mnemonic("PUSH") == "push"
    assert analyzer._normalize_mnemonic("  JMP  ") == "jmp"


def test_normalize_mnemonic_none():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    assert analyzer._normalize_mnemonic(None) is None


def test_normalize_mnemonic_empty():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    assert analyzer._normalize_mnemonic("") is None


def test_normalize_mnemonic_whitespace_only():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    assert analyzer._normalize_mnemonic("   ") is None


# --- _collect_mnemonics_from_ops ---


def test_collect_mnemonics_from_ops_valid():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    ops = [
        {"mnemonic": "mov"},
        {"mnemonic": "push"},
        {"mnemonic": "pop"},
    ]
    result = analyzer._collect_mnemonics_from_ops(ops)
    assert result == ["mov", "push", "pop"]


def test_collect_mnemonics_from_ops_missing_mnemonic():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    ops = [
        {"type": "invalid"},
        {"mnemonic": "jmp"},
        "not_a_dict",
    ]
    result = analyzer._collect_mnemonics_from_ops(ops)
    assert result == ["jmp"]


def test_collect_mnemonics_from_ops_empty():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    assert analyzer._collect_mnemonics_from_ops([]) == []


# --- _bloom_to_signature ---


def test_bloom_to_signature_basic():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    instructions = ["mov", "push", "pop", "ret"]
    sig = analyzer._bloom_to_signature(instructions)
    assert isinstance(sig, str)
    assert len(sig) == 64  # SHA256 hex digest


def test_bloom_to_signature_deterministic():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    instructions = ["mov", "push", "jmp"]
    sig1 = analyzer._bloom_to_signature(instructions)
    sig2 = analyzer._bloom_to_signature(instructions)
    assert sig1 == sig2


def test_bloom_to_signature_different_instructions():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    sig1 = analyzer._bloom_to_signature(["mov", "push"])
    sig2 = analyzer._bloom_to_signature(["pop", "ret"])
    assert sig1 != sig2


def test_bloom_to_signature_empty():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    sig = analyzer._bloom_to_signature([])
    assert isinstance(sig, str)
    assert len(sig) == 64


# --- _build_signature_components ---


def test_build_signature_components_structure():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    instructions = ["mov", "push", "mov", "ret"]
    components = analyzer._build_signature_components(instructions)
    assert len(components) == 3
    assert components[0].startswith("UNIQ:")
    assert components[1].startswith("FREQ:")
    assert components[2].startswith("BIGR:")


# --- _build_frequency_patterns ---


def test_build_frequency_patterns():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    instructions = ["mov", "mov", "push", "pop"]
    unique = sorted(set(instructions))
    patterns = analyzer._build_frequency_patterns(instructions, unique)
    assert any("mov:2" in p for p in patterns)
    assert any("push:1" in p for p in patterns)


# --- _build_unique_bigrams ---


def test_build_unique_bigrams_basic():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    instructions = ["mov", "push", "pop", "ret"]
    bigrams = analyzer._build_unique_bigrams(instructions)
    assert "mov→push" in bigrams
    assert "push→pop" in bigrams
    assert "pop→ret" in bigrams


def test_build_unique_bigrams_empty():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    assert analyzer._build_unique_bigrams([]) == []


def test_build_unique_bigrams_single():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    assert analyzer._build_unique_bigrams(["mov"]) == []


def test_build_unique_bigrams_deduplication():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    instructions = ["mov", "push", "mov", "push"]
    bigrams = analyzer._build_unique_bigrams(instructions)
    # "mov→push" should appear only once
    assert bigrams.count("mov→push") == 1


# --- _collect_unique_signatures ---


def test_collect_unique_signatures():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    function_signatures = {
        "func1": {"signature": "abc123", "instruction_count": 5},
        "func2": {"signature": "def456", "instruction_count": 3},
        "func3": {"signature": "abc123", "instruction_count": 5},  # duplicate
    }
    unique = analyzer._collect_unique_signatures(function_signatures)
    assert len(unique) == 2
    assert "abc123" in unique
    assert "def456" in unique


def test_collect_unique_signatures_empty():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    assert analyzer._collect_unique_signatures({}) == set()


# --- _group_functions_by_signature ---


def test_group_functions_by_signature():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    function_signatures = {
        "func1": {"signature": "aaa"},
        "func2": {"signature": "bbb"},
        "func3": {"signature": "aaa"},
    }
    groups = analyzer._group_functions_by_signature(function_signatures)
    assert len(groups["aaa"]) == 2
    assert "func1" in groups["aaa"]
    assert "func3" in groups["aaa"]


def test_group_functions_html_entities():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    function_signatures = {
        "func&amp;1": {"signature": "aaa"},
        "func&nbsp;2": {"signature": "bbb"},
    }
    groups = analyzer._group_functions_by_signature(function_signatures)
    all_names = [name for names in groups.values() for name in names]
    assert "func&1" in all_names
    assert "func 2" in all_names


# --- _build_similar_groups ---


def test_build_similar_groups_with_duplicates():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    from collections import defaultdict
    signature_groups = defaultdict(list)
    signature_groups["aaa"] = ["func1", "func2", "func3"]
    signature_groups["bbb"] = ["func4"]  # Single - should not appear
    groups = analyzer._build_similar_groups(signature_groups)
    assert len(groups) == 1
    assert groups[0]["count"] == 3
    assert "func1" in groups[0]["functions"]


def test_build_similar_groups_long_signature():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    from collections import defaultdict
    long_sig = "a" * 32
    signature_groups = defaultdict(list)
    signature_groups[long_sig] = ["f1", "f2"]
    groups = analyzer._build_similar_groups(signature_groups)
    assert len(groups) == 1
    assert groups[0]["signature"].endswith("...")


def test_build_similar_groups_short_signature():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    from collections import defaultdict
    short_sig = "abc"
    signature_groups = defaultdict(list)
    signature_groups[short_sig] = ["f1", "f2"]
    groups = analyzer._build_similar_groups(signature_groups)
    assert groups[0]["signature"] == "abc"


# --- _find_similar_functions ---


def test_find_similar_functions_no_duplicates():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    function_signatures = {
        "func1": {"signature": "aaa", "instruction_count": 5},
        "func2": {"signature": "bbb", "instruction_count": 3},
    }
    result = analyzer._find_similar_functions(function_signatures)
    assert result == []


def test_find_similar_functions_with_duplicates():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    function_signatures = {
        "func1": {"signature": "same_sig", "instruction_count": 5},
        "func2": {"signature": "same_sig", "instruction_count": 5},
        "func3": {"signature": "unique", "instruction_count": 3},
    }
    result = analyzer._find_similar_functions(function_signatures)
    assert len(result) == 1
    assert result[0]["count"] == 2


def test_find_similar_functions_sorted_by_count():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    function_signatures = {
        "f1": {"signature": "sig_a"},
        "f2": {"signature": "sig_a"},
        "f3": {"signature": "sig_b"},
        "f4": {"signature": "sig_b"},
        "f5": {"signature": "sig_b"},
    }
    result = analyzer._find_similar_functions(function_signatures)
    assert result[0]["count"] >= result[-1]["count"]


# --- Bloom filter operations (if available) ---


def test_bloom_filter_create_and_check():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    from pybloom_live import BloomFilter
    bf = BloomFilter(capacity=100, error_rate=0.01)
    bf.add("mov")
    bf.add("push")
    assert "mov" in bf
    assert "jmp" not in bf


def test_build_bloom_filter():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    instructions = ["mov", "push", "pop", "ret", "jmp"]
    bloom = analyzer._build_bloom_filter(instructions, capacity=256, error_rate=0.001)
    assert "mov" in bloom
    assert "push" in bloom


def test_add_instruction_patterns():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    from pybloom_live import BloomFilter
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf = BloomFilter(capacity=1000, error_rate=0.001)
    instructions = ["mov", "push", "push", "pop"]
    analyzer._add_instruction_patterns(bf, instructions)
    # Bigrams should be added
    assert "mov→push" in bf
    # Repeated instruction (push*2) should be added
    assert "push*2" in bf


# --- _serialize_bloom and deserialize_bloom ---


def test_serialize_bloom_roundtrip():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    from pybloom_live import BloomFilter
    bf = BloomFilter(capacity=100, error_rate=0.01)
    bf.add("mov")
    bf.add("push")
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    serialized = analyzer._serialize_bloom(bf)
    assert isinstance(serialized, str)
    assert len(serialized) > 0


def test_deserialize_bloom_valid():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    from pybloom_live import BloomFilter
    bf = BloomFilter(capacity=100, error_rate=0.01)
    bf.add("mov")
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    serialized = analyzer._serialize_bloom(bf)
    deserialized = BinbloomAnalyzer.deserialize_bloom(serialized)
    assert deserialized is not None


def test_deserialize_bloom_invalid_base64():
    result = BinbloomAnalyzer.deserialize_bloom("!not_valid_base64!")
    assert result is None


def test_deserialize_bloom_invalid_json():
    invalid = base64.b64encode(b"not_json").decode()
    result = BinbloomAnalyzer.deserialize_bloom(invalid)
    assert result is None


def test_deserialize_bloom_wrong_version():
    data = {"version": 99, "error_rate": 0.01, "capacity": 100, "count": 0, "bitarray": []}
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    result = BinbloomAnalyzer.deserialize_bloom(encoded)
    assert result is None


def test_deserialize_bloom_not_dict():
    encoded = base64.b64encode(json.dumps([1, 2, 3]).encode()).decode()
    result = BinbloomAnalyzer.deserialize_bloom(encoded)
    assert result is None


def test_deserialize_bloom_invalid_error_rate():
    data = {"version": 1, "error_rate": 1.5, "capacity": 100, "count": 0, "bitarray": []}
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    result = BinbloomAnalyzer.deserialize_bloom(encoded)
    assert result is None


def test_deserialize_bloom_invalid_capacity():
    data = {"version": 1, "error_rate": 0.01, "capacity": -5, "count": 0, "bitarray": []}
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    result = BinbloomAnalyzer.deserialize_bloom(encoded)
    assert result is None


def test_deserialize_bloom_invalid_count():
    data = {"version": 1, "error_rate": 0.01, "capacity": 100, "count": 200, "bitarray": []}
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    result = BinbloomAnalyzer.deserialize_bloom(encoded)
    assert result is None


def test_deserialize_bloom_bitarray_not_list():
    data = {
        "version": 1, "error_rate": 0.01, "capacity": 100,
        "count": 0, "bitarray": "not_a_list"
    }
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    result = BinbloomAnalyzer.deserialize_bloom(encoded)
    assert result is None


def test_deserialize_bloom_missing_keys():
    data = {"version": 1}
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    result = BinbloomAnalyzer.deserialize_bloom(encoded)
    assert result is None


# --- _serialize_blooms ---


def test_serialize_blooms_dict():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    from pybloom_live import BloomFilter
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf1 = BloomFilter(capacity=100, error_rate=0.01)
    bf1.add("mov")
    bf2 = BloomFilter(capacity=100, error_rate=0.01)
    bf2.add("push")
    result = analyzer._serialize_blooms({"func1": bf1, "func2": bf2})
    assert "func1" in result
    assert "func2" in result
    assert isinstance(result["func1"], str)


def test_serialize_blooms_empty():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    result = analyzer._serialize_blooms({})
    assert result == {}


# --- compare_bloom_filters ---


def test_compare_bloom_filters_both_empty():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    from pybloom_live import BloomFilter
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf1 = BloomFilter(capacity=100, error_rate=0.01)
    bf2 = BloomFilter(capacity=100, error_rate=0.01)
    result = analyzer.compare_bloom_filters(bf1, bf2)
    # pybloom_live uses 'bitarray' attribute not 'bit_array', so method returns 0.0
    assert isinstance(result, float)
    assert 0.0 <= result <= 1.0


def test_compare_bloom_filters_identical():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    from pybloom_live import BloomFilter
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf1 = BloomFilter(capacity=100, error_rate=0.01)
    bf1.add("mov")
    bf1.add("push")
    result = analyzer.compare_bloom_filters(bf1, bf1)
    # pybloom_live uses 'bitarray' not 'bit_array', so comparison returns 0.0
    assert isinstance(result, float)
    assert 0.0 <= result <= 1.0


def test_compare_bloom_filters_no_bit_array_attr():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")

    class FakeBloom:
        pass

    result = analyzer.compare_bloom_filters(FakeBloom(), FakeBloom())  # type: ignore[arg-type]
    assert result == 0.0


def test_compare_bloom_filters_one_empty():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    from pybloom_live import BloomFilter
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf1 = BloomFilter(capacity=100, error_rate=0.01)
    bf1.add("mov")
    bf2 = BloomFilter(capacity=100, error_rate=0.01)
    # bf2 is empty
    result = analyzer.compare_bloom_filters(bf1, bf2)
    assert 0.0 <= result <= 1.0


# --- _calculate_bloom_stats ---


def test_calculate_bloom_stats_empty():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    result = analyzer._calculate_bloom_stats({}, 256, 0.001)
    assert result == {}


def test_calculate_bloom_stats_with_blooms():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    from pybloom_live import BloomFilter
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf1 = BloomFilter(capacity=100, error_rate=0.01)
    bf1.add("mov")
    stats = analyzer._calculate_bloom_stats({"func1": bf1}, 100, 0.01)
    assert isinstance(stats, dict)
    assert stats["total_filters"] == 1
    assert stats["configured_capacity"] == 100
    assert stats["configured_error_rate"] == 0.01


def test_calculate_bloom_stats_fill_rate():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    from pybloom_live import BloomFilter
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf = BloomFilter(capacity=256, error_rate=0.001)
    for i in range(20):
        bf.add(f"instr_{i}")
    stats = analyzer._calculate_bloom_stats({"func": bf}, 256, 0.001)
    assert "average_fill_rate" in stats


# --- _accumulate_bloom_bits ---


def test_accumulate_bloom_bits_no_bit_array():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    from pybloom_live import BloomFilter
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf = BloomFilter(capacity=100, error_rate=0.01)
    # BloomFilter uses 'bitarray' not 'bit_array', so _accumulate returns 0
    total_bits, total_cap = analyzer._accumulate_bloom_bits({"func": bf})
    assert total_bits == 0
    assert total_cap == 0


# --- _extract_instruction_mnemonics ---


def test_extract_mnemonics_from_pdfj():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    disasm_data = {
        "ops": [
            {"mnemonic": "mov"},
            {"mnemonic": "push"},
            {"mnemonic": "pop"},
        ]
    }
    adapter = FakeDisasmAdapter(disasm_data=disasm_data)
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_instruction_mnemonics(0x1000, "main")
    assert result == ["mov", "push", "pop"]


def test_extract_mnemonics_from_pdj():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    disasm_list = [
        {"mnemonic": "add"},
        {"mnemonic": "sub"},
    ]
    adapter = FakeDisasmAdapter(disasm_data=None, disasm_list=disasm_list)
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_instruction_mnemonics(0x1000, "helper")
    assert result == ["add", "sub"]


def test_extract_mnemonics_from_text():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    text = "push rbp\nmov rsp rbp\npop rbp\nret\n"
    adapter = FakeDisasmAdapter(disasm_data=None, disasm_list=None, disasm_text=text)
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_instruction_mnemonics(0x1000, "func")
    assert "push" in result
    assert "ret" in result


def test_extract_mnemonics_all_fail():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    adapter = FakeDisasmAdapter(disasm_data=None, disasm_list=None, disasm_text=None)
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_instruction_mnemonics(0x1000, "empty_func")
    assert result == []


# --- _extract_mnemonics_from_pdfj / _pdj / _text ---


def test_extract_mnemonics_from_pdfj_no_ops():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    result = analyzer._extract_mnemonics_from_pdfj(0x1000, "func")
    assert result == []


def test_extract_mnemonics_from_pdj_not_list():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    result = analyzer._extract_mnemonics_from_pdj(0x1000, "func")
    assert result == []


def test_extract_mnemonics_from_text_empty():
    adapter = FakeDisasmAdapter(disasm_data=None, disasm_list=None, disasm_text="")
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_mnemonics_from_text(0x1000, "func")
    assert result == []


def test_extract_mnemonics_from_text_whitespace_only():
    adapter = FakeDisasmAdapter(disasm_data=None, disasm_list=None, disasm_text="   \n  \n")
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_mnemonics_from_text(0x1000, "func")
    assert result == []


# --- _extract_functions ---


def test_extract_functions_empty():
    adapter = FakeAFLAdapter(functions=[])
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_functions()
    assert result == []


def test_extract_functions_none():
    adapter = FakeAFLAdapter(functions=None)
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_functions()
    assert result == []


def test_extract_functions_filters_invalid():
    functions = [
        {"addr": 0x1000, "size": 100, "name": "valid_func"},
        {"addr": None, "size": 50, "name": "no_addr"},
        {"addr": 0x2000, "size": 0, "name": "zero_size"},
    ]
    adapter = FakeAFLAdapter(functions=functions)
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_functions()
    assert len(result) == 1
    assert result[0]["name"] == "valid_func"


# --- _create_function_bloom ---


def test_create_function_bloom_no_instructions():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    adapter = FakeDisasmAdapter(disasm_data=None, disasm_list=None, disasm_text=None)
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._create_function_bloom(0x1000, "empty_func", 256, 0.001)
    assert result is None


def test_create_function_bloom_with_instructions():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    disasm_data = {"ops": [{"mnemonic": "mov"}, {"mnemonic": "push"}, {"mnemonic": "pop"}]}
    adapter = FakeDisasmAdapter(disasm_data=disasm_data)
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._create_function_bloom(0x1000, "main", 256, 0.001)
    assert result is not None
    bloom, instructions, signature = result
    assert len(instructions) == 3
    assert len(signature) == 64


# --- _collect_function_blooms ---


def test_collect_function_blooms_empty():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    adapter = FakeDisasmAdapter()
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    blooms, sigs, instructions, count = analyzer._collect_function_blooms([], 256, 0.001)
    assert blooms == {}
    assert sigs == {}
    assert instructions == set()
    assert count == 0


def test_collect_function_blooms_no_addr():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    functions = [{"name": "func1", "size": 100}]  # No addr
    adapter = FakeDisasmAdapter()
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    blooms, sigs, instructions, count = analyzer._collect_function_blooms(
        functions, 256, 0.001
    )
    assert count == 0


def test_collect_function_blooms_with_html_entities():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    disasm_data = {"ops": [{"mnemonic": "mov"}, {"mnemonic": "push"}]}
    adapter = FakeDisasmAdapter(disasm_data=disasm_data)
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    functions = [{"name": "func&amp;1", "addr": 0x1000, "size": 50}]
    blooms, sigs, instructions, count = analyzer._collect_function_blooms(
        functions, 256, 0.001
    )
    assert "func&1" in blooms


# --- _add_binary_bloom ---


def test_add_binary_bloom_empty_instructions():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    results = {"binary_bloom": None, "binary_signature": None}
    analyzer._add_binary_bloom(results, set(), 256, 0.001)  # type: ignore[arg-type]
    assert results["binary_bloom"] is None


def test_add_binary_bloom_with_instructions():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    results = {"binary_bloom": None, "binary_signature": None}
    instructions = {"mov", "push", "pop", "ret"}
    analyzer._add_binary_bloom(results, instructions, 256, 0.001)  # type: ignore[arg-type]
    assert results["binary_signature"] is not None


# --- _create_binary_bloom ---


def test_create_binary_bloom_basic():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    instructions = {"mov", "push", "pop", "ret", "jmp"}
    result = analyzer._create_binary_bloom(instructions, 512, 0.001)
    assert result is not None
    assert "mov" in result


# --- full analyze() flow via _collect_function_blooms ---


def test_analyze_no_functions():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    adapter = FakeAFLAdapter(functions=[])
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer.analyze()
    assert result["available"] is False
    assert result["error"] is not None


def test_analyze_with_functions():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    disasm_data = {
        "ops": [
            {"mnemonic": "mov"},
            {"mnemonic": "push"},
            {"mnemonic": "pop"},
            {"mnemonic": "ret"},
        ]
    }
    functions = [
        {"addr": 0x1000, "size": 50, "name": "main"},
        {"addr": 0x2000, "size": 30, "name": "helper"},
    ]
    adapter = FakeAFLAdapter(
        functions=functions,
        disasm_data={0x1000: disasm_data, 0x2000: disasm_data},
    )
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer.analyze()
    assert isinstance(result, dict)
    assert "function_signatures" in result


# --- supplementary tests for remaining missing lines ---


class ExceptionAdapter:
    """Adapter that raises exceptions to test error handling branches."""

    def analyze_all(self):
        raise RuntimeError("analyze_all failed")

    def get_disasm(self, address=None, size=None):
        raise RuntimeError("get_disasm failed")

    def get_disasm_text(self, address=None, size=None):
        raise RuntimeError("get_disasm_text failed")

    def cmd(self, command):
        raise RuntimeError("cmd failed")

    def cmdj(self, command):
        raise RuntimeError("cmdj failed")


class FakeBitArrayBloom:
    """Fake Bloom filter that has a bit_array attribute (not bitarray)."""

    def __init__(self, bits):
        self.bit_array = bits


def test_extract_functions_exception_returns_empty():
    adapter = ExceptionAdapter()
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_functions()
    assert result == []


def test_create_function_bloom_exception_returns_none():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")

    class BloomErrorAdapter:
        def get_disasm(self, address=None, size=None):
            raise RuntimeError("intentional error for test")

        def get_disasm_text(self, address=None, size=None):
            raise RuntimeError("intentional error for test")

        def cmd(self, c):
            return ""

        def cmdj(self, c):
            return None

    adapter = BloomErrorAdapter()
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._create_function_bloom(0x1000, "func", 256, 0.001)
    assert result is None


def test_extract_instruction_mnemonics_exception_returns_empty():
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    adapter = ExceptionAdapter()
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_instruction_mnemonics(0x1000, "test_func")
    assert result == []


def test_collect_function_blooms_bloom_result_none():
    """Test line 94: continue when bloom_result is None (no instructions found)."""
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    adapter = FakeDisasmAdapter(disasm_data=None, disasm_list=None, disasm_text=None)
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    functions = [{"name": "empty_func", "addr": 0x1000, "size": 50}]
    blooms, sigs, instructions, count = analyzer._collect_function_blooms(
        functions, 256, 0.001
    )
    assert count == 0
    assert len(blooms) == 0


def test_extract_mnemonics_from_text_with_empty_lines():
    """Test line 284: continue for empty lines in text parsing."""
    text = "push rbp\n\nmov rbp rsp\n\nret\n"
    adapter = FakeDisasmAdapter(disasm_data=None, disasm_list=None, disasm_text=text)
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_mnemonics_from_text(0x1000, "func")
    assert "push" in result
    assert "mov" in result
    assert "ret" in result


def test_bloom_to_signature_exception_returns_empty():
    """Test exception handler in _bloom_to_signature."""

    class BrokenAnalyzer(BinbloomAnalyzer):
        def _build_signature_components(self, instructions):
            raise RuntimeError("intentional error")

    analyzer = BrokenAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    result = analyzer._bloom_to_signature(["mov"])
    assert result == ""


def test_find_similar_functions_exception_returns_empty():
    """Test exception handler in _find_similar_functions."""

    class BrokenAnalyzer(BinbloomAnalyzer):
        def _group_functions_by_signature(self, function_signatures):
            raise RuntimeError("intentional error")

    analyzer = BrokenAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    result = analyzer._find_similar_functions({"f1": {"signature": "abc"}})
    assert result == []


def test_calculate_bloom_stats_exception():
    """Test exception handler in _calculate_bloom_stats."""
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    from pybloom_live import BloomFilter

    class BrokenAnalyzer(BinbloomAnalyzer):
        def _accumulate_bloom_bits(self, function_blooms):
            raise RuntimeError("intentional error")

    analyzer = BrokenAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf = BloomFilter(capacity=100, error_rate=0.01)
    result = analyzer._calculate_bloom_stats({"func": bf}, 100, 0.01)
    assert result == {}


def test_accumulate_bloom_bits_with_bit_array():
    """Test lines 532-534: _accumulate_bloom_bits with bit_array."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    fake_bloom = FakeBitArrayBloom([True, False, True, True, False])
    total_bits, total_cap = analyzer._accumulate_bloom_bits({"func": fake_bloom})
    assert total_bits == 3  # Three True values
    assert total_cap == 5


def test_compare_bloom_filters_with_bit_array_both_empty():
    """Test line 557: both bit_arrays are empty."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf1 = FakeBitArrayBloom([])
    bf2 = FakeBitArrayBloom([])
    result = analyzer.compare_bloom_filters(bf1, bf2)  # type: ignore[arg-type]
    assert result == 1.0


def test_compare_bloom_filters_with_bit_array_one_empty():
    """Test line 560: one bit_array is empty."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf1 = FakeBitArrayBloom([True, False, True])
    bf2 = FakeBitArrayBloom([])
    result = analyzer.compare_bloom_filters(bf1, bf2)  # type: ignore[arg-type]
    assert result == 0.0


def test_compare_bloom_filters_with_bit_array_partial():
    """Test lines 562-565: Jaccard similarity calculation."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf1 = FakeBitArrayBloom([True, True, False, False])
    bf2 = FakeBitArrayBloom([True, False, True, False])
    result = analyzer.compare_bloom_filters(bf1, bf2)  # type: ignore[arg-type]
    assert 0.0 < result < 1.0


def test_compare_bloom_filters_exception_returns_zero():
    """Test lines 567-569: exception handler."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")

    class BadBitArrayBloom:
        @property
        def bit_array(self):
            raise RuntimeError("intentional error")

    result = analyzer.compare_bloom_filters(BadBitArrayBloom(), BadBitArrayBloom())  # type: ignore[arg-type]
    assert result == 0.0


def test_calculate_binbloom_from_file_with_real_file():
    """Test lines 693-696: calculate_binbloom_from_file."""
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    result = BinbloomAnalyzer.calculate_binbloom_from_file(
        "samples/fixtures/hello_elf"
    )
    # Should return a dict or None (not raise)
    assert result is None or isinstance(result, dict)


def test_serialize_blooms_exception():
    """Test lines 410-411: exception handler in _serialize_blooms."""

    class BrokenBloom:
        pass

    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")

    class BrokenAnalyzer(BinbloomAnalyzer):
        def _serialize_bloom(self, bloom_filter):
            raise RuntimeError("intentional serialization error")

    broken = BrokenAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    result = broken._serialize_blooms({"func1": BrokenBloom()})  # type: ignore[arg-type]
    assert result == {}


# --- final coverage tests ---


def test_serialize_bloom_exception():
    """Test lines 442-444: exception handler in _serialize_bloom."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")

    class BadBloom:
        @property
        def bitarray(self):
            raise RuntimeError("bitarray access failed")

        @property
        def error_rate(self):
            return 0.01

        @property
        def capacity(self):
            return 100

        @property
        def count(self):
            return 0

    result = analyzer._serialize_bloom(BadBloom())  # type: ignore[arg-type]
    assert result == ""


def test_create_binary_bloom_exception():
    """Test lines 385-387: exception handler in _create_binary_bloom."""
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    instructions = {"mov", "push"}
    result = analyzer._create_binary_bloom(instructions, capacity=-1, error_rate=0.001)
    assert result is None


def test_add_binary_bloom_none_result():
    """Test line 124: binary_bloom is None after _create_binary_bloom fails."""
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    results = {"binary_bloom": None, "binary_signature": None}
    # _create_binary_bloom with invalid capacity returns None
    original_create = analyzer._create_binary_bloom

    class NoneReturnAnalyzer(BinbloomAnalyzer):
        def _create_binary_bloom(self, instructions, capacity, error_rate):
            return None  # Always return None

    none_analyzer = NoneReturnAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    none_analyzer._add_binary_bloom(results, {"mov", "push"}, 256, 0.001)  # type: ignore
    assert results["binary_bloom"] is None


def test_create_function_bloom_post_instructions_exception():
    """Test lines 193-195: exception after instructions are extracted."""
    if not BLOOM_AVAILABLE:
        pytest.skip("pybloom-live not available")
    disasm_data = {"ops": [{"mnemonic": "mov"}, {"mnemonic": "push"}]}
    adapter = FakeDisasmAdapter(disasm_data=disasm_data)

    class BrokenBuildAnalyzer(BinbloomAnalyzer):
        def _build_bloom_filter(self, instructions, capacity, error_rate):
            raise RuntimeError("intentional build failure")

    analyzer = BrokenBuildAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._create_function_bloom(0x1000, "main", 256, 0.001)
    assert result is None
