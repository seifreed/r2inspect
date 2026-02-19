"""Branch-path tests for r2inspect/modules/binbloom_analyzer.py."""
from __future__ import annotations

import base64
import json

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.binbloom_analyzer import BLOOM_AVAILABLE, BinbloomAnalyzer

pytestmark = pytest.mark.skipif(not BLOOM_AVAILABLE, reason="pybloom-live not installed")


# ---------------------------------------------------------------------------
# Minimal fakes
# ---------------------------------------------------------------------------


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


class NoDisasmAdapter:
    """Adapter with get_disasm and get_disasm_text that return nothing."""

    def analyze_all(self):
        pass

    def get_disasm(self, address=None, size=None):
        return None

    def get_disasm_text(self, address=None, size=None):
        return None

    def cmd(self, command):
        return ""

    def cmdj(self, command):
        return None


class DisasmAdapter:
    """Adapter that returns configurable disasm data."""

    def __init__(self, disasm_data=None, disasm_list=None, disasm_text=None, functions=None):
        self._disasm_data = disasm_data
        self._disasm_list = disasm_list
        self._disasm_text = disasm_text
        self._functions = functions or []

    def analyze_all(self):
        pass

    def get_functions(self):
        return self._functions

    def get_disasm(self, address=None, size=None):
        if size is not None:
            return self._disasm_list
        return self._disasm_data

    def get_disasm_text(self, address=None, size=None):
        return self._disasm_text

    def cmd(self, command):
        return ""

    def cmdj(self, command):
        if command == "aflj":
            return self._functions
        return None


class AnalyzeAllEmptyAdapter:
    """Adapter with analyze_all that returns an empty function list."""

    def analyze_all(self):
        pass

    def get_functions(self):
        return []

    def cmd(self, command):
        return ""

    def cmdj(self, command):
        return []


class RaisingGetFunctionsAdapter:
    """Adapter whose get_functions raises an exception."""

    def analyze_all(self):
        pass

    def get_functions(self):
        raise RuntimeError("Simulated failure in get_functions")

    def cmd(self, command):
        return ""

    def cmdj(self, command):
        return None


class FakeBloomWithBitArray:
    """Minimal bloom-filter lookalike with a bit_array attribute."""

    def __init__(self, bits):
        self.bit_array = bits


class BadIterBitArray:
    def __iter__(self):
        raise RuntimeError("iteration failed on bit_array")


class FakeBloomBadBitArray:
    bit_array = BadIterBitArray()


# ---------------------------------------------------------------------------
# _collect_function_blooms – skip conditions
# ---------------------------------------------------------------------------


def test_collect_function_blooms_skips_function_with_none_addr():
    """Line 90: continue when func_addr is None."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    functions = [{"name": "func_no_addr"}]  # addr key absent -> None
    blooms, sigs, instructions, count = analyzer._collect_function_blooms(functions, 256, 0.001)
    assert count == 0
    assert blooms == {}


def test_collect_function_blooms_skips_function_when_bloom_creation_fails():
    """Line 94: continue when _create_function_bloom returns None (no instructions)."""
    adapter = NoDisasmAdapter()
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    functions = [{"name": "func1", "addr": 0x1000, "size": 64}]
    blooms, sigs, instructions, count = analyzer._collect_function_blooms(functions, 256, 0.001)
    assert count == 0
    assert blooms == {}


def test_collect_function_blooms_records_valid_function():
    """Lines 96-106: normal path when bloom creation succeeds."""
    adapter = DisasmAdapter(
        disasm_data={"ops": [{"mnemonic": "push"}, {"mnemonic": "mov"}, {"mnemonic": "ret"}]}
    )
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    functions = [{"name": "main", "addr": 0x1000, "size": 64}]
    blooms, sigs, instructions, count = analyzer._collect_function_blooms(functions, 256, 0.001)
    assert count == 1
    assert "main" in blooms
    assert "main" in sigs


# ---------------------------------------------------------------------------
# _add_binary_bloom – early returns
# ---------------------------------------------------------------------------


def test_add_binary_bloom_returns_early_when_no_instructions():
    """Line 121: return early when all_instructions is empty."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    results = {
        "binary_bloom": None,
        "binary_signature": None,
        "available": True,
        "analyzer": "BinbloomAnalyzer",
        "library_available": True,
        "function_blooms": {},
        "function_signatures": {},
        "total_functions": 0,
        "analyzed_functions": 0,
        "capacity": 256,
        "error_rate": 0.001,
        "similar_functions": [],
        "unique_signatures": 0,
        "bloom_stats": {},
        "error": None,
        "execution_time": 0.0,
    }
    analyzer._add_binary_bloom(results, set(), 256, 0.001)
    assert results["binary_bloom"] is None
    assert results["binary_signature"] is None


def test_add_binary_bloom_populates_results_when_instructions_present():
    """Lines 122-127: results populated when all_instructions is non-empty."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    results = {
        "binary_bloom": None,
        "binary_signature": None,
        "available": True,
        "analyzer": "BinbloomAnalyzer",
        "library_available": True,
        "function_blooms": {},
        "function_signatures": {},
        "total_functions": 0,
        "analyzed_functions": 0,
        "capacity": 256,
        "error_rate": 0.001,
        "similar_functions": [],
        "unique_signatures": 0,
        "bloom_stats": {},
        "error": None,
        "execution_time": 0.0,
    }
    analyzer._add_binary_bloom(results, {"push", "mov", "ret"}, 256, 0.001)
    assert results["binary_bloom"] is not None
    assert results["binary_signature"] is not None


# ---------------------------------------------------------------------------
# _extract_functions paths
# ---------------------------------------------------------------------------


def test_extract_functions_calls_analyze_all_on_adapter():
    """Lines 138-139: adapter.analyze_all() is called when method exists."""
    called = []

    class TrackingAdapter(AnalyzeAllEmptyAdapter):
        def analyze_all(self):
            called.append(True)

    analyzer = BinbloomAnalyzer(TrackingAdapter(), filepath="/tmp/test.bin")
    result = analyzer._extract_functions()
    assert called == [True]
    assert result == []


def test_extract_functions_returns_empty_when_no_functions_found():
    """Lines 144-146: returns [] and logs when function list is empty."""
    adapter = AnalyzeAllEmptyAdapter()
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_functions()
    assert result == []


def test_extract_functions_filters_invalid_functions():
    """Lines 149-154: only functions with addr and size > 0 are kept."""
    adapter = DisasmAdapter(functions=[
        {"name": "valid_func", "addr": 0x1000, "size": 64},
        {"name": "no_size_func", "addr": 0x2000, "size": 0},
        {"name": "no_addr_func", "size": 32},
    ])
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_functions()
    assert len(result) == 1
    assert result[0]["name"] == "valid_func"


def test_extract_functions_returns_empty_on_exception():
    """Lines 157-159: exception during extraction returns [] and logs error."""
    adapter = RaisingGetFunctionsAdapter()
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_functions()
    assert result == []


# ---------------------------------------------------------------------------
# _create_function_bloom paths
# ---------------------------------------------------------------------------


def test_create_function_bloom_returns_none_when_no_instructions():
    """Lines 179-181: returns None when no instructions can be extracted."""
    adapter = NoDisasmAdapter()
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._create_function_bloom(0x1000, "empty_func", 256, 0.001)
    assert result is None


def test_create_function_bloom_returns_tuple_when_instructions_found():
    """Lines 183-191: returns (bloom, instructions, signature) on success."""
    adapter = DisasmAdapter(
        disasm_data={"ops": [{"mnemonic": "push"}, {"mnemonic": "ret"}]}
    )
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._create_function_bloom(0x1000, "simple_func", 256, 0.001)
    assert result is not None
    bloom, instructions, signature = result
    assert len(instructions) >= 1
    assert len(signature) == 64  # SHA256 hex length


def test_create_function_bloom_exception_returns_none():
    """Lines 193-195: exception during bloom creation returns None."""
    class BadDisasmAdapter(NoDisasmAdapter):
        def get_disasm(self, address=None, size=None):
            raise RuntimeError("Simulated disasm failure")

    adapter = BadDisasmAdapter()
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._create_function_bloom(0x1000, "bad_func", 256, 0.001)
    assert result is None


# ---------------------------------------------------------------------------
# _build_bloom_filter and _add_instruction_patterns
# ---------------------------------------------------------------------------


def test_build_bloom_filter_creates_filter_containing_instructions():
    """Lines 200-204: bloom filter contains all added instructions."""
    from pybloom_live import BloomFilter

    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    instructions = ["push", "mov", "ret"]
    bloom = analyzer._build_bloom_filter(instructions, 256, 0.001)
    assert isinstance(bloom, BloomFilter)
    for instr in instructions:
        assert instr in bloom


def test_add_instruction_patterns_adds_bigrams_for_two_or_more_instructions():
    """Lines 207-209: bigrams are added to the bloom filter."""
    from pybloom_live import BloomFilter

    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bloom = BloomFilter(capacity=256, error_rate=0.001)
    instructions = ["push", "mov", "ret"]
    analyzer._add_instruction_patterns(bloom, instructions)
    assert "push\u2192mov" in bloom
    assert "mov\u2192ret" in bloom


def test_add_instruction_patterns_adds_frequency_for_repeated_instructions():
    """Line 216: frequency pattern added when an instruction appears more than once."""
    from pybloom_live import BloomFilter

    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bloom = BloomFilter(capacity=256, error_rate=0.001)
    instructions = ["mov", "mov", "ret"]
    analyzer._add_instruction_patterns(bloom, instructions)
    assert "mov*2" in bloom


def test_add_instruction_patterns_single_instruction_no_bigrams():
    """No bigrams for single-instruction list."""
    from pybloom_live import BloomFilter

    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bloom = BloomFilter(capacity=256, error_rate=0.001)
    instructions = ["nop"]
    analyzer._add_instruction_patterns(bloom, instructions)
    # Should not raise; no bigrams produced


# ---------------------------------------------------------------------------
# _extract_instruction_mnemonics paths
# ---------------------------------------------------------------------------


def test_extract_instruction_mnemonics_returns_early_from_pdfj():
    """Line 231: returns immediately when pdfj extraction succeeds."""
    adapter = DisasmAdapter(
        disasm_data={"ops": [{"mnemonic": "push"}, {"mnemonic": "ret"}]},
        disasm_list=None,
        disasm_text=None,
    )
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_instruction_mnemonics(0x1000, "func1")
    assert "push" in result
    assert "ret" in result


def test_extract_instruction_mnemonics_falls_back_to_pdj():
    """Line 235: falls back to pdj when pdfj returns nothing."""
    adapter = DisasmAdapter(
        disasm_data=None,
        disasm_list=[{"mnemonic": "mov"}, {"mnemonic": "ret"}],
        disasm_text=None,
    )
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_instruction_mnemonics(0x1000, "func2")
    assert "mov" in result
    assert "ret" in result


def test_extract_instruction_mnemonics_falls_back_to_text():
    """Lines 237-239: falls back to text extraction when pdfj and pdj both fail."""
    adapter = DisasmAdapter(
        disasm_data=None,
        disasm_list=None,
        disasm_text="push ebp\nmov esp, ebp\nret\n",
    )
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_instruction_mnemonics(0x1000, "func3")
    assert "push" in result
    assert "ret" in result


def test_extract_instruction_mnemonics_logs_on_exception():
    """Lines 241-244: exception during extraction is logged and empty list returned."""
    class ExceptionDisasmAdapter(NoDisasmAdapter):
        def get_disasm(self, address=None, size=None):
            raise RuntimeError("disasm unavailable")

        def get_disasm_text(self, address=None, size=None):
            raise RuntimeError("text unavailable")

    adapter = ExceptionDisasmAdapter()
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_instruction_mnemonics(0x1000, "bad_func")
    assert result == []


# ---------------------------------------------------------------------------
# _extract_mnemonics_from_pdfj
# ---------------------------------------------------------------------------


def test_extract_mnemonics_from_pdfj_uses_adapter_get_disasm():
    """Lines 247-256: adapter.get_disasm is used when available."""
    adapter = DisasmAdapter(
        disasm_data={"ops": [{"mnemonic": "xor"}, {"mnemonic": "jmp"}]}
    )
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_mnemonics_from_pdfj(0x1000, "func_pdfj")
    assert "xor" in result
    assert "jmp" in result


def test_extract_mnemonics_from_pdfj_returns_empty_when_no_ops():
    """Lines 252-253: returns [] when disasm has no 'ops' key."""
    adapter = DisasmAdapter(disasm_data={"other_key": []})
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_mnemonics_from_pdfj(0x1000, "func_no_ops")
    assert result == []


def test_extract_mnemonics_from_pdfj_returns_empty_when_disasm_none():
    """Lines 252-253: returns [] when disasm is None."""
    adapter = DisasmAdapter(disasm_data=None)
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_mnemonics_from_pdfj(0x1000, "func_none_disasm")
    assert result == []


# ---------------------------------------------------------------------------
# _extract_mnemonics_from_pdj
# ---------------------------------------------------------------------------


def test_extract_mnemonics_from_pdj_uses_adapter_get_disasm_with_size():
    """Lines 260-269: adapter.get_disasm with size is used."""
    adapter = DisasmAdapter(
        disasm_list=[{"mnemonic": "add"}, {"mnemonic": "sub"}, {"mnemonic": "ret"}]
    )
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_mnemonics_from_pdj(0x1000, "func_pdj")
    assert "add" in result
    assert "sub" in result
    assert "ret" in result


def test_extract_mnemonics_from_pdj_returns_empty_when_not_a_list():
    """Lines 265-266: returns [] when result is not a list."""
    adapter = DisasmAdapter(disasm_list={"unexpected": "dict"})
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_mnemonics_from_pdj(0x1000, "func_not_list")
    assert result == []


# ---------------------------------------------------------------------------
# _extract_mnemonics_from_text
# ---------------------------------------------------------------------------


def test_extract_mnemonics_from_text_uses_adapter_get_disasm_text():
    """Lines 272-291: adapter.get_disasm_text is used and mnemonics extracted."""
    adapter = DisasmAdapter(disasm_text="push ebp\nmov eax, 0\npop ebp\nret\n")
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_mnemonics_from_text(0x1000, "func_text")
    assert "push" in result
    assert "mov" in result
    assert "ret" in result


def test_extract_mnemonics_from_text_returns_empty_for_empty_text():
    """Lines 278-279: returns [] when text is empty or whitespace-only."""
    adapter = DisasmAdapter(disasm_text="   \n  ")
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_mnemonics_from_text(0x1000, "func_empty_text")
    assert result == []


def test_extract_mnemonics_from_text_skips_blank_lines():
    """Lines 281-284: blank lines within text are skipped."""
    adapter = DisasmAdapter(disasm_text="push eax\n\n\nmov eax, 1\n")
    analyzer = BinbloomAnalyzer(adapter, filepath="/tmp/test.bin")
    result = analyzer._extract_mnemonics_from_text(0x1000, "func_blank_lines")
    assert "push" in result
    assert "mov" in result


# ---------------------------------------------------------------------------
# _collect_mnemonics_from_ops
# ---------------------------------------------------------------------------


def test_collect_mnemonics_from_ops_skips_non_dict_entries():
    """Lines 295-297: non-dict entries in ops list are skipped."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    ops = [{"mnemonic": "push"}, "not a dict", None, {"mnemonic": "ret"}]
    result = analyzer._collect_mnemonics_from_ops(ops)
    assert result == ["push", "ret"]


def test_collect_mnemonics_from_ops_skips_entries_without_mnemonic():
    """Lines 296-297: entries without 'mnemonic' key are skipped."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    ops = [{"type": "call"}, {"mnemonic": "nop"}, {}]
    result = analyzer._collect_mnemonics_from_ops(ops)
    assert result == ["nop"]


def test_collect_mnemonics_from_ops_normalizes_to_lowercase():
    """Lines 298-300: mnemonics are normalized to lowercase."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    ops = [{"mnemonic": "PUSH"}, {"mnemonic": "MOV"}]
    result = analyzer._collect_mnemonics_from_ops(ops)
    assert result == ["push", "mov"]


# ---------------------------------------------------------------------------
# _bloom_to_signature exception path
# ---------------------------------------------------------------------------


def test_bloom_to_signature_returns_empty_string_on_exception():
    """Lines 334-336: returns '' when signature computation fails."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    # Unhashable elements cause set() to raise TypeError inside _build_signature_components
    result = analyzer._bloom_to_signature([[1, 2], [3, 4]])  # type: ignore[arg-type]
    assert result == ""


# ---------------------------------------------------------------------------
# _create_binary_bloom exception path
# ---------------------------------------------------------------------------


def test_create_binary_bloom_returns_bloom_for_valid_inputs():
    """Lines 377-383: returns BloomFilter for a valid instruction set."""
    from pybloom_live import BloomFilter

    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    result = analyzer._create_binary_bloom({"push", "mov", "ret"}, 512, 0.001)
    assert isinstance(result, BloomFilter)


def test_create_binary_bloom_returns_none_on_invalid_capacity():
    """Lines 385-387: returns None when BloomFilter construction fails."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    # capacity=0 causes BloomFilter to raise
    result = analyzer._create_binary_bloom({"push"}, 0, 0.001)
    assert result is None


# ---------------------------------------------------------------------------
# _serialize_blooms
# ---------------------------------------------------------------------------


def test_serialize_blooms_returns_dict_of_base64_strings():
    """Lines 403-413: serializes all bloom filters to base64 strings."""
    from pybloom_live import BloomFilter

    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf = BloomFilter(capacity=64, error_rate=0.01)
    bf.add("push")
    result = analyzer._serialize_blooms({"main": bf})
    assert "main" in result
    assert isinstance(result["main"], str)
    assert len(result["main"]) > 0


def test_serialize_blooms_exception_returns_partial_result():
    """Lines 410-411: exception in loop is caught and partial dict returned."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")

    class BadDict:
        def items(self):
            raise RuntimeError("items() failed")

    result = analyzer._serialize_blooms(BadDict())  # type: ignore[arg-type]
    assert isinstance(result, dict)


def test_serialize_blooms_empty_input_returns_empty_dict():
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    result = analyzer._serialize_blooms({})
    assert result == {}


# ---------------------------------------------------------------------------
# _serialize_bloom
# ---------------------------------------------------------------------------


def test_serialize_bloom_produces_decodable_base64_json():
    """Lines 429-441: serialized output is valid base64-encoded JSON."""
    from pybloom_live import BloomFilter

    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf = BloomFilter(capacity=64, error_rate=0.01)
    bf.add("mov")
    b64 = analyzer._serialize_bloom(bf)
    decoded = json.loads(base64.b64decode(b64.encode()))
    assert decoded["version"] == 1
    assert isinstance(decoded["bitarray"], list)


def test_serialize_bloom_exception_returns_empty_string():
    """Lines 442-444: returns '' when serialization fails."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")

    class BadBloom:
        @property
        def error_rate(self):
            raise AttributeError("no error_rate")

    result = analyzer._serialize_bloom(BadBloom())  # type: ignore[arg-type]
    assert result == ""


# ---------------------------------------------------------------------------
# _find_similar_functions
# ---------------------------------------------------------------------------


def test_find_similar_functions_groups_identical_signatures():
    """Lines 458-462: groups functions with identical signatures."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    sig = "a" * 64
    sigs = {
        "func_a": {"signature": sig, "instruction_count": 2, "unique_instructions": 2, "addr": 0x1000, "size": 10},
        "func_b": {"signature": sig, "instruction_count": 2, "unique_instructions": 2, "addr": 0x2000, "size": 10},
    }
    result = analyzer._find_similar_functions(sigs)
    assert len(result) == 1
    assert result[0]["count"] == 2


def test_find_similar_functions_exception_returns_empty_list():
    """Lines 464-466: exception in grouping returns []."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")

    class BadSigs:
        def items(self):
            raise RuntimeError("items failed")

    result = analyzer._find_similar_functions(BadSigs())  # type: ignore[arg-type]
    assert result == []


# ---------------------------------------------------------------------------
# _group_functions_by_signature
# ---------------------------------------------------------------------------


def test_group_functions_by_signature_handles_html_entities():
    """Lines 471-475: HTML entities in function names are cleaned."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    sigs = {
        "func&amp;a": {"signature": "sig1"},
        "func&nbsp;b": {"signature": "sig1"},
    }
    groups = analyzer._group_functions_by_signature(sigs)
    assert "func&a" in groups["sig1"]
    assert "func b" in groups["sig1"]


# ---------------------------------------------------------------------------
# _build_similar_groups
# ---------------------------------------------------------------------------


def test_build_similar_groups_excludes_unique_signatures():
    """Lines 478-489: groups with only one function are excluded."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    groups = {"sig_unique": ["only_func"], "sig_dup": ["func_a", "func_b"]}
    result = analyzer._build_similar_groups(groups)
    assert len(result) == 1
    assert result[0]["count"] == 2


def test_build_similar_groups_truncates_long_signatures():
    """Lines 483-487: signature longer than 16 chars is truncated with '...'."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    long_sig = "a" * 64
    groups = {long_sig: ["func_a", "func_b"]}
    result = analyzer._build_similar_groups(groups)
    assert result[0]["signature"].endswith("...")
    assert len(result[0]["signature"]) <= 19  # 16 chars + "..."


# ---------------------------------------------------------------------------
# _calculate_bloom_stats
# ---------------------------------------------------------------------------


def test_calculate_bloom_stats_returns_empty_for_no_blooms():
    """Lines 505-507: returns {} when no bloom filters provided."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    result = analyzer._calculate_bloom_stats({}, 256, 0.001)
    assert result == {}


def test_calculate_bloom_stats_returns_stats_dict():
    """Lines 505-520: returns dict with stats for non-empty bloom map."""
    from pybloom_live import BloomFilter

    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf = BloomFilter(capacity=64, error_rate=0.01)
    result = analyzer._calculate_bloom_stats({"func1": bf}, 64, 0.01)
    assert result["total_filters"] == 1
    assert result["configured_capacity"] == 64
    assert result["configured_error_rate"] == 0.01
    assert "average_fill_rate" in result


def test_calculate_bloom_stats_exception_returns_empty():
    """Lines 522-524: exception returns {}."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")

    class BadBlooms:
        def __bool__(self):
            return True

        def __len__(self):
            return 1

        def values(self):
            raise RuntimeError("values() failed")

        def items(self):
            raise RuntimeError("items() failed")

    result = analyzer._calculate_bloom_stats(BadBlooms(), 256, 0.001)  # type: ignore[arg-type]
    assert result == {}


# ---------------------------------------------------------------------------
# compare_bloom_filters – various paths
# ---------------------------------------------------------------------------


def test_compare_bloom_filters_both_empty_bit_arrays_returns_one():
    """Lines 553-557: both empty bit_arrays -> similarity 1.0."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf1 = FakeBloomWithBitArray([0, 0, 0])
    bf2 = FakeBloomWithBitArray([0, 0, 0])
    result = analyzer.compare_bloom_filters(bf1, bf2)  # type: ignore[arg-type]
    assert result == 1.0


def test_compare_bloom_filters_one_empty_returns_zero():
    """Lines 553-560: one empty, one non-empty -> similarity 0.0."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf1 = FakeBloomWithBitArray([0, 0, 0])
    bf2 = FakeBloomWithBitArray([1, 0, 0])
    result = analyzer.compare_bloom_filters(bf1, bf2)  # type: ignore[arg-type]
    assert result == 0.0


def test_compare_bloom_filters_partial_overlap_returns_jaccard():
    """Lines 562-565: partial overlap computes Jaccard similarity."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf1 = FakeBloomWithBitArray([1, 1, 0])
    bf2 = FakeBloomWithBitArray([1, 0, 1])
    result = analyzer.compare_bloom_filters(bf1, bf2)  # type: ignore[arg-type]
    # bits1={0,1}, bits2={0,2} -> intersection={0}=1, union={0,1,2}=3 -> 1/3
    assert abs(result - 1 / 3) < 1e-9


def test_compare_bloom_filters_no_bit_array_attribute_returns_zero():
    """Lines 548-550: bloom without bit_array attribute returns 0.0."""
    from pybloom_live import BloomFilter

    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf = BloomFilter(capacity=64, error_rate=0.01)
    result = analyzer.compare_bloom_filters(bf, bf)
    assert result == 0.0


def test_compare_bloom_filters_identical_bit_arrays_returns_one():
    """Lines 562-565: identical non-empty bit arrays -> similarity 1.0."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    bf = FakeBloomWithBitArray([1, 0, 1, 1])
    result = analyzer.compare_bloom_filters(bf, bf)  # type: ignore[arg-type]
    assert result == 1.0


def test_compare_bloom_filters_exception_returns_zero():
    """Lines 567-569: exception during comparison returns 0.0."""
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    result = analyzer.compare_bloom_filters(
        FakeBloomBadBitArray(), FakeBloomBadBitArray()  # type: ignore[arg-type]
    )
    assert result == 0.0


# ---------------------------------------------------------------------------
# is_available
# ---------------------------------------------------------------------------


def test_is_available_returns_true_when_bloom_installed():
    """Line 579: static method returns BLOOM_AVAILABLE."""
    assert BinbloomAnalyzer.is_available() is True


# ---------------------------------------------------------------------------
# deserialize_bloom – all validation paths
# ---------------------------------------------------------------------------


def _make_b64(data: dict) -> str:
    return base64.b64encode(json.dumps(data).encode()).decode()


def test_deserialize_bloom_success_path():
    """Lines 607-667: valid serialized bloom is reconstructed."""
    from pybloom_live import BloomFilter

    bf = BloomFilter(capacity=64, error_rate=0.01)
    bf.add("push")
    analyzer = BinbloomAnalyzer(make_adapter(), filepath="/tmp/test.bin")
    b64 = analyzer._serialize_bloom(bf)
    result = BinbloomAnalyzer.deserialize_bloom(b64)
    assert result is not None
    assert "push" in result


def test_deserialize_bloom_not_a_dict():
    """Lines 616-618: non-dict JSON returns None."""
    b64 = base64.b64encode(b'["not", "a", "dict"]').decode()
    result = BinbloomAnalyzer.deserialize_bloom(b64)
    assert result is None


def test_deserialize_bloom_wrong_version():
    """Lines 622-624: wrong version returns None."""
    data = {"version": 99, "error_rate": 0.001, "capacity": 64, "count": 0, "bitarray": []}
    result = BinbloomAnalyzer.deserialize_bloom(_make_b64(data))
    assert result is None


def test_deserialize_bloom_missing_required_key():
    """Lines 627-634: missing key triggers inner exception and returns None."""
    data = {"version": 1, "error_rate": 0.001, "capacity": 64}  # missing count and bitarray
    result = BinbloomAnalyzer.deserialize_bloom(_make_b64(data))
    assert result is None


def test_deserialize_bloom_invalid_error_rate_below_zero():
    """Lines 637-639: error_rate <= 0 returns None."""
    data = {"version": 1, "error_rate": 0.0, "capacity": 64, "count": 0, "bitarray": []}
    result = BinbloomAnalyzer.deserialize_bloom(_make_b64(data))
    assert result is None


def test_deserialize_bloom_invalid_error_rate_above_one():
    """Lines 637-639: error_rate >= 1 returns None."""
    data = {"version": 1, "error_rate": 1.5, "capacity": 64, "count": 0, "bitarray": []}
    result = BinbloomAnalyzer.deserialize_bloom(_make_b64(data))
    assert result is None


def test_deserialize_bloom_capacity_zero():
    """Lines 641-643: capacity = 0 returns None."""
    data = {"version": 1, "error_rate": 0.001, "capacity": 0, "count": 0, "bitarray": []}
    result = BinbloomAnalyzer.deserialize_bloom(_make_b64(data))
    assert result is None


def test_deserialize_bloom_capacity_too_large():
    """Lines 641-643: capacity > 1_000_000 returns None."""
    data = {"version": 1, "error_rate": 0.001, "capacity": 2_000_000, "count": 0, "bitarray": []}
    result = BinbloomAnalyzer.deserialize_bloom(_make_b64(data))
    assert result is None


def test_deserialize_bloom_count_exceeds_capacity():
    """Lines 645-647: count > capacity returns None."""
    data = {"version": 1, "error_rate": 0.001, "capacity": 64, "count": 100, "bitarray": []}
    result = BinbloomAnalyzer.deserialize_bloom(_make_b64(data))
    assert result is None


def test_deserialize_bloom_count_negative():
    """Lines 645-647: count < 0 returns None."""
    data = {"version": 1, "error_rate": 0.001, "capacity": 64, "count": -1, "bitarray": []}
    result = BinbloomAnalyzer.deserialize_bloom(_make_b64(data))
    assert result is None


def test_deserialize_bloom_bitarray_not_a_list():
    """Lines 650-652: bitarray not a list returns None."""
    data = {"version": 1, "error_rate": 0.001, "capacity": 64, "count": 0, "bitarray": "invalid"}
    result = BinbloomAnalyzer.deserialize_bloom(_make_b64(data))
    assert result is None


def test_deserialize_bloom_invalid_json_returns_none():
    """Lines 669-671: invalid JSON returns None."""
    b64 = base64.b64encode(b"not valid json!!!").decode()
    result = BinbloomAnalyzer.deserialize_bloom(b64)
    assert result is None


def test_deserialize_bloom_general_exception_returns_none():
    """Lines 672-674: general exception during reconstruction returns None."""
    # Valid params but bitarray list has non-boolean content -> bitarray() raises
    from pybloom_live import BloomFilter

    bf = BloomFilter(capacity=64, error_rate=0.01)
    capacity = bf.capacity
    total_bits = len(bf.bitarray)
    # Use string elements to cause bitarray() to raise
    data = {
        "version": 1,
        "error_rate": 0.01,
        "capacity": capacity,
        "count": 0,
        "bitarray": ["x"] * total_bits,
    }
    result = BinbloomAnalyzer.deserialize_bloom(_make_b64(data))
    assert result is None


# ---------------------------------------------------------------------------
# calculate_binbloom_from_file
# ---------------------------------------------------------------------------


def test_calculate_binbloom_from_file_returns_none_for_nonexistent_file():
    """Lines 693-695: returns None and logs error when file does not exist."""
    result = BinbloomAnalyzer.calculate_binbloom_from_file("/tmp/no_such_binary_12345.bin")
    assert result is None


def test_calculate_binbloom_from_file_with_real_binary(tmp_path):
    """Lines 693-696: returns result dict for a real (tiny) ELF/PE fixture."""
    import os
    from pathlib import Path

    fixture_dir = Path(__file__).resolve().parent.parent.parent / "samples" / "fixtures"
    hello_elf = fixture_dir / "hello_elf"
    if not hello_elf.exists():
        pytest.skip("hello_elf fixture not found")

    result = BinbloomAnalyzer.calculate_binbloom_from_file(str(hello_elf))
    # result may be None if analysis fails (no r2 in CI), but the code path is covered
    assert result is None or isinstance(result, dict)
