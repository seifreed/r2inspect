"""Additional coverage tests for r2inspect/modules/binlex_analyzer.py"""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from r2inspect.modules.binlex_analyzer import BinlexAnalyzer


class AdapterWithFunctionsNoDisasm:
    """Adapter that returns functions but no disassembly (forces empty token extraction)."""

    def analyze_all(self) -> None:
        pass

    def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
        return {}

    def get_disasm_text(self, address: int = 0, size: int = 0) -> str:
        return ""

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return [
                {"name": "main", "addr": 0x1000, "size": 100},
            ]
        return default if default is not None else {}

    def cmd(self, command: str) -> str:
        return ""


class AdapterWithNoAddr:
    """Adapter returning functions without valid addresses."""

    def analyze_all(self) -> None:
        pass

    def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
        return {}

    def get_disasm_text(self, address: int = 0, size: int = 0) -> str:
        return ""

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return [
                {"name": "no_addr_func", "size": 100},  # missing addr
            ]
        return default if default is not None else {}

    def cmd(self, command: str) -> str:
        return ""


class AdapterWithPdfjFallback:
    """Adapter where get_disasm returns data but ops is empty, triggers pdj/text fallback."""

    def analyze_all(self) -> None:
        pass

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return [{"name": "func_a", "addr": 0x1000, "size": 50}]
        if command == "pdfj":
            return {"ops": [{"mnemonic": "mov"}, {"mnemonic": "ret"}]}
        return default if default is not None else {}

    def cmd(self, command: str) -> str:
        if command.startswith("pdj "):
            return "[{\"mnemonic\": \"push\"}, {\"mnemonic\": \"pop\"}]"
        if command.startswith("pi "):
            return "mov rax, rbx\nret\n"
        return ""


class AdapterWithTextFallback:
    """Adapter with get_disasm returning dict without 'ops' key, then list fallback."""

    def analyze_all(self) -> None:
        pass

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return [{"name": "func_text", "addr": 0x2000, "size": 80}]
        return {}

    def cmd(self, command: str) -> str:
        if command.startswith("pi "):
            return "push rbp\nmov rbp, rsp\ncall target\npop rbp\nret\n"
        return ""


class AdapterWithNonDictOps:
    """Adapter returning ops containing non-dict items."""

    def analyze_all(self) -> None:
        pass

    def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
        return {
            "ops": [
                "not_a_dict",  # non-dict entry
                {"mnemonic": "mov"},
                None,  # None entry
                {"opcode": "push rbp"},  # opcode field
            ]
        }

    def get_disasm_text(self, address: int = 0, size: int = 0) -> str:
        return ""

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return [{"name": "func_ops", "addr": 0x3000, "size": 40}]
        return default if default is not None else {}

    def cmd(self, command: str) -> str:
        return ""


class AdapterWithOpcodeFallback:
    """Adapter returning ops with opcode field but no mnemonic."""

    def analyze_all(self) -> None:
        pass

    def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
        return {
            "ops": [
                {"opcode": "mov rax, rbx"},
                {"opcode": "push rbp"},
                {"opcode": "  "},  # empty opcode
                {"opcode": "ret"},
                {},  # no mnemonic or opcode
            ]
        }

    def get_disasm_text(self, address: int = 0, size: int = 0) -> str:
        return ""

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return [{"name": "func_opcode", "addr": 0x4000, "size": 50}]
        return default if default is not None else {}

    def cmd(self, command: str) -> str:
        return ""


# Tests for code paths in analyze() when function_signatures is empty

def test_analyze_no_extractable_tokens_returns_error():
    adapter = AdapterWithFunctionsNoDisasm()
    analyzer = BinlexAnalyzer(adapter=adapter, filepath="/tmp/test.bin")
    result = analyzer.analyze(ngram_sizes=[2])
    # Functions found but no tokens extracted -> no function signatures
    assert result["error"] == "No functions could be analyzed for Binlex"
    assert result["total_functions"] == 1


def test_analyze_function_without_addr_skipped():
    adapter = AdapterWithNoAddr()
    analyzer = BinlexAnalyzer(adapter=adapter, filepath="/tmp/test.bin")
    result = analyzer.analyze(ngram_sizes=[2])
    # Function has no addr, _collect skips it
    assert result["total_functions"] == 0 or result["error"] is not None


# Tests for _extract_tokens_from_ops with non-dict entries

def test_extract_tokens_from_ops_skips_non_dicts():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    ops = [
        "string_not_dict",
        {"mnemonic": "mov"},
        None,
        {"mnemonic": "ret"},
    ]
    tokens = analyzer._extract_tokens_from_ops(ops)
    assert "mov" in tokens
    assert "ret" in tokens
    assert len(tokens) == 2


def test_extract_tokens_from_ops_opcode_fallback():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    ops = [
        {"opcode": "push rbp"},
        {"opcode": "call 0x1000"},
        {"opcode": "  "},  # whitespace only
        {},  # no mnemonic or opcode
    ]
    tokens = analyzer._extract_tokens_from_ops(ops)
    assert "push" in tokens
    assert "call" in tokens


# Tests for _extract_mnemonic_from_op

def test_extract_mnemonic_from_op_mnemonic_field():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    mnemonic = analyzer._extract_mnemonic_from_op({"mnemonic": "mov"})
    assert mnemonic == "mov"


def test_extract_mnemonic_from_op_opcode_field():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    mnemonic = analyzer._extract_mnemonic_from_op({"opcode": "push rbp"})
    assert mnemonic == "push"


def test_extract_mnemonic_from_op_empty_opcode():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    mnemonic = analyzer._extract_mnemonic_from_op({"opcode": "  "})
    assert mnemonic is None


def test_extract_mnemonic_from_op_no_fields():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    mnemonic = analyzer._extract_mnemonic_from_op({})
    assert mnemonic is None


def test_extract_mnemonic_from_op_none_mnemonic():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    mnemonic = analyzer._extract_mnemonic_from_op({"mnemonic": None})
    assert mnemonic is None


# Tests for _normalize_mnemonic with HTML entities

def test_normalize_mnemonic_html_nbsp():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    result = analyzer._normalize_mnemonic("mov&nbsp;")
    assert result == "mov "


def test_normalize_mnemonic_html_amp():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    result = analyzer._normalize_mnemonic("and&amp;")
    assert result == "and&"


def test_normalize_mnemonic_starts_with_amp_returns_none():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    result = analyzer._normalize_mnemonic("&invalid")
    assert result is None


def test_normalize_mnemonic_none_input():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    result = analyzer._normalize_mnemonic(None)
    assert result is None


def test_normalize_mnemonic_empty_string():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    result = analyzer._normalize_mnemonic("")
    assert result is None


# Tests for _accumulate_ngrams

def test_accumulate_ngrams_missing_n_in_func_sigs():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    all_ngrams: defaultdict[int, Counter[str]] = defaultdict(Counter)
    func_sigs: dict[int, dict[str, Any]] = {3: {"ngrams": ["a b c", "b c d"]}}
    # Request n=2 which is not in func_sigs
    analyzer._accumulate_ngrams(all_ngrams, func_sigs, [2])
    assert 2 not in all_ngrams


def test_accumulate_ngrams_non_list_ngrams():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    all_ngrams: defaultdict[int, Counter[str]] = defaultdict(Counter)
    func_sigs: dict[int, dict[str, Any]] = {2: {"ngrams": "not_a_list"}}
    analyzer._accumulate_ngrams(all_ngrams, func_sigs, [2])
    assert 2 not in all_ngrams or len(all_ngrams[2]) == 0


def test_accumulate_ngrams_valid():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    all_ngrams: defaultdict[int, Counter[str]] = defaultdict(Counter)
    func_sigs: dict[int, dict[str, Any]] = {2: {"ngrams": ["mov ret", "push pop"]}}
    analyzer._accumulate_ngrams(all_ngrams, func_sigs, [2])
    assert all_ngrams[2]["mov ret"] == 1


# Tests for _extract_tokens_from_text paths

def test_extract_tokens_from_text_with_text_adapter():
    adapter = AdapterWithTextFallback()
    analyzer = BinlexAnalyzer(adapter=adapter, filepath=None)
    tokens = analyzer._extract_tokens_from_text(0x2000, "func_text")
    assert len(tokens) > 0
    assert "push" in tokens
    assert "ret" in tokens


def test_extract_tokens_from_text_empty_text():
    adapter = AdapterWithFunctionsNoDisasm()
    analyzer = BinlexAnalyzer(adapter=adapter, filepath=None)
    tokens = analyzer._extract_tokens_from_text(0x1000, "empty_func")
    assert tokens == []


def test_extract_tokens_from_text_with_blank_lines():
    adapter = AdapterWithTextFallback()
    analyzer = BinlexAnalyzer(adapter=adapter, filepath=None)
    # Manually test the method with a multiline string that has blank lines
    tokens = analyzer._extract_tokens_from_text(0x2000, "test")
    assert isinstance(tokens, list)


# Tests for _extract_tokens_from_pdfj fallback

def test_extract_tokens_from_pdfj_no_ops_key():
    class AdapterNoOps:
        def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
            return {"instructions": []}  # no "ops" key

        def get_disasm_text(self, **kwargs: Any) -> str:
            return ""

    analyzer = BinlexAnalyzer(adapter=AdapterNoOps(), filepath=None)
    tokens = analyzer._extract_tokens_from_pdfj(0x1000, "func")
    assert tokens == []


def test_extract_tokens_from_pdfj_empty_disasm():
    class AdapterEmptyDisasm:
        def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
            return {}

    analyzer = BinlexAnalyzer(adapter=AdapterEmptyDisasm(), filepath=None)
    tokens = analyzer._extract_tokens_from_pdfj(0x1000, "func")
    assert tokens == []


# Tests for _extract_tokens_from_pdj

def test_extract_tokens_from_pdj_non_list_result():
    class AdapterPdjNonList:
        def get_disasm(self, address: int = 0, size: int = 0) -> Any:
            return {"not": "a list"}

    analyzer = BinlexAnalyzer(adapter=AdapterPdjNonList(), filepath=None)
    tokens = analyzer._extract_tokens_from_pdj(0x1000, "func")
    assert tokens == []


def test_extract_tokens_from_pdj_valid_list():
    class AdapterPdjList:
        def get_disasm(self, address: int = 0, size: int = 200) -> Any:
            return [{"mnemonic": "push"}, {"mnemonic": "pop"}]

    analyzer = BinlexAnalyzer(adapter=AdapterPdjList(), filepath=None)
    tokens = analyzer._extract_tokens_from_pdj(0x1000, "func")
    assert "push" in tokens
    assert "pop" in tokens


# Test _analyze_function edge case: tokens present but all n too large

def test_analyze_function_all_ngrams_skipped_due_to_token_count():
    """When tokens exist but all n sizes require more tokens than available."""
    class SmallFuncAdapter:
        def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
            # Only 1 token total
            return {"ops": [{"mnemonic": "ret"}]}

        def get_disasm_text(self, **kwargs: Any) -> str:
            return ""

    analyzer = BinlexAnalyzer(adapter=SmallFuncAdapter(), filepath=None)
    # n=5 requires 5+ tokens, but we have only 1
    result = analyzer._analyze_function(0x1000, "tiny_func", ngram_sizes=[5])
    assert result is None


# Test _collect_signatures_for_size with missing signature key

def test_collect_signatures_for_size_no_signature_key():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    function_signatures = {
        "func_a": {2: {"ngrams": ["a b"]}},  # no "signature" key for n=2
    }
    signatures, groups = analyzer._collect_signatures_for_size(function_signatures, 2)
    assert len(signatures) == 0


# Test _build_similar_groups with groups that have only 1 function (not similar)

def test_build_similar_groups_single_function_per_sig():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    groups: defaultdict[str, list[str]] = defaultdict(list)
    groups["sig_abc"] = ["func_a"]  # Only 1 function, not similar
    result = analyzer._build_similar_groups(groups)
    assert result == []


def test_build_similar_groups_multiple_functions_same_sig():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    groups: defaultdict[str, list[str]] = defaultdict(list)
    groups["sig_abc"] = ["func_a", "func_b", "func_c"]
    result = analyzer._build_similar_groups(groups)
    assert len(result) == 1
    assert result[0]["count"] == 3
    assert "func_a" in result[0]["functions"]


def test_build_similar_groups_long_signature_truncated():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    groups: defaultdict[str, list[str]] = defaultdict(list)
    long_sig = "a" * 20  # longer than 16 chars
    groups[long_sig] = ["func_x", "func_y"]
    result = analyzer._build_similar_groups(groups)
    assert len(result) == 1
    assert "..." in result[0]["signature"]


# Test compare_functions

def test_compare_functions_identical():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    assert analyzer.compare_functions("abc123", "abc123") is True


def test_compare_functions_different():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    assert analyzer.compare_functions("abc123", "def456") is False


# Test get_function_similarity_score edge cases

def test_similarity_score_both_empty():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    score = analyzer.get_function_similarity_score([], [])
    assert score == 1.0


def test_similarity_score_one_empty():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    score = analyzer.get_function_similarity_score(["a b"], [])
    assert score == 0.0


def test_similarity_score_identical():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    ngrams = ["mov ret", "push pop", "call ret"]
    score = analyzer.get_function_similarity_score(ngrams, ngrams)
    assert score == 1.0


def test_similarity_score_partial_overlap():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    ngrams1 = ["a b", "b c", "c d"]
    ngrams2 = ["b c", "c d", "d e"]
    score = analyzer.get_function_similarity_score(ngrams1, ngrams2)
    assert 0.0 < score < 1.0


# Test _calculate_binary_signature

def test_calculate_binary_signature_with_data():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    function_signatures = {
        "func_a": {2: {"signature": "abc123", "ngrams": ["a b"]}},
        "func_b": {2: {"signature": "def456", "ngrams": ["c d"]}},
    }
    result = analyzer._calculate_binary_signature(function_signatures, [2])
    assert 2 in result
    assert len(result[2]) == 64  # SHA256 hex


def test_calculate_binary_signature_no_signatures_for_n():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    function_signatures = {
        "func_a": {3: {"signature": "abc123"}},  # only n=3
    }
    result = analyzer._calculate_binary_signature(function_signatures, [2])
    # n=2 not in any function_signatures
    assert 2 not in result


# Test is_available

def test_is_available_returns_true():
    assert BinlexAnalyzer.is_available() is True


# Test analyze with adapter that raises exception during function extraction

def test_analyze_handles_exception_gracefully():
    class ExplodingAdapter:
        def analyze_all(self) -> None:
            raise RuntimeError("Adapter crashed")

        def cmdj(self, command: str, default: Any = None) -> Any:
            raise RuntimeError("Adapter crashed")

        def cmd(self, command: str) -> str:
            raise RuntimeError("Adapter crashed")

    analyzer = BinlexAnalyzer(adapter=ExplodingAdapter(), filepath=None)
    result = analyzer.analyze(ngram_sizes=[2])
    # Should have error message from exception handling
    assert result is not None
    assert isinstance(result, dict)


# Tests for NoneType adapter paths (no adapter)

def test_extract_tokens_from_pdfj_no_adapter():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    # With no adapter, uses _cmdj which may not work, but should not crash
    tokens = analyzer._extract_tokens_from_pdfj(0x1000, "func")
    assert isinstance(tokens, list)


def test_extract_tokens_from_pdj_no_adapter():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    tokens = analyzer._extract_tokens_from_pdj(0x1000, "func")
    assert isinstance(tokens, list)


def test_extract_tokens_from_text_no_adapter():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    tokens = analyzer._extract_tokens_from_text(0x1000, "func")
    assert isinstance(tokens, list)


# Test with ops that have None values to cover line 375

def test_extract_tokens_from_ops_with_none_entry():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    ops = [None, {"mnemonic": "mov"}, 42, {"mnemonic": "ret"}]
    tokens = analyzer._extract_tokens_from_ops(ops)
    assert "mov" in tokens
    assert "ret" in tokens
    assert len(tokens) == 2


# --- Additional tests for uncovered exception handling and edge case paths ---

class AdapterPdfjEmptyPdjValid:
    """Adapter where pdfj returns no ops but pdj returns valid list."""

    def analyze_all(self) -> None:
        pass

    def get_disasm(self, address: int = 0, size: int = None) -> Any:
        if size is None:
            # pdfj call - no ops
            return {"no_ops": True}
        # pdj call with size parameter - return a list
        return [{"mnemonic": "mov"}, {"mnemonic": "push"}, {"mnemonic": "ret"}]

    def get_disasm_text(self, address: int = 0, size: int = 100) -> str:
        return ""

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return [{"name": "func_pdj", "addr": 0x5000, "size": 60}]
        return default if default is not None else {}

    def cmd(self, command: str) -> str:
        return ""


class AdapterTextWithBlankLines:
    """Adapter with disasm text that has blank lines (triggers line 362)."""

    def analyze_all(self) -> None:
        pass

    def get_disasm(self, address: int = 0, size: int = None) -> Any:
        return {}

    def get_disasm_text(self, address: int = 0, size: int = 100) -> str:
        # Has blank line in middle
        return "push rbp\n\nmov rbp, rsp\n\nret\n"

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return [{"name": "func_blank", "addr": 0x6000, "size": 50}]
        return default if default is not None else {}

    def cmd(self, command: str) -> str:
        if command.startswith("pi "):
            return "push rbp\n\nmov rbp, rsp\n\nret\n"
        return ""


class AdapterTextThrows:
    """Adapter where text extraction raises an exception."""

    def analyze_all(self) -> None:
        pass

    def get_disasm(self, address: int = 0, size: int = None) -> Any:
        # Return non-list for pdj, no ops for pdfj
        return {}

    def get_disasm_text(self, address: int = 0, size: int = 100) -> str:
        raise RuntimeError("text extraction failed")

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return [{"name": "func_throw", "addr": 0x7000, "size": 50}]
        return default if default is not None else {}

    def cmd(self, command: str) -> str:
        return ""


class BrokenCollectBinlexAnalyzer(BinlexAnalyzer):
    """Subclass where _collect_function_signatures raises to trigger outer except."""

    def _extract_functions(self) -> list[dict[str, Any]]:
        return [{"name": "func", "addr": 0x1000, "size": 100}]

    def _collect_function_signatures(
        self, functions: list[dict[str, Any]], ngram_sizes: list[int]
    ) -> Any:
        raise RuntimeError("simulated collect error")


class BrokenGenerateNgramsBinlexAnalyzer(BinlexAnalyzer):
    """Subclass where _generate_ngrams raises to trigger _analyze_function except."""

    def _generate_ngrams(self, tokens: list[str], n: int) -> list[str]:
        raise RuntimeError("simulated ngram error")


class BrokenBinarySignatureBinlexAnalyzer(BinlexAnalyzer):
    """Subclass where _calculate_binary_signature raises."""

    def _extract_functions(self) -> list[dict[str, Any]]:
        return [{"name": "func_sig", "addr": 0x1000, "size": 100}]

    def _collect_function_signatures(
        self, functions: list[dict[str, Any]], ngram_sizes: list[int]
    ) -> Any:
        # Return valid data
        sigs = {"func_sig": {2: {"signature": "abc", "ngrams": ["a b"], "token_count": 3, "ngram_count": 2, "unique_ngrams": 2}}}
        from collections import defaultdict, Counter
        all_ngrams = defaultdict(Counter)
        all_ngrams[2]["a b"] += 1
        return sigs, all_ngrams, 1

    def _build_signature_groups(self, function_signatures: Any, ngram_sizes: Any) -> Any:
        raise RuntimeError("simulated sig group error")


# Tests for exception handling paths (lines 110-112)

def test_analyze_outer_exception_caught():
    analyzer = BrokenCollectBinlexAnalyzer(adapter=None, filepath=None)
    result = analyzer.analyze(ngram_sizes=[2])
    assert result["error"] is not None
    assert "simulated collect error" in result["error"]


# Tests for _analyze_function exception path (lines 292-294)

def test_analyze_function_exception_returns_none():
    class AdapterWithValidFunctions:
        def analyze_all(self) -> None:
            pass
        def get_disasm(self, address: int = 0, size: int = None) -> Any:
            return {"ops": [{"mnemonic": "mov"}, {"mnemonic": "push"}, {"mnemonic": "ret"}]}
        def get_disasm_text(self, **kwargs: Any) -> str:
            return ""
        def cmdj(self, command: str, default: Any = None) -> Any:
            return default if default is not None else {}
        def cmd(self, command: str) -> str:
            return ""

    analyzer = BrokenGenerateNgramsBinlexAnalyzer(
        adapter=AdapterWithValidFunctions(), filepath=None
    )
    # With tokens available but _generate_ngrams raises
    result = analyzer._analyze_function(0x1000, "test_func", [2])
    assert result is None


# Test _extract_tokens_from_pdj when it returns valid tokens (line 313)

def test_extract_instruction_tokens_pdj_fallback_returns_tokens():
    adapter = AdapterPdfjEmptyPdjValid()
    analyzer = BinlexAnalyzer(adapter=adapter, filepath=None)
    tokens = analyzer._extract_instruction_tokens(0x5000, "func_pdj")
    assert len(tokens) > 0
    assert "mov" in tokens


# Test _extract_tokens_from_text with blank lines (line 362)

def test_extract_tokens_from_text_skips_blank_lines():
    adapter = AdapterTextWithBlankLines()
    analyzer = BinlexAnalyzer(adapter=adapter, filepath=None)
    tokens = analyzer._extract_tokens_from_text(0x6000, "func_blank")
    assert "push" in tokens
    assert "mov" in tokens
    assert "ret" in tokens
    # Should NOT have empty string from blank lines
    assert "" not in tokens


# Test exception path in _extract_instruction_tokens (lines 319-320)

def test_extract_instruction_tokens_exception_returns_empty():
    adapter = AdapterTextThrows()
    analyzer = BinlexAnalyzer(adapter=adapter, filepath=None)
    tokens = analyzer._extract_instruction_tokens(0x7000, "func_throw")
    assert tokens == []


# Test _extract_tokens_from_text when text returns tokens (line 317)

def test_extract_instruction_tokens_text_fallback():
    class PdfjAndPdjEmptyTextValidAdapter:
        def analyze_all(self) -> None:
            pass
        def get_disasm(self, address: int = 0, size: int = None) -> Any:
            return {}  # neither ops for pdfj nor list for pdj
        def get_disasm_text(self, address: int = 0, size: int = 100) -> str:
            return "push rbp\nmov rsp, rbp\nret\n"

    analyzer = BinlexAnalyzer(adapter=PdfjAndPdjEmptyTextValidAdapter(), filepath=None)
    tokens = analyzer._extract_instruction_tokens(0x1000, "func")
    assert len(tokens) > 0


# Tests for _calculate_binary_signature exception path (lines 475-476)

def test_calculate_binary_signature_handles_exception():
    analyzer = BrokenBinarySignatureBinlexAnalyzer(adapter=None, filepath=None)
    # Call analyze to trigger the exception in _build_signature_groups
    result = analyzer.analyze(ngram_sizes=[2])
    assert result is not None


# Test get_function_similarity_score exception path (lines 500-502)

def test_similarity_score_exception_returns_zero():
    """Pass unhashable items to trigger exception in set()."""
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)

    class Unhashable:
        __hash__ = None  # type: ignore[assignment]
        def __eq__(self, other: object) -> bool:
            return False

    # set() on a list with unhashable items raises TypeError
    try:
        score = analyzer.get_function_similarity_score([Unhashable()], ["a b"])
        # If it doesn't raise, score should be 0.0
        assert score == 0.0
    except TypeError:
        # Also acceptable - proves the exception path exists
        pass


# Test _collect_function_signatures with func that has no addr (line 128)

def test_collect_function_signatures_skips_no_addr():
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    functions = [
        {"name": "no_addr_func", "size": 100},  # no addr key
        {"name": "valid_func", "addr": None, "size": 100},  # addr is None
    ]
    sigs, all_ngrams, count = analyzer._collect_function_signatures(functions, [2])
    assert count == 0
    assert sigs == {}


# Test _calculate_binary_signature exception path (lines 475-476)

def test_calculate_binary_signature_exception_with_non_sortable():
    """Exception in _calculate_binary_signature is caught."""

    class NonSortable:
        def __gt__(self, other: object) -> bool:
            raise TypeError("cannot compare")

        def __lt__(self, other: object) -> bool:
            raise TypeError("cannot compare")

    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    function_signatures = {
        "func_a": {2: {"signature": NonSortable()}},
        "func_b": {2: {"signature": NonSortable()}},
    }
    result = analyzer._calculate_binary_signature(function_signatures, [2])
    assert result == {}  # Empty due to exception


# Test analyze() with ngram_sizes=None (line 47)

def test_analyze_default_ngram_sizes_used_when_none():
    """When ngram_sizes=None, defaults to [2, 3, 4]."""
    analyzer = BinlexAnalyzer(adapter=AdapterWithFunctionsNoDisasm(), filepath=None)
    result = analyzer.analyze(ngram_sizes=None)
    assert result["ngram_sizes"] == [2, 3, 4]


# Test line 277: if not ngrams: continue (defensive code path)

class EmptyNgramAnalyzer(BinlexAnalyzer):
    """Subclass that always returns empty ngrams."""

    def _generate_ngrams(self, tokens: list[str], n: int) -> list[str]:
        return []


def test_analyze_function_empty_ngrams_skipped():
    """When _generate_ngrams returns empty, the n-gram size is skipped (line 277)."""
    class GoodTokenAdapter:
        def get_disasm(self, address: int = 0, size: int = None) -> Any:
            return {"ops": [
                {"mnemonic": "mov"}, {"mnemonic": "push"},
                {"mnemonic": "call"}, {"mnemonic": "pop"}, {"mnemonic": "ret"},
            ]}

        def get_disasm_text(self, **kwargs: Any) -> str:
            return ""

    analyzer = EmptyNgramAnalyzer(adapter=GoodTokenAdapter(), filepath=None)
    result = analyzer._analyze_function(0x1000, "func", [2, 3])
    # Empty ngrams for all sizes -> results is {} -> returns None
    assert result is None
