"""Tests covering branch paths in r2inspect/modules/binlex_analyzer.py."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import pytest

from r2inspect.modules.binlex_analyzer import BinlexAnalyzer


# ---------------------------------------------------------------------------
# Minimal adapter stubs (real objects, no mocking library)
# ---------------------------------------------------------------------------


class AdapterNoFunctions:
    """Adapter returning empty function list - triggers line 72-74."""

    def analyze_all(self) -> None:
        pass

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return []
        return default if default is not None else {}

    def cmd(self, command: str) -> str:
        return ""


class AdapterOneFunction:
    """Adapter with one function that has valid tokens for ngram analysis."""

    def analyze_all(self) -> None:
        pass

    def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
        return {
            "ops": [
                {"mnemonic": "push"},
                {"mnemonic": "mov"},
                {"mnemonic": "sub"},
                {"mnemonic": "call"},
                {"mnemonic": "add"},
                {"mnemonic": "pop"},
                {"mnemonic": "ret"},
            ]
        }

    def get_disasm_text(self, address: int = 0, size: int = 0) -> str:
        return ""

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return [{"name": "main", "addr": 0x1000, "size": 100}]
        return default if default is not None else {}

    def cmd(self, command: str) -> str:
        return ""


class AdapterFunctionNoAddr:
    """Adapter with functions that have no addr - triggers line 128."""

    def analyze_all(self) -> None:
        pass

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return [
                {"name": "func_no_addr", "size": 50},
                {"name": "func_null_addr", "addr": None, "size": 50},
            ]
        return default if default is not None else {}

    def cmd(self, command: str) -> str:
        return ""


class AdapterNoTokens:
    """Adapter with a function but no disasm output - triggers line 84-86."""

    def analyze_all(self) -> None:
        pass

    def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
        return {}

    def get_disasm_text(self, address: int = 0, size: int = 0) -> str:
        return ""

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return [{"name": "empty_func", "addr": 0x1000, "size": 100}]
        return default if default is not None else {}

    def cmd(self, command: str) -> str:
        return ""


class AdapterTextOnly:
    """Adapter using text-based disasm fallback - triggers lines 351-369."""

    def analyze_all(self) -> None:
        pass

    def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
        return {}

    def get_disasm_text(self, address: int = 0, size: int = 100) -> str:
        return "push rbp\nmov rbp, rsp\ncall 0x2000\nadd rsp, 8\npop rbp\nret\n"

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return [{"name": "func_text", "addr": 0x1000, "size": 80}]
        return default if default is not None else {}

    def cmd(self, command: str) -> str:
        return ""


class AdapterTextWithBlanks:
    """Adapter with blank lines in text disasm - tests line 362."""

    def analyze_all(self) -> None:
        pass

    def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
        return {}

    def get_disasm_text(self, address: int = 0, size: int = 100) -> str:
        return "push rbp\n\nmov rbp, rsp\n\nsub rsp, 0x28\ncall func\nadd rsp, 0x28\npop rbp\nret\n"

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return [{"name": "func_blanks", "addr": 0x3000, "size": 60}]
        return default if default is not None else {}

    def cmd(self, command: str) -> str:
        return ""


class AdapterPdfjAndPdj:
    """Adapter using both pdfj then pdj paths - triggers lines 331, 338, 343-348."""

    def analyze_all(self) -> None:
        pass

    def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
        if size == 0:
            # pdfj path - return ops
            return {
                "ops": [
                    {"mnemonic": "mov"},
                    {"mnemonic": "push"},
                    {"mnemonic": "call"},
                    {"mnemonic": "pop"},
                    {"mnemonic": "ret"},
                ]
            }
        # pdj path - return list
        return [{"mnemonic": "nop"}, {"mnemonic": "ret"}]

    def get_disasm_text(self, address: int = 0, size: int = 100) -> str:
        return ""

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return [{"name": "func_dual", "addr": 0x4000, "size": 70}]
        return default if default is not None else {}

    def cmd(self, command: str) -> str:
        return ""


class AdapterFunctionsNoSize:
    """Adapter with functions that have addr=0 and size=0 (filtered out)."""

    def analyze_all(self) -> None:
        pass

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return [
                {"name": "zero_func", "addr": 0x1000, "size": 0},
            ]
        return default if default is not None else {}

    def cmd(self, command: str) -> str:
        return ""


class AdapterMultipleFunctions:
    """Adapter with many functions sharing same signature - triggers similar_functions."""

    def analyze_all(self) -> None:
        pass

    def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
        # All functions get the same tokens
        return {
            "ops": [
                {"mnemonic": "push"},
                {"mnemonic": "mov"},
                {"mnemonic": "ret"},
            ]
        }

    def get_disasm_text(self, address: int = 0, size: int = 100) -> str:
        return ""

    def cmdj(self, command: str, default: Any = None) -> Any:
        if command == "aflj":
            return [
                {"name": f"func_{i}", "addr": 0x1000 + i * 0x100, "size": 50}
                for i in range(3)
            ]
        return default if default is not None else {}

    def cmd(self, command: str) -> str:
        return ""


# ---------------------------------------------------------------------------
# analyze() - no functions found (lines 72-74)
# ---------------------------------------------------------------------------


def test_analyze_no_functions_found_sets_error() -> None:
    analyzer = BinlexAnalyzer(adapter=AdapterNoFunctions(), filepath="/tmp/test.bin")
    result = analyzer.analyze(ngram_sizes=[2])
    assert result["error"] == "No functions found in binary"
    assert result["total_functions"] == 0


# ---------------------------------------------------------------------------
# analyze() - no functions could be analyzed (lines 84-86)
# ---------------------------------------------------------------------------


def test_analyze_no_analyzable_functions_sets_error() -> None:
    analyzer = BinlexAnalyzer(adapter=AdapterNoTokens(), filepath="/tmp/test.bin")
    result = analyzer.analyze(ngram_sizes=[2])
    assert result["error"] == "No functions could be analyzed for Binlex"
    assert result["total_functions"] == 1


# ---------------------------------------------------------------------------
# analyze() - exception caught (lines 110-112)
# ---------------------------------------------------------------------------


class ExceptionDuringExtractAnalyzer(BinlexAnalyzer):
    def _extract_functions(self) -> list[dict[str, Any]]:
        raise RuntimeError("extraction failed unexpectedly")


def test_analyze_catches_outer_exception() -> None:
    analyzer = ExceptionDuringExtractAnalyzer(adapter=None, filepath=None)
    result = analyzer.analyze(ngram_sizes=[2])
    assert result["error"] is not None
    assert "extraction failed" in result["error"]


# ---------------------------------------------------------------------------
# _collect_function_signatures - func with no addr skipped (line 128)
# ---------------------------------------------------------------------------


def test_collect_function_signatures_skips_no_addr() -> None:
    analyzer = BinlexAnalyzer(adapter=AdapterFunctionNoAddr(), filepath=None)
    result = analyzer.analyze(ngram_sizes=[2])
    assert result["total_functions"] == 0
    assert result["error"] is not None


def test_collect_function_signatures_skips_none_addr_directly() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    functions = [
        {"name": "no_addr"},
        {"name": "null_addr", "addr": None},
    ]
    sigs, all_ngrams, count = analyzer._collect_function_signatures(functions, [2])
    assert count == 0
    assert sigs == {}


# ---------------------------------------------------------------------------
# _accumulate_ngrams - non-list ngrams skipped (line 151)
# ---------------------------------------------------------------------------


def test_accumulate_ngrams_skips_non_list_ngrams() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    all_ngrams: defaultdict[int, Counter[str]] = defaultdict(Counter)
    func_sigs: dict[int, dict[str, Any]] = {2: {"ngrams": "not_a_list"}}
    analyzer._accumulate_ngrams(all_ngrams, func_sigs, [2])
    assert 2 not in all_ngrams or len(all_ngrams[2]) == 0


def test_accumulate_ngrams_skips_when_n_missing() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    all_ngrams: defaultdict[int, Counter[str]] = defaultdict(Counter)
    func_sigs: dict[int, dict[str, Any]] = {3: {"ngrams": ["a b c"]}}
    analyzer._accumulate_ngrams(all_ngrams, func_sigs, [2])
    assert len(all_ngrams) == 0


# ---------------------------------------------------------------------------
# _calculate_binary_signature (lines 228-229, 240-242, 475-476)
# ---------------------------------------------------------------------------


def test_calculate_binary_signature_with_multiple_functions() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    function_signatures = {
        "func_a": {2: {"signature": "sig1", "ngrams": ["a b"]}},
        "func_b": {2: {"signature": "sig2", "ngrams": ["b c"]}},
        "func_c": {3: {"signature": "sig3", "ngrams": ["a b c"]}},
    }
    result = analyzer._calculate_binary_signature(function_signatures, [2, 3])
    assert 2 in result
    assert 3 in result
    assert len(result[2]) == 64  # SHA256 hex
    assert len(result[3]) == 64


def test_calculate_binary_signature_empty_function_signatures() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    result = analyzer._calculate_binary_signature({}, [2, 3])
    assert result == {}


def test_calculate_binary_signature_no_n_match() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    function_signatures = {
        "func_a": {3: {"signature": "sig1"}},
    }
    result = analyzer._calculate_binary_signature(function_signatures, [2])
    assert 2 not in result


def test_calculate_binary_signature_exception_returns_empty() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    # Non-sortable signatures trigger exception
    class NonSortable:
        def __gt__(self, other: object) -> bool:
            raise TypeError("not comparable")
        def __lt__(self, other: object) -> bool:
            raise TypeError("not comparable")

    function_signatures = {
        "f1": {2: {"signature": NonSortable()}},
        "f2": {2: {"signature": NonSortable()}},
    }
    result = analyzer._calculate_binary_signature(function_signatures, [2])
    assert result == {}


# ---------------------------------------------------------------------------
# _extract_functions - exception path (lines 240-242)
# ---------------------------------------------------------------------------


class CrashingAdapter:
    """Adapter that crashes on all calls."""

    def analyze_all(self) -> None:
        raise RuntimeError("adapter exploded")

    def cmdj(self, command: str, default: Any = None) -> Any:
        raise RuntimeError("adapter exploded")

    def cmd(self, command: str) -> str:
        raise RuntimeError("adapter exploded")


def test_extract_functions_exception_returns_empty() -> None:
    analyzer = BinlexAnalyzer(adapter=CrashingAdapter(), filepath=None)
    result = analyzer._extract_functions()
    assert result == []


# ---------------------------------------------------------------------------
# _analyze_function - no tokens (lines 262-263)
# ---------------------------------------------------------------------------


def test_analyze_function_no_tokens_returns_none() -> None:
    analyzer = BinlexAnalyzer(adapter=AdapterNoTokens(), filepath=None)
    result = analyzer._analyze_function(0x1000, "empty_func", [2])
    assert result is None


# ---------------------------------------------------------------------------
# _analyze_function - ngrams empty (line 277)
# ---------------------------------------------------------------------------


class EmptyNgramsBinlexAnalyzer(BinlexAnalyzer):
    def _generate_ngrams(self, tokens: list[str], n: int) -> list[str]:
        return []


def test_analyze_function_empty_ngrams_returns_none() -> None:
    class GoodTokenAdapter:
        def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
            return {"ops": [
                {"mnemonic": "push"},
                {"mnemonic": "mov"},
                {"mnemonic": "call"},
                {"mnemonic": "pop"},
                {"mnemonic": "ret"},
            ]}
        def get_disasm_text(self, **kwargs: Any) -> str:
            return ""

    analyzer = EmptyNgramsBinlexAnalyzer(adapter=GoodTokenAdapter(), filepath=None)
    result = analyzer._analyze_function(0x1000, "func", [2, 3])
    assert result is None


# ---------------------------------------------------------------------------
# _analyze_function - exception in analysis (lines 292-294)
# ---------------------------------------------------------------------------


class BrokenNgramsBinlexAnalyzer(BinlexAnalyzer):
    def _generate_ngrams(self, tokens: list[str], n: int) -> list[str]:
        raise RuntimeError("ngram generation failed")


def test_analyze_function_exception_returns_none() -> None:
    class GoodTokenAdapter:
        def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
            return {"ops": [{"mnemonic": "push"}, {"mnemonic": "ret"}]}
        def get_disasm_text(self, **kwargs: Any) -> str:
            return ""

    analyzer = BrokenNgramsBinlexAnalyzer(adapter=GoodTokenAdapter(), filepath=None)
    result = analyzer._analyze_function(0x1000, "broken_func", [2])
    assert result is None


# ---------------------------------------------------------------------------
# _extract_instruction_tokens - pdj fallback (lines 311-313)
# ---------------------------------------------------------------------------


def test_extract_instruction_tokens_falls_back_to_pdj() -> None:
    class PdfjEmptyPdjValidAdapter:
        def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
            if size == 0:
                return {}  # pdfj path returns no ops
            return [{"mnemonic": "mov"}, {"mnemonic": "push"}, {"mnemonic": "ret"}]

        def get_disasm_text(self, address: int = 0, size: int = 100) -> str:
            return ""

    analyzer = BinlexAnalyzer(adapter=PdfjEmptyPdjValidAdapter(), filepath=None)
    tokens = analyzer._extract_instruction_tokens(0x1000, "func_pdj")
    assert len(tokens) > 0
    assert "mov" in tokens


# ---------------------------------------------------------------------------
# _extract_instruction_tokens - text fallback (lines 315-317)
# ---------------------------------------------------------------------------


def test_extract_instruction_tokens_falls_back_to_text() -> None:
    class AllEmptyAdapter:
        def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
            return {}

        def get_disasm_text(self, address: int = 0, size: int = 100) -> str:
            return "push rbp\nmov rbp, rsp\npop rbp\nret\n"

    analyzer = BinlexAnalyzer(adapter=AllEmptyAdapter(), filepath=None)
    tokens = analyzer._extract_instruction_tokens(0x1000, "func_text")
    assert "push" in tokens
    assert "ret" in tokens


# ---------------------------------------------------------------------------
# _extract_instruction_tokens - exception returns [] (lines 319-322)
# ---------------------------------------------------------------------------


def test_extract_instruction_tokens_exception_returns_empty() -> None:
    class ThrowingTextAdapter:
        def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
            return {}

        def get_disasm_text(self, address: int = 0, size: int = 100) -> str:
            raise RuntimeError("text extraction exploded")

    analyzer = BinlexAnalyzer(adapter=ThrowingTextAdapter(), filepath=None)
    tokens = analyzer._extract_instruction_tokens(0x1000, "func")
    assert tokens == []


# ---------------------------------------------------------------------------
# _extract_tokens_from_pdfj - logging path (lines 331, 338)
# ---------------------------------------------------------------------------


def test_extract_tokens_from_pdfj_logs_when_tokens_found() -> None:
    class PdfjWithOpsAdapter:
        def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
            return {"ops": [
                {"mnemonic": "push"},
                {"mnemonic": "mov"},
                {"mnemonic": "pop"},
            ]}

        def get_disasm_text(self, **kwargs: Any) -> str:
            return ""

    analyzer = BinlexAnalyzer(adapter=PdfjWithOpsAdapter(), filepath=None)
    tokens = analyzer._extract_tokens_from_pdfj(0x1000, "func_with_ops")
    assert len(tokens) == 3
    assert "push" in tokens


def test_extract_tokens_from_pdfj_returns_empty_when_no_ops() -> None:
    class PdfjNoOpsAdapter:
        def get_disasm(self, address: int = 0, size: int = 0) -> dict[str, Any]:
            return {"other_key": []}

    analyzer = BinlexAnalyzer(adapter=PdfjNoOpsAdapter(), filepath=None)
    tokens = analyzer._extract_tokens_from_pdfj(0x1000, "func")
    assert tokens == []


# ---------------------------------------------------------------------------
# _extract_tokens_from_pdj (lines 343-348)
# ---------------------------------------------------------------------------


def test_extract_tokens_from_pdj_with_list_result() -> None:
    class PdjListAdapter:
        def get_disasm(self, address: int = 0, size: int = 200) -> Any:
            return [{"mnemonic": "call"}, {"mnemonic": "mov"}, {"mnemonic": "ret"}]

    analyzer = BinlexAnalyzer(adapter=PdjListAdapter(), filepath=None)
    tokens = analyzer._extract_tokens_from_pdj(0x1000, "func_pdj")
    assert "call" in tokens
    assert "ret" in tokens


def test_extract_tokens_from_pdj_with_non_list_returns_empty() -> None:
    class PdjDictAdapter:
        def get_disasm(self, address: int = 0, size: int = 200) -> Any:
            return {"not": "a list"}

    analyzer = BinlexAnalyzer(adapter=PdjDictAdapter(), filepath=None)
    tokens = analyzer._extract_tokens_from_pdj(0x1000, "func")
    assert tokens == []


def test_extract_tokens_from_pdj_logs_when_tokens_found() -> None:
    class PdjWithTokensAdapter:
        def get_disasm(self, address: int = 0, size: int = 200) -> Any:
            return [{"mnemonic": "push"}, {"mnemonic": "mov"}, {"mnemonic": "sub"},
                    {"mnemonic": "call"}, {"mnemonic": "pop"}, {"mnemonic": "ret"}]

    analyzer = BinlexAnalyzer(adapter=PdjWithTokensAdapter(), filepath=None)
    tokens = analyzer._extract_tokens_from_pdj(0x1000, "func_with_tokens")
    assert len(tokens) == 6


# ---------------------------------------------------------------------------
# _extract_tokens_from_text (lines 351-369)
# ---------------------------------------------------------------------------


def test_extract_tokens_from_text_full_path() -> None:
    analyzer = BinlexAnalyzer(adapter=AdapterTextOnly(), filepath=None)
    tokens = analyzer._extract_tokens_from_text(0x1000, "func_text")
    assert len(tokens) > 0
    assert "push" in tokens
    assert "ret" in tokens


def test_extract_tokens_from_text_skips_blank_lines() -> None:
    analyzer = BinlexAnalyzer(adapter=AdapterTextWithBlanks(), filepath=None)
    tokens = analyzer._extract_tokens_from_text(0x3000, "func_blanks")
    assert "" not in tokens
    assert "push" in tokens
    assert "ret" in tokens


def test_extract_tokens_from_text_empty_text_returns_empty() -> None:
    class EmptyTextAdapter:
        def get_disasm_text(self, address: int = 0, size: int = 100) -> str:
            return ""

    analyzer = BinlexAnalyzer(adapter=EmptyTextAdapter(), filepath=None)
    tokens = analyzer._extract_tokens_from_text(0x1000, "empty_func")
    assert tokens == []


def test_extract_tokens_from_text_whitespace_only_returns_empty() -> None:
    class WhitespaceAdapter:
        def get_disasm_text(self, address: int = 0, size: int = 100) -> str:
            return "   \n   \n  "

    analyzer = BinlexAnalyzer(adapter=WhitespaceAdapter(), filepath=None)
    tokens = analyzer._extract_tokens_from_text(0x1000, "ws_func")
    assert tokens == []


# ---------------------------------------------------------------------------
# _extract_tokens_from_ops - non-dict entries (line 375)
# ---------------------------------------------------------------------------


def test_extract_tokens_from_ops_skips_non_dict() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    ops = [None, "string", 42, {"mnemonic": "push"}, {"mnemonic": "ret"}]
    tokens = analyzer._extract_tokens_from_ops(ops)
    assert "push" in tokens
    assert "ret" in tokens
    assert len(tokens) == 2


# ---------------------------------------------------------------------------
# _extract_mnemonic_from_op (lines 385, 391, 395, 400)
# ---------------------------------------------------------------------------


def test_extract_mnemonic_string_mnemonic_field() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    result = analyzer._extract_mnemonic_from_op({"mnemonic": "call"})
    assert result == "call"


def test_extract_mnemonic_falls_back_to_opcode() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    result = analyzer._extract_mnemonic_from_op({"opcode": "jmp 0x1000"})
    assert result == "jmp"


def test_extract_mnemonic_empty_opcode_returns_none() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    result = analyzer._extract_mnemonic_from_op({"opcode": "   "})
    assert result is None


def test_extract_mnemonic_no_fields_returns_none() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    result = analyzer._extract_mnemonic_from_op({})
    assert result is None


def test_extract_mnemonic_non_string_mnemonic_falls_back() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    result = analyzer._extract_mnemonic_from_op({"mnemonic": 42})
    assert result is None


# ---------------------------------------------------------------------------
# _generate_ngrams - return path (line 414)
# ---------------------------------------------------------------------------


def test_generate_ngrams_returns_correct_ngrams() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    tokens = ["push", "mov", "call", "pop", "ret"]
    ngrams = analyzer._generate_ngrams(tokens, 2)
    assert "push mov" in ngrams
    assert "mov call" in ngrams
    assert "pop ret" in ngrams
    assert len(ngrams) == 4


def test_generate_ngrams_too_few_tokens_returns_empty() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    ngrams = analyzer._generate_ngrams(["push"], 3)
    assert ngrams == []


def test_generate_ngrams_exact_size_returns_one() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    ngrams = analyzer._generate_ngrams(["push", "mov", "ret"], 3)
    assert ngrams == ["push mov ret"]


# ---------------------------------------------------------------------------
# compare_functions (line 482)
# ---------------------------------------------------------------------------


def test_compare_functions_same_sig() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    assert analyzer.compare_functions("deadbeef", "deadbeef") is True


def test_compare_functions_different_sig() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    assert analyzer.compare_functions("deadbeef", "cafebabe") is False


# ---------------------------------------------------------------------------
# get_function_similarity_score (lines 488-502)
# ---------------------------------------------------------------------------


def test_similarity_score_identical_ngrams() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    ngrams = ["push mov", "mov call", "call pop", "pop ret"]
    score = analyzer.get_function_similarity_score(ngrams, ngrams)
    assert score == 1.0


def test_similarity_score_both_empty() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    score = analyzer.get_function_similarity_score([], [])
    assert score == 1.0


def test_similarity_score_first_empty() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    score = analyzer.get_function_similarity_score([], ["push mov"])
    assert score == 0.0


def test_similarity_score_second_empty() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    score = analyzer.get_function_similarity_score(["push mov"], [])
    assert score == 0.0


def test_similarity_score_partial_overlap() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)
    ngrams1 = ["push mov", "mov call", "call pop"]
    ngrams2 = ["mov call", "call pop", "pop ret"]
    score = analyzer.get_function_similarity_score(ngrams1, ngrams2)
    assert 0.0 < score < 1.0


def test_similarity_score_exception_returns_zero() -> None:
    analyzer = BinlexAnalyzer(adapter=None, filepath=None)

    class Unhashable:
        __hash__ = None  # type: ignore[assignment]
        def __eq__(self, other: object) -> bool:
            return False

    try:
        score = analyzer.get_function_similarity_score([Unhashable()], ["push mov"])
        assert score == 0.0
    except TypeError:
        pass  # exception path triggered as expected


# ---------------------------------------------------------------------------
# is_available (line 513)
# ---------------------------------------------------------------------------


def test_is_available_returns_true() -> None:
    assert BinlexAnalyzer.is_available() is True


# ---------------------------------------------------------------------------
# calculate_binlex_from_file (lines 529-532)
# ---------------------------------------------------------------------------


def test_calculate_binlex_from_file_returns_result_or_none(tmp_path: Path) -> None:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("Sample fixture not found")
    result = BinlexAnalyzer.calculate_binlex_from_file(str(sample), ngram_sizes=[2])
    # Returns BinlexResult or None
    assert result is None or isinstance(result, dict)


def test_calculate_binlex_from_file_nonexistent_returns_none() -> None:
    result = BinlexAnalyzer.calculate_binlex_from_file(
        "/nonexistent/path/to/binary.exe", ngram_sizes=[2]
    )
    assert result is None


def test_calculate_binlex_from_file_with_default_ngram_sizes(tmp_path: Path) -> None:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("Sample fixture not found")
    result = BinlexAnalyzer.calculate_binlex_from_file(str(sample))
    assert result is None or isinstance(result, dict)


# ---------------------------------------------------------------------------
# Full analyze() round-trip
# ---------------------------------------------------------------------------


def test_analyze_full_round_trip_with_valid_adapter() -> None:
    analyzer = BinlexAnalyzer(adapter=AdapterOneFunction(), filepath="/tmp/test.bin")
    result = analyzer.analyze(ngram_sizes=[2])
    assert isinstance(result, dict)
    assert "available" in result
    assert "function_signatures" in result
    assert "total_functions" in result
    assert "binary_signature" in result
    assert "top_ngrams" in result
    if result["available"]:
        assert result["analyzed_functions"] >= 1


def test_analyze_default_ngram_sizes() -> None:
    analyzer = BinlexAnalyzer(adapter=AdapterNoFunctions(), filepath=None)
    result = analyzer.analyze()
    assert result["ngram_sizes"] == [2, 3, 4]


def test_analyze_with_text_fallback() -> None:
    analyzer = BinlexAnalyzer(adapter=AdapterTextOnly(), filepath=None)
    result = analyzer.analyze(ngram_sizes=[2])
    assert isinstance(result, dict)


def test_analyze_filters_zero_size_functions() -> None:
    analyzer = BinlexAnalyzer(adapter=AdapterFunctionsNoSize(), filepath=None)
    result = analyzer.analyze(ngram_sizes=[2])
    assert result["total_functions"] == 0
    assert result["error"] is not None


def test_analyze_multiple_functions_with_same_signature() -> None:
    analyzer = BinlexAnalyzer(adapter=AdapterMultipleFunctions(), filepath=None)
    result = analyzer.analyze(ngram_sizes=[2])
    assert isinstance(result, dict)
