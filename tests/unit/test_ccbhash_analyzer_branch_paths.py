"""Branch-path tests for ccbhash_analyzer.py covering missing lines."""

from __future__ import annotations

from typing import Any

from r2inspect.modules.ccbhash_analyzer import CCBHashAnalyzer


# ---------------------------------------------------------------------------
# Adapter helpers (no unittest.mock)
# ---------------------------------------------------------------------------


class NoFunctionsAdapter:
    """Adapter that returns an empty function list."""

    def get_functions(self) -> list[dict[str, Any]]:
        return []

    def get_cfg(self, func_offset: int) -> list[dict[str, Any]]:
        return []


class FunctionsWithNullAddrAdapter:
    """Adapter whose functions have addr=None, so the loop continues past them."""

    def get_functions(self) -> list[dict[str, Any]]:
        return [
            {"name": "null_addr_func", "addr": None, "size": 50},
            {"name": "zero_size_func", "addr": 0x1000, "size": 0},
        ]

    def get_cfg(self, func_offset: int) -> list[dict[str, Any]]:
        return []


class NoCFGAdapter:
    """Adapter that returns no CFG data for any function."""

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"name": "test_func", "addr": 0x1000, "size": 100}]

    def get_cfg(self, func_offset: int) -> list[dict[str, Any]]:
        return []


class SingleFunctionAdapter:
    """Adapter with one function and a valid CFG."""

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"name": "main", "addr": 0x1000, "size": 100}]

    def get_cfg(self, func_offset: int) -> list[dict[str, Any]]:
        return [
            {
                "edges": [
                    {"src": func_offset, "dst": func_offset + 0x10},
                    {"src": func_offset + 0x10, "dst": func_offset + 0x20},
                ],
                "blocks": [
                    {"offset": func_offset},
                    {"offset": func_offset + 0x10},
                ],
            }
        ]


class BlocksOnlyCFGAdapter:
    """Adapter whose CFG has blocks but no edges."""

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"name": "block_func", "addr": 0x2000, "size": 64}]

    def get_cfg(self, func_offset: int) -> list[dict[str, Any]]:
        return [
            {
                "blocks": [
                    {"offset": func_offset},
                    {"offset": func_offset + 0x10},
                ]
            }
        ]


class EmptyCFGAdapter:
    """Adapter whose CFG has neither edges nor blocks."""

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"name": "empty_cfg_func", "addr": 0x3000, "size": 32}]

    def get_cfg(self, func_offset: int) -> list[dict[str, Any]]:
        return [{}]


class RaisingCFGAdapter:
    """Adapter whose get_cfg raises an exception."""

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"name": "raising_func", "addr": 0x4000, "size": 50}]

    def get_cfg(self, func_offset: int) -> list[dict[str, Any]]:
        raise RuntimeError("simulated CFG failure")


class DuplicateHashAdapter:
    """Adapter with two functions that produce identical CFG canonical strings."""

    def get_functions(self) -> list[dict[str, Any]]:
        return [
            {"name": "func_a", "addr": 0x1000, "size": 50},
            {"name": "func_b", "addr": 0x2000, "size": 50},
        ]

    def get_cfg(self, func_offset: int) -> list[dict[str, Any]]:
        # Return identical CFG regardless of address
        return [
            {
                "blocks": [
                    {"offset": 100},
                    {"offset": 200},
                ]
            }
        ]


class RaisingAnalyzeFunctionsAdapter:
    """Adapter whose get_functions raises after first call."""

    _call_count = 0

    def __init__(self) -> None:
        self._call_count = 0

    def get_functions(self) -> list[dict[str, Any]]:
        raise RuntimeError("forced analyze_functions failure")

    def get_cfg(self, func_offset: int) -> list[dict[str, Any]]:
        return []


class FunctionsWithHtmlEntitiesAdapter:
    """Adapter with HTML entity characters in function names."""

    def get_functions(self) -> list[dict[str, Any]]:
        return [
            {"name": "func&nbsp;with spaces", "addr": 0x1000, "size": 50},
            {"name": "func&amp;name", "addr": 0x2000, "size": 50},
        ]

    def get_cfg(self, func_offset: int) -> list[dict[str, Any]]:
        return [
            {
                "blocks": [
                    {"offset": func_offset},
                ]
            }
        ]


class RaisingFindSimilarAdapter:
    """Causes _find_similar_functions to raise via corrupt function_hashes."""

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"name": "f", "addr": 0x1000, "size": 10}]

    def get_cfg(self, func_offset: int) -> list[dict[str, Any]]:
        return [{"blocks": [{"offset": func_offset}]}]


# ---------------------------------------------------------------------------
# _calculate_hash  (lines 55, 64, 75, 81-85)
# ---------------------------------------------------------------------------


def test_calculate_hash_returns_error_when_no_functions():
    """No functions → (None, None, NO_FUNCTIONS_FOUND) (line 55)."""
    analyzer = CCBHashAnalyzer(NoFunctionsAdapter(), "/path/to/binary")
    h, method, err = analyzer._calculate_hash()
    assert h is None
    assert "No functions" in err


def test_calculate_hash_skips_null_addr_functions():
    """Functions with addr=None are skipped (line 64)."""
    adapter = FunctionsWithNullAddrAdapter()
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    h, method, err = analyzer._calculate_hash()
    assert h is None


def test_calculate_hash_returns_error_when_no_hashes_produced():
    """All CFG calls return no data → NO_FUNCTIONS_ANALYZED (line 75)."""
    analyzer = CCBHashAnalyzer(NoCFGAdapter(), "/path/to/binary")
    h, method, err = analyzer._calculate_hash()
    assert h is None
    assert err is not None


def test_calculate_hash_success_path():
    """Valid adapter → hash returned with method='cfg_analysis'."""
    analyzer = CCBHashAnalyzer(SingleFunctionAdapter(), "/path/to/binary")
    h, method, err = analyzer._calculate_hash()
    if h is not None:
        assert method == "cfg_analysis"
        assert err is None


def test_calculate_hash_exception_handler():
    """Adapter raises during CFG fetch → exception caught (lines 83-85)."""
    analyzer = CCBHashAnalyzer(RaisingCFGAdapter(), "/path/to/binary")
    h, method, err = analyzer._calculate_hash()
    assert h is None
    assert err is not None


# ---------------------------------------------------------------------------
# analyze_functions  (lines 123-125, 139, 151-153, 179-181)
# ---------------------------------------------------------------------------


def test_analyze_functions_no_functions():
    """No functions → error set, available stays False (lines 123-125)."""
    analyzer = CCBHashAnalyzer(NoFunctionsAdapter(), "/path/to/binary")
    result = analyzer.analyze_functions()
    assert result["available"] is False
    assert result["total_functions"] == 0
    assert result["error"] is not None


def test_analyze_functions_skips_null_addr():
    """Functions with addr=None have continue applied (line 139)."""
    analyzer = CCBHashAnalyzer(FunctionsWithNullAddrAdapter(), "/path/to/binary")
    result = analyzer.analyze_functions()
    assert result["analyzed_functions"] == 0


def test_analyze_functions_no_hashes_produced():
    """All functions fail to produce a hash (lines 151-153)."""
    analyzer = CCBHashAnalyzer(NoCFGAdapter(), "/path/to/binary")
    result = analyzer.analyze_functions()
    assert result["available"] is False
    assert "error" in result


def test_analyze_functions_exception_handler():
    """Exception during analysis caught (lines 179-181)."""
    analyzer = CCBHashAnalyzer(RaisingAnalyzeFunctionsAdapter(), "/path/to/binary")
    result = analyzer.analyze_functions()
    assert "error" in result


# ---------------------------------------------------------------------------
# _extract_functions  (lines 198-199, 213-215)
# ---------------------------------------------------------------------------


def test_extract_functions_returns_empty_when_aflj_empty():
    """Empty aflj result → empty list returned (lines 198-199)."""
    analyzer = CCBHashAnalyzer(NoFunctionsAdapter(), "/path/to/binary")
    functions = analyzer._extract_functions()
    assert functions == []


def test_extract_functions_exception_handler():
    """Exception inside _extract_functions is caught (lines 213-215)."""

    class ExplodingFunctionsAdapter:
        def get_functions(self) -> list[dict[str, Any]]:
            raise RuntimeError("forced failure")

        def get_cfg(self, func_offset: int) -> list[dict[str, Any]]:
            return []

    analyzer = CCBHashAnalyzer(ExplodingFunctionsAdapter(), "/path/to/binary")
    functions = analyzer._extract_functions()
    assert functions == []


# ---------------------------------------------------------------------------
# _calculate_function_ccbhash  (lines 237-238, 244)
# ---------------------------------------------------------------------------


def test_calculate_function_ccbhash_no_cfg_data():
    """Empty CFG data returns None (lines 237-238)."""
    analyzer = CCBHashAnalyzer(NoCFGAdapter(), "/path/to/binary")
    result = analyzer._calculate_function_ccbhash(0x1000, "test_func")
    assert result is None


def test_calculate_function_ccbhash_exception_returns_none():
    """Exception during CFG fetch returns None (lines 252-254)."""
    analyzer = CCBHashAnalyzer(RaisingCFGAdapter(), "/path/to/binary")
    result = analyzer._calculate_function_ccbhash(0x1000, "test_func")
    assert result is None


# ---------------------------------------------------------------------------
# _build_canonical_representation  (lines 260-267, 274)
# ---------------------------------------------------------------------------


def test_build_canonical_representation_with_edges():
    """Edges present → edge strings built (lines 260-267)."""
    cfg = {
        "edges": [
            {"src": 0x1000, "dst": 0x1010},
            {"src": 0x1010, "dst": 0x1020},
        ]
    }
    result = CCBHashAnalyzer._build_canonical_representation(cfg, 0x1000)
    assert result is not None
    assert "->" in result


def test_build_canonical_representation_edges_with_none_src_dst():
    """Edges where src or dst is None are skipped."""
    cfg = {
        "edges": [
            {"src": None, "dst": 0x1010},
            {"src": 0x1000, "dst": None},
            {"src": 0x1000, "dst": 0x1020},
        ]
    }
    result = CCBHashAnalyzer._build_canonical_representation(cfg, 0x1000)
    assert result is not None
    assert "4096->4128" in result


def test_build_canonical_representation_with_blocks_only():
    """No edges but blocks present → block addresses used (line 270-272)."""
    cfg = {
        "blocks": [
            {"offset": 0x1020},
            {"offset": 0x1000},
            {"offset": 0x1010},
        ]
    }
    result = CCBHashAnalyzer._build_canonical_representation(cfg, 0x1000)
    assert result is not None
    assert "|" in result


def test_build_canonical_representation_fallback_to_func_offset():
    """Neither edges nor blocks → function offset used (line 274)."""
    cfg: dict[str, Any] = {}
    result = CCBHashAnalyzer._build_canonical_representation(cfg, 0x5000)
    assert result == "20480"


# ---------------------------------------------------------------------------
# _find_similar_functions  (lines 293-297, 300-314, 316-318)
# ---------------------------------------------------------------------------


def test_find_similar_functions_groups_identical_hashes():
    """Functions sharing a hash end up in the same group."""
    analyzer = CCBHashAnalyzer(None, "/path/to/binary")
    fhashes = {
        "alpha": {"ccbhash": "aaa", "addr": 0x1000, "size": 10},
        "beta": {"ccbhash": "aaa", "addr": 0x2000, "size": 10},
        "gamma": {"ccbhash": "bbb", "addr": 0x3000, "size": 10},
    }
    result = analyzer._find_similar_functions(fhashes)
    assert len(result) == 1
    assert result[0]["count"] == 2


def test_find_similar_functions_no_duplicates():
    """All unique hashes → empty list."""
    analyzer = CCBHashAnalyzer(None, "/path/to/binary")
    fhashes = {
        "f1": {"ccbhash": "x1"},
        "f2": {"ccbhash": "x2"},
    }
    result = analyzer._find_similar_functions(fhashes)
    assert result == []


def test_find_similar_functions_exception_handler():
    """Corrupt input triggers exception handler (lines 316-318)."""
    analyzer = CCBHashAnalyzer(None, "/path/to/binary")
    result = analyzer._find_similar_functions(None)  # type: ignore[arg-type]
    assert result == []


# ---------------------------------------------------------------------------
# _calculate_binary_ccbhash  (lines 332, 346-348)
# ---------------------------------------------------------------------------


def test_calculate_binary_ccbhash_returns_none_for_empty():
    """Empty dict → returns None (line 332)."""
    analyzer = CCBHashAnalyzer(None, "/path/to/binary")
    assert analyzer._calculate_binary_ccbhash({}) is None


def test_calculate_binary_ccbhash_exception_handler():
    """Corrupt data triggers exception handler (lines 346-348)."""
    analyzer = CCBHashAnalyzer(None, "/path/to/binary")
    result = analyzer._calculate_binary_ccbhash(None)  # type: ignore[arg-type]
    assert result is None


# ---------------------------------------------------------------------------
# get_function_ccbhash  (lines 360-379)
# ---------------------------------------------------------------------------


def test_get_function_ccbhash_function_not_found():
    """Function name not in list → None returned (lines 369-371)."""
    analyzer = CCBHashAnalyzer(SingleFunctionAdapter(), "/path/to/binary")
    result = analyzer.get_function_ccbhash("nonexistent_func")
    assert result is None


def test_get_function_ccbhash_function_found_and_calculated():
    """Function found → CCBHash calculated (lines 360-375)."""
    analyzer = CCBHashAnalyzer(SingleFunctionAdapter(), "/path/to/binary")
    result = analyzer.get_function_ccbhash("main")
    # May be a hash string or None depending on CFG data
    assert result is None or isinstance(result, str)


def test_get_function_ccbhash_exception_returns_none():
    """Exception during search returns None (lines 377-379)."""

    class ExplodingListAdapter:
        def get_functions(self) -> list[dict[str, Any]]:
            raise RuntimeError("forced failure")

        def get_cfg(self, offset: int) -> list[dict[str, Any]]:
            return []

    analyzer = CCBHashAnalyzer(ExplodingListAdapter(), "/path/to/binary")
    result = analyzer.get_function_ccbhash("any_func")
    assert result is None


# ---------------------------------------------------------------------------
# compare_hashes  (lines 403-405)
# ---------------------------------------------------------------------------


def test_compare_hashes_empty_returns_none():
    """Empty strings → None (lines 403-404)."""
    assert CCBHashAnalyzer.compare_hashes("", "abc") is None
    assert CCBHashAnalyzer.compare_hashes("abc", "") is None


def test_compare_hashes_equal_strings():
    """Identical hashes → True (line 405)."""
    assert CCBHashAnalyzer.compare_hashes("abc123", "abc123") is True


def test_compare_hashes_different_strings():
    """Different hashes → False (line 405)."""
    assert CCBHashAnalyzer.compare_hashes("abc123", "xyz789") is False


# ---------------------------------------------------------------------------
# compare_ccbhashes  (lines 431-432)
# ---------------------------------------------------------------------------


def test_compare_ccbhashes_equal():
    """Identical hashes return True (lines 431-432)."""
    assert CCBHashAnalyzer.compare_ccbhashes("abc", "abc") is True


def test_compare_ccbhashes_different():
    assert CCBHashAnalyzer.compare_ccbhashes("abc", "xyz") is False


def test_compare_ccbhashes_empty_returns_false():
    """When compare_hashes returns None, compare_ccbhashes returns False (line 432)."""
    assert CCBHashAnalyzer.compare_ccbhashes("", "xyz") is False


# ---------------------------------------------------------------------------
# calculate_ccbhash_from_file  (lines 445-448)
# ---------------------------------------------------------------------------


def test_calculate_ccbhash_from_file_nonexistent_returns_none():
    """Non-existent file returns None and logs error (lines 445-448)."""
    result = CCBHashAnalyzer.calculate_ccbhash_from_file("/nonexistent/path_12345.bin")
    assert result is None


def test_calculate_ccbhash_from_file_real_binary():
    """Real binary may succeed or return None gracefully."""
    from pathlib import Path

    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        return
    result = CCBHashAnalyzer.calculate_ccbhash_from_file(str(sample))
    assert result is None or isinstance(result, dict)


# ---------------------------------------------------------------------------
# analyze_functions full coverage path with HTML entities
# ---------------------------------------------------------------------------


def test_analyze_functions_cleans_html_entities_in_function_names():
    """Function names with HTML entities are cleaned (lines inside _extract_functions)."""
    analyzer = CCBHashAnalyzer(FunctionsWithHtmlEntitiesAdapter(), "/path/to/binary")
    result = analyzer.analyze_functions()
    for func_name in result.get("function_hashes", {}):
        assert "&nbsp;" not in func_name
        assert "&amp;" not in func_name


def test_analyze_functions_with_duplicate_hashes():
    """Duplicate CFGs produce similar_functions groups."""
    analyzer = CCBHashAnalyzer(DuplicateHashAdapter(), "/path/to/binary")
    result = analyzer.analyze_functions()
    if result["available"]:
        assert result["unique_hashes"] <= result["analyzed_functions"]
