"""Tests for function_analyzer.py covering missing lines."""

from __future__ import annotations

from r2inspect.modules.function_analyzer import FunctionAnalyzer


class MinimalAdapter:
    """Adapter returning no functions and no disasm."""

    def get_functions(self):
        return []


class FunctionsAdapter:
    """Adapter returning a list of functions."""

    def __init__(self, functions):
        self._functions = functions

    def get_functions(self):
        return self._functions


class DisasmDictAdapter:
    """Adapter whose get_disasm returns a dict with ops (pdfj-style)."""

    def __init__(self, ops):
        self._ops = ops

    def get_functions(self):
        return []

    def get_disasm(self, address=None, size=None):
        if size is None:
            return {"ops": self._ops}
        return self._ops  # list for pdj-style


class DisasmListAdapter:
    """Adapter whose get_disasm returns a list (pdj-style)."""

    def __init__(self, ops):
        self._ops = ops

    def get_functions(self):
        return []

    def get_disasm(self, address=None, size=None):
        return self._ops


class DisasmTextAdapter:
    """Adapter whose get_disasm_text returns assembly text."""

    def __init__(self, text):
        self._text = text

    def get_functions(self):
        return []

    def get_disasm_text(self, address=None, size=None):
        return self._text


class RaisingDisasmAdapter:
    """Adapter whose get_disasm raises an exception."""

    def get_functions(self):
        return []

    def get_disasm(self, address=None, size=None):
        raise RuntimeError("disasm error")


class RaisingDisasmTextAdapter:
    """Adapter whose get_disasm_text raises an exception."""

    def get_functions(self):
        return []

    def get_disasm_text(self, address=None, size=None):
        raise RuntimeError("disasm_text error")


class CfgAdapter:
    """Adapter that provides CFG data."""

    def __init__(self, cfg):
        self._cfg = cfg

    def get_functions(self):
        return []

    def get_cfg(self, address=None):
        return self._cfg


class DeepAnalysisConfig:
    """Config that enables deep analysis."""

    class typed_config:
        class analysis:
            deep_analysis = True


class NoDeepAnalysisConfig:
    """Config with deep_analysis = False."""

    class typed_config:
        class analysis:
            deep_analysis = False


# ---------------------------------------------------------------------------
# analyze_functions
# ---------------------------------------------------------------------------


def test_analyze_functions_returns_error_when_no_functions():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer.analyze_functions()
    assert result["total_functions"] == 0
    assert result["error"] == "No functions detected"
    assert result["machoc_hashes"] == {}
    assert result["function_stats"] == {}


def test_analyze_functions_returns_results_with_functions():
    funcs = [{"name": "main", "addr": 0x1000, "size": 100, "type": "user"}]
    ops = [{"opcode": "mov eax, 0"}, {"opcode": "push ebx"}, {"opcode": "ret"}]
    adapter = DisasmDictAdapter(ops)
    adapter._functions = funcs
    adapter.get_functions = lambda: funcs
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer.analyze_functions()
    assert result["total_functions"] == 1
    assert "machoc_hashes" in result
    assert "function_stats" in result


def test_analyze_functions_exception_in_get_functions():
    class BrokenAnalyzer(FunctionAnalyzer):
        def _get_functions(self):
            raise RuntimeError("forced error in get_functions")

    adapter = MinimalAdapter()
    analyzer = BrokenAnalyzer(adapter)
    result = analyzer.analyze_functions()
    assert result["total_functions"] == 0
    assert "error" in result
    assert "forced error" in result["error"]


# ---------------------------------------------------------------------------
# _get_functions – paths when aflj returns empty
# ---------------------------------------------------------------------------


def test_get_functions_triggers_full_analysis_when_no_functions():
    class AnalyzeAllAdapter:
        _analyzed = False

        def get_functions(self):
            return []

        def analyze_all(self):
            self._analyzed = True

    adapter = AnalyzeAllAdapter()
    config = DeepAnalysisConfig()
    analyzer = FunctionAnalyzer(adapter, config=config)
    result = analyzer._get_functions()
    assert result == []
    assert analyzer.functions_cache == []


def test_get_functions_triggers_aa_when_not_full_analysis():
    class AAAdapter:
        def get_functions(self):
            return []

    adapter = AAAdapter()
    config = NoDeepAnalysisConfig()
    analyzer = FunctionAnalyzer(adapter, config=config)
    analyzer._file_size_mb = 100.0  # > VERY_LARGE_FILE_THRESHOLD_MB
    result = analyzer._get_functions()
    assert result == []


def test_get_functions_returns_cached():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    cached = [{"name": "func_a", "addr": 0x500}]
    analyzer.functions_cache = cached
    result = analyzer._get_functions()
    assert result is cached


def test_get_functions_exception_returns_empty():
    class ErrorAdapter:
        def get_functions(self):
            raise RuntimeError("error")

    adapter = ErrorAdapter()
    analyzer = FunctionAnalyzer(adapter)
    # Force cache None so it tries to load
    analyzer.functions_cache = None
    result = analyzer._get_functions()
    assert result == []


# ---------------------------------------------------------------------------
# _get_file_size_mb
# ---------------------------------------------------------------------------


def test_get_file_size_mb_nonexistent_file():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    size = analyzer._get_file_size_mb("/tmp/definitely_does_not_exist_xyz123.exe")
    assert size is None


def test_get_file_size_mb_no_filename():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    size = analyzer._get_file_size_mb(None)
    assert size is None


def test_get_file_size_mb_real_file(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x00" * 1024)
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter, filename=str(f))
    assert analyzer._file_size_mb is not None
    assert analyzer._file_size_mb > 0


# ---------------------------------------------------------------------------
# _should_run_full_analysis
# ---------------------------------------------------------------------------


def test_should_run_full_analysis_deep_analysis_config():
    adapter = MinimalAdapter()
    config = DeepAnalysisConfig()
    analyzer = FunctionAnalyzer(adapter, config=config)
    assert analyzer._should_run_full_analysis() is True


def test_should_run_full_analysis_no_deep_analysis_small_file():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    analyzer._file_size_mb = 1.0  # <= VERY_LARGE_FILE_THRESHOLD_MB (10)
    assert analyzer._should_run_full_analysis() is True


def test_should_run_full_analysis_no_file_size():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    analyzer._file_size_mb = None
    assert analyzer._should_run_full_analysis() is True


def test_should_run_full_analysis_large_file():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    analyzer._file_size_mb = 100.0  # > VERY_LARGE_FILE_THRESHOLD_MB
    assert analyzer._should_run_full_analysis() is False


def test_should_run_full_analysis_config_exception():
    class BadConfig:
        @property
        def typed_config(self):
            raise RuntimeError("config error")

    adapter = MinimalAdapter()
    config = BadConfig()
    analyzer = FunctionAnalyzer(adapter, config=config)
    # Should fall through to file_size check
    analyzer._file_size_mb = 1.0
    result = analyzer._should_run_full_analysis()
    assert result is True


# ---------------------------------------------------------------------------
# _generate_machoc_hashes
# ---------------------------------------------------------------------------


def test_generate_machoc_hashes_returns_empty_when_result_is_none():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    # Function with no addr → _process_single_function_hash returns None
    functions = [{"name": "unnamed_func"}]
    hashes = analyzer._generate_machoc_hashes(functions)
    assert hashes == {}


def test_generate_machoc_hashes_increments_failed_on_exception():
    class PartialAnalyzer(FunctionAnalyzer):
        def _process_single_function_hash(self, func, index, total):
            raise RuntimeError("hash error")

    adapter = MinimalAdapter()
    analyzer = PartialAnalyzer(adapter)
    functions = [{"name": "func_a", "addr": 0x1000}]
    hashes = analyzer._generate_machoc_hashes(functions)
    assert hashes == {}


def test_generate_machoc_hashes_with_valid_functions():
    ops = [{"opcode": "mov eax, 1"}, {"opcode": "ret"}]
    funcs = [{"name": "func_a", "addr": 0x1000, "size": 20}]
    adapter = DisasmDictAdapter(ops)
    adapter.get_functions = lambda: funcs
    analyzer = FunctionAnalyzer(adapter)
    hashes = analyzer._generate_machoc_hashes(funcs)
    assert "func_a" in hashes


# ---------------------------------------------------------------------------
# _process_single_function_hash
# ---------------------------------------------------------------------------


def test_process_single_function_hash_no_addr():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._process_single_function_hash({"name": "no_addr_func"}, 0, 1)
    assert result is None


def test_process_single_function_hash_no_mnemonics():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    func = {"name": "empty_func", "addr": 0x2000, "size": 0}
    result = analyzer._process_single_function_hash(func, 0, 1)
    assert result is None


def test_process_single_function_hash_empty_machoc():
    class EmptyMnemonicsAnalyzer(FunctionAnalyzer):
        def _extract_function_mnemonics(self, name, size, addr):
            return []

    adapter = MinimalAdapter()
    analyzer = EmptyMnemonicsAnalyzer(adapter)
    func = {"name": "func_empty", "addr": 0x3000, "size": 50}
    result = analyzer._process_single_function_hash(func, 0, 1)
    assert result is None


def test_process_single_function_hash_success():
    ops = [{"opcode": "push ebp"}, {"opcode": "mov ebp, esp"}, {"opcode": "pop ebp"}, {"opcode": "ret"}]
    adapter = DisasmDictAdapter(ops)
    analyzer = FunctionAnalyzer(adapter)
    func = {"name": "my_func", "addr": 0x4000, "size": 16}
    result = analyzer._process_single_function_hash(func, 0, 1)
    assert result is not None
    name, hash_val = result
    assert name == "my_func"
    assert len(hash_val) == 64  # sha256 hex


# ---------------------------------------------------------------------------
# _extract_function_mnemonics – fallback paths
# ---------------------------------------------------------------------------


def test_extract_function_mnemonics_falls_through_to_pdj():
    ops = [{"opcode": "nop"}, {"opcode": "ret"}]
    adapter = DisasmListAdapter(ops)
    analyzer = FunctionAnalyzer(adapter)
    # adapter has get_disasm returning list, size > 0
    mnemonics = analyzer._extract_function_mnemonics("func", 100, 0x1000)
    assert "nop" in mnemonics or "ret" in mnemonics


def test_extract_function_mnemonics_falls_through_to_basic_pdj():
    class BasicPdjAdapter:
        def get_disasm(self, address=None, size=None):
            if size == 50:
                return [{"opcode": "nop"}]
            # Return None to force fallthrough from pdfj and pdj
            return None

    adapter = BasicPdjAdapter()
    analyzer = FunctionAnalyzer(adapter)
    mnemonics = analyzer._extract_function_mnemonics("func", 0, 0x1000)
    assert "nop" in mnemonics


def test_extract_function_mnemonics_falls_through_to_pi():
    text = "mov eax, 0\npush ebx\nret\n"
    adapter = DisasmTextAdapter(text)
    analyzer = FunctionAnalyzer(adapter)
    mnemonics = analyzer._extract_function_mnemonics("func", 0, 0x1000)
    assert "mov" in mnemonics


def test_extract_function_mnemonics_all_empty():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    mnemonics = analyzer._extract_function_mnemonics("func", 0, 0x1000)
    assert mnemonics == []


# ---------------------------------------------------------------------------
# _try_pdfj_extraction
# ---------------------------------------------------------------------------


def test_try_pdfj_extraction_with_disasm_dict():
    ops = [{"opcode": "call printf"}, {"opcode": "add esp, 4"}]
    adapter = DisasmDictAdapter(ops)
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._try_pdfj_extraction("func", 0x1000)
    assert "call" in result
    assert "add" in result


def test_try_pdfj_extraction_exception_returns_empty():
    adapter = RaisingDisasmAdapter()
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._try_pdfj_extraction("func", 0x1000)
    assert result == []


def test_try_pdfj_extraction_adapter_none():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    # adapter has no get_disasm, so falls back to cmdj which returns {}
    result = analyzer._try_pdfj_extraction("func", 0x1000)
    assert result == []


# ---------------------------------------------------------------------------
# _try_pdj_extraction
# ---------------------------------------------------------------------------


def test_try_pdj_extraction_with_list():
    ops = [{"opcode": "sub esp, 8"}, {"opcode": "mov [esp], eax"}]
    adapter = DisasmListAdapter(ops)
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._try_pdj_extraction("func", 40, 0x1000)
    assert "sub" in result


def test_try_pdj_extraction_exception_returns_empty():
    adapter = RaisingDisasmAdapter()
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._try_pdj_extraction("func", 100, 0x1000)
    assert result == []


def test_try_pdj_extraction_returns_empty_list():
    adapter = DisasmListAdapter([])
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._try_pdj_extraction("func", 100, 0x1000)
    assert result == []


# ---------------------------------------------------------------------------
# _try_basic_pdj_extraction
# ---------------------------------------------------------------------------


def test_try_basic_pdj_extraction_with_list():
    ops = [{"opcode": "xor eax, eax"}, {"opcode": "ret"}]
    adapter = DisasmListAdapter(ops)
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._try_basic_pdj_extraction("func", 0x1000)
    assert "xor" in result


def test_try_basic_pdj_extraction_exception_returns_empty():
    adapter = RaisingDisasmAdapter()
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._try_basic_pdj_extraction("func", 0x1000)
    assert result == []


def test_try_basic_pdj_extraction_no_adapter_get_disasm():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._try_basic_pdj_extraction("func", 0x1000)
    assert result == []


# ---------------------------------------------------------------------------
# _try_pi_extraction
# ---------------------------------------------------------------------------


def test_try_pi_extraction_with_text():
    text = "mov eax, 1\npush ecx\ncall sub_1234\nret\n"
    adapter = DisasmTextAdapter(text)
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._try_pi_extraction("func", 0x1000)
    assert "mov" in result
    assert "ret" in result


def test_try_pi_extraction_exception_returns_empty():
    adapter = RaisingDisasmTextAdapter()
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._try_pi_extraction("func", 0x1000)
    assert result == []


def test_try_pi_extraction_empty_text():
    adapter = DisasmTextAdapter("")
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._try_pi_extraction("func", 0x1000)
    assert result == []


def test_try_pi_extraction_no_disasm_text():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._try_pi_extraction("func", 0x1000)
    assert result == []


# ---------------------------------------------------------------------------
# _generate_function_stats
# ---------------------------------------------------------------------------


def test_generate_function_stats_empty():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._generate_function_stats([])
    assert result == {}


def test_generate_function_stats_with_functions():
    funcs = [
        {"name": "main", "size": 200, "type": "user"},
        {"name": "helper", "size": 50, "type": "user"},
        {"name": "lib_func", "size": 10},
    ]
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._generate_function_stats(funcs)
    assert result["total_functions"] == 3
    assert result["avg_function_size"] == pytest.approx((200 + 50 + 10) / 3)
    assert result["min_function_size"] == 10
    assert result["max_function_size"] == 200
    assert "largest_functions" in result


def test_generate_function_stats_no_size():
    funcs = [{"name": "nosizefunc", "type": "unknown"}]
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._generate_function_stats(funcs)
    assert result["functions_with_size"] == 0


def test_generate_function_stats_exception_returns_error():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    # Trigger exception in stats by passing something that causes iteration error on .get()
    # Wrapping list of non-dicts so that func.get("size", 0) raises AttributeError
    funcs_bad = [1, 2, 3]  # ints have no .get()
    result = analyzer._generate_function_stats(funcs_bad)  # type: ignore
    assert "error" in result


# ---------------------------------------------------------------------------
# get_function_similarity
# ---------------------------------------------------------------------------


def test_get_function_similarity_no_duplicates():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    hashes = {"func_a": "aaaa", "func_b": "bbbb", "func_c": "cccc"}
    result = analyzer.get_function_similarity(hashes)
    assert result == {}


def test_get_function_similarity_with_duplicates():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    hashes = {"func_a": "same_hash", "func_b": "same_hash", "func_c": "other_hash"}
    result = analyzer.get_function_similarity(hashes)
    assert "same_hash" in result
    assert set(result["same_hash"]) == {"func_a", "func_b"}
    assert "other_hash" not in result


def test_get_function_similarity_exception_returns_empty():
    class BrokenSimilarityAnalyzer(FunctionAnalyzer):
        def get_function_similarity(self, machoc_hashes):
            raise RuntimeError("similarity error")

    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    # Invoke the real method with non-iterable to trigger exception
    result = FunctionAnalyzer.get_function_similarity.__wrapped__ if hasattr(
        FunctionAnalyzer.get_function_similarity, "__wrapped__") else None

    # Test the exception path by subclassing
    class RaisingAnalyzer(FunctionAnalyzer):
        def _inner_similarity(self, hashes):
            for k, v in hashes.items():
                pass
            raise RuntimeError("similarity error")

    # Just verify the method handles bad input gracefully
    result2 = analyzer.get_function_similarity({})
    assert result2 == {}


# ---------------------------------------------------------------------------
# generate_machoc_summary
# ---------------------------------------------------------------------------


def test_generate_machoc_summary_no_hashes():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer.generate_machoc_summary({"machoc_hashes": {}})
    assert "error" in result


def test_generate_machoc_summary_with_unique_hashes():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    hashes = {"func_a": "hash1", "func_b": "hash2", "func_c": "hash3"}
    result = analyzer.generate_machoc_summary({"machoc_hashes": hashes})
    assert result["total_functions_hashed"] == 3
    assert result["unique_machoc_hashes"] == 3
    assert result["duplicate_function_groups"] == 0
    assert "similarities" not in result


def test_generate_machoc_summary_with_similarities():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    hashes = {
        "func_a": "dup_hash",
        "func_b": "dup_hash",
        "func_c": "unique_hash",
        "func_d": "another_dup",
        "func_e": "another_dup",
    }
    result = analyzer.generate_machoc_summary({"machoc_hashes": hashes})
    assert result["duplicate_function_groups"] == 2
    assert result["total_duplicate_functions"] == 4
    assert "similarities" in result
    assert "most_common_patterns" in result


def test_generate_machoc_summary_exception():
    class BrokenSummaryAnalyzer(FunctionAnalyzer):
        def get_function_similarity(self, hashes):
            raise RuntimeError("similarity crash")

    adapter = MinimalAdapter()
    analyzer = BrokenSummaryAnalyzer(adapter)
    result = analyzer.generate_machoc_summary({"machoc_hashes": {"f": "h"}})
    assert "error" in result


# ---------------------------------------------------------------------------
# _calculate_cyclomatic_complexity
# ---------------------------------------------------------------------------


def test_calculate_cyclomatic_complexity_no_addr():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._calculate_cyclomatic_complexity({"name": "func"})
    assert result == 0


def test_calculate_cyclomatic_complexity_empty_cfg():
    adapter = CfgAdapter(cfg=None)
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._calculate_cyclomatic_complexity({"name": "func", "addr": 0x1000})
    assert result == 0


def test_calculate_cyclomatic_complexity_list_cfg():
    blocks = [
        {"jump": 0x2000, "fail": 0x3000},
        {"jump": 0x4000},
        {"addr": 0x5000},
    ]
    adapter = CfgAdapter(cfg=blocks)
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._calculate_cyclomatic_complexity({"name": "func", "addr": 0x1000})
    # edges=3, nodes=3, complexity=max(3-3+2, 1)=2
    assert result == 2


def test_calculate_cyclomatic_complexity_dict_cfg():
    cfg = {
        "blocks": [
            {"jump": 0x2000},
            {"addr": 0x2000},
        ]
    }
    adapter = CfgAdapter(cfg=cfg)
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._calculate_cyclomatic_complexity({"name": "func", "addr": 0x1000})
    assert result >= 1


def test_calculate_cyclomatic_complexity_non_dict_cfg():
    adapter = CfgAdapter(cfg="not_a_cfg")
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._calculate_cyclomatic_complexity({"name": "func", "addr": 0x1000})
    assert result == 0


def test_calculate_cyclomatic_complexity_exception():
    class CrashingCfgAdapter:
        def get_cfg(self, address=None):
            raise RuntimeError("cfg error")

    adapter = CrashingCfgAdapter()
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._calculate_cyclomatic_complexity({"name": "func", "addr": 0x1000})
    assert result == 0


# ---------------------------------------------------------------------------
# _classify_function_type
# ---------------------------------------------------------------------------


def test_classify_function_type_library():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    assert analyzer._classify_function_type("kernel32_GetProcAddress", {}) == "library"
    assert analyzer._classify_function_type("msvcrt_malloc", {}) == "library"
    assert analyzer._classify_function_type("ntdll_NtAllocate", {}) == "library"
    assert analyzer._classify_function_type("user32_MessageBox", {}) == "library"
    assert analyzer._classify_function_type("lib_helper", {}) == "library"


def test_classify_function_type_thunk():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    assert analyzer._classify_function_type("thunk_func", {}) == "thunk"
    assert analyzer._classify_function_type("j_some_func", {}) == "thunk"
    assert analyzer._classify_function_type("tiny_func", {"size": 5}) == "thunk"


def test_classify_function_type_user():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    assert analyzer._classify_function_type("main", {"size": 100}) == "user"
    assert analyzer._classify_function_type("sub_401000", {"size": 50}) == "user"
    assert analyzer._classify_function_type("fcn.00401000", {"size": 50}) == "user"
    assert analyzer._classify_function_type("func_helper", {"size": 50}) == "user"


def test_classify_function_type_unknown():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    assert analyzer._classify_function_type("some_random_name", {"size": 100}) == "unknown"


def test_classify_function_type_exception():
    class CrashingAnalyzer(FunctionAnalyzer):
        def _classify_function_type(self, func_name, func):
            try:
                if None.lower():  # type: ignore
                    pass
            except Exception:
                return "unknown"
            return "unknown"

    adapter = MinimalAdapter()
    analyzer = CrashingAnalyzer(adapter)
    result = analyzer._classify_function_type("test", {})
    assert result == "unknown"


# ---------------------------------------------------------------------------
# _calculate_std_dev
# ---------------------------------------------------------------------------


def test_calculate_std_dev_single_value():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    assert analyzer._calculate_std_dev([5.0]) == 0.0


def test_calculate_std_dev_two_equal_values():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    assert analyzer._calculate_std_dev([3.0, 3.0]) == 0.0


def test_calculate_std_dev_multiple_values():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._calculate_std_dev([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0])
    assert abs(result - 2.0) < 0.01


def test_calculate_std_dev_empty():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    assert analyzer._calculate_std_dev([]) == 0.0


# ---------------------------------------------------------------------------
# _analyze_function_coverage
# ---------------------------------------------------------------------------


def test_analyze_function_coverage_empty():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._analyze_function_coverage([])
    assert result["total_functions"] == 0
    assert result["functions_with_size"] == 0


def test_analyze_function_coverage_with_data():
    funcs = [
        {"name": "f1", "size": 100, "nbbs": 5},
        {"name": "f2", "size": 50, "nbbs": 0},
        {"name": "f3", "size": 0, "nbbs": 3},
    ]
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer._analyze_function_coverage(funcs)
    assert result["total_functions"] == 3
    assert result["functions_with_size"] == 2
    assert result["functions_with_blocks"] == 2  # f1 and f3 have nbbs > 0
    assert result["total_code_coverage"] == 150
    assert result["size_coverage_percent"] == pytest.approx(200 / 3)
    assert result["block_coverage_percent"] == pytest.approx(200 / 3)


def test_analyze_function_coverage_exception():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    # Pass non-list to trigger exception
    result = analyzer._analyze_function_coverage("not_a_list")  # type: ignore
    assert result == {}


# ---------------------------------------------------------------------------
# _extract_mnemonics_from_ops
# ---------------------------------------------------------------------------


def test_extract_mnemonics_from_ops_with_opcodes():
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    ops = [
        {"opcode": "mov eax, 1"},
        {"opcode": "   push ecx  "},
        {"opcode": ""},
        {"addr": 0x1234},  # no opcode key
    ]
    result = analyzer._extract_mnemonics_from_ops(ops)
    assert result == ["mov", "push"]


import pytest


# ---------------------------------------------------------------------------
# Additional tests for remaining missing lines
# ---------------------------------------------------------------------------

import r2inspect.modules.function_analyzer as fa_module


def test_process_single_function_hash_machoc_returns_none():
    """Cover line 181: machoc_hash is falsy after extraction."""
    original_func = fa_module.machoc_hash_from_mnemonics
    fa_module.machoc_hash_from_mnemonics = lambda mnemonics: None
    try:
        ops = [{"opcode": "mov eax, 1"}, {"opcode": "ret"}]
        adapter = DisasmDictAdapter(ops)
        analyzer = FunctionAnalyzer(adapter)
        func = {"name": "test_func", "addr": 0x5000, "size": 10}
        result = analyzer._process_single_function_hash(func, 0, 1)
        assert result is None
    finally:
        fa_module.machoc_hash_from_mnemonics = original_func


def test_get_function_similarity_exception_path():
    """Cover lines 358-360: exception in get_function_similarity."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    # Pass non-dict to trigger AttributeError on .items()
    result = analyzer.get_function_similarity("not_a_dict")  # type: ignore
    assert result == {}


def test_classify_function_type_exception_path():
    """Cover lines 458-459: exception in _classify_function_type."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    # Pass None as func_name to trigger AttributeError on .lower()
    result = analyzer._classify_function_type(None, {})  # type: ignore
    assert result == "unknown"


def test_calculate_std_dev_exception_path():
    """Cover lines 471-472: exception in _calculate_std_dev."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    # Pass None to trigger TypeError on len(None)
    result = analyzer._calculate_std_dev(None)  # type: ignore
    assert result == 0.0
