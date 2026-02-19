"""Branch-path coverage for r2inspect/modules/export_analyzer.py."""

from __future__ import annotations

from r2inspect.modules.export_analyzer import ExportAnalyzer


# ---------------------------------------------------------------------------
# Minimal stub adapter – controls what _cmd_list returns
# ---------------------------------------------------------------------------


class StubAdapter:
    """
    Fake adapter that returns pre-configured data for the two r2 commands
    used by ExportAnalyzer:
      - get_exports()  -> used by _cmd_list("iEj")
      - get_function_info(address)  -> used by _cmd_list("afij @ <addr>")
    """

    def __init__(
        self,
        exports: list | None = None,
        func_info: list | None = None,
        raise_on_exports: bool = False,
    ) -> None:
        self._exports = exports if exports is not None else []
        self._func_info = func_info if func_info is not None else []
        self._raise_on_exports = raise_on_exports

    def get_exports(self) -> list:
        if self._raise_on_exports:
            raise RuntimeError("exports unavailable")
        return self._exports

    def get_function_info(self, _address: int) -> list:
        return self._func_info


def _make_analyzer(adapter: StubAdapter) -> ExportAnalyzer:
    return ExportAnalyzer(adapter=adapter, config=None)


# ---------------------------------------------------------------------------
# supports_format – "DLL" case (line 26)
# ---------------------------------------------------------------------------


def test_supports_format_dll():
    analyzer = _make_analyzer(StubAdapter())
    assert analyzer.supports_format("DLL") is True


def test_supports_format_pe():
    analyzer = _make_analyzer(StubAdapter())
    assert analyzer.supports_format("PE") is True


def test_supports_format_unsupported_format():
    analyzer = _make_analyzer(StubAdapter())
    assert analyzer.supports_format("MACHO") is False


# ---------------------------------------------------------------------------
# get_exports – non-dict export skipped (lines 56-57)
# ---------------------------------------------------------------------------


def test_get_exports_skips_non_dict_entries():
    adapter = StubAdapter(exports=["not-a-dict", 42, None, {"name": "valid", "vaddr": 0}])
    analyzer = _make_analyzer(adapter)
    exports = analyzer.get_exports()
    # Only the dict entry should produce a result
    assert len(exports) == 1
    assert exports[0]["name"] == "valid"


# ---------------------------------------------------------------------------
# get_exports – exception handling (lines 61-62)
# ---------------------------------------------------------------------------


def test_get_exports_returns_empty_list_on_exception():
    adapter = StubAdapter(raise_on_exports=True)
    analyzer = _make_analyzer(adapter)
    result = analyzer.get_exports()
    assert result == []


# ---------------------------------------------------------------------------
# _analyze_export – exception inside _get_export_characteristics swallowed
# ---------------------------------------------------------------------------


def test_analyze_export_returns_result_with_empty_characteristics_when_inner_exception():
    # _get_export_characteristics catches its own exceptions; the export
    # result is still returned (characteristics is empty dict, no "error" key)
    class AdapterRaisingOnFuncInfo(StubAdapter):
        def get_function_info(self, _address: int) -> list:
            raise RuntimeError("func info error")

    adapter = AdapterRaisingOnFuncInfo(
        exports=[{"name": "export_fn", "vaddr": 0x1000}]
    )
    analyzer = _make_analyzer(adapter)
    exports = analyzer.get_exports()
    assert len(exports) == 1
    assert exports[0]["name"] == "export_fn"
    assert isinstance(exports[0]["characteristics"], dict)


# ---------------------------------------------------------------------------
# _get_export_characteristics – DllExport name prefix (line 99)
# ---------------------------------------------------------------------------


def test_get_export_characteristics_dll_prefix_sets_dll_export():
    adapter = StubAdapter(exports=[{"name": "DllMain", "vaddr": 0}])
    analyzer = _make_analyzer(adapter)
    result = analyzer._get_export_characteristics({"name": "DllMain", "vaddr": 0})
    assert result.get("dll_export") is True


# ---------------------------------------------------------------------------
# _get_export_characteristics – non-dict func info (lines 133-134)
# ---------------------------------------------------------------------------


def test_get_export_characteristics_non_dict_func_info_sets_not_is_function():
    # get_function_info returns a list with a non-dict element
    adapter = StubAdapter(func_info=["not-a-dict"])
    analyzer = _make_analyzer(adapter)
    result = analyzer._get_export_characteristics({"name": "fn", "vaddr": 0x1000})
    assert result.get("is_function") is False


# ---------------------------------------------------------------------------
# _get_export_characteristics – no func_info returned (line 136)
# ---------------------------------------------------------------------------


def test_get_export_characteristics_empty_func_info_sets_not_is_function():
    adapter = StubAdapter(func_info=[])
    analyzer = _make_analyzer(adapter)
    result = analyzer._get_export_characteristics({"name": "fn", "vaddr": 0x2000})
    assert result.get("is_function") is False


# ---------------------------------------------------------------------------
# _get_export_characteristics – suspicious name (lines 115-119)
# ---------------------------------------------------------------------------


def test_get_export_characteristics_suspicious_name_detected():
    adapter = StubAdapter()
    analyzer = _make_analyzer(adapter)
    result = analyzer._get_export_characteristics({"name": "InjectPayload", "vaddr": 0})
    assert result.get("suspicious_name") is True
    assert result.get("suspicious_pattern") == "inject"


# ---------------------------------------------------------------------------
# _update_export_stats – forwarded export (line 176)
# ---------------------------------------------------------------------------


def test_update_export_stats_forwarded_export_increments_counter():
    analyzer = _make_analyzer(StubAdapter())
    stats = {
        "total_exports": 0,
        "function_exports": 0,
        "data_exports": 0,
        "forwarded_exports": 0,
        "suspicious_exports": 0,
        "export_names": [],
    }
    exp = {
        "name": "ForwardedFn",
        "is_forwarded": True,
        "characteristics": {"is_function": True},
    }
    analyzer._update_export_stats(stats, exp)
    assert stats["forwarded_exports"] == 1
    assert stats["function_exports"] == 1


# ---------------------------------------------------------------------------
# _update_export_stats – data export (line 181)
# ---------------------------------------------------------------------------


def test_update_export_stats_data_export_increments_data_counter():
    analyzer = _make_analyzer(StubAdapter())
    stats = {
        "total_exports": 0,
        "function_exports": 0,
        "data_exports": 0,
        "forwarded_exports": 0,
        "suspicious_exports": 0,
        "export_names": [],
    }
    exp = {
        "name": "DataSymbol",
        "is_forwarded": False,
        "characteristics": {"is_function": False},
    }
    analyzer._update_export_stats(stats, exp)
    assert stats["data_exports"] == 1
    assert stats["function_exports"] == 0


# ---------------------------------------------------------------------------
# _update_export_stats – non-dict skipped (lines 170-171)
# ---------------------------------------------------------------------------


def test_update_export_stats_skips_non_dict_entry():
    analyzer = _make_analyzer(StubAdapter())
    stats = {
        "total_exports": 0,
        "function_exports": 0,
        "data_exports": 0,
        "forwarded_exports": 0,
        "suspicious_exports": 0,
        "export_names": [],
    }
    analyzer._update_export_stats(stats, "not-a-dict")
    assert stats["export_names"] == []
    assert stats["function_exports"] == 0


# ---------------------------------------------------------------------------
# _update_export_stats – suspicious export (line 183)
# ---------------------------------------------------------------------------


def test_update_export_stats_suspicious_export_increments_counter():
    analyzer = _make_analyzer(StubAdapter())
    stats = {
        "total_exports": 0,
        "function_exports": 0,
        "data_exports": 0,
        "forwarded_exports": 0,
        "suspicious_exports": 0,
        "export_names": [],
    }
    exp = {
        "name": "RunPayload",
        "is_forwarded": False,
        "characteristics": {"is_function": True, "suspicious_name": True},
    }
    analyzer._update_export_stats(stats, exp)
    assert stats["suspicious_exports"] == 1


# ---------------------------------------------------------------------------
# get_export_statistics – exception path (lines 163-164)
# ---------------------------------------------------------------------------


def test_get_export_statistics_returns_defaults_on_exception():
    class AdapterRaisingOnStats(StubAdapter):
        def get_exports(self) -> list:
            raise RuntimeError("stats error")

    adapter = AdapterRaisingOnStats()
    analyzer = _make_analyzer(adapter)
    stats = analyzer.get_export_statistics()
    assert stats["total_exports"] == 0
    assert stats["export_names"] == []
