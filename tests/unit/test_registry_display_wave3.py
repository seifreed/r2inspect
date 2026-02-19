"""Coverage tests for display_sections_hashing, display_sections_metadata,
and analyzer_registry missing lines."""

from __future__ import annotations

import io
import sys

import pytest
from rich.console import Console
from rich.table import Table

from r2inspect.cli.display_sections_hashing import (
    _add_ccbhash_entries,
    _add_impfuzzy_entries,
    _add_telfhash_entries,
    _display_ccbhash,
    _display_impfuzzy,
    _display_ssdeep,
    _display_telfhash,
    _display_tlsh,
)
from r2inspect.cli.display_sections_metadata import (
    _add_rich_header_entries,
    _display_rich_header,
)
from r2inspect.registry.analyzer_registry import AnalyzerCategory, AnalyzerRegistry
from r2inspect.abstractions.base_analyzer import BaseAnalyzer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_console() -> Console:
    return Console(file=io.StringIO(), record=True, width=120, highlight=False)


def _text(console: Console) -> str:
    return console.export_text()


def _make_table() -> Table:
    t = Table()
    t.add_column("Property")
    t.add_column("Value")
    return t


# ---------------------------------------------------------------------------
# Concrete BaseAnalyzer subclass for registry tests
# ---------------------------------------------------------------------------

class ConcreteAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict:
        return {}

    def get_name(self) -> str:
        return "concrete"

    def get_category(self) -> str:
        return "hashing"

    def get_supported_formats(self) -> set:
        return {"PE"}

    def get_description(self) -> str:
        return "Concrete test analyzer"


class AbstractSubAnalyzer(BaseAnalyzer):
    """BaseAnalyzer subclass that intentionally omits analyze() implementation."""
    pass


class PlainDummy:
    def __init__(self) -> None:
        pass

    def analyze(self) -> dict:
        return {}


# ---------------------------------------------------------------------------
# display_sections_hashing - _display_ssdeep (lines 39-41)
# ---------------------------------------------------------------------------

def test_ssdeep_unavailable_no_error(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    c = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: c)
    _display_ssdeep({"ssdeep": {"available": False}})
    assert "Not Available" in _text(c)


def test_ssdeep_unavailable_with_error(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    c = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: c)
    _display_ssdeep({"ssdeep": {"available": False, "error": "ssdeep-lib-missing"}})
    text = _text(c)
    assert "Not Available" in text
    assert "ssdeep-lib-missing" in text


# ---------------------------------------------------------------------------
# display_sections_hashing - _display_tlsh (lines 59-61)
# ---------------------------------------------------------------------------

def test_tlsh_unavailable_with_error(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    c = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: c)
    _display_tlsh({"tlsh": {"available": False, "error": "tlsh-lib-missing"}})
    text = _text(c)
    assert "Not Available" in text
    assert "tlsh-lib-missing" in text


# ---------------------------------------------------------------------------
# display_sections_hashing - _display_telfhash (lines 89-90, 94-96)
# ---------------------------------------------------------------------------

def test_telfhash_available_is_elf(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    c = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: c)
    _display_telfhash({
        "telfhash": {
            "available": True,
            "is_elf": True,
            "telfhash": "T1DEADBEEF",
            "symbol_count": 10,
            "filtered_symbols": 3,
            "symbols_used": ["sym_a", "sym_b"],
        }
    })
    text = _text(c)
    assert "T1DEADBEEF" in text
    assert "Available" in text


def test_telfhash_unavailable_with_error(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    c = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: c)
    _display_telfhash({"telfhash": {"available": False, "error": "telfhash-err"}})
    text = _text(c)
    assert "Not Available" in text
    assert "telfhash-err" in text


# ---------------------------------------------------------------------------
# display_sections_hashing - _add_telfhash_entries (lines 103-113)
# ---------------------------------------------------------------------------

def test_add_telfhash_entries_no_telfhash_value():
    t = _make_table()
    _add_telfhash_entries(t, {
        "telfhash": None,
        "symbol_count": 5,
        "filtered_symbols": 1,
        "symbols_used": [],
    })
    rows = [str(row) for row in t.rows]
    # Just ensure no exception and table has rows
    assert len(t.rows) >= 3


def test_add_telfhash_entries_many_symbols():
    t = _make_table()
    symbols = [f"sym_{i}" for i in range(8)]
    _add_telfhash_entries(t, {
        "telfhash": "T1ABC",
        "symbol_count": 8,
        "filtered_symbols": 0,
        "symbols_used": symbols,
    })
    # The "Symbols Used" row should contain "more"
    console = Console(file=io.StringIO(), record=True, width=200)
    console.print(t)
    text = console.export_text()
    assert "more" in text


# ---------------------------------------------------------------------------
# display_sections_hashing - _display_impfuzzy (lines 128-132)
# ---------------------------------------------------------------------------

def test_impfuzzy_unavailable_with_error_no_library(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    c = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: c)
    _display_impfuzzy({
        "impfuzzy": {
            "available": False,
            "error": "impfuzzy-error",
            "library_available": False,
        }
    })
    text = _text(c)
    assert "Not Available" in text
    assert "impfuzzy-error" in text
    assert "pyimpfuzzy" in text


def test_impfuzzy_unavailable_no_library_no_error(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    c = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: c)
    _display_impfuzzy({"impfuzzy": {"available": False, "library_available": False}})
    text = _text(c)
    assert "pyimpfuzzy" in text


# ---------------------------------------------------------------------------
# display_sections_hashing - _add_impfuzzy_entries (line 141, 151-154)
# ---------------------------------------------------------------------------

def test_add_impfuzzy_entries_with_hash():
    t = _make_table()
    _add_impfuzzy_entries(t, {
        "impfuzzy_hash": "3:ABCDEF:GHIJKL",
        "import_count": 5,
        "dll_count": 2,
        "imports_processed": [],
    })
    console = Console(file=io.StringIO(), record=True, width=200)
    console.print(t)
    text = console.export_text()
    assert "ABCDEF" in text


def test_add_impfuzzy_entries_many_imports():
    t = _make_table()
    imports = [f"kernel32!func{i}" for i in range(12)]
    _add_impfuzzy_entries(t, {
        "impfuzzy_hash": None,
        "import_count": 12,
        "dll_count": 1,
        "imports_processed": imports,
    })
    console = Console(file=io.StringIO(), record=True, width=200)
    console.print(t)
    text = console.export_text()
    assert "more" in text


# ---------------------------------------------------------------------------
# display_sections_hashing - _display_ccbhash (lines 169-171)
# ---------------------------------------------------------------------------

def test_ccbhash_unavailable_with_error(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    c = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: c)
    _display_ccbhash({"ccbhash": {"available": False, "error": "ccb-error"}})
    text = _text(c)
    assert "Not Available" in text
    assert "ccb-error" in text


# ---------------------------------------------------------------------------
# display_sections_hashing - _add_ccbhash_entries (line 198)
# ---------------------------------------------------------------------------

def test_add_ccbhash_entries_no_similar_functions(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    c = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: c)
    # similar_functions empty triggers early return at line 198
    _display_ccbhash({
        "ccbhash": {
            "available": True,
            "binary_ccbhash": "deadbeef" * 8,
            "total_functions": 10,
            "analyzed_functions": 10,
            "unique_hashes": 8,
            "similar_functions": [],
        }
    })
    text = _text(c)
    assert "CCBHash" in text


# ---------------------------------------------------------------------------
# display_sections_metadata - _display_rich_header (lines 19-35)
# ---------------------------------------------------------------------------

def test_display_rich_header_not_present(monkeypatch):
    from r2inspect.cli import display_sections_metadata
    c = _make_console()
    monkeypatch.setattr(display_sections_metadata, "_get_console", lambda: c)
    _display_rich_header({})
    assert "Rich Header" not in _text(c)


def test_display_rich_header_available_is_pe(monkeypatch):
    from r2inspect.cli import display_sections_metadata
    c = _make_console()
    monkeypatch.setattr(display_sections_metadata, "_get_console", lambda: c)
    _display_rich_header({
        "rich_header": {
            "available": True,
            "is_pe": True,
            "xor_key": 0xDEAD,
            "checksum": 0xBEEF,
            "richpe_hash": "aabbccdd",
            "compilers": [
                {"compiler_name": "MSVC", "count": 3, "build_number": 1900},
            ],
        }
    })
    text = _text(c)
    assert "Rich Header" in text
    assert "Available" in text
    assert "aabbccdd" in text


def test_display_rich_header_available_not_pe(monkeypatch):
    from r2inspect.cli import display_sections_metadata
    c = _make_console()
    monkeypatch.setattr(display_sections_metadata, "_get_console", lambda: c)
    _display_rich_header({"rich_header": {"available": True, "is_pe": False}})
    text = _text(c)
    assert "Rich Header" in text
    assert "Not PE" in text


def test_display_rich_header_not_available_with_error(monkeypatch):
    from r2inspect.cli import display_sections_metadata
    c = _make_console()
    monkeypatch.setattr(display_sections_metadata, "_get_console", lambda: c)
    _display_rich_header({"rich_header": {"available": False, "error": "rich-err"}})
    text = _text(c)
    assert "Not Available" in text
    assert "rich-err" in text


# ---------------------------------------------------------------------------
# display_sections_metadata - _add_rich_header_entries (lines 39-65)
# ---------------------------------------------------------------------------

def test_add_rich_header_entries_full():
    t = _make_table()
    _add_rich_header_entries(t, {
        "xor_key": 0xABCD1234,
        "checksum": 0x12345678,
        "richpe_hash": "feedcafe",
        "compilers": [
            {"compiler_name": f"Compiler{i}", "count": i, "build_number": 1900 + i}
            for i in range(7)
        ],
    })
    console = Console(file=io.StringIO(), record=True, width=200)
    console.print(t)
    text = console.export_text()
    assert "0xABCD1234" in text
    assert "feedcafe" in text
    assert "more" in text


def test_add_rich_header_entries_no_optional_fields():
    t = _make_table()
    _add_rich_header_entries(t, {
        "xor_key": None,
        "checksum": None,
        "richpe_hash": None,
        "compilers": [],
    })
    # No exception is the goal
    assert len(t.rows) >= 1


def test_add_rich_header_entries_five_or_fewer_compilers():
    t = _make_table()
    _add_rich_header_entries(t, {
        "xor_key": 0x1,
        "checksum": 0x2,
        "richpe_hash": "aa",
        "compilers": [
            {"compiler_name": f"MSVC{i}", "count": i, "build_number": 1900}
            for i in range(3)
        ],
    })
    console = Console(file=io.StringIO(), record=True, width=200)
    console.print(t)
    text = console.export_text()
    assert "MSVC0" in text
    assert "more" not in text


# ---------------------------------------------------------------------------
# analyzer_registry - _get_base_analyzer_class ImportError (lines 97-99)
# ---------------------------------------------------------------------------

def test_get_base_analyzer_class_import_error(monkeypatch):
    registry = AnalyzerRegistry(lazy_loading=False)
    registry._base_analyzer_class = None
    monkeypatch.setitem(sys.modules, "r2inspect.abstractions.base_analyzer", None)
    result = registry._get_base_analyzer_class()
    assert result is None


# ---------------------------------------------------------------------------
# analyzer_registry - is_base_analyzer TypeError (line 119)
# ---------------------------------------------------------------------------

def test_is_base_analyzer_type_error():
    registry = AnalyzerRegistry(lazy_loading=False)
    # Passing a non-class (instance) makes issubclass raise TypeError
    result = registry.is_base_analyzer(object())  # type: ignore[arg-type]
    assert result is False


# ---------------------------------------------------------------------------
# analyzer_registry - validate_analyzer abstract analyze (lines 215-217)
# ---------------------------------------------------------------------------

def test_validate_analyzer_abstract_analyze():
    registry = AnalyzerRegistry(lazy_loading=False)
    # AbstractSubAnalyzer inherits from BaseAnalyzer but does not implement analyze()
    is_valid, err = registry.validate_analyzer(AbstractSubAnalyzer)
    assert not is_valid
    assert err is not None
    assert "abstract" in err.lower() or "not implemented" in err.lower()


# ---------------------------------------------------------------------------
# analyzer_registry - validate_analyzer no analyze attribute (lines 211-212)
# ---------------------------------------------------------------------------

def test_validate_analyzer_no_analyze_attribute(monkeypatch):
    registry = AnalyzerRegistry(lazy_loading=False)

    class NoAnalyzeClass:
        def __init__(self) -> None:
            pass

    monkeypatch.setattr(registry, "is_base_analyzer", lambda c: True)
    is_valid, err = registry.validate_analyzer(NoAnalyzeClass)
    assert not is_valid
    assert err is not None
    assert "analyze" in err


# ---------------------------------------------------------------------------
# analyzer_registry - register_from_instance (lines 272-295)
# ---------------------------------------------------------------------------

def test_register_from_instance_success():
    registry = AnalyzerRegistry(lazy_loading=False)
    instance = ConcreteAnalyzer()
    registry.register_from_instance(instance)
    assert registry.is_registered("concrete")
    meta = registry.get_metadata("concrete")
    assert meta is not None
    assert meta.category == AnalyzerCategory.HASHING


def test_register_from_instance_with_overrides():
    registry = AnalyzerRegistry(lazy_loading=False)
    instance = ConcreteAnalyzer()
    registry.register_from_instance(
        instance,
        name="overridden",
        required=True,
        override_description="overridden desc",
        override_formats={"ELF"},
        override_category=AnalyzerCategory.DETECTION,
    )
    assert registry.is_registered("overridden")
    meta = registry.get_metadata("overridden")
    assert meta is not None
    assert meta.required is True
    assert meta.description == "overridden desc"
    assert "ELF" in (meta.file_formats or set())
    assert meta.category == AnalyzerCategory.DETECTION


def test_register_from_instance_non_base_analyzer_raises():
    registry = AnalyzerRegistry(lazy_loading=False)
    instance = PlainDummy()
    with pytest.raises(ValueError, match="not a BaseAnalyzer"):
        registry.register_from_instance(instance)


# ---------------------------------------------------------------------------
# analyzer_registry - _validate_registration_name empty (line 426)
# ---------------------------------------------------------------------------

def test_register_empty_name_raises():
    registry = AnalyzerRegistry(lazy_loading=False)
    with pytest.raises(ValueError, match="cannot be empty"):
        registry.register(name="", analyzer_class=PlainDummy, category=AnalyzerCategory.METADATA)


# ---------------------------------------------------------------------------
# analyzer_registry - _resolve_registration_mode (lines 460, 464)
# ---------------------------------------------------------------------------

def test_resolve_registration_mode_neither_raises():
    registry = AnalyzerRegistry(lazy_loading=False)
    with pytest.raises(ValueError, match="Must provide either"):
        registry._resolve_registration_mode(None, None, None)


def test_resolve_registration_mode_both_raises():
    registry = AnalyzerRegistry(lazy_loading=False)
    with pytest.raises(ValueError, match="Cannot provide both"):
        registry._resolve_registration_mode(
            PlainDummy, "some.module", "SomeClass"
        )


# ---------------------------------------------------------------------------
# analyzer_registry - _handle_lazy_registration category None (line 485)
# ---------------------------------------------------------------------------

def test_register_lazy_no_category_raises():
    registry = AnalyzerRegistry(lazy_loading=True)
    with pytest.raises(ValueError, match="Category is required"):
        registry.register(
            name="lazy_no_cat",
            module_path="r2inspect.registry.categories",
            class_name="AnalyzerCategory",
            # no category
        )


# ---------------------------------------------------------------------------
# analyzer_registry - _handle_lazy_registration None module_path (line 483)
# ---------------------------------------------------------------------------

def test_handle_lazy_registration_none_module_path_raises():
    registry = AnalyzerRegistry(lazy_loading=False)
    with pytest.raises(ValueError, match="module_path and class_name are required"):
        registry._handle_lazy_registration(
            name="x",
            module_path=None,
            class_name=None,
            category=AnalyzerCategory.METADATA,
            file_formats=None,
            required=False,
            dependencies=None,
            description="",
        )


# ---------------------------------------------------------------------------
# analyzer_registry - _lazy_fallback_analyzer_class (lines 531-536)
# ---------------------------------------------------------------------------

def test_lazy_fallback_analyzer_class_success():
    registry = AnalyzerRegistry(lazy_loading=False)
    cls = registry._lazy_fallback_analyzer_class(
        "r2inspect.registry.categories", "AnalyzerCategory"
    )
    assert cls is AnalyzerCategory


def test_lazy_fallback_analyzer_class_none_raises():
    registry = AnalyzerRegistry(lazy_loading=False)
    with pytest.raises(ValueError, match="module_path and class_name are required"):
        registry._lazy_fallback_analyzer_class(None, None)


# ---------------------------------------------------------------------------
# analyzer_registry - _ensure_analyzer_class None (line 541)
# ---------------------------------------------------------------------------

def test_ensure_analyzer_class_none_raises():
    registry = AnalyzerRegistry(lazy_loading=False)
    with pytest.raises(ValueError, match="analyzer_class is required"):
        registry._ensure_analyzer_class(None)


# ---------------------------------------------------------------------------
# analyzer_registry - _ensure_category None (line 569)
# ---------------------------------------------------------------------------

def test_ensure_category_none_raises():
    registry = AnalyzerRegistry(lazy_loading=False)
    with pytest.raises(ValueError, match="Category must be provided"):
        registry._ensure_category(PlainDummy, None)


# ---------------------------------------------------------------------------
# analyzer_registry - unregister (lines 592-595)
# ---------------------------------------------------------------------------

def test_unregister_registered_analyzer():
    registry = AnalyzerRegistry(lazy_loading=False)
    registry.register(
        name="to_remove",
        analyzer_class=PlainDummy,
        category=AnalyzerCategory.METADATA,
    )
    assert registry.is_registered("to_remove")
    result = registry.unregister("to_remove")
    assert result is True
    assert not registry.is_registered("to_remove")


def test_unregister_not_found():
    registry = AnalyzerRegistry(lazy_loading=False)
    result = registry.unregister("does_not_exist")
    assert result is False
