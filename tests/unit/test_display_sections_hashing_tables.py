"""Comprehensive tests for display_sections_hashing.py - all hash types."""

import io

from rich.console import Console
from rich.table import Table

from r2inspect.cli.display_sections_hashing import (
    _add_ccbhash_entries,
    _add_impfuzzy_entries,
    _add_telfhash_entries,
    _add_tlsh_entries,
    _display_ccbhash,
    _display_impfuzzy,
    _display_ssdeep,
    _display_telfhash,
    _display_tlsh,
)


def _make_console():
    return Console(file=io.StringIO(), record=True, width=120)


def _get_text(console: Console) -> str:
    return console.export_text()


def test_display_ssdeep_available(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    
    console = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {
        "ssdeep": {
            "available": True,
            "hash_value": "3:ABC:XYZ",
            "method_used": "native",
        }
    }
    
    _display_ssdeep(results)
    text = _get_text(console)
    
    assert "SSDeep" in text
    assert "native" in text
    assert "Available" in text


def test_display_ssdeep_not_available_with_error(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    
    console = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {
        "ssdeep": {
            "available": False,
            "error": "SSDeep library not found",
        }
    }
    
    _display_ssdeep(results)
    text = _get_text(console)
    
    assert "SSDeep" in text
    assert "Not Available" in text
    assert "SSDeep library not found" in text


def test_display_ssdeep_not_present(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    
    console = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {}
    
    _display_ssdeep(results)
    text = _get_text(console)
    
    assert "SSDeep" not in text


def test_display_tlsh_available(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    
    console = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {
        "tlsh": {
            "available": True,
            "binary_tlsh": "T1ABC123",
            "text_section_tlsh": "T1DEF456",
            "stats": {
                "functions_analyzed": 50,
                "functions_with_tlsh": 45,
            },
        }
    }
    
    _display_tlsh(results)
    text = _get_text(console)
    
    assert "TLSH" in text
    assert "T1ABC123" in text
    assert "T1DEF456" in text
    assert "50" in text
    assert "45" in text


def test_display_tlsh_not_available_with_error(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    
    console = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {
        "tlsh": {
            "available": False,
            "error": "TLSH computation failed",
        }
    }
    
    _display_tlsh(results)
    text = _get_text(console)
    
    assert "TLSH" in text
    assert "Not Available" in text
    assert "TLSH computation failed" in text


def test_display_tlsh_not_present(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    
    console = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {}
    
    _display_tlsh(results)
    text = _get_text(console)
    
    assert "TLSH" not in text


def test_add_tlsh_entries_full_data():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    tlsh_info = {
        "binary_tlsh": "T1BINARY123",
        "text_section_tlsh": "T1TEXT456",
        "stats": {
            "functions_analyzed": 100,
            "functions_with_tlsh": 95,
        },
    }
    
    _add_tlsh_entries(table, tlsh_info)
    
    assert len(table.rows) == 4


def test_add_tlsh_entries_missing_binary():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    tlsh_info = {
        "text_section_tlsh": "T1TEXT456",
        "stats": {
            "functions_analyzed": 100,
            "functions_with_tlsh": 95,
        },
    }
    
    _add_tlsh_entries(table, tlsh_info)
    
    assert len(table.rows) == 4


def test_add_tlsh_entries_missing_text():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    tlsh_info = {
        "binary_tlsh": "T1BINARY123",
        "stats": {},
    }
    
    _add_tlsh_entries(table, tlsh_info)
    
    assert len(table.rows) == 4


def test_display_telfhash_elf_available(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    
    console = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {
        "telfhash": {
            "available": True,
            "is_elf": True,
            "telfhash": "t1abc123def456",
            "symbol_count": 100,
            "filtered_symbols": 80,
            "symbols_used": ["symbol1", "symbol2", "symbol3"],
        }
    }
    
    _display_telfhash(results)
    text = _get_text(console)
    
    assert "Telfhash" in text
    assert "t1abc123def456" in text
    assert "100" in text
    assert "80" in text


def test_display_telfhash_not_elf(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    
    console = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {
        "telfhash": {
            "available": True,
            "is_elf": False,
        }
    }
    
    _display_telfhash(results)
    text = _get_text(console)
    
    assert "Telfhash" in text
    assert "Not ELF File" in text


def test_display_telfhash_not_available_with_error(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    
    console = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {
        "telfhash": {
            "available": False,
            "error": "Telfhash computation error",
        }
    }
    
    _display_telfhash(results)
    text = _get_text(console)
    
    assert "Telfhash" in text
    assert "Not Available" in text
    assert "Telfhash computation error" in text


def test_display_telfhash_not_present(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    
    console = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {}
    
    _display_telfhash(results)
    text = _get_text(console)
    
    assert "Telfhash" not in text


def test_add_telfhash_entries_full_data():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    telfhash_info = {
        "telfhash": "t1hash123",
        "symbol_count": 200,
        "filtered_symbols": 150,
        "symbols_used": [f"symbol{i}" for i in range(10)],
    }
    
    _add_telfhash_entries(table, telfhash_info)
    
    assert len(table.rows) == 4


def test_add_telfhash_entries_no_hash():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    telfhash_info = {
        "symbol_count": 100,
        "filtered_symbols": 80,
    }
    
    _add_telfhash_entries(table, telfhash_info)
    
    assert len(table.rows) == 3


def test_add_telfhash_entries_few_symbols():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    telfhash_info = {
        "telfhash": "t1hash",
        "symbol_count": 3,
        "filtered_symbols": 2,
        "symbols_used": ["sym1", "sym2"],
    }
    
    _add_telfhash_entries(table, telfhash_info)
    
    assert len(table.rows) == 4
    assert "more" not in str(table)


def test_add_telfhash_entries_no_symbols():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    telfhash_info = {
        "telfhash": "t1hash",
        "symbol_count": 0,
        "filtered_symbols": 0,
        "symbols_used": [],
    }
    
    _add_telfhash_entries(table, telfhash_info)
    
    assert len(table.rows) == 3


def test_display_impfuzzy_available(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    
    console = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {
        "impfuzzy": {
            "available": True,
            "impfuzzy_hash": "96:ABCD:EFG",
            "import_count": 50,
            "dll_count": 5,
            "imports_processed": ["kernel32.CreateFile", "user32.MessageBox"],
        }
    }
    
    _display_impfuzzy(results)
    text = _get_text(console)
    
    assert "Impfuzzy" in text
    assert "50" in text
    assert "5" in text


def test_display_impfuzzy_not_available_with_error(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    
    console = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {
        "impfuzzy": {
            "available": False,
            "error": "Import parsing failed",
        }
    }
    
    _display_impfuzzy(results)
    text = _get_text(console)
    
    assert "Impfuzzy" in text
    assert "Not Available" in text
    assert "Import parsing failed" in text


def test_display_impfuzzy_library_not_available(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    
    console = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {
        "impfuzzy": {
            "available": False,
            "library_available": False,
        }
    }
    
    _display_impfuzzy(results)
    text = _get_text(console)
    
    assert "Impfuzzy" in text
    assert "pyimpfuzzy" in text


def test_display_impfuzzy_not_present(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    
    console = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {}
    
    _display_impfuzzy(results)
    text = _get_text(console)
    
    assert "Impfuzzy" not in text


def test_add_impfuzzy_entries_full_data():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    impfuzzy_info = {
        "impfuzzy_hash": "96:ABC:DEF",
        "import_count": 100,
        "dll_count": 10,
        "imports_processed": [f"dll{i}.func{i}" for i in range(15)],
    }
    
    _add_impfuzzy_entries(table, impfuzzy_info)
    
    assert len(table.rows) == 4


def test_add_impfuzzy_entries_no_hash():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    impfuzzy_info = {
        "import_count": 50,
        "dll_count": 5,
    }
    
    _add_impfuzzy_entries(table, impfuzzy_info)
    
    assert len(table.rows) == 2


def test_add_impfuzzy_entries_few_imports():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    impfuzzy_info = {
        "impfuzzy_hash": "96:ABC:DEF",
        "import_count": 5,
        "dll_count": 2,
        "imports_processed": ["func1", "func2"],
    }
    
    _add_impfuzzy_entries(table, impfuzzy_info)
    
    assert len(table.rows) == 4
    assert "more" not in str(table)


def test_add_impfuzzy_entries_no_imports():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    impfuzzy_info = {
        "impfuzzy_hash": "96:ABC:DEF",
        "import_count": 0,
        "dll_count": 0,
    }
    
    _add_impfuzzy_entries(table, impfuzzy_info)
    
    assert len(table.rows) == 3


def test_display_ccbhash_available(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    
    console = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {
        "ccbhash": {
            "available": True,
            "binary_ccbhash": "ccb123abc",
            "total_functions": 100,
            "analyzed_functions": 95,
            "unique_hashes": 80,
            "similar_functions": [],
        }
    }
    
    _display_ccbhash(results)
    text = _get_text(console)
    
    assert "CCBHash" in text
    assert "ccb123abc" in text
    assert "100" in text
    assert "95" in text
    assert "80" in text


def test_display_ccbhash_not_available_with_error(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    
    console = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {
        "ccbhash": {
            "available": False,
            "error": "CCBHash analysis failed",
        }
    }
    
    _display_ccbhash(results)
    text = _get_text(console)
    
    assert "CCBHash" in text
    assert "Not Available" in text
    assert "CCBHash analysis failed" in text


def test_display_ccbhash_not_present(monkeypatch):
    from r2inspect.cli import display_sections_hashing
    
    console = _make_console()
    monkeypatch.setattr(display_sections_hashing, "_get_console", lambda: console)
    
    results = {}
    
    _display_ccbhash(results)
    text = _get_text(console)
    
    assert "CCBHash" not in text


def test_add_ccbhash_entries_basic():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    ccbhash_info = {
        "binary_ccbhash": "ccb_hash_123",
        "total_functions": 100,
        "analyzed_functions": 95,
        "unique_hashes": 80,
    }
    
    _add_ccbhash_entries(table, ccbhash_info)
    
    assert len(table.rows) == 4


def test_add_ccbhash_entries_no_hash():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    ccbhash_info = {
        "total_functions": 100,
        "analyzed_functions": 95,
        "unique_hashes": 80,
    }
    
    _add_ccbhash_entries(table, ccbhash_info)
    
    assert len(table.rows) == 3


def test_add_ccbhash_entries_with_similar_functions():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    ccbhash_info = {
        "binary_ccbhash": "ccb123",
        "total_functions": 100,
        "analyzed_functions": 95,
        "unique_hashes": 80,
        "similar_functions": [
            {
                "count": 10,
                "functions": ["func1&nbsp;test&amp;x", "func2", "func3", "func4"],
            }
        ],
    }
    
    _add_ccbhash_entries(table, ccbhash_info)
    
    assert len(table.rows) >= 7


def test_add_ccbhash_entries_with_many_similar_functions():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    ccbhash_info = {
        "binary_ccbhash": "ccb123",
        "total_functions": 100,
        "analyzed_functions": 95,
        "unique_hashes": 80,
        "similar_functions": [
            {
                "count": 10,
                "functions": [f"function_{i}" for i in range(10)],
            }
        ],
    }
    
    _add_ccbhash_entries(table, ccbhash_info)
    
    assert len(table.rows) >= 7


def test_add_ccbhash_entries_no_similar_functions():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    ccbhash_info = {
        "binary_ccbhash": "ccb123",
        "total_functions": 100,
        "analyzed_functions": 95,
        "unique_hashes": 80,
        "similar_functions": [],
    }
    
    _add_ccbhash_entries(table, ccbhash_info)
    
    assert len(table.rows) == 4


def test_add_ccbhash_entries_empty_similar_group():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    ccbhash_info = {
        "binary_ccbhash": "ccb123",
        "total_functions": 100,
        "analyzed_functions": 95,
        "unique_hashes": 80,
        "similar_functions": [{}],
    }
    
    _add_ccbhash_entries(table, ccbhash_info)
    
    assert len(table.rows) >= 4


def test_add_ccbhash_entries_long_hash():
    table = Table()
    table.add_column("Property")
    table.add_column("Value")
    
    ccbhash_info = {
        "binary_ccbhash": "a" * 100,
        "total_functions": 10,
        "analyzed_functions": 9,
        "unique_hashes": 8,
    }
    
    _add_ccbhash_entries(table, ccbhash_info)
    
    assert len(table.rows) == 4
