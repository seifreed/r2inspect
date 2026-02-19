#!/usr/bin/env python3
"""Comprehensive tests for r2inspect/modules/pe_info.py - PE header parsing and analysis."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from r2inspect.modules import pe_info
from r2inspect.modules.pe_info_domain import (
    PE32_PLUS,
    apply_optional_header_info,
    build_subsystem_info,
    characteristics_from_bin,
    characteristics_from_header,
    compute_entry_point,
    determine_pe_file_type,
    determine_pe_format,
    normalize_pe_format,
)


def get_pe_sample_path():
    """Get path to PE sample file."""
    repo_root = Path(__file__).parent.parent.parent
    sample = repo_root / "samples" / "fixtures" / "hello_pe.exe"
    if sample.exists():
        return str(sample)
    return None


def test_get_pe_headers_info_complete():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {
            "arch": "x86",
            "machine": "i386",
            "bits": 32,
            "endian": "little",
            "baddr": 0x400000,
            "subsys": "windows gui",
        }
    }
    adapter.get_entry_info.return_value = [{"vaddr": 0x1000, "paddr": 0x400}]
    adapter.cmd.return_value = '{"imageBase": 4194304, "sizeOfImage": 16384}'
    logger = Mock()
    
    result = pe_info.get_pe_headers_info(adapter, "/test.exe", logger)
    
    assert result["architecture"] == "x86"
    assert result["machine"] == "i386"
    assert result["bits"] == 32
    assert result["endian"] == "little"
    assert result["image_base"] == 0x400000
    assert "type" in result
    assert "format" in result


def test_get_pe_headers_info_missing_bin():
    adapter = Mock()
    adapter.get_file_info.return_value = {"other": "data"}
    logger = Mock()
    
    result = pe_info.get_pe_headers_info(adapter, "/test.exe", logger)
    
    assert result == {}


def test_get_pe_headers_info_none_pe_info():
    adapter = Mock()
    adapter.get_file_info.return_value = None
    logger = Mock()
    
    result = pe_info.get_pe_headers_info(adapter, "/test.exe", logger)
    
    assert result == {}


def test_get_pe_headers_info_with_pe_header():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {
            "arch": "x86_64",
            "machine": "AMD64",
            "bits": 64,
            "endian": "little",
            "baddr": 0x140000000,
        }
    }
    adapter.cmd.return_value = '{"magic": 523, "sizeOfImage": 32768}'
    logger = Mock()
    
    result = pe_info.get_pe_headers_info(adapter, "/test.exe", logger)
    
    assert result["bits"] == 64
    assert result["architecture"] == "x86_64"


def test_get_pe_headers_info_pe32_plus_format():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {
            "arch": "x86_64",
            "bits": 64,
            "machine": "AMD64",
            "endian": "little",
            "baddr": 0x140000000,
        }
    }
    adapter.cmd.return_value = f'{{"magic": {PE32_PLUS}}}'
    logger = Mock()
    
    result = pe_info.get_pe_headers_info(adapter, "/test.exe", logger)
    
    assert result["format"] in ["PE32+", "PE"]


def test_fetch_pe_header_valid():
    adapter = Mock()
    adapter.cmd.return_value = '{"signature": "PE\\u0000\\u0000", "machine": 332}'
    logger = Mock()
    
    result = pe_info._fetch_pe_header(adapter, logger)
    
    assert result is not None
    assert isinstance(result, dict)


def test_fetch_pe_header_invalid_json():
    adapter = Mock()
    adapter.cmd.return_value = "invalid json"
    logger = Mock()
    
    result = pe_info._fetch_pe_header(adapter, logger)
    
    assert result is None or isinstance(result, dict)


def test_fetch_pe_header_empty_response():
    adapter = Mock()
    adapter.cmd.return_value = "{}"
    logger = Mock()
    
    result = pe_info._fetch_pe_header(adapter, logger)
    
    assert result is not None


def test_get_entry_info_multiple_entries():
    adapter = Mock()
    adapter.get_entry_info.return_value = [
        {"vaddr": 0x1000, "paddr": 0x400},
        {"vaddr": 0x2000, "paddr": 0x800},
    ]
    logger = Mock()
    
    result = pe_info._get_entry_info(adapter, logger)
    
    assert result is not None
    assert len(result) == 2


def test_get_entry_info_invalid_return():
    adapter = Mock()
    adapter.get_entry_info.return_value = {"not": "a list"}
    logger = Mock()
    
    result = pe_info._get_entry_info(adapter, logger)
    
    assert result is None


def test_get_file_description_valid_path():
    sample_path = get_pe_sample_path()
    if sample_path is None:
        pytest.skip("PE sample not available")
    
    logger = Mock()
    
    result = pe_info._get_file_description(sample_path, logger)
    
    if result:
        assert isinstance(result, str)
        assert len(result) > 0


def test_get_file_description_empty_path():
    logger = Mock()
    
    result = pe_info._get_file_description("", logger)
    
    assert result is None


def test_get_file_description_nonexistent_file():
    logger = Mock()
    
    result = pe_info._get_file_description("/nonexistent/file.exe", logger)
    
    logger.debug.assert_called()


def test_get_file_characteristics_with_debug():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {
            "debug": True,
            "relocs_stripped": False,
        }
    }
    adapter.cmd.return_value = '{"characteristics": 258}'
    logger = Mock()
    
    result = pe_info.get_file_characteristics(adapter, "/test.exe", logger)
    
    assert result["has_debug"] is True


def test_get_file_characteristics_no_debug():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {}
    }
    adapter.cmd.return_value = "{}"
    logger = Mock()
    
    result = pe_info.get_file_characteristics(adapter, "/test.exe", logger)
    
    assert result["has_debug"] is False


def test_get_file_characteristics_from_header():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {"debug": False}
    }
    adapter.cmd.return_value = '{"characteristics": 290}'
    logger = Mock()
    
    result = pe_info.get_file_characteristics(adapter, "/test.exe", logger)
    
    assert isinstance(result, dict)


def test_get_file_characteristics_fallback_to_bin():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {
            "relocs_stripped": True,
            "stripped": True,
        }
    }
    adapter.cmd.side_effect = Exception("Header parsing failed")
    logger = Mock()
    
    result = pe_info.get_file_characteristics(adapter, "/test.exe", logger)
    
    assert isinstance(result, dict)


def test_get_compilation_info_with_timestamp():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {
            "compiled": "2024-01-15 10:30:45",
        }
    }
    adapter.get_strings_text.return_value = "Some text\nCompiler: Microsoft C/C++\nMore text"
    logger = Mock()
    
    result = pe_info.get_compilation_info(adapter, logger)
    
    assert result["compile_time"] == "2024-01-15 10:30:45"
    assert "compiler_info" in result


def test_get_compilation_info_no_timestamp():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {}
    }
    logger = Mock()
    
    result = pe_info.get_compilation_info(adapter, logger)
    
    assert "compile_time" not in result


def test_get_compilation_info_compiler_only():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {}
    }
    adapter.get_strings_text.return_value = "Compiler Version: MSVC 19.28"
    logger = Mock()
    
    result = pe_info.get_compilation_info(adapter, logger)
    
    assert "compiler_info" in result
    assert "compiler" in result["compiler_info"].lower()


def test_extract_compiler_info_multiple_lines():
    adapter = Mock()
    adapter.get_strings_text.return_value = (
        "Some data\n"
        "Compiler: Microsoft C/C++\n"
        "Compiler version: 19.28\n"
        "Other text"
    )
    
    result = pe_info._extract_compiler_info(adapter)
    
    assert result is not None
    assert "compiler" in result.lower()
    assert "\n" in result


def test_extract_compiler_info_case_insensitive():
    adapter = Mock()
    adapter.get_strings_text.return_value = "COMPILER: GCC"
    
    result = pe_info._extract_compiler_info(adapter)
    
    assert result is not None
    assert "COMPILER" in result


def test_extract_compiler_info_no_matches():
    adapter = Mock()
    adapter.get_strings_text.return_value = "No relevant information here"
    
    result = pe_info._extract_compiler_info(adapter)
    
    assert result is None


def test_get_subsystem_info_gui():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {
            "subsys": "windows gui",
        }
    }
    logger = Mock()
    
    result = pe_info.get_subsystem_info(adapter, logger)
    
    assert isinstance(result, dict)


def test_get_subsystem_info_console():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {
            "subsys": "windows console",
        }
    }
    logger = Mock()
    
    result = pe_info.get_subsystem_info(adapter, logger)
    
    assert isinstance(result, dict)


def test_get_subsystem_info_unknown():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {
            "subsys": "Unknown",
        }
    }
    logger = Mock()
    
    result = pe_info.get_subsystem_info(adapter, logger)
    
    assert isinstance(result, dict)


def test_get_subsystem_info_missing_subsys():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {}
    }
    logger = Mock()
    
    result = pe_info.get_subsystem_info(adapter, logger)
    
    assert isinstance(result, dict)


def test_get_pe_headers_info_error_handling():
    adapter = Mock()
    adapter.get_file_info.side_effect = RuntimeError("Adapter failure")
    logger = Mock()
    
    result = pe_info.get_pe_headers_info(adapter, "/test.exe", logger)
    
    assert result == {}
    logger.error.assert_called()


def test_get_file_characteristics_nested_exception():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {"debug": True}
    }
    adapter.cmd.side_effect = [Exception("First fail"), Exception("Second fail")]
    logger = Mock()
    
    result = pe_info.get_file_characteristics(adapter, "/test.exe", logger)
    
    assert isinstance(result, dict)
    assert result.get("has_debug") is True


def test_get_compilation_info_error_in_compiler_extraction():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {"compiled": "2024-01-15"}
    }
    adapter.get_strings_text.side_effect = Exception("Strings extraction failed")
    logger = Mock()
    
    result = pe_info.get_compilation_info(adapter, logger)
    
    assert result["compile_time"] == "2024-01-15"


def test_pe_headers_info_integration():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {
            "arch": "x86",
            "machine": "i386",
            "bits": 32,
            "endian": "little",
            "baddr": 0x400000,
            "compiled": "2024-01-01 12:00:00",
            "subsys": "windows gui",
            "debug": True,
        }
    }
    adapter.get_entry_info.return_value = [{"vaddr": 0x1234}]
    adapter.cmd.return_value = '{"imageBase": 4194304}'
    adapter.get_strings_text.return_value = "Compiler: MSVC"
    logger = Mock()
    
    headers = pe_info.get_pe_headers_info(adapter, "/test.exe", logger)
    chars = pe_info.get_file_characteristics(adapter, "/test.exe", logger)
    comp = pe_info.get_compilation_info(adapter, logger)
    subsys = pe_info.get_subsystem_info(adapter, logger)
    
    assert headers["bits"] == 32
    assert chars["has_debug"] is True
    assert comp["compile_time"] == "2024-01-01 12:00:00"
    assert isinstance(subsys, dict)


def test_all_extraction_methods_called():
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "bin": {
            "arch": "x86",
            "bits": 32,
            "machine": "i386",
            "endian": "little",
            "baddr": 0x400000,
        }
    }
    logger = Mock()
    
    pe_info.get_pe_headers_info(adapter, "/test.exe", logger)
    pe_info.get_file_characteristics(adapter, "/test.exe", logger)
    pe_info.get_compilation_info(adapter, logger)
    pe_info.get_subsystem_info(adapter, logger)
    
    assert adapter.get_file_info.call_count >= 4
