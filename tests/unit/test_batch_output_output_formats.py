"""Comprehensive tests for batch output formatting in batch_output.py."""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from r2inspect.cli.batch_output import (
    get_csv_fieldnames,
    write_csv_results,
    determine_csv_file_path,
    create_json_batch_summary,
    create_batch_summary,
    _show_summary_table,
    _simplify_file_type,
    _extract_compile_time,
    _compiler_name,
    _collect_yara_matches,
    _build_small_row,
    _build_large_row,
    _build_summary_table_small,
    _build_summary_table_large,
    setup_batch_output_directory,
    find_files_to_process,
    find_files_by_extensions,
    display_no_files_message,
    _configure_batch_logging,
    _prepare_batch_run,
    _init_batch_results,
)


def test_get_csv_fieldnames():
    """Test CSV fieldnames retrieval."""
    fieldnames = get_csv_fieldnames()
    assert isinstance(fieldnames, list)
    assert "name" in fieldnames
    assert "md5" in fieldnames
    assert "sha256" in fieldnames
    assert "file_type" in fieldnames
    assert "compiler" in fieldnames
    assert "yara_matches" in fieldnames


def test_write_csv_results_basic(tmp_path):
    """Test writing basic CSV results."""
    csv_file = tmp_path / "results.csv"
    all_results = {
        "test.exe": {
            "file_info": {
                "name": "test.exe",
                "size": 1024,
                "md5": "abc123",
                "sha256": "def456",
                "file_type": "PE32",
            }
        }
    }
    
    write_csv_results(csv_file, all_results)
    
    assert csv_file.exists()
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) >= 1


def test_write_csv_results_multiple_files(tmp_path):
    """Test writing CSV results for multiple files."""
    csv_file = tmp_path / "results.csv"
    all_results = {
        "test1.exe": {
            "file_info": {
                "name": "test1.exe",
                "md5": "abc123",
                "sha256": "def456",
                "file_type": "PE32",
            }
        },
        "test2.exe": {
            "file_info": {
                "name": "test2.exe",
                "md5": "ghi789",
                "sha256": "jkl012",
                "file_type": "PE32+",
            }
        }
    }
    
    write_csv_results(csv_file, all_results)
    
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) >= 2


def test_write_csv_results_empty(tmp_path):
    """Test writing CSV results with empty data."""
    csv_file = tmp_path / "results.csv"
    all_results = {}
    
    write_csv_results(csv_file, all_results)
    
    assert csv_file.exists()
    with open(csv_file, 'r') as f:
        content = f.read()
        assert "name" in content


def test_determine_csv_file_path_with_filename(tmp_path):
    """Test CSV file path determination with specific filename."""
    csv_path = tmp_path / "custom.csv"
    timestamp = "20240101_120000"
    
    result_path, result_name = determine_csv_file_path(csv_path, timestamp)
    
    assert result_path == csv_path
    assert result_name == "custom.csv"


def test_determine_csv_file_path_with_directory(tmp_path):
    """Test CSV file path determination with directory."""
    timestamp = "20240101_120000"
    
    result_path, result_name = determine_csv_file_path(tmp_path, timestamp)
    
    assert result_path.parent == tmp_path
    assert f"r2inspect_{timestamp}.csv" in str(result_path)
    assert result_name == f"r2inspect_{timestamp}.csv"


def test_create_json_batch_summary_basic(tmp_path):
    """Test creating basic JSON batch summary."""
    all_results = {
        "test.exe": {
            "file_info": {"name": "test.exe"}
        }
    }
    failed_files = []
    timestamp = "20240101_120000"
    
    output_filename = create_json_batch_summary(
        all_results=all_results,
        failed_files=failed_files,
        output_path=tmp_path,
        timestamp=timestamp
    )
    
    assert "individual JSONs" in output_filename
    summary_file = tmp_path / f"r2inspect_batch_{timestamp}.json"
    assert summary_file.exists()


def test_create_json_batch_summary_with_failures(tmp_path):
    """Test creating JSON batch summary with failed files."""
    all_results = {"test.exe": {"file_info": {"name": "test.exe"}}}
    failed_files = [
        ("failed1.exe", "Error message 1"),
        ("failed2.exe", "Error message 2")
    ]
    timestamp = "20240101_120000"
    
    create_json_batch_summary(all_results, failed_files, tmp_path, timestamp)
    
    summary_file = tmp_path / f"r2inspect_batch_{timestamp}.json"
    with open(summary_file) as f:
        data = json.load(f)
        assert data["batch_summary"]["total_files"] == 3
        assert data["batch_summary"]["successful_analyses"] == 1
        assert data["batch_summary"]["failed_analyses"] == 2
        assert len(data["failed_files"]) == 2


def test_create_json_batch_summary_with_statistics(tmp_path):
    """Test JSON batch summary includes statistics."""
    all_results = {
        "test.exe": {
            "file_info": {"name": "test.exe", "file_type": "PE32"}
        }
    }
    failed_files = []
    timestamp = "20240101_120000"
    
    create_json_batch_summary(all_results, failed_files, tmp_path, timestamp)
    
    summary_file = tmp_path / f"r2inspect_batch_{timestamp}.json"
    with open(summary_file) as f:
        data = json.load(f)
        assert "statistics" in data
        assert "batch_summary" in data


def test_create_batch_summary_csv_only(tmp_path):
    """Test creating batch summary with CSV only."""
    all_results = {"test.exe": {"file_info": {"name": "test.exe"}}}
    failed_files = []
    
    output_filename = create_batch_summary(
        all_results=all_results,
        failed_files=failed_files,
        output_path=tmp_path,
        output_json=False,
        output_csv=True
    )
    
    assert output_filename is not None
    assert ".csv" in output_filename


def test_create_batch_summary_json_only(tmp_path, capsys):
    """Test creating batch summary with JSON only."""
    all_results = {"test.exe": {"file_info": {"name": "test.exe"}}}
    failed_files = []
    
    output_filename = create_batch_summary(
        all_results=all_results,
        failed_files=failed_files,
        output_path=tmp_path,
        output_json=True,
        output_csv=False
    )
    
    assert output_filename is not None
    assert "individual JSONs" in output_filename


def test_create_batch_summary_json_and_csv(tmp_path, capsys):
    """Test creating batch summary with both JSON and CSV."""
    all_results = {"test.exe": {"file_info": {"name": "test.exe"}}}
    failed_files = []
    
    output_filename = create_batch_summary(
        all_results=all_results,
        failed_files=failed_files,
        output_path=tmp_path,
        output_json=True,
        output_csv=True
    )
    
    assert output_filename is not None
    assert "individual JSONs" in output_filename


def test_create_batch_summary_custom_csv_filename(tmp_path, capsys):
    """Test creating batch summary with custom CSV filename."""
    csv_file = tmp_path / "custom.csv"
    all_results = {"test.exe": {"file_info": {"name": "test.exe"}}}
    failed_files = []
    
    output_filename = create_batch_summary(
        all_results=all_results,
        failed_files=failed_files,
        output_path=csv_file,
        output_json=True,
        output_csv=True
    )
    
    assert "custom.csv" in output_filename


def test_show_summary_table_small(capsys):
    """Test summary table display for small result set."""
    all_results = {
        f"test{i}.exe": {
            "file_info": {
                "name": f"test{i}.exe",
                "file_type": "PE32"
            }
        }
        for i in range(5)
    }
    
    _show_summary_table(all_results)
    captured = capsys.readouterr()
    assert "Analysis Summary" in captured.out


def test_show_summary_table_large(capsys):
    """Test summary table display for large result set."""
    all_results = {
        f"test{i}.exe": {
            "file_info": {
                "name": f"test{i}.exe",
                "file_type": "PE32"
            }
        }
        for i in range(15)
    }
    
    _show_summary_table(all_results)
    captured = capsys.readouterr()
    assert "and 5 more files" in captured.out


def test_simplify_file_type_pe32():
    """Test file type simplification for PE32."""
    assert _simplify_file_type("PE32 executable, 4 sections") == "PE32 (x86)"


def test_simplify_file_type_pe32_plus():
    """Test file type simplification for PE32+."""
    assert _simplify_file_type("PE32+ executable, 5 sections") == "PE32+ (x64)"


def test_simplify_file_type_elf():
    """Test file type simplification for ELF."""
    assert _simplify_file_type("ELF 64-bit LSB executable") == "ELF"


def test_simplify_file_type_macho():
    """Test file type simplification for Mach-O."""
    assert _simplify_file_type("Mach-O 64-bit executable") == "Mach-O"


def test_simplify_file_type_unknown():
    """Test file type simplification for unknown type."""
    assert _simplify_file_type("Unknown format") == "Unknown format"


def test_simplify_file_type_empty():
    """Test file type simplification for empty string."""
    assert _simplify_file_type("") == "Unknown"


def test_extract_compile_time_pe():
    """Test compile time extraction from PE info."""
    result = {"pe_info": {"compile_time": "2024-01-01 12:00:00"}}
    assert _extract_compile_time(result) == "2024-01-01 12:00:00"


def test_extract_compile_time_elf():
    """Test compile time extraction from ELF info."""
    result = {"elf_info": {"compile_time": "2024-01-01 13:00:00"}}
    assert _extract_compile_time(result) == "2024-01-01 13:00:00"


def test_extract_compile_time_macho():
    """Test compile time extraction from Mach-O info."""
    result = {"macho_info": {"compile_time": "2024-01-01 14:00:00"}}
    assert _extract_compile_time(result) == "2024-01-01 14:00:00"


def test_extract_compile_time_none():
    """Test compile time extraction when not available."""
    result = {}
    assert _extract_compile_time(result) == "N/A"


def test_compiler_name_detected():
    """Test compiler name extraction when detected."""
    result = {
        "compiler": {
            "detected": True,
            "compiler": "GCC",
            "version": "11.2.0"
        }
    }
    assert _compiler_name(result) == "GCC 11.2.0"


def test_compiler_name_no_version():
    """Test compiler name extraction without version."""
    result = {
        "compiler": {
            "detected": True,
            "compiler": "MSVC",
            "version": "Unknown"
        }
    }
    assert _compiler_name(result) == "MSVC"


def test_compiler_name_not_detected():
    """Test compiler name when not detected."""
    result = {"compiler": {"detected": False}}
    assert _compiler_name(result) == "Unknown"


def test_compiler_name_missing():
    """Test compiler name when compiler info missing."""
    result = {}
    assert _compiler_name(result) == "Unknown"


def test_collect_yara_matches_list():
    """Test YARA matches collection from list."""
    result = {
        "yara_matches": [
            {"rule": "Packer_UPX"},
            {"rule": "Malware_Trojan"}
        ]
    }
    matches = _collect_yara_matches(result)
    assert "Packer_UPX" in matches
    assert "Malware_Trojan" in matches


def test_collect_yara_matches_objects():
    """Test YARA matches collection from objects."""
    match1 = Mock()
    match1.rule = "Rule1"
    match2 = Mock()
    match2.rule = "Rule2"
    
    result = {"yara_matches": [match1, match2]}
    matches = _collect_yara_matches(result)
    assert "Rule1" in matches
    assert "Rule2" in matches


def test_collect_yara_matches_none():
    """Test YARA matches collection when none exist."""
    result = {"yara_matches": []}
    assert _collect_yara_matches(result) == "None"


def test_collect_yara_matches_not_list():
    """Test YARA matches collection when not a list."""
    result = {"yara_matches": "not a list"}
    assert _collect_yara_matches(result) == "None"


def test_collect_yara_matches_missing():
    """Test YARA matches collection when missing."""
    result = {}
    assert _collect_yara_matches(result) == "None"


def test_build_small_row_basic():
    """Test building small table row."""
    result = {
        "file_info": {
            "name": "test.exe",
            "file_type": "PE32 executable"
        },
        "pe_info": {"compile_time": "2024-01-01"},
        "compiler": {"detected": True, "compiler": "GCC"}
    }
    
    filename, file_type, compiler, compile_time = _build_small_row("test.exe", result)
    assert filename == "test.exe"
    assert file_type == "PE32 (x86)"
    assert "GCC" in compiler
    assert compile_time == "2024-01-01"


def test_build_small_row_error():
    """Test building small table row with error."""
    result = {}
    filename, file_type, compiler, compile_time = _build_small_row("test.exe", result)
    assert filename == "test.exe"
    assert file_type in ["Error", "Unknown"]


def test_build_large_row_basic():
    """Test building large table row."""
    result = {
        "file_info": {
            "md5": "abc123",
            "file_type": "PE32 executable"
        },
        "pe_info": {"compile_time": "2024-01-01"},
        "compiler": {"detected": True, "compiler": "GCC"},
        "yara_matches": [{"rule": "Test_Rule"}]
    }
    
    md5, file_type, compiler, compile_time, yara = _build_large_row("test.exe", result)
    assert md5 == "abc123"
    assert file_type == "PE32 (x86)"
    assert "Test_Rule" in yara


def test_build_large_row_error():
    """Test building large table row with error."""
    result = {}
    md5, file_type, compiler, compile_time, yara = _build_large_row("test.exe", result)
    assert md5 in ["test.exe", "N/A"]
    assert file_type in ["Error", "Unknown"]


def test_build_summary_table_small():
    """Test building small summary table."""
    all_results = {
        "test.exe": {
            "file_info": {
                "name": "test.exe",
                "file_type": "PE32"
            }
        }
    }
    
    table = _build_summary_table_small(all_results)
    assert table is not None
    assert table.title == "Analysis Summary"


def test_build_summary_table_small_limits_to_10():
    """Test small summary table limits to 10 files."""
    all_results = {
        f"test{i}.exe": {
            "file_info": {"name": f"test{i}.exe", "file_type": "PE32"}
        }
        for i in range(15)
    }
    
    table = _build_summary_table_small(all_results)
    assert len(table.rows) == 10


def test_build_summary_table_large():
    """Test building large summary table."""
    all_results = {
        "test.exe": {
            "file_info": {
                "md5": "abc123",
                "file_type": "PE32"
            }
        }
    }
    
    table = _build_summary_table_large(all_results)
    assert table is not None
    assert table.title == "Analysis Summary"


def test_setup_batch_output_directory_json(tmp_path):
    """Test batch output directory setup for JSON."""
    import os
    os.chdir(tmp_path)
    
    output_path = setup_batch_output_directory(
        output_dir=None,
        output_json=True,
        output_csv=False
    )
    
    assert output_path.name == "output"
    assert output_path.exists()


def test_setup_batch_output_directory_csv(tmp_path):
    """Test batch output directory setup for CSV."""
    import os
    os.chdir(tmp_path)
    
    output_path = setup_batch_output_directory(
        output_dir=None,
        output_json=False,
        output_csv=True
    )
    
    assert output_path.name == "output"


def test_setup_batch_output_directory_custom_dir(tmp_path):
    """Test batch output directory with custom directory."""
    custom_dir = tmp_path / "custom"
    
    output_path = setup_batch_output_directory(
        output_dir=str(custom_dir),
        output_json=False,
        output_csv=False
    )
    
    assert output_path == custom_dir
    assert output_path.exists()


def test_setup_batch_output_directory_csv_file(tmp_path):
    """Test batch output directory with CSV file path."""
    csv_file = tmp_path / "subdir" / "results.csv"
    
    output_path = setup_batch_output_directory(
        output_dir=str(csv_file),
        output_json=False,
        output_csv=True
    )
    
    assert output_path == csv_file
    assert output_path.parent.exists()


def test_find_files_to_process_auto_detect(tmp_path):
    """Test finding files with auto-detection."""
    from r2inspect.cli.batch_processing import find_executable_files_by_magic
    
    with patch('r2inspect.cli.batch_processing.find_executable_files_by_magic') as mock_find:
        mock_find.return_value = []
        
        files = find_files_to_process(
            batch_path=tmp_path,
            auto_detect=True,
            extensions=None,
            recursive=True,
            verbose=False,
            quiet=True
        )


def test_find_files_to_process_extensions(tmp_path):
    """Test finding files by extensions."""
    test_file = tmp_path / "test.exe"
    test_file.touch()
    
    files = find_files_to_process(
        batch_path=tmp_path,
        auto_detect=False,
        extensions="exe",
        recursive=False,
        verbose=False,
        quiet=True
    )
    
    assert test_file in files


def test_find_files_to_process_no_extensions(tmp_path):
    """Test finding files without extensions returns empty."""
    files = find_files_to_process(
        batch_path=tmp_path,
        auto_detect=False,
        extensions=None,
        recursive=False,
        verbose=False,
        quiet=True
    )
    
    assert files == []


def test_find_files_by_extensions_single(tmp_path):
    """Test finding files by single extension."""
    exe_file = tmp_path / "test.exe"
    exe_file.touch()
    
    files = find_files_by_extensions(tmp_path, "exe", recursive=False)
    assert exe_file in files


def test_find_files_by_extensions_multiple(tmp_path):
    """Test finding files by multiple extensions."""
    exe_file = tmp_path / "test.exe"
    exe_file.touch()
    dll_file = tmp_path / "test.dll"
    dll_file.touch()
    
    files = find_files_by_extensions(tmp_path, "exe,dll", recursive=False)
    assert exe_file in files
    assert dll_file in files


def test_display_no_files_message_auto(capsys):
    """Test no files message for auto-detect."""
    display_no_files_message(auto_detect=True, extensions=None)
    captured = capsys.readouterr()
    assert "No executable files detected" in captured.out


def test_display_no_files_message_extensions(capsys):
    """Test no files message for extensions."""
    display_no_files_message(auto_detect=False, extensions="exe")
    captured = capsys.readouterr()
    assert "No files found with extensions: exe" in captured.out


def test_configure_batch_logging_verbose():
    """Test batch logging configuration in verbose mode."""
    _configure_batch_logging(verbose=True, quiet=False)


def test_configure_batch_logging_quiet():
    """Test batch logging configuration in quiet mode."""
    _configure_batch_logging(verbose=False, quiet=True)


def test_configure_batch_logging_normal():
    """Test batch logging configuration in normal mode."""
    from r2inspect.utils.logger import configure_batch_logging
    
    with patch('r2inspect.utils.logger.configure_batch_logging'):
        _configure_batch_logging(verbose=False, quiet=False)


def test_prepare_batch_run_success(tmp_path):
    """Test successful batch run preparation."""
    test_file = tmp_path / "test.exe"
    test_file.touch()
    
    result = _prepare_batch_run(
        batch_path=tmp_path,
        auto_detect=False,
        extensions="exe",
        recursive=False,
        verbose=False,
        quiet=True,
        output_dir=None,
        output_json=True,
        output_csv=False,
        threads=4
    )
    
    assert result is not None
    files, output_path = result
    assert test_file in files


def test_prepare_batch_run_no_files(tmp_path, capsys):
    """Test batch run preparation with no files found."""
    result = _prepare_batch_run(
        batch_path=tmp_path,
        auto_detect=False,
        extensions="exe",
        recursive=False,
        verbose=False,
        quiet=True,
        output_dir=None,
        output_json=False,
        output_csv=False,
        threads=4
    )
    
    assert result is None


def test_init_batch_results():
    """Test batch results initialization."""
    results, failed = _init_batch_results()
    assert results == {}
    assert failed == []
