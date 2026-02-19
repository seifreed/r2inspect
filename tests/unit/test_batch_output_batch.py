#!/usr/bin/env python3
"""
Comprehensive tests for r2inspect/cli/batch_output.py module.
Tests CSV/JSON output, batch processing, file discovery, and summary generation.
Coverage target: 100% (currently 17%)
"""

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from r2inspect.cli.batch_output import (
    _build_large_row,
    _build_small_row,
    _build_summary_table_large,
    _build_summary_table_small,
    _collect_yara_matches,
    _compiler_name,
    _configure_batch_logging,
    _extract_compile_time,
    _init_batch_results,
    _prepare_batch_run,
    _show_summary_table,
    _simplify_file_type,
    create_batch_summary,
    create_json_batch_summary,
    determine_csv_file_path,
    display_no_files_message,
    find_files_by_extensions,
    find_files_to_process,
    get_csv_fieldnames,
    setup_batch_output_directory,
    write_csv_results,
)


def test_get_csv_fieldnames_contains_all_required():
    """Test CSV fieldnames include all required fields"""
    fields = get_csv_fieldnames()
    required_fields = [
        "name", "size", "md5", "sha1", "sha256", "sha512",
        "file_type", "compile_time", "compiler", "imports", "exports"
    ]
    for field in required_fields:
        assert field in fields


def test_get_csv_fieldnames_count():
    """Test CSV fieldnames returns expected number of fields"""
    fields = get_csv_fieldnames()
    assert len(fields) > 30


def test_write_csv_results_creates_file(tmp_path):
    """Test CSV results file is created with headers"""
    csv_file = tmp_path / "results.csv"
    results = {
        "file1.exe": {
            "file_info": {
                "name": "file1.exe",
                "size": 1024,
                "md5": "abc123",
                "sha1": "def456",
                "sha256": "ghi789",
                "sha512": "jkl012",
                "file_type": "PE32",
            }
        }
    }
    write_csv_results(csv_file, results)
    
    assert csv_file.exists()
    with open(csv_file, "r") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        assert "name" in fieldnames
        assert "sha256" in fieldnames


def test_write_csv_results_multiple_files(tmp_path):
    """Test CSV output with multiple files"""
    csv_file = tmp_path / "results.csv"
    results = {
        "file1.exe": {
            "file_info": {"name": "file1.exe", "size": 1024, "md5": "abc123"}
        },
        "file2.dll": {
            "file_info": {"name": "file2.dll", "size": 2048, "md5": "def456"}
        }
    }
    write_csv_results(csv_file, results)
    
    with open(csv_file, "r") as f:
        rows = list(csv.DictReader(f))
        assert len(rows) == 2


def test_write_csv_results_empty(tmp_path):
    """Test CSV output with no results"""
    csv_file = tmp_path / "empty.csv"
    write_csv_results(csv_file, {})
    
    assert csv_file.exists()
    with open(csv_file, "r") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 0


def test_determine_csv_file_path_with_csv_extension(tmp_path):
    """Test CSV file path determination with .csv extension"""
    output_path = tmp_path / "custom_results.csv"
    csv_file, filename = determine_csv_file_path(output_path, "20240101_120000")
    
    assert csv_file == output_path
    assert filename == "custom_results.csv"


def test_determine_csv_file_path_with_directory(tmp_path):
    """Test CSV file path determination with directory"""
    output_path = tmp_path / "output"
    timestamp = "20240101_120000"
    csv_file, filename = determine_csv_file_path(output_path, timestamp)
    
    assert csv_file.name == f"r2inspect_{timestamp}.csv"
    assert filename == f"r2inspect_{timestamp}.csv"


def test_create_json_batch_summary_creates_file(tmp_path):
    """Test JSON batch summary file creation"""
    results = {
        "file1.exe": {"file_info": {"name": "file1.exe", "size": 1024}}
    }
    failed = [("file2.exe", "Analysis failed")]
    timestamp = "20240101_120000"
    
    output_filename = create_json_batch_summary(results, failed, tmp_path, timestamp)
    
    assert "r2inspect_batch_" in output_filename
    summary_file = tmp_path / f"r2inspect_batch_{timestamp}.json"
    assert summary_file.exists()


def test_create_json_batch_summary_structure(tmp_path):
    """Test JSON batch summary has correct structure"""
    results = {
        "file1.exe": {"file_info": {"name": "file1.exe"}}
    }
    failed = [("file2.exe", "Error message")]
    timestamp = "20240101_120000"
    
    create_json_batch_summary(results, failed, tmp_path, timestamp)
    summary_file = tmp_path / f"r2inspect_batch_{timestamp}.json"
    
    with open(summary_file, "r") as f:
        data = json.load(f)
    
    assert "batch_summary" in data
    assert "results" in data
    assert "failed_files" in data
    assert "statistics" in data
    assert data["batch_summary"]["total_files"] == 2
    assert data["batch_summary"]["successful_analyses"] == 1
    assert data["batch_summary"]["failed_analyses"] == 1


def test_create_json_batch_summary_failed_files_structure(tmp_path):
    """Test failed files are properly formatted in JSON"""
    results = {}
    failed = [
        ("file1.exe", "Error 1"),
        ("file2.dll", "Error 2")
    ]
    timestamp = "20240101_120000"
    
    create_json_batch_summary(results, failed, tmp_path, timestamp)
    summary_file = tmp_path / f"r2inspect_batch_{timestamp}.json"
    
    with open(summary_file, "r") as f:
        data = json.load(f)
    
    assert len(data["failed_files"]) == 2
    assert data["failed_files"][0]["file"] == "file1.exe"
    assert data["failed_files"][0]["error"] == "Error 1"


def test_find_files_by_extensions_single_extension(tmp_path):
    """Test finding files by single extension"""
    (tmp_path / "file1.exe").touch()
    (tmp_path / "file2.exe").touch()
    (tmp_path / "file3.dll").touch()
    
    files = find_files_by_extensions(tmp_path, "exe", False)
    assert len(files) == 2


def test_find_files_by_extensions_multiple_extensions(tmp_path):
    """Test finding files by multiple extensions"""
    (tmp_path / "file1.exe").touch()
    (tmp_path / "file2.dll").touch()
    (tmp_path / "file3.sys").touch()
    (tmp_path / "file4.txt").touch()
    
    files = find_files_by_extensions(tmp_path, "exe,dll,sys", False)
    assert len(files) == 3


def test_find_files_by_extensions_recursive(tmp_path):
    """Test recursive file search"""
    (tmp_path / "file1.exe").touch()
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    (subdir / "file2.exe").touch()
    
    files = find_files_by_extensions(tmp_path, "exe", True)
    assert len(files) == 2


def test_find_files_by_extensions_no_matches(tmp_path):
    """Test finding files when no matches exist"""
    (tmp_path / "file1.txt").touch()
    (tmp_path / "file2.doc").touch()
    
    files = find_files_by_extensions(tmp_path, "exe", False)
    assert len(files) == 0


def test_display_no_files_message_auto_detect(capsys):
    """Test display message for no files in auto-detect mode"""
    display_no_files_message(auto_detect=True, extensions=None)
    captured = capsys.readouterr()
    assert "no executable files" in captured.out.lower()


def test_display_no_files_message_with_extensions(capsys):
    """Test display message for no files with extensions"""
    display_no_files_message(auto_detect=False, extensions="exe,dll")
    captured = capsys.readouterr()
    assert "exe,dll" in captured.out


def test_setup_batch_output_directory_creates_directory(tmp_path):
    """Test output directory creation"""
    output_dir = tmp_path / "output"
    path = setup_batch_output_directory(str(output_dir), True, False)
    
    assert path.exists()
    assert path.is_dir()


def test_setup_batch_output_directory_with_csv_file(tmp_path):
    """Test output directory setup with CSV filename"""
    output_file = tmp_path / "results" / "output.csv"
    path = setup_batch_output_directory(str(output_file), False, True)
    
    assert output_file.parent.exists()


def test_setup_batch_output_directory_with_json_file(tmp_path):
    """Test output directory setup with JSON filename"""
    output_file = tmp_path / "results" / "output.json"
    path = setup_batch_output_directory(str(output_file), True, False)
    
    assert output_file.parent.exists()


def test_setup_batch_output_directory_default():
    """Test default output directory creation"""
    path = setup_batch_output_directory(None, True, True)
    assert path.name == "output"


def test_setup_batch_output_directory_fallback():
    """Test fallback output directory creation"""
    path = setup_batch_output_directory(None, False, False)
    assert path.name == "r2inspect_batch_results"


def test_configure_batch_logging_verbose():
    """Test batch logging configuration in verbose mode"""
    _configure_batch_logging(verbose=True, quiet=False)


def test_configure_batch_logging_quiet():
    """Test batch logging configuration in quiet mode"""
    import logging
    _configure_batch_logging(verbose=False, quiet=True)
    
    logger = logging.getLogger("r2inspect")
    assert logger.level == logging.CRITICAL


def test_configure_batch_logging_normal():
    """Test batch logging configuration in normal mode"""
    _configure_batch_logging(verbose=False, quiet=False)


def test_init_batch_results():
    """Test initialization of batch results"""
    results, failed = _init_batch_results()
    assert results == {}
    assert failed == []


def test_simplify_file_type_pe32():
    """Test file type simplification for PE32"""
    result = _simplify_file_type("PE32 executable, 5 sections")
    assert result == "PE32 (x86)"


def test_simplify_file_type_pe32_plus():
    """Test file type simplification for PE32+"""
    result = _simplify_file_type("PE32+ executable, 6 sections")
    assert result == "PE32+ (x64)"


def test_simplify_file_type_elf():
    """Test file type simplification for ELF"""
    result = _simplify_file_type("ELF 64-bit LSB executable, 10 sections")
    assert result == "ELF"


def test_simplify_file_type_macho():
    """Test file type simplification for Mach-O"""
    result = _simplify_file_type("Mach-O 64-bit x86_64 executable")
    assert result == "Mach-O"


def test_simplify_file_type_unknown():
    """Test file type simplification for unknown format"""
    result = _simplify_file_type("")
    assert result == "Unknown"


def test_extract_compile_time_pe():
    """Test compile time extraction from PE info"""
    result_data = {
        "pe_info": {"compile_time": "2024-01-01 12:00:00"}
    }
    compile_time = _extract_compile_time(result_data)
    assert compile_time == "2024-01-01 12:00:00"


def test_extract_compile_time_elf():
    """Test compile time extraction from ELF info"""
    result_data = {
        "elf_info": {"compile_time": "2024-01-01 12:00:00"}
    }
    compile_time = _extract_compile_time(result_data)
    assert compile_time == "2024-01-01 12:00:00"


def test_extract_compile_time_macho():
    """Test compile time extraction from Mach-O info"""
    result_data = {
        "macho_info": {"compile_time": "2024-01-01 12:00:00"}
    }
    compile_time = _extract_compile_time(result_data)
    assert compile_time == "2024-01-01 12:00:00"


def test_extract_compile_time_missing():
    """Test compile time extraction when not available"""
    result_data = {}
    compile_time = _extract_compile_time(result_data)
    assert compile_time == "N/A"


def test_compiler_name_detected():
    """Test compiler name extraction when detected"""
    result_data = {
        "compiler": {
            "detected": True,
            "compiler": "Microsoft Visual C++",
            "version": "14.0"
        }
    }
    name = _compiler_name(result_data)
    assert "Microsoft Visual C++" in name
    assert "14.0" in name


def test_compiler_name_detected_no_version():
    """Test compiler name extraction without version"""
    result_data = {
        "compiler": {
            "detected": True,
            "compiler": "GCC"
        }
    }
    name = _compiler_name(result_data)
    assert name == "GCC"


def test_compiler_name_not_detected():
    """Test compiler name when not detected"""
    result_data = {
        "compiler": {"detected": False}
    }
    name = _compiler_name(result_data)
    assert name == "Unknown"


def test_compiler_name_missing():
    """Test compiler name when compiler info is missing"""
    result_data = {}
    name = _compiler_name(result_data)
    assert name == "Unknown"


def test_collect_yara_matches_list():
    """Test YARA matches collection from list"""
    result_data = {
        "yara_matches": [
            {"rule": "malware_rule"},
            {"rule": "suspicious_rule"}
        ]
    }
    matches = _collect_yara_matches(result_data)
    assert "malware_rule" in matches
    assert "suspicious_rule" in matches


def test_collect_yara_matches_empty():
    """Test YARA matches collection when empty"""
    result_data = {"yara_matches": []}
    matches = _collect_yara_matches(result_data)
    assert matches == "None"


def test_collect_yara_matches_missing():
    """Test YARA matches collection when missing"""
    result_data = {}
    matches = _collect_yara_matches(result_data)
    assert matches == "None"


def test_collect_yara_matches_not_list():
    """Test YARA matches collection when not a list"""
    result_data = {"yara_matches": "invalid"}
    matches = _collect_yara_matches(result_data)
    assert matches == "None"


def test_build_small_row_success():
    """Test building small table row successfully"""
    result_data = {
        "file_info": {
            "name": "test.exe",
            "file_type": "PE32 executable, 5 sections"
        },
        "pe_info": {"compile_time": "2024-01-01"},
        "compiler": {"detected": True, "compiler": "MSVC"}
    }
    filename, file_type, compiler, compile_time = _build_small_row("test.exe", result_data)
    
    assert filename == "test.exe"
    assert file_type == "PE32 (x86)"
    assert compiler == "MSVC"
    assert compile_time == "2024-01-01"


def test_build_small_row_error():
    """Test building small table row with error"""
    result_data = {}
    filename, file_type, compiler, compile_time = _build_small_row("test.exe", result_data)
    
    assert filename == "test.exe"
    assert file_type == "Unknown"


def test_build_large_row_success():
    """Test building large table row successfully"""
    result_data = {
        "file_info": {
            "md5": "abc123",
            "file_type": "PE32+ executable"
        },
        "compiler": {"detected": True, "compiler": "GCC"},
        "yara_matches": [{"rule": "test_rule"}]
    }
    md5, file_type, compiler, compile_time, yara = _build_large_row("test.exe", result_data)
    
    assert md5 == "abc123"
    assert file_type == "PE32+ (x64)"
    assert "test_rule" in yara


def test_build_large_row_error():
    """Test building large table row with error"""
    result_data = {}
    md5, file_type, compiler, compile_time, yara = _build_large_row("test.exe", result_data)
    
    assert file_type == "Unknown"


def test_build_summary_table_small():
    """Test building small summary table"""
    results = {
        "file1.exe": {
            "file_info": {"name": "file1.exe", "file_type": "PE32"}
        },
        "file2.exe": {
            "file_info": {"name": "file2.exe", "file_type": "PE32"}
        }
    }
    table = _build_summary_table_small(results)
    assert table.title == "Analysis Summary"


def test_build_summary_table_small_limit():
    """Test small summary table only shows first 10 files"""
    results = {f"file{i}.exe": {"file_info": {"name": f"file{i}.exe"}} for i in range(15)}
    table = _build_summary_table_small(results)
    assert table.row_count == 10


def test_build_summary_table_large():
    """Test building large summary table"""
    results = {
        "file1.exe": {
            "file_info": {"md5": "abc123", "file_type": "PE32"}
        }
    }
    table = _build_summary_table_large(results)
    assert table.title == "Analysis Summary"


def test_show_summary_table_small(capsys):
    """Test showing summary table for small result set"""
    results = {f"file{i}.exe": {"file_info": {"name": f"file{i}.exe"}} for i in range(5)}
    _show_summary_table(results)
    captured = capsys.readouterr()
    assert "Analysis Summary" in captured.out


def test_show_summary_table_large(capsys):
    """Test showing summary table for large result set"""
    results = {f"file{i}.exe": {"file_info": {"name": f"file{i}.exe"}} for i in range(15)}
    _show_summary_table(results)
    captured = capsys.readouterr()
    assert "Analysis Summary" in captured.out
    assert "more files" in captured.out


def test_create_batch_summary_csv_only(tmp_path):
    """Test creating batch summary with CSV only"""
    results = {"file1.exe": {"file_info": {"name": "file1.exe"}}}
    failed = []
    
    output_path = tmp_path / "output.csv"
    output_filename = create_batch_summary(results, failed, output_path, False, True)
    assert output_filename is not None
    assert ".csv" in output_filename


def test_create_batch_summary_json_only(tmp_path):
    """Test creating batch summary with JSON only"""
    results = {"file1.exe": {"file_info": {"name": "file1.exe"}}}
    failed = []
    
    output_filename = create_batch_summary(results, failed, tmp_path, True, False)
    assert output_filename is not None
    assert "r2inspect_batch_" in output_filename


def test_create_batch_summary_both_formats(tmp_path):
    """Test creating batch summary with both CSV and JSON"""
    results = {"file1.exe": {"file_info": {"name": "file1.exe"}}}
    failed = []
    
    output_filename = create_batch_summary(results, failed, tmp_path, True, True)
    assert output_filename is not None
    assert ".csv" in output_filename
    assert "JSON" in output_filename


def test_create_batch_summary_no_formats(tmp_path):
    """Test creating batch summary with no output formats"""
    results = {"file1.exe": {"file_info": {"name": "file1.exe"}}}
    failed = []
    
    output_filename = create_batch_summary(results, failed, tmp_path, False, False)
    assert output_filename is None


def test_find_files_to_process_auto_detect(tmp_path):
    """Test finding files with auto-detect enabled"""
    (tmp_path / "test.exe").write_bytes(b"MZ" + b"\x00" * 100)
    
    files = find_files_to_process(tmp_path, True, None, False, False, quiet=True)
    assert isinstance(files, list)


def test_find_files_to_process_with_extensions(tmp_path):
    """Test finding files by extensions"""
    (tmp_path / "file1.exe").touch()
    (tmp_path / "file2.dll").touch()
    
    files = find_files_to_process(tmp_path, False, "exe,dll", False, False, quiet=True)
    assert len(files) == 2


def test_find_files_to_process_no_files(tmp_path):
    """Test finding files when directory is empty"""
    files = find_files_to_process(tmp_path, False, "exe", False, False, quiet=True)
    assert len(files) == 0


def test_prepare_batch_run_success(tmp_path):
    """Test successful batch run preparation"""
    (tmp_path / "file1.exe").touch()
    
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
        threads=1
    )
    assert result is not None
    files, output_path = result
    assert len(files) > 0


def test_prepare_batch_run_no_files(tmp_path):
    """Test batch run preparation with no files"""
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
        threads=1
    )
    assert result is None
