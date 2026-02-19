"""Tests for cli/batch_output.py - edge cases and uncovered paths."""

from pathlib import Path
from unittest.mock import Mock, patch

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
    find_files_to_process,
    get_csv_fieldnames,
    setup_batch_output_directory,
    write_csv_results,
)


def test_simplify_file_type_pe32():
    """Test file type simplification for PE32."""
    file_type = "PE32 executable, 6 sections"
    result = _simplify_file_type(file_type)
    assert result == "PE32 (x86)"


def test_simplify_file_type_pe32_plus():
    """Test file type simplification for PE32+."""
    file_type = "PE32+ executable, 8 sections"
    result = _simplify_file_type(file_type)
    assert result == "PE32+ (x64)"


def test_simplify_file_type_elf():
    """Test file type simplification for ELF."""
    file_type = "ELF 64-bit executable"
    result = _simplify_file_type(file_type)
    assert result == "ELF"


def test_simplify_file_type_macho():
    """Test file type simplification for Mach-O."""
    file_type = "Mach-O 64-bit executable"
    result = _simplify_file_type(file_type)
    assert result == "Mach-O"


def test_simplify_file_type_unknown():
    """Test file type simplification for unknown."""
    file_type = "Unknown format"
    result = _simplify_file_type(file_type)
    assert result == "Unknown format"


def test_simplify_file_type_empty():
    """Test file type simplification for empty string."""
    file_type = ""
    result = _simplify_file_type(file_type)
    assert result == "Unknown"


def test_extract_compile_time_pe():
    """Test compile time extraction from PE info."""
    result = {
        "pe_info": {"compile_time": "2024-01-01 12:00:00"},
    }
    compile_time = _extract_compile_time(result)
    assert compile_time == "2024-01-01 12:00:00"


def test_extract_compile_time_elf():
    """Test compile time extraction from ELF info."""
    result = {
        "elf_info": {"compile_time": "2024-02-01 14:00:00"},
    }
    compile_time = _extract_compile_time(result)
    assert compile_time == "2024-02-01 14:00:00"


def test_extract_compile_time_macho():
    """Test compile time extraction from Mach-O info."""
    result = {
        "macho_info": {"compile_time": "2024-03-01 16:00:00"},
    }
    compile_time = _extract_compile_time(result)
    assert compile_time == "2024-03-01 16:00:00"


def test_extract_compile_time_not_available():
    """Test compile time extraction when not available."""
    result = {"file_info": {}}
    compile_time = _extract_compile_time(result)
    assert compile_time == "N/A"


def test_compiler_name_detected():
    """Test compiler name extraction when detected."""
    result = {
        "compiler": {
            "detected": True,
            "compiler": "MSVC",
            "version": "19.0",
        }
    }
    name = _compiler_name(result)
    assert name == "MSVC 19.0"


def test_compiler_name_detected_no_version():
    """Test compiler name extraction without version."""
    result = {
        "compiler": {
            "detected": True,
            "compiler": "GCC",
            "version": "Unknown",
        }
    }
    name = _compiler_name(result)
    assert name == "GCC"


def test_compiler_name_not_detected():
    """Test compiler name when not detected."""
    result = {
        "compiler": {
            "detected": False,
        }
    }
    name = _compiler_name(result)
    assert name == "Unknown"


def test_compiler_name_missing():
    """Test compiler name when compiler info missing."""
    result = {}
    name = _compiler_name(result)
    assert name == "Unknown"


def test_collect_yara_matches_list_dicts():
    """Test YARA matches collection from list of dicts."""
    result = {
        "yara_matches": [
            {"rule": "Malware.Generic"},
            {"rule": "Trojan.Downloader"},
        ]
    }
    matches = _collect_yara_matches(result)
    assert "Malware.Generic" in matches
    assert "Trojan.Downloader" in matches


def test_collect_yara_matches_objects():
    """Test YARA matches collection from objects with rule attribute."""
    class YaraMatch:
        def __init__(self, rule):
            self.rule = rule
    
    result = {
        "yara_matches": [
            YaraMatch("Rule1"),
            YaraMatch("Rule2"),
        ]
    }
    matches = _collect_yara_matches(result)
    assert "Rule1" in matches
    assert "Rule2" in matches


def test_collect_yara_matches_none():
    """Test YARA matches when none exist."""
    result = {"yara_matches": []}
    matches = _collect_yara_matches(result)
    assert matches == "None"


def test_collect_yara_matches_not_list():
    """Test YARA matches when not a list."""
    result = {"yara_matches": "invalid"}
    matches = _collect_yara_matches(result)
    assert matches == "None"


def test_build_small_row():
    """Test building small table row."""
    result = {
        "file_info": {
            "name": "malware.exe",
            "file_type": "PE32 executable, 6 sections",
        },
        "pe_info": {
            "compile_time": "2024-01-01",
        },
        "compiler": {
            "detected": True,
            "compiler": "MSVC",
            "version": "19.0",
        },
    }
    filename, file_type, compiler, compile_time = _build_small_row("file1", result)
    
    assert filename == "malware.exe"
    assert file_type == "PE32 (x86)"
    assert compiler == "MSVC 19.0"
    assert compile_time == "2024-01-01"


def test_build_small_row_error():
    """Test building small row with error."""
    result = None  # Will cause error
    filename, file_type, compiler, compile_time = _build_small_row("file1", result)
    
    assert filename == "file1"
    assert file_type == "Error"
    assert compiler == "Error"


def test_build_large_row():
    """Test building large table row."""
    result = {
        "file_info": {
            "md5": "abc123",
            "file_type": "PE32+ executable",
        },
        "pe_info": {
            "compile_time": "2024-01-01",
        },
        "compiler": {
            "detected": True,
            "compiler": "GCC",
        },
        "yara_matches": [{"rule": "TestRule"}],
    }
    md5, file_type, compiler, compile_time, yara = _build_large_row("file1", result)
    
    assert md5 == "abc123"
    assert file_type == "PE32+ (x64)"
    assert "GCC" in compiler
    assert compile_time == "2024-01-01"
    assert "TestRule" in yara


def test_build_large_row_error():
    """Test building large row with error."""
    result = None  # Will cause error
    md5, file_type, compiler, compile_time, yara = _build_large_row("file1", result)
    
    assert md5 == "file1"
    assert file_type == "Error"


def test_build_summary_table_small():
    """Test building small summary table."""
    results = {
        f"file{i}": {
            "file_info": {
                "name": f"file{i}.exe",
                "file_type": "PE32",
            }
        }
        for i in range(15)
    }
    
    table = _build_summary_table_small(results)
    
    assert table is not None
    assert table.title == "Analysis Summary"


def test_build_summary_table_large():
    """Test building large summary table."""
    results = {
        "file1": {
            "file_info": {
                "md5": "abc123",
                "file_type": "PE32",
            }
        }
    }
    
    table = _build_summary_table_large(results)
    
    assert table is not None
    assert table.title == "Analysis Summary"


def test_show_summary_table_small():
    """Test showing summary table for many files."""
    results = {
        f"file{i}": {
            "file_info": {
                "name": f"file{i}.exe",
                "file_type": "PE32",
            }
        }
        for i in range(15)
    }
    
    with patch("r2inspect.cli.batch_output.console") as mock_console:
        _show_summary_table(results)
        
        assert mock_console.print.call_count >= 1


def test_show_summary_table_large():
    """Test showing summary table for few files."""
    results = {
        "file1": {
            "file_info": {
                "md5": "abc123",
                "file_type": "PE32",
            }
        }
    }
    
    with patch("r2inspect.cli.batch_output.console") as mock_console:
        _show_summary_table(results)
        
        assert mock_console.print.call_count >= 1


def test_display_no_files_message_auto_detect():
    """Test no files message with auto-detect."""
    with patch("r2inspect.cli.batch_output.console") as mock_console:
        display_no_files_message(auto_detect=True, extensions=None)
        
        assert mock_console.print.call_count >= 1


def test_display_no_files_message_extensions():
    """Test no files message with extensions."""
    with patch("r2inspect.cli.batch_output.console") as mock_console:
        display_no_files_message(auto_detect=False, extensions="exe,dll")
        
        assert mock_console.print.call_count >= 1


def test_setup_batch_output_directory_csv_file(tmp_path):
    """Test setup with CSV filename."""
    csv_file = tmp_path / "results.csv"
    output = setup_batch_output_directory(str(csv_file), False, True)
    
    assert output.parent.exists()


def test_setup_batch_output_directory_json_file(tmp_path):
    """Test setup with JSON filename."""
    json_file = tmp_path / "results.json"
    output = setup_batch_output_directory(str(json_file), True, False)
    
    assert output.parent.exists()


def test_setup_batch_output_directory_default():
    """Test setup with default directory."""
    with patch("r2inspect.cli.batch_output.Path") as mock_path:
        mock_instance = Mock()
        mock_path.return_value = mock_instance
        
        output = setup_batch_output_directory(None, True, False)
        
        assert output is not None


def test_configure_batch_logging_verbose():
    """Test batch logging configuration with verbose."""
    _configure_batch_logging(verbose=True, quiet=False)


def test_configure_batch_logging_quiet():
    """Test batch logging configuration with quiet."""
    _configure_batch_logging(verbose=False, quiet=True)


def test_init_batch_results():
    """Test batch results initialization."""
    results, failed = _init_batch_results()
    
    assert results == {}
    assert failed == []


def test_prepare_batch_run(tmp_path):
    """Test batch run preparation."""
    (tmp_path / "test.exe").write_bytes(b"MZ")
    
    with patch("r2inspect.cli.batch_output.find_files_to_process") as mock_find:
        mock_find.return_value = [tmp_path / "test.exe"]
        
        result = _prepare_batch_run(
            batch_path=tmp_path,
            auto_detect=True,
            extensions=None,
            recursive=False,
            verbose=False,
            quiet=True,
            output_dir=None,
            output_json=True,
            output_csv=False,
            threads=4,
        )
        
        assert result is not None
        files, output_path = result
        assert len(files) == 1


def test_prepare_batch_run_no_files(tmp_path):
    """Test batch run preparation with no files."""
    with patch("r2inspect.cli.batch_output.find_files_to_process") as mock_find:
        mock_find.return_value = []
        
        result = _prepare_batch_run(
            batch_path=tmp_path,
            auto_detect=True,
            extensions=None,
            recursive=False,
            verbose=False,
            quiet=False,
            output_dir=None,
            output_json=False,
            output_csv=False,
            threads=4,
        )
        
        assert result is None


def test_find_files_to_process_auto_detect(tmp_path):
    """Test finding files with auto-detect."""
    with patch("r2inspect.cli.batch_processing.find_executable_files_by_magic") as mock_find:
        mock_find.return_value = [tmp_path / "test.exe"]
        
        files = find_files_to_process(
            batch_path=tmp_path,
            auto_detect=True,
            extensions=None,
            recursive=False,
            verbose=False,
            quiet=True,
        )
        
        assert len(files) == 1


def test_find_files_to_process_extensions(tmp_path):
    """Test finding files with extensions."""
    with patch("r2inspect.cli.batch_output.core_find_files_by_extensions") as mock_find:
        mock_find.return_value = [tmp_path / "test.exe"]
        
        files = find_files_to_process(
            batch_path=tmp_path,
            auto_detect=False,
            extensions="exe,dll",
            recursive=False,
            verbose=False,
            quiet=True,
        )
        
        assert len(files) == 1


def test_find_files_to_process_no_extensions(tmp_path):
    """Test finding files without extensions."""
    files = find_files_to_process(
        batch_path=tmp_path,
        auto_detect=False,
        extensions=None,
        recursive=False,
        verbose=False,
        quiet=True,
    )
    
    assert files == []


def test_create_batch_summary_csv_only(tmp_path):
    """Test creating batch summary with CSV only."""
    results = {
        "file1": {
            "file_info": {"name": "file1.exe"},
        }
    }
    failed = []
    
    output_file = create_batch_summary(
        all_results=results,
        failed_files=failed,
        output_path=tmp_path / "results.csv",
        output_json=False,
        output_csv=True,
    )
    
    assert output_file is not None


def test_create_batch_summary_json_csv(tmp_path):
    """Test creating batch summary with JSON and CSV."""
    results = {
        "file1": {
            "file_info": {"name": "file1.exe"},
        }
    }
    failed = []
    
    output_file = create_batch_summary(
        all_results=results,
        failed_files=failed,
        output_path=tmp_path / "results.csv",
        output_json=True,
        output_csv=True,
    )
    
    assert output_file is not None
    assert "individual JSONs" in output_file


def test_create_batch_summary_json_only(tmp_path):
    """Test creating batch summary with JSON only."""
    results = {
        "file1": {
            "file_info": {"name": "file1.exe"},
        }
    }
    failed = [("file2.exe", "Error occurred")]
    
    output_file = create_batch_summary(
        all_results=results,
        failed_files=failed,
        output_path=tmp_path,
        output_json=True,
        output_csv=False,
    )
    
    assert output_file is not None


def test_create_json_batch_summary(tmp_path):
    """Test creating JSON batch summary file."""
    results = {
        "file1": {
            "file_info": {"name": "file1.exe"},
        }
    }
    failed = [("file2.exe", "Failed to analyze")]
    
    output_file = create_json_batch_summary(
        all_results=results,
        failed_files=failed,
        output_path=tmp_path,
        timestamp="20240101_120000",
    )
    
    assert output_file is not None
    assert "individual JSONs" in output_file


def test_get_csv_fieldnames():
    """Test getting CSV fieldnames."""
    fields = get_csv_fieldnames()
    
    assert "name" in fields
    assert "md5" in fields
    assert "sha256" in fields
    assert "file_type" in fields


def test_write_csv_results(tmp_path):
    """Test writing CSV results."""
    results = {
        "file1": {
            "file_info": {"name": "file1.exe", "size": 1024},
        }
    }
    
    csv_file = tmp_path / "results.csv"
    write_csv_results(csv_file, results)
    
    assert csv_file.exists()
    content = csv_file.read_text()
    assert "name" in content


def test_determine_csv_file_path_with_csv_file(tmp_path):
    """Test determine CSV path with CSV file."""
    csv_path = tmp_path / "custom.csv"
    
    csv_file, name = determine_csv_file_path(csv_path, "timestamp")
    
    assert csv_file == csv_path
    assert name == "custom.csv"


def test_determine_csv_file_path_with_directory(tmp_path):
    """Test determine CSV path with directory."""
    dir_path = tmp_path / "output"
    
    csv_file, name = determine_csv_file_path(dir_path, "20240101_120000")
    
    assert csv_file.parent == dir_path
    assert name.endswith(".csv")
    assert "r2inspect_" in name
