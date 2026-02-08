from pathlib import Path

import pytest

from r2inspect.cli import batch_output, batch_processing, display, interactive
from r2inspect.cli.analysis_runner import output_csv_results, output_json_results
from r2inspect.utils.output import OutputFormatter


class _SimpleInspector:
    def __init__(self, strings=None, file_info=None):
        self._strings = strings or []
        self._file_info = file_info or {}

    def get_strings(self):
        return self._strings

    def get_file_info(self):
        return self._file_info


def test_display_results_renders_core_sections(capsys):
    results = {
        "file_info": {
            "size": 1,
            "path": "/tmp/sample.bin",
            "name": "sample.bin",
            "mime_type": "application/octet-stream",
            "file_type": "data",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "sha512": "sha512",
            "enhanced_detection": {
                "file_format": "PE",
                "format_category": "Executable",
                "architecture": "x86",
                "bits": 32,
                "endianness": "Little",
                "confidence": 0.95,
            },
            "threat_level": "Low",
        },
        "pe_info": {"imphash": "abcd", "sections": [".text", ".data"]},
        "security": {"nx": True, "aslr": False},
        "ssdeep": {"available": True, "hash_value": "3:abc", "method_used": "native"},
        "tlsh": {"available": False, "error": "not installed"},
        "telfhash": {
            "available": True,
            "is_elf": True,
            "telfhash": "telfhash",
            "symbol_count": 6,
            "filtered_symbols": 1,
            "symbols_used": ["a", "b", "c", "d", "e", "f"],
        },
        "rich_header": {
            "available": True,
            "is_pe": True,
            "xor_key": 1,
            "checksum": 2,
            "richpe_hash": "rich",
            "compilers": [{"compiler_name": "MSVC", "count": 1, "build_number": 100}],
        },
        "binbloom": {
            "available": True,
            "total_functions": 1,
            "analyzed_functions": 1,
            "capacity": 128,
            "error_rate": 0.01,
            "unique_signatures": 1,
            "function_signatures": {
                "f1": {
                    "signature": "sig1",
                    "instruction_count": 3,
                    "unique_instructions": 2,
                }
            },
        },
        "functions": {"total_functions": 2, "machoc_hashes": {"f1": "h1", "f2": "h1"}},
        "indicators": [{"type": "packer", "description": "packed", "severity": "high"}],
    }

    display.display_results(results)
    out = capsys.readouterr().out
    assert "File Information" in out
    assert "PE Analysis" in out
    assert "Security Features" in out
    assert "SSDeep Fuzzy Hash" in out
    assert "TLSH Locality Sensitive Hash" in out
    assert "Telfhash" in out
    assert "Rich Header" in out
    assert "Binbloom" in out
    assert "Suspicious Indicators" in out


def test_interactive_helpers_output(capsys):
    inspector = _SimpleInspector(strings=["one", "two"], file_info={"name": "sample.bin"})
    interactive.show_strings_only(inspector)
    interactive._print_help()
    formatter = OutputFormatter({})
    interactive._show_info_table("File Information", {"name": "sample.bin"}, formatter)
    out = capsys.readouterr().out
    assert "one" in out
    assert "Available commands" in out
    assert "File Information" in out


def test_output_json_csv_results_error_on_directory(tmp_path):
    formatter = OutputFormatter({"file_info": {"name": "sample"}})
    output_dir = tmp_path / "outdir"
    output_dir.mkdir()

    with pytest.raises(IsADirectoryError):
        output_json_results(formatter, str(output_dir))
    with pytest.raises(IsADirectoryError):
        output_csv_results(formatter, str(output_dir))


def test_batch_output_summary_and_stats(tmp_path):
    all_results = {
        "a.bin": {
            "file_info": {"file_type": "PE"},
            "packer_info": {"detected": True, "name": "UPX"},
        },
        "b.bin": {
            "file_info": {"file_type": "ELF"},
            "compiler": {"detected": True, "compiler": "gcc"},
        },
    }
    failed = [("c.bin", "error")]
    timestamp = "20250101_000000"

    summary_name = batch_output.create_json_batch_summary(all_results, failed, tmp_path, timestamp)
    summary_file = tmp_path / f"r2inspect_batch_{timestamp}.json"
    assert summary_file.exists()
    assert "r2inspect_batch" in summary_name

    summary = summary_file.read_text(encoding="utf-8")
    assert '"total_files": 3' in summary
    assert '"successful_analyses": 2' in summary
    assert '"failed_analyses": 1' in summary

    stats = batch_output.collect_batch_statistics(all_results)
    assert stats["file_types"]["PE"] == 1
    assert stats["file_types"]["ELF"] == 1
    assert stats["compilers"]["gcc"] == 1
    assert stats["packers_detected"][0]["packer"] == "UPX"


def test_find_files_to_process_with_extensions(tmp_path, capsys):
    (tmp_path / "a.exe").write_text("x")
    (tmp_path / "b.dll").write_text("x")
    files = batch_processing.find_files_to_process(
        batch_path=tmp_path,
        auto_detect=False,
        extensions="exe,dll",
        recursive=False,
        verbose=False,
        quiet=False,
    )
    out = capsys.readouterr().out
    assert "extensions: exe,dll" in out
    names = sorted([f.name for f in files])
    assert names == ["a.exe", "b.dll"]
