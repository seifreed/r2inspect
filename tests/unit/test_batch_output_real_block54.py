from __future__ import annotations

from pathlib import Path

from r2inspect.cli.batch_output import (
    _build_summary_table_large,
    _build_summary_table_small,
    _collect_yara_matches,
    _compiler_name,
    _extract_compile_time,
    _show_summary_table,
    _simplify_file_type,
    create_batch_summary,
)


def _result(name: str) -> dict:
    return {
        "file_info": {
            "name": name,
            "file_type": "PE32+ executable, 18 sections",
            "md5": "deadbeef",
        },
        "pe_info": {"compile_time": "2026-01-30"},
        "compiler": {"detected": True, "compiler": "GCC", "version": "15.2.0"},
        "yara_matches": [{"rule": "test_rule"}],
    }


def test_summary_helpers(tmp_path: Path, capsys):
    result = _result("hello_pe.exe")

    assert _simplify_file_type("PE32+ executable, 18 sections") == "PE32+ (x64)"
    assert _extract_compile_time(result) == "2026-01-30"
    assert _compiler_name(result).startswith("GCC")
    assert _collect_yara_matches(result) == "test_rule"

    all_results = {"hello_pe.exe": result}
    _show_summary_table(all_results)
    assert "Analysis Summary" in capsys.readouterr().out

    # Build tables directly
    assert _build_summary_table_large(all_results).title == "Analysis Summary"

    # Small table path when >10 results
    large_results = {f"f{i}": _result(f"f{i}") for i in range(12)}
    _show_summary_table(large_results)
    out = capsys.readouterr().out
    assert "Analysis Summary" in out


def test_create_batch_summary_paths(tmp_path: Path):
    all_results = {"hello_pe.exe": _result("hello_pe.exe")}
    failed_files = []

    # JSON only
    out_json = create_batch_summary(all_results, failed_files, tmp_path, True, False)
    assert out_json is not None

    # CSV only
    out_csv = create_batch_summary(all_results, failed_files, tmp_path, False, True)
    assert out_csv is not None

    # Both JSON and CSV
    out_both = create_batch_summary(all_results, failed_files, tmp_path, True, True)
    assert out_both is not None
