from __future__ import annotations

from pathlib import Path

from r2inspect.cli import batch_output


class RuleObj:
    def __init__(self, rule: str) -> None:
        self.rule = rule


def _sample_result(file_type: str = "PE32+ executable, 7 sections") -> dict:
    return {
        "file_info": {
            "name": "sample.exe",
            "file_type": file_type,
            "md5": "deadbeef",
        },
        "pe_info": {"compile_time": "2026"},
        "compiler": {"detected": True, "compiler": "MSVC", "version": "1"},
        "yara_matches": [{"rule": "r1"}, RuleObj("r2"), "r3"],
    }


def test_find_files_by_extensions_recursive(tmp_path: Path) -> None:
    (tmp_path / "a.bin").write_bytes(b"X")
    subdir = tmp_path / "sub"
    subdir.mkdir()
    (subdir / "b.bin").write_bytes(b"Y")

    files_nonrec = batch_output.find_files_by_extensions(tmp_path, "bin", recursive=False)
    assert (tmp_path / "a.bin") in files_nonrec
    assert (subdir / "b.bin") not in files_nonrec

    files_rec = batch_output.find_files_by_extensions(tmp_path, "bin", recursive=True)
    assert (subdir / "b.bin") in files_rec


def test_find_files_to_process_and_no_files_message(tmp_path: Path) -> None:
    # extensions None returns empty list
    files = batch_output.find_files_to_process(
        tmp_path, auto_detect=False, extensions=None, recursive=False, verbose=False
    )
    assert files == []

    # auto-detect path (may return empty when magic missing)
    batch_output.find_files_to_process(
        tmp_path, auto_detect=True, extensions=None, recursive=False, verbose=False, quiet=True
    )
    batch_output.find_files_to_process(
        tmp_path, auto_detect=True, extensions=None, recursive=False, verbose=False, quiet=False
    )

    # display messages
    batch_output.display_no_files_message(auto_detect=True, extensions=None)
    batch_output.display_no_files_message(auto_detect=False, extensions="exe")


def test_setup_batch_output_directory_variants(tmp_path: Path) -> None:
    csv_file = tmp_path / "out.csv"
    out = batch_output.setup_batch_output_directory(
        str(csv_file), output_json=False, output_csv=True
    )
    assert out == csv_file

    json_file = tmp_path / "nested" / "out.json"
    out2 = batch_output.setup_batch_output_directory(
        str(json_file), output_json=True, output_csv=False
    )
    assert out2 == json_file
    assert json_file.parent.exists()

    out3 = batch_output.setup_batch_output_directory(None, output_json=True, output_csv=False)
    assert out3.name == "output"

    out4 = batch_output.setup_batch_output_directory(None, output_json=False, output_csv=False)
    assert out4.name == "r2inspect_batch_results"


def test_create_batch_summary_cases(tmp_path: Path) -> None:
    results = {"a": _sample_result()}
    failed = [("b", "err")]

    # CSV only
    out = batch_output.create_batch_summary(
        results, failed, tmp_path, output_json=False, output_csv=True
    )
    assert out is not None

    # JSON + CSV with output_path as csv file
    csv_path = tmp_path / "summary.csv"
    out2 = batch_output.create_batch_summary(
        results, failed, csv_path, output_json=True, output_csv=True
    )
    assert "individual JSONs" in (out2 or "")

    # JSON + CSV with output_path as directory
    out_dir = tmp_path / "outdir"
    out_dir.mkdir()
    out2b = batch_output.create_batch_summary(
        results, failed, out_dir, output_json=True, output_csv=True
    )
    assert "individual JSONs" in (out2b or "")

    # JSON only
    out3 = batch_output.create_batch_summary(
        results, failed, tmp_path, output_json=True, output_csv=False
    )
    assert out3 is not None


def test_summary_helpers_and_rows(tmp_path: Path) -> None:
    # simplify file types
    assert batch_output._simplify_file_type("PE32+ executable, 7 sections") == "PE32+ (x64)"
    assert batch_output._simplify_file_type("PE32 executable, 2 sections") == "PE32 (x86)"
    assert batch_output._simplify_file_type("ELF 64-bit") == "ELF"
    assert batch_output._simplify_file_type("Mach-O 64-bit") == "Mach-O"
    assert batch_output._simplify_file_type("") == "Unknown"

    # compile time
    assert batch_output._extract_compile_time({"pe_info": {"compile_time": "x"}}) == "x"
    assert batch_output._extract_compile_time({}) == "N/A"

    # compiler name
    compiler = {"compiler": {"detected": True, "compiler": "GCC", "version": "12"}}
    assert batch_output._compiler_name(compiler) == "GCC 12"
    assert batch_output._compiler_name({}) == "Unknown"

    # yara matches
    assert batch_output._collect_yara_matches({"yara_matches": "bad"}) == "None"
    matches = batch_output._collect_yara_matches(_sample_result())
    assert "r1" in matches and "r2" in matches and "r3" in matches

    # row builders
    ok_small = batch_output._build_small_row("k", _sample_result())
    assert ok_small[0] == "sample.exe"
    ok_large = batch_output._build_large_row("k", _sample_result())
    assert ok_large[0] == "deadbeef"

    bad_small = batch_output._build_small_row("k", object())
    bad_large = batch_output._build_large_row("k", object())
    assert bad_small[1] == "Error"
    assert bad_large[1] == "Error"

    # summary table for >10 entries
    many = {str(i): _sample_result() for i in range(12)}
    batch_output._show_summary_table(many)

    # summary table for <=10 entries
    batch_output._show_summary_table({"a": _sample_result()})


def test_collect_batch_statistics_and_updates() -> None:
    stats = {
        "packers_detected": [],
        "crypto_patterns": [],
        "suspicious_indicators": [],
        "file_types": {},
        "architectures": {},
        "compilers": {},
    }
    result = {
        "packer_info": {"detected": True, "name": "UPX"},
        "crypto_info": ["AES"],
        "indicators": [{"type": "Anti", "description": "x"}],
        "file_info": {"file_type": "PE", "architecture": "x86"},
        "compiler": {"detected": True, "compiler": "MSVC"},
    }
    batch_output.update_packer_stats(stats, "f", result)
    batch_output.update_crypto_stats(stats, "f", result)
    batch_output.update_indicator_stats(stats, "f", result)
    batch_output.update_file_type_stats(stats, result)
    batch_output.update_compiler_stats(stats, result)
    assert stats["packers_detected"]
    assert stats["crypto_patterns"]
    assert stats["suspicious_indicators"]
    assert stats["file_types"]
    assert stats["architectures"]
    assert stats["compilers"]

    collected = batch_output.collect_batch_statistics({"f": result})
    assert collected["packers_detected"]


def test_prepare_and_run_batch_analysis(tmp_path: Path) -> None:
    # prepare batch run with no files
    prepared_none = batch_output._prepare_batch_run(
        tmp_path,
        auto_detect=False,
        extensions="exe",
        recursive=False,
        verbose=False,
        quiet=False,
        output_dir=None,
        output_json=False,
        output_csv=False,
        threads=1,
    )
    assert prepared_none is None

    # setup with actual file
    sample_src = Path("samples/fixtures/hello_pe.exe")
    sample_dst = tmp_path / "hello_pe.exe"
    sample_dst.write_bytes(sample_src.read_bytes())

    prepared = batch_output._prepare_batch_run(
        tmp_path,
        auto_detect=False,
        extensions="exe",
        recursive=False,
        verbose=False,
        quiet=False,
        output_dir=str(tmp_path / "out"),
        output_json=False,
        output_csv=False,
        threads=1,
    )
    assert prepared is not None

    # cover logging configuration
    batch_output._configure_batch_logging(verbose=False, quiet=True)

    # run batch analysis (single file, no json/csv)
    from r2inspect.config import Config

    config_obj = Config(str(tmp_path / "config.json"))
    batch_output.run_batch_analysis(
        batch_dir=str(tmp_path),
        options={},
        output_json=False,
        output_csv=False,
        output_dir=str(tmp_path / "out"),
        recursive=False,
        extensions="exe",
        verbose=False,
        config_obj=config_obj,
        auto_detect=False,
        threads=1,
        quiet=True,
    )

    # run with empty dir to hit early return
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    batch_output.run_batch_analysis(
        batch_dir=str(empty_dir),
        options={},
        output_json=False,
        output_csv=False,
        output_dir=str(tmp_path / "out2"),
        recursive=False,
        extensions="exe",
        verbose=False,
        config_obj=config_obj,
        auto_detect=False,
        threads=1,
        quiet=True,
    )
