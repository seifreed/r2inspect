from __future__ import annotations

from pathlib import Path

from r2inspect.cli import batch_output


class _YaraObj:
    rule = "obj_rule"


def test_batch_output_helpers_and_summary(tmp_path: Path) -> None:
    all_results = {
        "a.bin": {
            "packer_info": {"detected": True, "name": "UPX"},
            "crypto_info": ["AES"],
            "indicators": [{"type": "x"}],
            "file_info": {
                "file_type": "PE32+ executable, 3 sections",
                "architecture": "x86-64",
                "md5": "m",
                "name": "a.bin",
            },
            "compiler": {"detected": True, "compiler": "GCC", "version": "1.0"},
            "yara_matches": [{"rule": "r1"}, _YaraObj(), "r3"],
            "pe_info": {"compile_time": "now"},
        }
    }

    stats = batch_output.collect_batch_statistics(all_results)
    assert stats["packers_detected"]
    assert stats["crypto_patterns"]
    assert stats["suspicious_indicators"]

    csv_path, _ = batch_output.determine_csv_file_path(tmp_path, "t")
    assert csv_path.parent == tmp_path
    csv_path, csv_name = batch_output.determine_csv_file_path(tmp_path / "out.csv", "t")
    assert csv_name == "out.csv"

    output_dir = tmp_path / "out"
    output_dir.mkdir()
    output_name = batch_output.create_batch_summary(
        all_results, [], output_dir, output_json=False, output_csv=True
    )
    assert output_name is not None

    output_name = batch_output.create_batch_summary(
        all_results, [], output_dir, output_json=True, output_csv=False
    )
    assert output_name is not None

    output_name = batch_output.create_batch_summary(
        all_results, [], output_dir, output_json=True, output_csv=True
    )
    assert output_name is not None

    output_name = batch_output.create_batch_summary(
        all_results, [], tmp_path / "results.csv", output_json=True, output_csv=True
    )
    assert output_name is not None

    out_dir = batch_output.setup_batch_output_directory(str(tmp_path / "dir"), False, False)
    assert out_dir.exists()
    out_file = batch_output.setup_batch_output_directory(
        str(tmp_path / "nested" / "out.csv"), True, False
    )
    assert out_file.parent.exists()
    default_dir = batch_output.setup_batch_output_directory(None, True, False)
    assert default_dir.name == "output"


def test_batch_output_file_search_and_tables(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("x", encoding="utf-8")
    (tmp_path / "b.bin").write_text("x", encoding="utf-8")

    files = batch_output.find_files_by_extensions(tmp_path, "txt,bin", recursive=False)
    assert len(files) == 2

    assert batch_output.find_files_to_process(tmp_path, False, None, False, False) == []
    batch_output.find_files_to_process(tmp_path, True, None, False, False, quiet=True)

    batch_output.display_no_files_message(auto_detect=True, extensions=None)
    batch_output.display_no_files_message(auto_detect=False, extensions="exe")

    big_results = {f"{i}.bin": {"file_info": {"name": f"{i}.bin"}} for i in range(12)}
    batch_output._show_summary_table(big_results)

    assert batch_output._collect_yara_matches({"yara_matches": "bad"}) == "None"
    assert batch_output._collect_yara_matches({"yara_matches": []}) == "None"

    assert batch_output._build_small_row("x", None)[1] == "Error"
    assert batch_output._build_large_row("x", None)[1] == "Error"
