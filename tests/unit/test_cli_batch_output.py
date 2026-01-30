from pathlib import Path

from r2inspect.cli.batch_output import (
    collect_batch_statistics,
    determine_csv_file_path,
    find_files_by_extensions,
    get_csv_fieldnames,
    setup_batch_output_directory,
    write_csv_results,
)


def test_get_csv_fieldnames_contains_expected():
    fields = get_csv_fieldnames()
    assert "name" in fields
    assert "sha256" in fields


def test_determine_csv_file_path(tmp_path):
    path = tmp_path / "results.csv"
    csv_file, name = determine_csv_file_path(path, "ts")
    assert csv_file == path
    assert name == "results.csv"

    dir_path = tmp_path / "out"
    csv_file, name = determine_csv_file_path(dir_path, "ts")
    assert csv_file.name.startswith("r2inspect_")
    assert name.endswith(".csv")


def test_setup_batch_output_directory(tmp_path):
    output = setup_batch_output_directory(str(tmp_path / "out"), True, False)
    assert output.exists()


def test_collect_batch_statistics():
    results = {
        "file1": {
            "file_info": {"file_type": "PE", "architecture": "x86"},
            "indicators": [{"type": "Suspicious"}],
        }
    }
    stats = collect_batch_statistics(results)
    assert stats["file_types"]["PE"] == 1
    assert stats["architectures"]["x86"] == 1


def test_write_csv_results(tmp_path):
    results = {"file1": {"file_info": {"name": "file1", "size": 1}}}
    csv_file = tmp_path / "out.csv"
    write_csv_results(csv_file, results)
    content = csv_file.read_text()
    assert content.startswith("name,size")


def test_find_files_by_extensions(tmp_path):
    (tmp_path / "a.exe").write_text("x")
    files = find_files_by_extensions(tmp_path, "exe", recursive=False)
    assert len(files) == 1
