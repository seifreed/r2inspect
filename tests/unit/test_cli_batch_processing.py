from pathlib import Path

from r2inspect.cli.batch_processing import (
    determine_csv_file_path,
    find_files_by_extensions,
    is_elf_executable,
    is_macho_executable,
    is_pe_executable,
    is_script_executable,
    setup_batch_mode,
    setup_single_file_output,
)


def test_executable_signature_checks():
    assert is_elf_executable(b"\x7fELF" + b"\x00" * 10) is True
    assert is_macho_executable(b"\xfe\xed\xfa\xce" + b"\x00") is True
    assert is_script_executable(b"#!" + b"/bin/sh") is True

    # PE check with minimal header
    header = b"MZ" + b"\x00" * 58 + (64).to_bytes(4, "little")

    class FakeHandle:
        def __init__(self):
            self.seeked = 0

        def seek(self, pos):
            self.seeked = pos

        def read(self, n):
            return b"PE\x00\x00"

    assert is_pe_executable(header, FakeHandle()) is True


def test_setup_batch_mode_defaults():
    recursive, auto_detect, output = setup_batch_mode("batch", None, False, True, None)
    assert recursive is True
    assert auto_detect is True
    assert output == "output"


def test_setup_single_file_output(tmp_path):
    output = setup_single_file_output(True, False, None, str(tmp_path / "sample.exe"))
    assert str(output).endswith("_analysis.json")


def test_determine_csv_file_path(tmp_path):
    path = tmp_path / "results.csv"
    csv_file, name = determine_csv_file_path(path, "ts")
    assert csv_file == path
    assert name == "results.csv"

    dir_path = tmp_path / "out"
    csv_file, name = determine_csv_file_path(dir_path, "ts")
    assert csv_file.name.startswith("r2inspect_")
    assert name.endswith(".csv")


def test_find_files_by_extensions(tmp_path):
    (tmp_path / "a.exe").write_text("x")
    (tmp_path / "b.dll").write_text("x")
    files = find_files_by_extensions(tmp_path, "exe,dll", recursive=False)
    names = sorted([f.name for f in files])
    assert names == ["a.exe", "b.dll"]
