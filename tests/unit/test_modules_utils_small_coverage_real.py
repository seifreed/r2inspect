from __future__ import annotations

from hashlib import md5
from pathlib import Path

import pytest

from r2inspect.factory import create_inspector
from r2inspect.modules import (
    domain_helpers,
    pe_info_domain,
    pe_resources,
    search_helpers,
    security_scoring,
    similarity_scoring,
    string_classification,
    string_extraction,
)
from r2inspect.utils import command_helpers, hashing


class DummyLogger:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)


@pytest.mark.requires_r2
def test_search_helpers_adapter_and_none(samples_dir: Path) -> None:
    sample = samples_dir / "hello_pe.exe"
    with create_inspector(str(sample)) as inspector:
        adapter = inspector.adapter
        assert search_helpers.search_text(None, None, " test ") == ""
        assert isinstance(search_helpers.search_text(adapter, None, " test "), str)
        assert search_helpers.search_hex(None, None, " ff ") == ""
        assert isinstance(search_helpers.search_hex(adapter, None, " ff "), str)


def test_domain_helpers_entropy_and_clamp() -> None:
    assert domain_helpers.shannon_entropy(b"") == 0.0
    assert domain_helpers.shannon_entropy(b"\x00") == 0.0
    assert domain_helpers.shannon_entropy(b"\x00\x01") > 0.0
    assert domain_helpers.entropy_from_ints([]) == 0.0
    assert domain_helpers.entropy_from_ints([0, 1, 2]) > 0.0
    assert domain_helpers.clamp_score(-1) == 0
    assert domain_helpers.clamp_score(150) == 100
    assert domain_helpers.clamp_score(42) == 42


def test_domain_helpers_misc() -> None:
    imports = [{"name": "CreateFile"}, {"name": "Sleep"}]
    suspicious = {"createfile"}
    assert domain_helpers.count_suspicious_imports(imports, suspicious) == 0
    suspicious = {"CreateFile"}
    assert domain_helpers.count_suspicious_imports(imports, suspicious) == 1
    assert domain_helpers.normalize_section_name(None) == ""
    assert domain_helpers.normalize_section_name(".TEXT") == ".text"
    assert (
        domain_helpers.suspicious_section_name_indicator(".crypt", ["crypt"])
        == "Suspicious section name: crypt"
    )
    assert domain_helpers.suspicious_section_name_indicator(".text", ["crypt"]) is None


def test_similarity_scoring_branches() -> None:
    assert similarity_scoring.jaccard_similarity(set(), set()) == 1.0
    assert similarity_scoring.jaccard_similarity(set(), {1}) == 0.0
    assert similarity_scoring.jaccard_similarity({1}, set()) == 0.0
    assert similarity_scoring.jaccard_similarity({1, 2}, {2, 3}) == 1 / 3
    assert similarity_scoring.normalized_difference_similarity(0, 10) == 0.0
    assert similarity_scoring.normalized_difference_similarity(10, 5) == 0.5


def test_string_classification_and_extraction() -> None:
    assert string_classification.classify_string_type("https://example.com") == "url"
    assert string_classification.classify_string_type("C:\\Windows\\System32") == "path"
    assert string_classification.classify_string_type("HKEY_LOCAL_MACHINE\\SOFTWARE") == "registry"
    assert string_classification.classify_string_type("CreateFileW") == "api"
    assert string_classification.classify_string_type("invalid operation failed") == "error"
    assert string_classification.classify_string_type("plain") is None

    entries = [{"string": "ok"}, {"string": "no"}, {"string": "longer"}]
    assert string_extraction.extract_strings_from_entries(None, 3) == []
    assert string_extraction.extract_strings_from_entries(entries, 3) == ["longer"]

    data = [65, 66, 67, 0, 68, 69, 70, 71]
    assert string_extraction.extract_ascii_from_bytes(data, min_length=3, limit=10) == [
        "ABC",
        "DEFG",
    ]
    assert string_extraction.extract_ascii_from_bytes(["x", 0, 65], min_length=1, limit=2) == ["A"]
    assert string_extraction.split_null_terminated("", min_length=2, limit=5) == []
    assert string_extraction.split_null_terminated("a\0bc\0def", min_length=2, limit=2) == [
        "bc",
        "def",
    ]


def test_utils_hashing_variants(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello")

    hashes = hashing.calculate_hashes(str(sample))
    assert hashes["md5"]
    assert hashes["sha1"]
    assert hashes["sha256"]
    assert hashes["sha512"]

    missing = hashing.calculate_hashes(str(tmp_path / "missing.bin"))
    assert missing == {"md5": "", "sha1": "", "sha256": "", "sha512": ""}

    error_hashes = hashing.calculate_hashes(str(tmp_path))
    for value in error_hashes.values():
        assert value.startswith("Error:")

    assert hashing.calculate_imphash([]) is None
    assert hashing.calculate_imphash([{"library": "", "name": ""}]) is None
    expected = md5(b"kernel32.dll.exitprocess", usedforsecurity=False).hexdigest()
    assert (
        hashing.calculate_imphash([{"library": "KERNEL32.dll", "name": "ExitProcess"}]) == expected
    )

    assert hashing.calculate_ssdeep(str(tmp_path / "missing.bin")) is None


@pytest.mark.requires_r2
def test_command_helpers_branches(samples_dir: Path) -> None:
    sample = samples_dir / "hello_pe.exe"
    with create_inspector(str(sample)) as inspector:
        adapter = inspector.adapter

        assert command_helpers._parse_address("pdj") == ("pdj", None)
        assert command_helpers._parse_address("pdj @ 0x10") == ("pdj", 16)
        assert command_helpers._parse_address("pdj@") == ("pdj", None)
        assert command_helpers._parse_address("pdj@bad") == ("pdj", None)

        assert command_helpers._parse_size("pdj") is None
        assert command_helpers._parse_size("pdj 10") == 10
        assert command_helpers._parse_size("pdj bad") is None

        assert isinstance(command_helpers._handle_search(adapter, "/xj ff"), list | str)
        assert isinstance(command_helpers._handle_search(adapter, "/c abc"), list | str)
        assert isinstance(command_helpers._handle_search(adapter, "/x aa"), list | str)
        assert command_helpers._handle_search(adapter, "nop") is None

        assert isinstance(command_helpers._handle_simple(adapter, "iz~fnv", "iz~fnv", None), str)
        assert isinstance(command_helpers._handle_simple(adapter, "aflj", "aflj@0x10", 16), list)
        assert isinstance(command_helpers._handle_simple(adapter, "aflj", "aflj", None), list)
        assert isinstance(
            command_helpers._handle_simple(adapter, "afij", "afij@0x20", 32), dict | list
        )
        assert isinstance(command_helpers._handle_simple(adapter, "i", "i", None), str)

        assert isinstance(command_helpers._handle_disasm(adapter, "pdfj", 16), dict)
        assert isinstance(command_helpers._handle_disasm(adapter, "pdj 4", 16), list)
        assert isinstance(command_helpers._handle_disasm(adapter, "pi 8", 32), str)
        assert isinstance(command_helpers._handle_disasm(adapter, "agj", 48), dict | list)

        assert isinstance(command_helpers._handle_bytes(adapter, "p8j 2", 16), list)
        assert command_helpers._handle_bytes(adapter, "p8j", None) is None
        assert command_helpers._handle_bytes(adapter, "p8", 16) is None
        assert isinstance(command_helpers._handle_bytes(adapter, "p8 2", 16), str)
        assert isinstance(command_helpers._handle_bytes(adapter, "pxj 1", 17), list)

        assert command_helpers.cmd(None, None, "i") == ""
        assert isinstance(command_helpers.cmd(adapter, None, "i"), str)
        assert command_helpers.cmdj(adapter, None, "unknown", {"x": 1}) == {"x": 1}
        assert isinstance(command_helpers.cmd_list(adapter, None, "aflj"), list)
        assert command_helpers.cmd_list(adapter, None, "i") == []


@pytest.mark.requires_r2
def test_pe_resource_helpers_and_domain(samples_dir: Path) -> None:
    logger = DummyLogger()
    sample = samples_dir / "hello_pe.exe"
    with create_inspector(str(sample)) as inspector:
        adapter = inspector.adapter

        resources = pe_resources.get_resource_info(adapter, logger)
        assert isinstance(resources, list)

        version = pe_resources.get_version_info(adapter, logger)
        assert isinstance(version, dict)

    bin_info = {"class": "PE32", "format": "Unknown", "bits": 64}
    assert pe_info_domain.determine_pe_file_type(bin_info, None, "DLL") == "DLL"
    assert pe_info_domain.determine_pe_file_type({"class": "XYZ"}, None, None) == "XYZ"
    assert pe_info_domain.determine_pe_format(bin_info, None) == "PE32+"
    assert pe_info_domain.determine_pe_format({"format": "PE32", "bits": 0}, None) == "PE32"
    assert pe_info_domain.normalize_pe_format("PE32+") == "PE"
    assert pe_info_domain.compute_entry_point({"baddr": 1, "boffset": 2}, [{"vaddr": 10}]) == 10
    assert pe_info_domain.apply_optional_header_info({"image_base": 1}, None) == {"image_base": 1}
    assert (
        pe_info_domain.apply_optional_header_info(
            {"image_base": 1, "entry_point": 2},
            {"optional_header": {"ImageBase": 0x1000, "AddressOfEntryPoint": 0x10}},
        )["entry_point"]
        == 0x1010
    )
    assert pe_info_domain.characteristics_from_header(None) is None
    assert (
        pe_info_domain.characteristics_from_header({"file_header": {"Characteristics": "x"}})
        is None
    )
    assert pe_info_domain.characteristics_from_header(
        {"file_header": {"Characteristics": 0x2002}}
    ) == {
        "is_dll": True,
        "is_executable": True,
    }
    assert pe_info_domain.normalize_resource_entries([{"name": "A"}]) == [
        {"name": "A", "type": "Unknown", "size": 0, "lang": "Unknown"}
    ]
    assert pe_info_domain.parse_version_info_text("a=b\nc=d") == {"a": "b", "c": "d"}
    assert pe_info_domain.characteristics_from_bin({"type": "dll"}, "file.exe")["is_dll"] is True
    assert pe_info_domain.build_subsystem_info("Windows GUI")["gui_app"] is True
    assert pe_info_domain.build_subsystem_info("Console")["gui_app"] is False
    assert pe_info_domain.build_subsystem_info("Other")["gui_app"] is None


def test_security_scoring_helpers() -> None:
    result = {
        "mitigations": {"ASLR": {"enabled": True}, "DEP": {"enabled": False}},
        "vulnerabilities": [{"severity": "high"}, {"severity": "medium"}],
    }
    score = security_scoring.build_security_score(result)
    assert score["max_score"] > 0
    assert score["score"] >= 0
    assert score["grade"] in {"A", "B", "C", "D", "F", "Unknown"}
