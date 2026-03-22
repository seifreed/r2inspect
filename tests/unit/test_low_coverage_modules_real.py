from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from r2inspect.cli import validators
from r2inspect.domain.services import function_analysis as function_domain
from r2inspect.error_handling import classifier as error_handler
from r2inspect.infrastructure import command_helpers, r2_helpers, r2_session
from r2inspect.modules import (
    pe_imports,
    resource_analyzer as resource_analysis,
    security_scoring,
    simhash_detailed,
)
from r2inspect.schemas import results_loader
from r2inspect.schemas.results_models import AnalysisResult
from r2inspect.domain.formats import pe_info as pe_info_domain
from r2inspect.domain.formats import import_analysis as import_domain
from r2inspect.domain.formats import elf as elf_domain
from r2inspect.domain.formats import macho as macho_domain
from r2inspect.domain.formats import string as string_domain
from r2inspect.domain.formats import crypto as crypto_domain
from r2inspect.domain.formats import similarity as similarity_scoring


@dataclass
class _TinyR2:
    payload: str = '{"ok": true}'

    def cmd(self, _command: str) -> str:
        return self.payload


class _Adapter:
    def search_hex_json(self, query: str):
        return [{"query": query}]

    def search_text(self, query: str):
        return [query]

    def search_hex(self, query: str):
        return [query]

    def get_functions(self):
        return [{"name": "main"}]

    def get_function_info(self, address: int):
        return {"address": address}

    def get_functions_at(self, address: int):
        return [{"address": address}]

    def get_disasm(self, address=None, size=None):
        return {"address": address, "size": size}

    def get_disasm_text(self, address=None, size=None):
        return f"{address}:{size}"

    def get_cfg(self, address=None):
        return {"cfg": address}

    def read_bytes_list(self, address: int, size: int):
        return list(range(min(size, 4))) + [address]

    def read_bytes(self, address: int, size: int):
        return bytes([(address + i) % 256 for i in range(size)])


def test_canonical_modules_export_real_symbols() -> None:
    assert r2_session.R2Session is not None
    assert "R2Session" in r2_session.__all__

    assert callable(command_helpers.cmd)
    assert callable(r2_helpers.cmdj)

    assert error_handler.ErrorClassifier is not None
    assert hasattr(error_handler, "safe_execute")


def test_r2_commands_dispatch_without_mocks() -> None:
    adapter = _Adapter()
    fallback = _TinyR2(payload="fallback")

    assert command_helpers.cmdj(adapter, None, "/xj 4142", []) == [{"query": "4142"}]
    assert command_helpers.cmdj(adapter, None, "afij @ 0x401000", {})["address"] == 0x401000
    assert command_helpers.cmdj(adapter, None, "aflj", [])[0]["name"] == "main"
    assert isinstance(command_helpers.cmdj(adapter, None, "pdj 8 @ 0x1000", {}), dict)
    assert command_helpers.cmd(adapter, None, "p8 4 @ 0x10")
    assert command_helpers.cmd(None, fallback, "i") == "fallback"


def test_cli_validators_paths_and_sanitization(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")

    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()

    assert validators.validate_file_input(str(sample)) == []
    assert validators.validate_file_input(str(empty))
    assert validators.validate_batch_input(str(batch_dir)) == []
    assert validators.validate_batch_input(str(sample))

    output_parent_file = tmp_path / "not_a_dir"
    output_parent_file.write_text("x", encoding="utf-8")
    assert validators.validate_output_input(str(output_parent_file / "out"))

    config_bad = tmp_path / "cfg.txt"
    config_bad.write_text("x", encoding="utf-8")
    assert validators.validate_config_input(str(config_bad))

    assert validators.validate_extensions_input("exe,py$")
    assert validators.validate_extensions_input("a" * 11)
    assert validators.validate_threads_input(0)
    assert validators.validate_threads_input(100)
    assert validators.validate_threads_input(4) == []

    assert validators.sanitize_xor_string("A B-._") == "A B-._"
    assert validators.sanitize_xor_string("***") is None
    assert validators.handle_xor_input("***") is None


def test_cli_input_mode_exits(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        validators.validate_input_mode(None, None)
    with pytest.raises(SystemExit):
        validators.validate_input_mode("a", "b")
    with pytest.raises(SystemExit):
        validators.validate_single_file(str(tmp_path / "missing.bin"))


def test_results_loader_full_payload_and_branches() -> None:
    payload = {
        "file_info": {
            "name": "x",
            "path": "/tmp/x",
            "size": 1,
            "md5": "m",
            "sha1": "s1",
            "sha256": "s256",
            "file_type": "PE",
            "architecture": "x86",
            "bits": 32,
            "endian": "little",
            "mime_type": "application/octet-stream",
        },
        "hashing": {"ssdeep": "3:aa:bb", "tlsh": "T1"},
        "security": {"nx": True, "relro": "full", "aslr": True},
        "imports": [{"name": "CreateFileA", "library": "kernel32.dll", "ordinal": 1}],
        "exports": [{"name": "exp", "address": "0x1000", "size": 4}],
        "sections": [{"name": ".text", "virtual_address": 4096, "virtual_size": 10}],
        "strings": ["abc"],
        "yara_matches": [{"rule": "r", "namespace": "n"}],
        "functions": [{"name": "main", "address": 4096}],
        "anti_analysis": {"anti_debug": True},
        "packer": {"is_packed": True, "confidence": 60},
        "crypto": {"algorithms": [{"name": "AES"}]},
        "indicators": [{"type": "x", "description": "y", "severity": "High"}],
        "error": None,
        "timestamp": datetime.now(UTC).isoformat(),
        "execution_time": 1.2,
    }

    result = results_loader.from_dict(payload)
    dumped = result.to_dict()
    assert dumped["file_info"]["name"] == "x"
    assert dumped["security"]["nx"] is True
    assert dumped["imports"][0]["name"] == "CreateFileA"

    empty_result = AnalysisResult()
    for loader in (
        results_loader._load_file_info,
        results_loader._load_hashing,
        results_loader._load_security,
        results_loader._load_imports,
        results_loader._load_exports,
        results_loader._load_sections,
        results_loader._load_yara_matches,
        results_loader._load_functions,
        results_loader._load_anti_analysis,
        results_loader._load_packer,
        results_loader._load_crypto,
        results_loader._load_indicators,
    ):
        loader(empty_result, {})

    results_loader._load_strings(empty_result, {"strings": ["z"]})
    assert empty_result.strings == ["z"]

    results_loader._load_error(empty_result, {"error": "boom"})
    assert empty_result.error == "boom"

    results_loader._load_timestamp(empty_result, {"timestamp": "invalid"})
    results_loader._load_timestamp(empty_result, {"timestamp": datetime.now(UTC)})
    results_loader._load_execution_time(empty_result, {"execution_time": 9.5})
    assert empty_result.execution_time == 9.5


def test_function_domain_helpers() -> None:
    ops = [{"opcode": "mov eax, ebx"}, {"opcode": " add rax,1 "}, {"x": 1}]
    assert function_domain.extract_mnemonics_from_ops(ops) == ["mov", "add"]
    assert function_domain.extract_mnemonics_from_text("mov eax\n\nadd ebx") == ["mov", "add"]
    assert function_domain.extract_mnemonics_from_text("  ") == []
    assert function_domain.machoc_hash_from_mnemonics([]) is None
    assert function_domain.machoc_hash_from_mnemonics(["mov"])


def test_elf_domain_helpers() -> None:
    comment = "GCC: (Ubuntu) 13.2.0\nclang version 18.1.2"
    parsed = elf_domain.parse_comment_compiler_info(comment)
    assert parsed["compiler_version"] == "18.1.2"

    dwarf = elf_domain.parse_dwarf_info(
        [
            "DW_AT_producer : GNU C17 11.4.0",
            "compilation date 2024-01-31",
        ]
    )
    assert dwarf["compiler"].startswith("GCC")
    assert dwarf["compile_time"] == "2024-01-31"

    assert elf_domain.parse_dwarf_producer("nope") is None
    assert elf_domain.parse_dwarf_compile_time("nothing") is None
    assert elf_domain.parse_build_id_data(None) is None
    assert elf_domain.parse_build_id_data("xx 11 22 33 44 55") == "55"

    section = elf_domain.find_section_by_name([{"name": ".text"}], "text")
    assert section and section["name"] == ".text"
    assert elf_domain.build_section_read_commands({"vaddr": 4096, "size": 10}, "px") == (
        "s 4096",
        "px 10",
    )
    assert elf_domain.build_section_read_commands({"vaddr": 0, "size": 10}, "px") is None


def test_pe_info_domain_helpers() -> None:
    assert pe_info_domain.determine_pe_file_type({"class": "PE32"}, None, "dynamic dll") == "DLL"
    assert pe_info_domain.determine_pe_file_type({"class": "PE32"}, None, "driver sys") == "SYS"
    assert pe_info_domain.determine_pe_file_type({"class": "custom"}, None, None) == "custom"

    assert pe_info_domain.determine_pe_format({"format": "PE32"}, None) == "PE32"
    assert pe_info_domain.determine_pe_format({"format": "Unknown", "bits": 64}, None) == "PE32+"
    assert (
        pe_info_domain.determine_pe_format(
            {"format": "Unknown", "bits": 0}, {"optional_header": {"Magic": 0x10B}}
        )
        == "PE32"
    )

    assert pe_info_domain.normalize_pe_format("pe32+") == "PE"
    assert pe_info_domain.normalize_pe_format("Unknown") == "PE"

    assert pe_info_domain.compute_entry_point({"baddr": 4096, "boffset": 2}, None) == 4098
    assert pe_info_domain.compute_entry_point({}, [{"vaddr": 123}]) == 123

    info = pe_info_domain.apply_optional_header_info(
        {"image_base": 0, "entry_point": 0},
        {"optional_header": {"ImageBase": 0x400000, "AddressOfEntryPoint": 0x1000}},
    )
    assert info["entry_point"] == 0x401000

    assert pe_info_domain.characteristics_from_header(
        {"file_header": {"Characteristics": 0x2002}}
    ) == {
        "is_dll": True,
        "is_executable": True,
    }
    assert (
        pe_info_domain.characteristics_from_header({"file_header": {"Characteristics": "x"}})
        is None
    )

    resources = pe_info_domain.normalize_resource_entries([{"name": "A"}, {}])
    assert resources[0]["name"] == "A"
    assert pe_info_domain.parse_version_info_text("a=1\nb = 2")["b"] == "2"

    flags = pe_info_domain.characteristics_from_bin({"type": "dynamic library"}, "sample.dll")
    assert flags["is_dll"] is True

    assert pe_info_domain.build_subsystem_info("Windows GUI")["gui_app"] is True
    assert pe_info_domain.build_subsystem_info("Console")["gui_app"] is False


def test_import_domain_helpers() -> None:
    api_categories = {
        "Anti-Analysis": ["IsDebuggerPresent"],
        "Process/Thread Management": ["CreateProcess"],
        "Memory Management": ["VirtualAllocEx"],
        "Registry": ["RegSetValueEx"],
        import_domain.NETWORK_CATEGORY: ["connect"],
    }
    imports = [
        {"name": "IsDebuggerPresent", "category": "Anti-Analysis"},
        {"name": "CreateProcessA", "category": "Process/Thread Management"},
        {"name": "VirtualAllocEx", "category": "Memory Management"},
        {"name": "WriteProcessMemory", "category": "Injection"},
        {"name": "SetThreadContext", "category": "Injection"},
        {"name": "connect", "category": import_domain.NETWORK_CATEGORY},
        {"name": "SetWindowsHookEx", "category": "Persistence"},
        {"name": "CryptEncrypt", "category": "Cryptography"},
        {"name": "CryptDecrypt", "category": "Cryptography"},
        {"name": "CryptCreateHash", "category": "Cryptography"},
        {"name": "BCryptEncrypt", "category": "Cryptography"},
        {"name": "RegSetValueEx", "category": "Registry"},
    ]

    categorized = import_domain.categorize_apis(imports, api_categories)
    assert categorized["Anti-Analysis"]["count"] == 1

    suspicious, score = import_domain.assess_api_risk(
        {
            "Anti-Analysis": {"count": 3},
            "DLL Injection": {"count": 3},
            "Process/Thread Management": {"count": 4},
            "Memory Management": {"count": 4},
            "Registry": {"count": 5},
            import_domain.NETWORK_CATEGORY: {"count": 3},
        }
    )
    assert suspicious and score > 0

    patterns = import_domain.find_suspicious_patterns(imports)
    names = {p["pattern"] for p in patterns}
    assert "DLL Injection" in names
    assert "Process Hollowing" in names
    assert "Keylogging" in names

    counts = import_domain.count_import_categories(imports)
    assert counts["Cryptography"] == 4

    categories = import_domain.build_api_categories()
    max_score, tags = import_domain.find_max_risk_score("CreateRemoteThread", categories)
    assert max_score >= 90 and tags

    assert import_domain.risk_level_from_score(85) == "Critical"
    assert import_domain.risk_level_from_score(65) == "High"
    assert import_domain.risk_level_from_score(45) == "Medium"
    assert import_domain.risk_level_from_score(25) == "Low"
    assert import_domain.risk_level_from_score(10) == "Minimal"


def test_string_domain_helpers() -> None:
    strings = ["abc", "http://example.com", "AAAA!!!!", "48656c6c6f", "SGVsbG8="]
    filtered = string_domain.filter_strings(strings, min_length=3, max_length=64)
    assert "abc" in filtered
    assert string_domain.parse_search_results("0x10 a\nbad\n0x20 b") == ["0x10", "0x20"]
    assert string_domain.xor_string("A", 1) == "@"

    calls = {"value": 0}

    def _search(hex_pattern: str) -> str:
        calls["value"] += 1
        return "0x100 hit" if hex_pattern else ""

    matches = string_domain.build_xor_matches("A", _search)
    assert matches and calls["value"] == 255

    suspicious = string_domain.find_suspicious(
        ["contact me at a@b.com", "AES key", "HKEY_LOCAL_MACHINE\\X"]
    )
    assert suspicious

    assert string_domain.decode_base64("SGVsbG8=")["decoded"] == "Hello"
    assert string_domain.decode_base64("!!!") is None
    assert string_domain.decode_hex("48656c6c6f")["decoded"] == "Hello"
    assert string_domain.decode_hex("xyz") is None
    assert string_domain.is_base64("SGVsbG8=") is True
    assert string_domain.is_hex("41") is False


def test_crypto_domain_helpers() -> None:
    detected: dict[str, list] = {}
    strings = [
        {"string": "AES256 encrypt", "vaddr": 0x1000},
        {"string": "std::vector", "vaddr": 0x2000},
        {"string": "OpenSSL EVP_EncryptInit", "vaddr": 0x3000},
    ]
    crypto_domain.detect_algorithms_from_strings(strings, detected)
    assert "AES" in detected
    assert "OpenSSL" in detected

    consolidated = crypto_domain.consolidate_detections(
        {"AES": [{"confidence": 0.4, "evidence_type": "String Reference"}]}
    )
    assert consolidated[0]["algorithm"] == "AES"
    assert crypto_domain._is_candidate_string("ab") is False
    assert crypto_domain._matches_any_pattern("aes", [r"aes"]) is True


def test_macho_similarity_security_helpers() -> None:
    assert macho_domain.estimate_from_sdk_version("11.0") == "~2020 (SDK 11.0)"
    assert macho_domain.estimate_from_sdk_version("2.0") is None
    assert macho_domain.platform_from_version_min("LC_VERSION_MIN_MACOSX") == "macOS"
    assert macho_domain.platform_from_version_min("LC_X") is None
    assert macho_domain.dylib_timestamp_to_string(0) == (None, None)

    load_cmds = macho_domain.build_load_commands([{"type": "LC_ID_DYLIB", "size": 1}])
    assert load_cmds[0]["type"] == "LC_ID_DYLIB"
    sections = macho_domain.build_sections([{"name": "__text", "size": 1}])
    assert sections[0]["name"] == "__text"

    assert similarity_scoring.jaccard_similarity(set(), set()) == 1.0
    assert similarity_scoring.jaccard_similarity({1}, set()) == 0.0
    assert similarity_scoring.normalized_difference_similarity(10, 5) == 0.5
    assert similarity_scoring.normalized_difference_similarity(0, 5) == 0.0

    score = security_scoring.build_security_score(
        {
            "mitigations": {
                "ASLR": {"enabled": True, "high_entropy": True},
                "DEP": {"enabled": True},
                "CFG": {"enabled": True},
            },
            "vulnerabilities": [{"severity": "medium"}, {"severity": "high"}],
        }
    )
    assert score["max_score"] > 0
    assert score["grade"] in {"A", "B", "C", "D", "F"}


class _ImportLogger:
    def __init__(self) -> None:
        self.debug_messages: list[str] = []
        self.error_messages: list[str] = []

    def debug(self, message: str) -> None:
        self.debug_messages.append(message)

    def error(self, message: str) -> None:
        self.error_messages.append(message)


class _ImportAdapter:
    def __init__(self, imports: list[dict[str, object]]) -> None:
        self._imports = imports

    def get_imports(self) -> list[dict[str, object]]:
        return self._imports


def test_pe_imports_helpers() -> None:
    imports = [
        {"libname": "KERNEL32.DLL", "name": "CreateFileA"},
        {"libname": "user32.dll", "name": "MessageBoxA"},
        {"libname": "", "name": "NoLib"},
    ]
    grouped = pe_imports.group_imports_by_library(imports)
    assert "KERNEL32.DLL" in grouped
    assert pe_imports.normalize_library_name("KERNEL32.DLL", ["dll"]) == "kernel32"
    assert pe_imports.compute_imphash(["a.b"])

    logger = _ImportLogger()
    adapter = _ImportAdapter(imports)
    imphash = pe_imports.calculate_imphash(adapter, logger)
    assert imphash
    assert logger.error_messages == []


class _ResourceAnalyzer:
    def _init_result_structure(self, payload: dict[str, object]) -> dict[str, object]:
        return dict(payload)

    def _get_resource_directory(self):
        return {"vaddr": 4096}

    def _parse_resources(self):
        return [{"name": "RT_VERSION"}]

    def _analyze_resource_types(self, result, resources):
        result["resource_types"] = [r.get("name") for r in resources]

    def _extract_version_info(self, result, _resources):
        result["version_info"] = {"company": "x"}

    def _extract_manifest(self, result, _resources):
        result["manifest"] = "ok"

    def _extract_icons(self, result, _resources):
        result["icons"] = ["icon"]

    def _extract_strings(self, result, _resources):
        result["strings"] = ["abc"]

    def _calculate_statistics(self, result, resources):
        result["statistics"] = {"count": len(resources)}

    def _check_suspicious_resources(self, result, _resources):
        result["suspicious_resources"] = []


class _ResourceAnalyzerFail(_ResourceAnalyzer):
    def _parse_resources(self):
        raise RuntimeError("boom")


class _ResourceLogger:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)


def test_resource_analysis_and_simhash_detailed() -> None:
    logger = _ResourceLogger()
    ok = resource_analysis.run_resource_analysis(_ResourceAnalyzer(), logger)
    assert ok["available"] is True
    assert ok["has_resources"] is True

    failed = resource_analysis.run_resource_analysis(_ResourceAnalyzerFail(), logger)
    assert failed["available"] is False
    assert logger.errors

    unavailable = simhash_detailed.run_detailed_simhash_analysis(
        filepath="/tmp/x",
        simhash_available=False,
        no_features_error="no features",
        extract_string_features=lambda: [],
        extract_opcodes_features=lambda: [],
        extract_function_features=lambda: {},
        find_similar_functions=lambda _x: [],
        log_debug=lambda _m: None,
        log_error=lambda _m: None,
    )
    assert unavailable["available"] is False

    available = simhash_detailed.run_detailed_simhash_analysis(
        filepath="/tmp/x",
        simhash_available=True,
        no_features_error="no features",
        extract_string_features=lambda: ["str_a", "str_b"],
        extract_opcodes_features=lambda: ["mov", "add"],
        extract_function_features=lambda: {
            "f1": {"simhash": 1},
            "f2": {"simhash": 2},
        },
        find_similar_functions=lambda _x: [{"pair": ["f1", "f2"]}],
        log_debug=lambda _m: None,
        log_error=lambda _m: None,
    )
    assert available["available"] is True
    assert available["combined_simhash"]["feature_count"] == 4
