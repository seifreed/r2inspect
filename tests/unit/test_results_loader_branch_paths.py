"""Tests covering branch paths in r2inspect/schemas/results_loader.py."""

from __future__ import annotations

from datetime import datetime

from r2inspect.schemas.results_loader import (
    _load_anti_analysis,
    _load_crypto,
    _load_error,
    _load_execution_time,
    _load_exports,
    _load_file_info,
    _load_functions,
    _load_hashing,
    _load_imports,
    _load_indicators,
    _load_packer,
    _load_sections,
    _load_security,
    _load_strings,
    _load_timestamp,
    _load_yara_matches,
    from_dict,
)
from r2inspect.schemas.results_models import AnalysisResult


# ---------------------------------------------------------------------------
# from_dict - complete deserialization (lines 36-53)
# ---------------------------------------------------------------------------


def test_from_dict_returns_analysis_result_instance() -> None:
    result = from_dict({})
    assert isinstance(result, AnalysisResult)


def test_from_dict_calls_all_loaders_with_empty_dict() -> None:
    result = from_dict({})
    assert result.error is None
    assert result.execution_time == 0.0
    assert result.imports == []
    assert result.exports == []
    assert result.sections == []
    assert result.yara_matches == []
    assert result.functions == []
    assert result.indicators == []


def test_from_dict_populates_file_info(tmp_path: object) -> None:
    data: dict = {
        "file_info": {
            "name": "malware.dll",
            "path": "/samples/malware.dll",
            "size": 20480,
            "md5": "aabbccdd",
            "sha1": "11223344",
            "sha256": "aabbccddeeff0011",
            "file_type": "PE32+",
            "architecture": "x86_64",
            "bits": 64,
            "endian": "little",
            "mime_type": "application/x-dosexec",
        }
    }
    result = from_dict(data)
    assert result.file_info is not None
    assert result.file_info.name == "malware.dll"
    assert result.file_info.bits == 64
    assert result.file_info.architecture == "x86_64"


def test_from_dict_populates_hashing() -> None:
    data: dict = {
        "hashing": {
            "ssdeep": "96:hash:value",
            "tlsh": "T1ABCD",
            "imphash": "abc123",
            "impfuzzy": "fuzz",
            "ccbhash": "ccbval",
            "simhash": "simval",
            "telfhash": "telfval",
            "rich_hash": "richval",
            "machoc_hash": "machocval",
        }
    }
    result = from_dict(data)
    assert result.hashing is not None
    assert result.hashing.ssdeep == "96:hash:value"
    assert result.hashing.tlsh == "T1ABCD"
    assert result.hashing.imphash == "abc123"
    assert result.hashing.machoc_hash == "machocval"


def test_from_dict_populates_security() -> None:
    data: dict = {
        "security": {
            "nx": True,
            "pie": False,
            "canary": True,
            "dep": True,
            "stack_canary": False,
            "relro": "partial",
            "aslr": True,
            "seh": True,
            "guard_cf": False,
            "authenticode": True,
            "fortify": False,
            "rpath": False,
            "runpath": True,
            "high_entropy_va": True,
        }
    }
    result = from_dict(data)
    assert result.security is not None
    assert result.security.nx is True
    assert result.security.relro == "partial"
    assert result.security.runpath is True
    assert result.security.high_entropy_va is True


def test_from_dict_populates_imports_list() -> None:
    data: dict = {
        "imports": [
            {
                "name": "VirtualAlloc",
                "library": "kernel32.dll",
                "address": "0x7ff000",
                "ordinal": 0,
                "category": "memory",
                "risk_score": 8,
                "risk_level": "High",
                "risk_tags": ["memory_alloc", "injection"],
            },
            {
                "name": "GetProcAddress",
                "library": "kernel32.dll",
                "address": "0x7ff100",
                "ordinal": 1,
                "category": "api",
                "risk_score": 5,
                "risk_level": "Medium",
                "risk_tags": [],
            },
        ]
    }
    result = from_dict(data)
    assert result.imports is not None
    assert len(result.imports) == 2
    assert result.imports[0].name == "VirtualAlloc"
    assert result.imports[0].risk_level == "High"
    assert result.imports[1].name == "GetProcAddress"


def test_from_dict_populates_exports_list() -> None:
    data: dict = {
        "exports": [
            {"name": "DllEntryPoint", "address": "0x1000", "ordinal": 1, "size": 256},
            {"name": "exported_func", "address": "0x2000", "ordinal": 2, "size": 128},
        ]
    }
    result = from_dict(data)
    assert result.exports is not None
    assert len(result.exports) == 2
    assert result.exports[0].name == "DllEntryPoint"
    assert result.exports[1].ordinal == 2


def test_from_dict_populates_sections() -> None:
    data: dict = {
        "sections": [
            {
                "name": ".text",
                "virtual_address": 0x1000,
                "virtual_size": 0x5000,
                "raw_size": 0x5200,
                "entropy": 6.1,
                "permissions": "r-x",
                "is_executable": True,
                "is_writable": False,
                "is_readable": True,
                "flags": "CODE",
                "suspicious_indicators": [],
            },
            {
                "name": ".data",
                "virtual_address": 0x6000,
                "virtual_size": 0x1000,
                "raw_size": 0x1000,
                "entropy": 3.2,
                "permissions": "rw-",
                "is_executable": False,
                "is_writable": True,
                "is_readable": True,
                "flags": None,
                "suspicious_indicators": ["high_entropy"],
            },
        ]
    }
    result = from_dict(data)
    assert result.sections is not None
    assert len(result.sections) == 2
    assert result.sections[0].name == ".text"
    assert result.sections[0].is_executable is True
    assert result.sections[1].flags is None
    assert result.sections[1].suspicious_indicators == ["high_entropy"]


def test_from_dict_populates_strings() -> None:
    data: dict = {"strings": ["cmd.exe", "powershell", "http://evil.com", "WININET.DLL"]}
    result = from_dict(data)
    assert result.strings == ["cmd.exe", "powershell", "http://evil.com", "WININET.DLL"]


def test_from_dict_populates_yara_matches() -> None:
    data: dict = {
        "yara_matches": [
            {
                "rule": "Detect_Mimikatz",
                "namespace": "malware",
                "tags": ["credential_theft", "post_exploit"],
                "meta": {"author": "defender", "version": "1.0"},
                "strings": ["$sekurlsa", "$wdigest"],
            }
        ]
    }
    result = from_dict(data)
    assert result.yara_matches is not None
    assert len(result.yara_matches) == 1
    assert result.yara_matches[0].rule == "Detect_Mimikatz"
    assert len(result.yara_matches[0].tags) == 2


def test_from_dict_populates_functions() -> None:
    data: dict = {
        "functions": [
            {
                "name": "sub_1400",
                "address": 0x1400,
                "size": 300,
                "complexity": 12,
                "basic_blocks": 15,
                "call_refs": 4,
                "data_refs": 2,
            }
        ]
    }
    result = from_dict(data)
    assert result.functions is not None
    assert len(result.functions) == 1
    assert result.functions[0].address == 0x1400
    assert result.functions[0].complexity == 12


def test_from_dict_populates_anti_analysis() -> None:
    data: dict = {
        "anti_analysis": {
            "anti_debug": True,
            "anti_vm": True,
            "anti_sandbox": True,
            "timing_checks": False,
            "techniques": ["NtQueryInformationProcess", "CheckRemoteDebuggerPresent"],
        }
    }
    result = from_dict(data)
    assert result.anti_analysis is not None
    assert result.anti_analysis.anti_debug is True
    assert result.anti_analysis.anti_sandbox is True
    assert len(result.anti_analysis.techniques) == 2


def test_from_dict_populates_packer() -> None:
    data: dict = {
        "packer": {
            "is_packed": True,
            "packer_type": "ASPack",
            "confidence": 75,
            "indicators": ["suspicious_ep", "low_sections"],
        }
    }
    result = from_dict(data)
    assert result.packer is not None
    assert result.packer.is_packed is True
    assert result.packer.packer_type == "ASPack"
    assert result.packer.confidence == 75


def test_from_dict_populates_crypto() -> None:
    data: dict = {
        "crypto": {
            "algorithms": ["AES-256", "SHA-256", "HMAC"],
            "constants": ["0x63626361", "0x67666564"],
            "functions": ["aes_encrypt", "sha256_init"],
        }
    }
    result = from_dict(data)
    assert result.crypto is not None
    assert len(result.crypto.algorithms) == 3
    assert "AES-256" in result.crypto.algorithms
    assert len(result.crypto.functions) == 2


def test_from_dict_populates_indicators() -> None:
    data: dict = {
        "indicators": [
            {"type": "network", "description": "Hardcoded IP address", "severity": "High"},
            {"type": "file_drop", "description": "Drops executable", "severity": "Critical"},
        ]
    }
    result = from_dict(data)
    assert result.indicators is not None
    assert len(result.indicators) == 2
    assert result.indicators[0].severity == "High"
    assert result.indicators[1].type == "file_drop"


def test_from_dict_populates_error() -> None:
    data: dict = {"error": "r2pipe command timeout"}
    result = from_dict(data)
    assert result.error == "r2pipe command timeout"


def test_from_dict_error_is_none() -> None:
    data: dict = {"error": None}
    result = from_dict(data)
    assert result.error is None


def test_from_dict_timestamp_valid_iso_string() -> None:
    data: dict = {"timestamp": "2024-11-15T08:45:00"}
    result = from_dict(data)
    assert result.timestamp == datetime(2024, 11, 15, 8, 45, 0)


def test_from_dict_timestamp_invalid_string_keeps_default() -> None:
    data: dict = {"timestamp": "this-is-not-a-date"}
    result = from_dict(data)
    assert result.timestamp is not None


def test_from_dict_timestamp_datetime_object() -> None:
    dt = datetime(2024, 12, 31, 23, 59, 59)
    data: dict = {"timestamp": dt}
    result = from_dict(data)
    assert result.timestamp == dt


def test_from_dict_timestamp_none_keeps_default() -> None:
    data: dict = {"timestamp": None}
    result = from_dict(data)
    assert result.timestamp is not None


def test_from_dict_execution_time() -> None:
    data: dict = {"execution_time": 7.89}
    result = from_dict(data)
    assert result.execution_time == 7.89


def test_from_dict_execution_time_zero() -> None:
    data: dict = {"execution_time": 0.0}
    result = from_dict(data)
    assert result.execution_time == 0.0


# ---------------------------------------------------------------------------
# _load_file_info (lines 57-60)
# ---------------------------------------------------------------------------


def test_load_file_info_with_data() -> None:
    result = AnalysisResult()
    _load_file_info(
        result,
        {
            "file_info": {
                "name": "test.exe",
                "path": "/tmp/test.exe",
                "size": 4096,
                "md5": "md5val",
                "sha1": "sha1val",
                "sha256": "sha256val",
                "file_type": "ELF",
                "architecture": "arm64",
                "bits": 64,
                "endian": "big",
                "mime_type": "application/x-elf",
            }
        },
    )
    assert result.file_info is not None
    assert result.file_info.name == "test.exe"
    assert result.file_info.architecture == "arm64"


def test_load_file_info_empty_dict_sets_defaults() -> None:
    result = AnalysisResult()
    _load_file_info(result, {"file_info": {}})
    assert result.file_info is not None
    assert result.file_info.name == ""
    assert result.file_info.size == 0
    assert result.file_info.bits == 0


def test_load_file_info_not_in_data_skips() -> None:
    result = AnalysisResult()
    original = result.file_info
    _load_file_info(result, {})
    assert result.file_info is original


# ---------------------------------------------------------------------------
# _load_hashing (lines 76-79)
# ---------------------------------------------------------------------------


def test_load_hashing_with_full_data() -> None:
    result = AnalysisResult()
    _load_hashing(
        result,
        {
            "hashing": {
                "ssdeep": "3:abc",
                "tlsh": "T0001",
                "imphash": "imp",
                "impfuzzy": "fuzz",
                "ccbhash": "ccb",
                "simhash": "sim",
                "telfhash": "telf",
                "rich_hash": "rich",
                "machoc_hash": "machoc",
            }
        },
    )
    assert result.hashing is not None
    assert result.hashing.ssdeep == "3:abc"
    assert result.hashing.rich_hash == "rich"


def test_load_hashing_not_in_data_skips() -> None:
    result = AnalysisResult()
    original = result.hashing
    _load_hashing(result, {})
    assert result.hashing is original


# ---------------------------------------------------------------------------
# _load_security (lines 93-96)
# ---------------------------------------------------------------------------


def test_load_security_with_full_data() -> None:
    result = AnalysisResult()
    _load_security(
        result,
        {
            "security": {
                "nx": True,
                "pie": True,
                "canary": False,
                "dep": True,
                "stack_canary": False,
                "relro": "full",
                "aslr": True,
                "seh": False,
                "guard_cf": True,
                "authenticode": False,
                "fortify": True,
                "rpath": False,
                "runpath": False,
                "high_entropy_va": True,
            }
        },
    )
    assert result.security is not None
    assert result.security.guard_cf is True
    assert result.security.relro == "full"


def test_load_security_not_in_data_skips() -> None:
    result = AnalysisResult()
    original = result.security
    _load_security(result, {})
    assert result.security is original


# ---------------------------------------------------------------------------
# _load_imports (lines 115-118)
# ---------------------------------------------------------------------------


def test_load_imports_with_one_entry() -> None:
    result = AnalysisResult()
    _load_imports(
        result,
        {
            "imports": [
                {
                    "name": "RegSetValueEx",
                    "library": "advapi32.dll",
                    "address": "0x3000",
                    "ordinal": 3,
                    "category": "registry",
                    "risk_score": 6,
                    "risk_level": "High",
                    "risk_tags": ["persistence"],
                }
            ]
        },
    )
    assert len(result.imports) == 1
    assert result.imports[0].name == "RegSetValueEx"
    assert result.imports[0].risk_tags == ["persistence"]


def test_load_imports_empty_list_leaves_empty() -> None:
    result = AnalysisResult()
    _load_imports(result, {"imports": []})
    assert result.imports == []


def test_load_imports_not_in_data_skips() -> None:
    result = AnalysisResult()
    _load_imports(result, {})
    assert result.imports == []


# ---------------------------------------------------------------------------
# _load_exports (lines 134-137)
# ---------------------------------------------------------------------------


def test_load_exports_with_entries() -> None:
    result = AnalysisResult()
    _load_exports(
        result,
        {
            "exports": [
                {"name": "ExportedFunc1", "address": "0x5000", "ordinal": 10, "size": 64},
                {"name": "ExportedFunc2", "address": "0x5100", "ordinal": 11, "size": 32},
            ]
        },
    )
    assert len(result.exports) == 2
    assert result.exports[0].ordinal == 10
    assert result.exports[1].name == "ExportedFunc2"


def test_load_exports_not_in_data_skips() -> None:
    result = AnalysisResult()
    _load_exports(result, {})
    assert result.exports == []


# ---------------------------------------------------------------------------
# _load_sections (lines 149-152)
# ---------------------------------------------------------------------------


def test_load_sections_with_entries() -> None:
    result = AnalysisResult()
    _load_sections(
        result,
        {
            "sections": [
                {
                    "name": ".rsrc",
                    "virtual_address": 0x8000,
                    "virtual_size": 0x200,
                    "raw_size": 0x200,
                    "entropy": 2.1,
                    "permissions": "r--",
                    "is_executable": False,
                    "is_writable": False,
                    "is_readable": True,
                    "flags": "DATA",
                    "suspicious_indicators": [],
                }
            ]
        },
    )
    assert len(result.sections) == 1
    assert result.sections[0].name == ".rsrc"
    assert result.sections[0].entropy == 2.1


def test_load_sections_not_in_data_skips() -> None:
    result = AnalysisResult()
    _load_sections(result, {})
    assert result.sections == []


# ---------------------------------------------------------------------------
# _load_strings (lines 171-172)
# ---------------------------------------------------------------------------


def test_load_strings_present_in_data() -> None:
    result = AnalysisResult()
    _load_strings(result, {"strings": ["hello", "world"]})
    assert result.strings == ["hello", "world"]


def test_load_strings_not_in_data_leaves_default() -> None:
    result = AnalysisResult()
    _load_strings(result, {})
    assert result.strings == []


# ---------------------------------------------------------------------------
# _load_yara_matches (lines 176-179)
# ---------------------------------------------------------------------------


def test_load_yara_matches_with_entries() -> None:
    result = AnalysisResult()
    _load_yara_matches(
        result,
        {
            "yara_matches": [
                {
                    "rule": "RuleA",
                    "namespace": "ns1",
                    "tags": ["packed"],
                    "meta": {"ref": "CVE-2024-001"},
                    "strings": ["$packed_stub"],
                }
            ]
        },
    )
    assert len(result.yara_matches) == 1
    assert result.yara_matches[0].rule == "RuleA"
    assert result.yara_matches[0].meta == {"ref": "CVE-2024-001"}


def test_load_yara_matches_not_in_data_skips() -> None:
    result = AnalysisResult()
    _load_yara_matches(result, {})
    assert result.yara_matches == []


# ---------------------------------------------------------------------------
# _load_functions (lines 192-195)
# ---------------------------------------------------------------------------


def test_load_functions_with_entries() -> None:
    result = AnalysisResult()
    _load_functions(
        result,
        {
            "functions": [
                {
                    "name": "sym_imp_strncpy",
                    "address": 0x2000,
                    "size": 40,
                    "complexity": 2,
                    "basic_blocks": 3,
                    "call_refs": 1,
                    "data_refs": 0,
                }
            ]
        },
    )
    assert len(result.functions) == 1
    assert result.functions[0].name == "sym_imp_strncpy"
    assert result.functions[0].data_refs == 0


def test_load_functions_not_in_data_skips() -> None:
    result = AnalysisResult()
    _load_functions(result, {})
    assert result.functions == []


# ---------------------------------------------------------------------------
# _load_anti_analysis (lines 210-213)
# ---------------------------------------------------------------------------


def test_load_anti_analysis_with_data() -> None:
    result = AnalysisResult()
    _load_anti_analysis(
        result,
        {
            "anti_analysis": {
                "anti_debug": True,
                "anti_vm": False,
                "anti_sandbox": True,
                "timing_checks": True,
                "techniques": ["VirtualPC_check", "cpuid"],
            }
        },
    )
    assert result.anti_analysis is not None
    assert result.anti_analysis.anti_debug is True
    assert result.anti_analysis.timing_checks is True
    assert "cpuid" in result.anti_analysis.techniques


def test_load_anti_analysis_not_in_data_skips() -> None:
    result = AnalysisResult()
    _load_anti_analysis(result, {})
    assert result.anti_analysis.anti_debug is False


# ---------------------------------------------------------------------------
# _load_packer (lines 223-226)
# ---------------------------------------------------------------------------


def test_load_packer_with_data() -> None:
    result = AnalysisResult()
    _load_packer(
        result,
        {
            "packer": {
                "is_packed": True,
                "packer_type": "Themida",
                "confidence": 95,
                "indicators": ["obfuscated_ep", "virtualization"],
            }
        },
    )
    assert result.packer.is_packed is True
    assert result.packer.packer_type == "Themida"
    assert result.packer.confidence == 95


def test_load_packer_not_in_data_skips() -> None:
    result = AnalysisResult()
    _load_packer(result, {})
    assert result.packer.is_packed is False


# ---------------------------------------------------------------------------
# _load_crypto (lines 235-238)
# ---------------------------------------------------------------------------


def test_load_crypto_with_data() -> None:
    result = AnalysisResult()
    _load_crypto(
        result,
        {
            "crypto": {
                "algorithms": ["ChaCha20", "Poly1305"],
                "constants": ["0x61707865"],
                "functions": ["chacha_block", "poly1305_update"],
            }
        },
    )
    assert result.crypto.algorithms == ["ChaCha20", "Poly1305"]
    assert len(result.crypto.functions) == 2


def test_load_crypto_not_in_data_skips() -> None:
    result = AnalysisResult()
    _load_crypto(result, {})
    assert result.crypto.algorithms == []


# ---------------------------------------------------------------------------
# _load_indicators (lines 246-249)
# ---------------------------------------------------------------------------


def test_load_indicators_with_entries() -> None:
    result = AnalysisResult()
    _load_indicators(
        result,
        {
            "indicators": [
                {
                    "type": "c2_communication",
                    "description": "Found hardcoded C2 URL",
                    "severity": "Critical",
                },
                {
                    "type": "keylogger",
                    "description": "Hooks keyboard input",
                    "severity": "High",
                },
            ]
        },
    )
    assert len(result.indicators) == 2
    assert result.indicators[0].type == "c2_communication"
    assert result.indicators[0].severity == "Critical"


def test_load_indicators_not_in_data_skips() -> None:
    result = AnalysisResult()
    _load_indicators(result, {})
    assert result.indicators == []


# ---------------------------------------------------------------------------
# _load_error (line 260)
# ---------------------------------------------------------------------------


def test_load_error_sets_error_field() -> None:
    result = AnalysisResult()
    _load_error(result, {"error": "timeout during analysis"})
    assert result.error == "timeout during analysis"


def test_load_error_none_value() -> None:
    result = AnalysisResult()
    _load_error(result, {"error": None})
    assert result.error is None


def test_load_error_missing_key_sets_none() -> None:
    result = AnalysisResult()
    _load_error(result, {})
    assert result.error is None


# ---------------------------------------------------------------------------
# _load_timestamp (lines 264-273)
# ---------------------------------------------------------------------------


def test_load_timestamp_valid_iso_string() -> None:
    result = AnalysisResult()
    _load_timestamp(result, {"timestamp": "2025-01-01T00:00:00"})
    assert result.timestamp == datetime(2025, 1, 1, 0, 0, 0)


def test_load_timestamp_invalid_string_keeps_default() -> None:
    result = AnalysisResult()
    original = result.timestamp
    _load_timestamp(result, {"timestamp": "not-a-timestamp"})
    assert result.timestamp == original


def test_load_timestamp_datetime_instance() -> None:
    result = AnalysisResult()
    dt = datetime(2023, 6, 15, 12, 30, 0)
    _load_timestamp(result, {"timestamp": dt})
    assert result.timestamp == dt


def test_load_timestamp_none_value_skips() -> None:
    result = AnalysisResult()
    original = result.timestamp
    _load_timestamp(result, {"timestamp": None})
    assert result.timestamp == original


def test_load_timestamp_missing_key_skips() -> None:
    result = AnalysisResult()
    original = result.timestamp
    _load_timestamp(result, {})
    assert result.timestamp == original


# ---------------------------------------------------------------------------
# _load_execution_time (line 277)
# ---------------------------------------------------------------------------


def test_load_execution_time_sets_value() -> None:
    result = AnalysisResult()
    _load_execution_time(result, {"execution_time": 12.345})
    assert result.execution_time == 12.345


def test_load_execution_time_missing_uses_default() -> None:
    result = AnalysisResult()
    _load_execution_time(result, {})
    assert result.execution_time == 0.0


# ---------------------------------------------------------------------------
# Full round-trip with all fields
# ---------------------------------------------------------------------------


def test_from_dict_full_round_trip() -> None:
    data: dict = {
        "file_info": {
            "name": "ransomware.exe",
            "path": "/samples/ransomware.exe",
            "size": 131072,
            "md5": "deadbeef",
            "sha1": "cafebabe0000",
            "sha256": "0" * 64,
            "file_type": "PE32",
            "architecture": "x86",
            "bits": 32,
            "endian": "little",
            "mime_type": "application/x-dosexec",
        },
        "hashing": {"ssdeep": "3:hash:val", "tlsh": "T001"},
        "security": {"nx": True, "pie": False},
        "imports": [{"name": "CryptEncrypt", "library": "advapi32.dll"}],
        "exports": [{"name": "DllMain", "address": "0x1000"}],
        "sections": [{"name": ".text", "entropy": 7.8, "is_executable": True}],
        "strings": ["ENCRYPTION KEY", "README_HOW_TO.txt"],
        "yara_matches": [{"rule": "Detect_Ransomware", "namespace": "malware"}],
        "functions": [{"name": "encrypt_files", "address": 0x5000, "size": 800}],
        "anti_analysis": {"anti_debug": True, "anti_vm": True},
        "packer": {"is_packed": False},
        "crypto": {"algorithms": ["RSA-2048"]},
        "indicators": [{"type": "ransomware", "severity": "Critical"}],
        "error": None,
        "timestamp": "2024-06-01T09:00:00",
        "execution_time": 2.5,
    }
    result = from_dict(data)
    assert result.file_info.name == "ransomware.exe"
    assert result.hashing.ssdeep == "3:hash:val"
    assert result.security.nx is True
    assert len(result.imports) == 1
    assert len(result.exports) == 1
    assert len(result.sections) == 1
    assert result.strings == ["ENCRYPTION KEY", "README_HOW_TO.txt"]
    assert len(result.yara_matches) == 1
    assert len(result.functions) == 1
    assert result.anti_analysis.anti_debug is True
    assert result.packer.is_packed is False
    assert result.crypto.algorithms == ["RSA-2048"]
    assert len(result.indicators) == 1
    assert result.error is None
    assert result.timestamp == datetime(2024, 6, 1, 9, 0, 0)
    assert result.execution_time == 2.5
