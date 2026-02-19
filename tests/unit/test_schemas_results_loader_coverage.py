"""Coverage tests for r2inspect/schemas/results_loader.py"""

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


def test_from_dict_empty_returns_default_result():
    result = from_dict({})
    assert isinstance(result, AnalysisResult)
    assert result.error is None
    assert result.execution_time == 0.0
    # Defaults are populated by AnalysisResult dataclass factories
    assert result.imports == []
    assert result.exports == []
    assert result.sections == []
    assert result.strings == []
    assert result.yara_matches == []
    assert result.functions == []
    assert result.indicators == []


def test_from_dict_with_file_info():
    data = {
        "file_info": {
            "name": "test.exe",
            "path": "/tmp/test.exe",
            "size": 1024,
            "md5": "abc123",
            "sha1": "def456",
            "sha256": "ghi789",
            "file_type": "PE",
            "architecture": "x86",
            "bits": 32,
            "endian": "little",
            "mime_type": "application/x-dosexec",
        }
    }
    result = from_dict(data)
    assert result.file_info is not None
    assert result.file_info.name == "test.exe"
    assert result.file_info.size == 1024
    assert result.file_info.architecture == "x86"


def test_from_dict_with_hashing():
    data = {
        "hashing": {
            "ssdeep": "3:abc",
            "tlsh": "T1234",
            "imphash": "imp123",
            "impfuzzy": "fuzzy",
            "ccbhash": "ccb",
            "simhash": "sim",
            "telfhash": "telf",
            "rich_hash": "rich",
            "machoc_hash": "machoc",
        }
    }
    result = from_dict(data)
    assert result.hashing is not None
    assert result.hashing.ssdeep == "3:abc"
    assert result.hashing.tlsh == "T1234"


def test_from_dict_with_security():
    data = {
        "security": {
            "nx": True,
            "pie": True,
            "canary": True,
            "dep": False,
            "stack_canary": True,
            "relro": "full",
            "aslr": True,
            "seh": False,
            "guard_cf": False,
            "authenticode": False,
            "fortify": True,
            "rpath": False,
            "runpath": False,
            "high_entropy_va": True,
        }
    }
    result = from_dict(data)
    assert result.security is not None
    assert result.security.nx is True
    assert result.security.relro == "full"


def test_from_dict_with_imports():
    data = {
        "imports": [
            {
                "name": "CreateFile",
                "library": "kernel32.dll",
                "address": "0x1000",
                "ordinal": 0,
                "category": "file",
                "risk_score": 3,
                "risk_level": "Medium",
                "risk_tags": ["file_ops"],
            }
        ]
    }
    result = from_dict(data)
    assert result.imports is not None
    assert len(result.imports) == 1
    assert result.imports[0].name == "CreateFile"
    assert result.imports[0].risk_level == "Medium"


def test_from_dict_with_exports():
    data = {
        "exports": [
            {"name": "DllMain", "address": "0x2000", "ordinal": 1, "size": 100}
        ]
    }
    result = from_dict(data)
    assert result.exports is not None
    assert len(result.exports) == 1
    assert result.exports[0].name == "DllMain"
    assert result.exports[0].ordinal == 1


def test_from_dict_with_sections():
    data = {
        "sections": [
            {
                "name": ".text",
                "virtual_address": 0x1000,
                "virtual_size": 0x2000,
                "raw_size": 0x2000,
                "entropy": 6.5,
                "permissions": "r-x",
                "is_executable": True,
                "is_writable": False,
                "is_readable": True,
                "flags": "CODE",
                "suspicious_indicators": [],
            }
        ]
    }
    result = from_dict(data)
    assert result.sections is not None
    assert len(result.sections) == 1
    assert result.sections[0].name == ".text"
    assert result.sections[0].entropy == 6.5


def test_from_dict_with_strings():
    data = {"strings": ["hello", "world", "kernel32"]}
    result = from_dict(data)
    assert result.strings == ["hello", "world", "kernel32"]


def test_from_dict_strings_empty_list():
    data = {"strings": []}
    result = from_dict(data)
    assert result.strings == []


def test_from_dict_with_yara_matches():
    data = {
        "yara_matches": [
            {
                "rule": "MalwareRule",
                "namespace": "default",
                "tags": ["malware", "trojan"],
                "meta": {"author": "analyst"},
                "strings": ["$str1"],
            }
        ]
    }
    result = from_dict(data)
    assert result.yara_matches is not None
    assert len(result.yara_matches) == 1
    assert result.yara_matches[0].rule == "MalwareRule"
    assert result.yara_matches[0].tags == ["malware", "trojan"]


def test_from_dict_with_functions():
    data = {
        "functions": [
            {
                "name": "main",
                "address": 0x1000,
                "size": 200,
                "complexity": 5,
                "basic_blocks": 8,
                "call_refs": 3,
                "data_refs": 1,
            }
        ]
    }
    result = from_dict(data)
    assert result.functions is not None
    assert len(result.functions) == 1
    assert result.functions[0].name == "main"
    assert result.functions[0].complexity == 5


def test_from_dict_with_anti_analysis():
    data = {
        "anti_analysis": {
            "anti_debug": True,
            "anti_vm": True,
            "anti_sandbox": False,
            "timing_checks": True,
            "techniques": ["IsDebuggerPresent", "RDTSC"],
        }
    }
    result = from_dict(data)
    assert result.anti_analysis is not None
    assert result.anti_analysis.anti_debug is True
    assert result.anti_analysis.techniques == ["IsDebuggerPresent", "RDTSC"]


def test_from_dict_with_packer():
    data = {
        "packer": {
            "is_packed": True,
            "packer_type": "UPX",
            "confidence": 90,
            "indicators": ["high_entropy", "small_sections"],
        }
    }
    result = from_dict(data)
    assert result.packer is not None
    assert result.packer.is_packed is True
    assert result.packer.packer_type == "UPX"


def test_from_dict_with_crypto():
    data = {
        "crypto": {
            "algorithms": ["AES", "RC4"],
            "constants": ["0xDEADBEEF"],
            "functions": ["encrypt_data"],
        }
    }
    result = from_dict(data)
    assert result.crypto is not None
    assert result.crypto.algorithms == ["AES", "RC4"]


def test_from_dict_with_indicators():
    data = {
        "indicators": [
            {
                "type": "suspicious_import",
                "description": "Loads kernel32",
                "severity": "High",
            }
        ]
    }
    result = from_dict(data)
    assert result.indicators is not None
    assert len(result.indicators) == 1
    assert result.indicators[0].severity == "High"


def test_from_dict_with_error():
    data = {"error": "Analysis failed: file not found"}
    result = from_dict(data)
    assert result.error == "Analysis failed: file not found"


def test_from_dict_error_none():
    data = {"error": None}
    result = from_dict(data)
    assert result.error is None


def test_from_dict_with_timestamp_string_valid():
    data = {"timestamp": "2024-01-15T10:30:00"}
    result = from_dict(data)
    assert result.timestamp is not None
    assert result.timestamp == datetime(2024, 1, 15, 10, 30, 0)


def test_from_dict_with_timestamp_string_invalid():
    data = {"timestamp": "not-a-date"}
    result = from_dict(data)
    # Invalid string -> ValueError caught, timestamp keeps default
    assert result.timestamp is not None


def test_from_dict_with_timestamp_datetime_object():
    dt = datetime(2024, 6, 1, 12, 0, 0)
    data = {"timestamp": dt}
    result = from_dict(data)
    assert result.timestamp == dt


def test_from_dict_timestamp_none():
    data = {"timestamp": None}
    result = from_dict(data)
    # timestamp is None in dict -> _load_timestamp skips
    assert result.timestamp is not None  # keeps default


def test_from_dict_with_execution_time():
    data = {"execution_time": 3.14}
    result = from_dict(data)
    assert result.execution_time == 3.14


def test_from_dict_execution_time_default():
    result = from_dict({})
    assert result.execution_time == 0.0


def test_load_file_info_with_defaults():
    result = AnalysisResult()
    _load_file_info(result, {"file_info": {}})
    assert result.file_info is not None
    assert result.file_info.name == ""
    assert result.file_info.size == 0


def test_load_file_info_missing():
    result = AnalysisResult()
    original = result.file_info
    _load_file_info(result, {})
    assert result.file_info is original


def test_load_hashing_missing():
    result = AnalysisResult()
    original = result.hashing
    _load_hashing(result, {})
    assert result.hashing is original


def test_load_security_missing():
    result = AnalysisResult()
    original = result.security
    _load_security(result, {})
    assert result.security is original


def test_load_imports_missing():
    result = AnalysisResult()
    _load_imports(result, {})
    assert result.imports == []


def test_load_imports_empty_list():
    result = AnalysisResult()
    _load_imports(result, {"imports": []})
    assert result.imports == []


def test_load_exports_missing():
    result = AnalysisResult()
    _load_exports(result, {})
    assert result.exports == []


def test_load_exports_empty_list():
    result = AnalysisResult()
    _load_exports(result, {"exports": []})
    assert result.exports == []


def test_load_sections_missing():
    result = AnalysisResult()
    _load_sections(result, {})
    assert result.sections == []


def test_load_sections_empty_list():
    result = AnalysisResult()
    _load_sections(result, {"sections": []})
    assert result.sections == []


def test_load_strings_missing():
    result = AnalysisResult()
    _load_strings(result, {})
    assert result.strings == []


def test_load_yara_matches_missing():
    result = AnalysisResult()
    _load_yara_matches(result, {})
    assert result.yara_matches == []


def test_load_yara_matches_empty():
    result = AnalysisResult()
    _load_yara_matches(result, {"yara_matches": []})
    assert result.yara_matches == []


def test_load_functions_missing():
    result = AnalysisResult()
    _load_functions(result, {})
    assert result.functions == []


def test_load_functions_empty():
    result = AnalysisResult()
    _load_functions(result, {"functions": []})
    assert result.functions == []


def test_load_anti_analysis_missing():
    result = AnalysisResult()
    _load_anti_analysis(result, {})
    assert result.anti_analysis.anti_debug is False


def test_load_packer_missing():
    result = AnalysisResult()
    _load_packer(result, {})
    assert result.packer.is_packed is False


def test_load_crypto_missing():
    result = AnalysisResult()
    _load_crypto(result, {})
    assert result.crypto.algorithms == []


def test_load_indicators_missing():
    result = AnalysisResult()
    _load_indicators(result, {})
    assert result.indicators == []


def test_load_indicators_empty():
    result = AnalysisResult()
    _load_indicators(result, {"indicators": []})
    assert result.indicators == []


def test_load_error_present():
    result = AnalysisResult()
    _load_error(result, {"error": "some error"})
    assert result.error == "some error"


def test_load_timestamp_missing():
    result = AnalysisResult()
    _load_timestamp(result, {})
    # timestamp unchanged (still the default)
    assert result.timestamp is not None


def test_load_execution_time_present():
    result = AnalysisResult()
    _load_execution_time(result, {"execution_time": 2.5})
    assert result.execution_time == 2.5


def test_load_execution_time_missing():
    result = AnalysisResult()
    _load_execution_time(result, {})
    assert result.execution_time == 0.0


def test_from_dict_full_data():
    data = {
        "file_info": {"name": "malware.exe", "path": "/tmp/malware.exe", "size": 4096},
        "hashing": {"ssdeep": "6:abcdef"},
        "security": {"nx": True, "pie": False},
        "imports": [{"name": "LoadLibrary", "library": "kernel32.dll"}],
        "exports": [{"name": "DllEntryPoint", "address": "0x100"}],
        "sections": [{"name": ".rdata", "virtual_address": 0x3000, "virtual_size": 0x100}],
        "strings": ["notepad.exe", "cmd.exe"],
        "yara_matches": [{"rule": "Detect_UPX", "namespace": "ns"}],
        "functions": [{"name": "sub_1000", "address": 0x1000, "size": 50}],
        "anti_analysis": {"anti_debug": False, "anti_vm": True},
        "packer": {"is_packed": False, "packer_type": ""},
        "crypto": {"algorithms": ["XOR"]},
        "indicators": [{"type": "network", "description": "URL found", "severity": "Low"}],
        "error": None,
        "timestamp": "2024-03-01T09:00:00",
        "execution_time": 1.23,
    }
    result = from_dict(data)
    assert result.file_info.name == "malware.exe"
    assert result.hashing.ssdeep == "6:abcdef"
    assert result.security.nx is True
    assert result.strings == ["notepad.exe", "cmd.exe"]
    assert result.execution_time == 1.23
