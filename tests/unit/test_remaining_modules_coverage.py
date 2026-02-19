#!/usr/bin/env python3
"""Unit tests for remaining modules (items 12-22)."""

# ---------------------------------------------------------------------------
# 12. exploit_mitigation_rules
# ---------------------------------------------------------------------------
from r2inspect.modules.exploit_mitigation_rules import (
    DLL_CHARACTERISTICS,
    generate_recommendations,
)


def _full_disabled_result():
    return {
        "mitigations": {
            "ASLR": {"enabled": False, "high_entropy": False},
            "DEP": {"enabled": False},
            "CFG": {"enabled": False},
            "Integrity": {"enabled": False},
            "StackCookies": {"enabled": False},
            "SafeSEH": {"enabled": False},
            "Authenticode": {"enabled": False},
        },
        "pe_info": {"is_64bit": False},
    }


def test_generate_recommendations_all_disabled():
    result = _full_disabled_result()
    recs = generate_recommendations(result)
    types = [r["mitigation"] for r in recs]
    assert "ASLR" in types
    assert "DEP/NX" in types
    assert "Control Flow Guard" in types
    assert "Stack Cookies" in types


def test_generate_recommendations_aslr_no_high_entropy():
    result = _full_disabled_result()
    result["mitigations"]["ASLR"] = {"enabled": True, "high_entropy": False}
    recs = generate_recommendations(result)
    types = [r["mitigation"] for r in recs]
    assert "High Entropy ASLR" in types


def test_generate_recommendations_safeseh_32bit():
    result = _full_disabled_result()
    result["pe_info"]["is_64bit"] = False
    recs = generate_recommendations(result)
    types = [r["mitigation"] for r in recs]
    assert "SafeSEH" in types


def test_generate_recommendations_safeseh_64bit_skipped():
    result = _full_disabled_result()
    result["pe_info"]["is_64bit"] = True
    recs = generate_recommendations(result)
    types = [r["mitigation"] for r in recs]
    assert "SafeSEH" not in types


def test_dll_characteristics_has_key():
    assert 0x0040 in DLL_CHARACTERISTICS
    assert DLL_CHARACTERISTICS[0x0040] == "DYNAMIC_BASE"
    assert 0x0100 in DLL_CHARACTERISTICS
    assert DLL_CHARACTERISTICS[0x0100] == "NX_COMPAT"


# ---------------------------------------------------------------------------
# 14. search_helpers
# ---------------------------------------------------------------------------
from r2inspect.modules.search_helpers import search_hex, search_text


class _SearchStub:
    def search_text(self, pattern):
        return f"text:{pattern}"

    def search_hex(self, pattern):
        return f"hex:{pattern}"


def test_search_text_with_adapter():
    stub = _SearchStub()
    result = search_text(stub, None, "hello")
    assert result == "text:hello"


def test_search_text_no_adapter():
    assert search_text(None, None, "hello") == ""


def test_search_text_strips_whitespace():
    stub = _SearchStub()
    result = search_text(stub, None, "  hello  ")
    assert result == "text:hello"


def test_search_hex_with_adapter():
    stub = _SearchStub()
    result = search_hex(stub, None, "deadbeef")
    assert result == "hex:deadbeef"


def test_search_hex_no_adapter():
    assert search_hex(None, None, "deadbeef") == ""


# ---------------------------------------------------------------------------
# 15. string_classification
# ---------------------------------------------------------------------------
from r2inspect.modules.string_classification import (
    classify_string_type,
    is_api_string,
    is_path_string,
    is_registry_string,
    is_url_string,
)


def test_is_api_string_true():
    assert is_api_string("CreateFileW") is True
    assert is_api_string("GetProcAddress") is True
    assert is_api_string("LoadLibraryA") is True


def test_is_api_string_false():
    assert is_api_string("printf") is False
    assert is_api_string("hello world") is False


def test_is_path_string_backslash():
    assert is_path_string("C:\\Windows\\System32") is True


def test_is_path_string_forward_slash():
    assert is_path_string("/etc/passwd") is True


def test_is_path_string_too_short():
    assert is_path_string("a/b") is False


def test_is_path_string_url_excluded():
    assert is_path_string("http://evil.com/path") is False


def test_is_url_string_http():
    assert is_url_string("http://example.com") is True


def test_is_url_string_https():
    assert is_url_string("https://example.com") is True


def test_is_url_string_ftp():
    assert is_url_string("ftp://files.example.com") is True


def test_is_url_string_false():
    assert is_url_string("not a url") is False
    assert is_url_string("C:\\path") is False


def test_is_registry_string_hkey():
    assert is_registry_string("HKEY_LOCAL_MACHINE\\Software") is True


def test_is_registry_string_hklm():
    assert is_registry_string("HKLM\\Software") is True


def test_is_registry_string_hkcu():
    assert is_registry_string("HKCU\\Software\\App") is True


def test_is_registry_string_software_backslash():
    assert is_registry_string("SOFTWARE\\Microsoft") is True


def test_is_registry_string_false():
    assert is_registry_string("hello world") is False


def test_classify_string_type_url():
    assert classify_string_type("https://evil.com") == "url"


def test_classify_string_type_path_windows():
    assert classify_string_type("C:\\Windows\\system32\\cmd.exe") == "path"


def test_classify_string_type_path_unix():
    assert classify_string_type("/etc/passwd") == "path"


def test_classify_string_type_registry():
    assert classify_string_type("HKEY_LOCAL_MACHINE\\Software") == "registry"


def test_classify_string_type_error_string():
    assert classify_string_type("error occurred") == "error"


def test_classify_string_type_none():
    assert classify_string_type("plaintext") is None


# ---------------------------------------------------------------------------
# 16. output_json
# ---------------------------------------------------------------------------
import json

from r2inspect.utils.output_json import JsonOutputFormatter


def test_json_output_formatter_basic():
    data = {"key": "value", "number": 42}
    formatter = JsonOutputFormatter(data)
    output = formatter.to_json()
    parsed = json.loads(output)
    assert parsed["key"] == "value"
    assert parsed["number"] == 42


def test_json_output_formatter_indent():
    data = {"a": 1}
    formatter = JsonOutputFormatter(data)
    output = formatter.to_json(indent=4)
    assert "    " in output  # 4-space indent


def test_json_output_formatter_non_serializable():
    class _Custom:
        def __str__(self):
            return "custom_obj"

    data = {"obj": _Custom()}
    formatter = JsonOutputFormatter(data)
    output = formatter.to_json()
    parsed = json.loads(output)
    assert "custom_obj" in parsed["obj"]


def test_json_output_formatter_nested():
    data = {"nested": {"a": [1, 2, 3]}}
    formatter = JsonOutputFormatter(data)
    output = formatter.to_json()
    parsed = json.loads(output)
    assert parsed["nested"]["a"] == [1, 2, 3]


# ---------------------------------------------------------------------------
# 19. macho_security_domain
# ---------------------------------------------------------------------------
from r2inspect.modules.macho_security_domain import has_arc
from r2inspect.modules.macho_security_domain import has_stack_canary as macho_has_stack_canary
from r2inspect.modules.macho_security_domain import is_encrypted, is_signed
from r2inspect.modules.macho_security_domain import is_pie as macho_is_pie


def test_macho_is_pie_dylib():
    info = {"bin": {"filetype": "DYLIB"}}
    assert macho_is_pie(info) is True


def test_macho_is_pie_with_pie():
    info = {"bin": {"filetype": "MH_PIE"}}
    assert macho_is_pie(info) is True


def test_macho_is_pie_not():
    info = {"bin": {"filetype": "EXEC"}}
    assert macho_is_pie(info) is False


def test_macho_is_pie_missing_bin():
    assert macho_is_pie(None) is False
    assert macho_is_pie({}) is False


def test_macho_has_stack_canary_true():
    symbols = [{"name": "___stack_chk_fail"}]
    assert macho_has_stack_canary(symbols) is True


def test_macho_has_stack_canary_guard():
    symbols = [{"name": "___stack_chk_guard"}]
    assert macho_has_stack_canary(symbols) is True


def test_macho_has_stack_canary_false():
    symbols = [{"name": "printf"}]
    assert macho_has_stack_canary(symbols) is False


def test_macho_has_stack_canary_none():
    assert macho_has_stack_canary(None) is False


def test_macho_has_arc_true():
    symbols = [{"name": "_objc_retain"}]
    assert has_arc(symbols) is True


def test_macho_has_arc_release():
    symbols = [{"name": "_objc_release"}]
    assert has_arc(symbols) is True


def test_macho_has_arc_false():
    symbols = [{"name": "malloc"}]
    assert has_arc(symbols) is False


def test_macho_is_encrypted_true():
    headers = [{"type": "LC_ENCRYPTION_INFO", "cryptid": 1}]
    assert is_encrypted(headers) is True


def test_macho_is_encrypted_zero_cryptid():
    headers = [{"type": "LC_ENCRYPTION_INFO", "cryptid": 0}]
    assert is_encrypted(headers) is False


def test_macho_is_encrypted_wrong_type():
    headers = [{"type": "LC_LOAD_DYLIB"}]
    assert is_encrypted(headers) is False


def test_macho_is_encrypted_none():
    assert is_encrypted(None) is False


def test_macho_is_signed_true():
    headers = [{"type": "LC_CODE_SIGNATURE"}]
    assert is_signed(headers) is True


def test_macho_is_signed_false():
    headers = [{"type": "LC_LOAD_DYLIB"}]
    assert is_signed(headers) is False


def test_macho_is_signed_none():
    assert is_signed(None) is False


# ---------------------------------------------------------------------------
# 21. elf_security_domain
# ---------------------------------------------------------------------------
from r2inspect.modules.elf_security_domain import has_nx, has_relro, path_features
from r2inspect.modules.elf_security_domain import has_stack_canary as elf_has_stack_canary
from r2inspect.modules.elf_security_domain import is_pie as elf_is_pie


def test_elf_has_nx_true():
    headers = [{"type": "GNU_STACK", "flags": "rw"}]
    assert has_nx(headers) is True


def test_elf_has_nx_false_executable():
    headers = [{"type": "GNU_STACK", "flags": "rwx"}]
    assert has_nx(headers) is False


def test_elf_has_nx_no_gnu_stack():
    headers = [{"type": "LOAD", "flags": "rx"}]
    assert has_nx(headers) is False


def test_elf_has_nx_empty():
    assert has_nx([]) is False
    assert has_nx(None) is False


def test_elf_has_stack_canary_true():
    symbols = [{"name": "__stack_chk_fail"}]
    assert elf_has_stack_canary(symbols) is True


def test_elf_has_stack_canary_guard():
    symbols = [{"name": "__stack_chk_guard"}]
    assert elf_has_stack_canary(symbols) is True


def test_elf_has_stack_canary_false():
    assert elf_has_stack_canary([{"name": "printf"}]) is False


def test_elf_has_stack_canary_none():
    assert elf_has_stack_canary(None) is False


def test_elf_has_relro_true():
    assert has_relro("BIND_NOW 0x1") is True


def test_elf_has_relro_false():
    assert has_relro("NEEDED libc.so") is False
    assert has_relro(None) is False
    assert has_relro("") is False


def test_elf_is_pie_dyn():
    info = {"bin": {"class": "DYN"}}
    assert elf_is_pie(info) is True


def test_elf_is_pie_exec():
    info = {"bin": {"class": "EXEC"}}
    assert elf_is_pie(info) is False


def test_elf_is_pie_missing():
    assert elf_is_pie(None) is False
    assert elf_is_pie({}) is False


def test_elf_path_features_rpath():
    result = path_features("RPATH /usr/local/lib")
    assert result["rpath"] is True
    assert result["runpath"] is False


def test_elf_path_features_runpath():
    result = path_features("RUNPATH /opt/lib")
    assert result["runpath"] is True
    assert result["rpath"] is False


def test_elf_path_features_none():
    result = path_features(None)
    assert result["rpath"] is False
    assert result["runpath"] is False


# ---------------------------------------------------------------------------
# 22. authenticode_analyzer – test pure utility methods via a stub adapter
# ---------------------------------------------------------------------------
from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer


class _StubAdapter:
    """Minimal stub: all commands return empty so analyze() exits cleanly."""

    def cmdj(self, cmd):
        return {}

    def cmd(self, cmd):
        return ""


def _make_analyzer():
    return AuthenticodeAnalyzer(_StubAdapter())


def test_authenticode_get_cert_type_name_known():
    a = _make_analyzer()
    assert a._get_cert_type_name(0x0001) == "X.509"
    assert a._get_cert_type_name(0x0002) == "PKCS#7"
    assert a._get_cert_type_name(0x0003) == "RESERVED"
    assert a._get_cert_type_name(0x0004) == "TS_STACK_SIGNED"


def test_authenticode_get_cert_type_name_unknown():
    a = _make_analyzer()
    result = a._get_cert_type_name(0x9999)
    assert "UNKNOWN" in result
    assert "0x9999" in result


def test_authenticode_parse_win_cert_header():
    a = _make_analyzer()
    # little-endian: length=0x00000100, revision=0x0200, type=0x0002
    data = [0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00]
    length, revision, cert_type = a._parse_win_cert_header(data)
    assert length == 0x00000100
    assert revision == 0x0200
    assert cert_type == 0x0002


def test_authenticode_find_pattern_true():
    a = _make_analyzer()
    data = [0x00, 0x01, 0x02, 0x03, 0x04]
    assert a._find_pattern(data, [0x01, 0x02, 0x03]) is True


def test_authenticode_find_pattern_false():
    a = _make_analyzer()
    data = [0x00, 0x01, 0x02]
    assert a._find_pattern(data, [0x03, 0x04]) is False


def test_authenticode_find_pattern_empty():
    a = _make_analyzer()
    assert a._find_pattern([], [0x01]) is False


def test_authenticode_find_all_patterns():
    a = _make_analyzer()
    data = [0x01, 0x02, 0x00, 0x01, 0x02]
    positions = a._find_all_patterns(data, [0x01, 0x02])
    assert positions == [0, 3]


def test_authenticode_detect_digest_sha256():
    a = _make_analyzer()
    sha256_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
    data = [0x00] * 5 + sha256_oid + [0x00] * 5
    assert a._detect_digest_algorithm(data) == "SHA256"


def test_authenticode_detect_digest_sha1():
    a = _make_analyzer()
    sha1_oid = [0x2B, 0x0E, 0x03, 0x02, 0x1A]
    data = [0x00] * 5 + sha1_oid + [0x00] * 5
    assert a._detect_digest_algorithm(data) == "SHA1"


def test_authenticode_detect_digest_none():
    a = _make_analyzer()
    assert a._detect_digest_algorithm([0x00, 0x01, 0x02]) is None


def test_authenticode_detect_encryption_rsa():
    a = _make_analyzer()
    rsa_oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
    data = [0x00] * 3 + rsa_oid + [0x00] * 3
    assert a._detect_encryption_algorithm(data) == "RSA"


def test_authenticode_detect_encryption_none():
    a = _make_analyzer()
    assert a._detect_encryption_algorithm([0x00, 0x01]) is None


def test_authenticode_verify_signature_no_sig():
    a = _make_analyzer()
    sig_info = {"has_signature": False, "certificates": [], "errors": [], "security_directory": None}
    assert a._verify_signature_integrity(sig_info) is False


def test_authenticode_verify_signature_no_certs():
    a = _make_analyzer()
    sig_info = {
        "has_signature": True,
        "certificates": [],
        "errors": [],
        "security_directory": {"size": 100},
    }
    assert a._verify_signature_integrity(sig_info) is False


def test_authenticode_verify_signature_with_errors():
    a = _make_analyzer()
    sig_info = {
        "has_signature": True,
        "certificates": [{"type": "PKCS#7"}],
        "errors": ["some error"],
        "security_directory": {"size": 100},
    }
    assert a._verify_signature_integrity(sig_info) is False


def test_authenticode_verify_signature_zero_size():
    a = _make_analyzer()
    sig_info = {
        "has_signature": True,
        "certificates": [{"type": "PKCS#7"}],
        "errors": [],
        "security_directory": {"size": 0},
    }
    assert a._verify_signature_integrity(sig_info) is False


def test_authenticode_analyze_no_headers():
    """analyze() should return available=False when headers are missing."""
    a = _make_analyzer()
    result = a.analyze()
    # With stub returning empty dicts, _has_required_headers returns False
    assert result["available"] is False


# ---------------------------------------------------------------------------
# 13. pe_analyzer – test static/metadata methods via stub adapter
# ---------------------------------------------------------------------------
from r2inspect.modules.pe_analyzer import PEAnalyzer


class _PEStubAdapter:
    def cmdj(self, cmd):
        return {}

    def cmd(self, cmd):
        return ""

    def get_imports(self):
        return []

    def get_symbols(self):
        return []

    def get_file_info(self):
        return {}


def test_pe_analyzer_get_category():
    a = PEAnalyzer(_PEStubAdapter())
    assert a.get_category() == "format"


def test_pe_analyzer_get_description():
    a = PEAnalyzer(_PEStubAdapter())
    desc = a.get_description()
    assert "PE" in desc


def test_pe_analyzer_supports_format():
    a = PEAnalyzer(_PEStubAdapter())
    assert a.supports_format("PE") is True
    assert a.supports_format("pe32") is True
    assert a.supports_format("ELF") is False


def test_pe_analyzer_analyze_returns_dict():
    a = PEAnalyzer(_PEStubAdapter())
    result = a.analyze()
    assert isinstance(result, dict)
    assert "format" in result


# ---------------------------------------------------------------------------
# 18. macho_security – test pure domain helpers via stub adapter
# ---------------------------------------------------------------------------
from r2inspect.modules.macho_security import _get_headers, _get_info, get_security_features


class _MachoStubAdapter:
    def get_symbols(self):
        return []

    def get_headers_json(self):
        return []

    def get_file_info(self):
        return {}


class _MachoLogger:
    def error(self, msg):
        pass


def test_macho_get_headers_none_adapter():
    assert _get_headers(None) == []


def test_macho_get_headers_list():
    class Stub:
        def get_headers_json(self):
            return [{"type": "LC_CODE_SIGNATURE"}]

    result = _get_headers(Stub())
    assert result == [{"type": "LC_CODE_SIGNATURE"}]


def test_macho_get_headers_dict_wrapped():
    class Stub:
        def get_headers_json(self):
            return {"type": "LC_CODE_SIGNATURE"}

    result = _get_headers(Stub())
    assert result == [{"type": "LC_CODE_SIGNATURE"}]


def test_macho_get_info_none_adapter():
    assert _get_info(None) is None


def test_macho_get_info_empty():
    class Stub:
        def get_file_info(self):
            return {}

    # Empty dict is falsy → _get_info returns None
    assert _get_info(Stub()) is None


def test_macho_get_security_features_basic():
    result = get_security_features(_MachoStubAdapter(), _MachoLogger())
    assert isinstance(result, dict)
    assert "pie" in result
    assert "stack_canary" in result
    assert "arc" in result
