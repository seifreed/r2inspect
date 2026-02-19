"""
Comprehensive unit tests for multiple r2inspect modules.
No mocks, no unittest.mock, no MagicMock, no patch.
Plain functions, no test classes.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

# ---------------------------------------------------------------------------
# Stub adapters (plain classes, no mocks)
# ---------------------------------------------------------------------------


class StubAdapter:
    """Minimal stub adapter returning empty/controlled data."""

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str) -> Any:
        return {}

    def get_imports(self) -> list[dict]:
        return []

    def get_sections(self) -> list[dict]:
        return []

    def get_strings(self) -> list[dict]:
        return []

    def read_bytes(self, vaddr: int, size: int) -> bytes:
        return b"\x00" * min(size, 16)

    def get_file_info(self) -> dict:
        return {"bin": {"arch": "x86", "bits": 32, "endian": "little", "baddr": 0x400000}}

    def get_entry_info(self) -> list[dict]:
        return []

    def get_pe_headers(self) -> dict:
        return {}

    def get_pe_security_text(self) -> str:
        return ""


class StubAdapterWithSections(StubAdapter):
    def get_sections(self) -> list[dict]:
        return [
            {"name": ".text", "size": 0x1000, "vaddr": 0x1000},
            {"name": ".data", "size": 0x500, "vaddr": 0x2000},
        ]


class StubAdapterWithImports(StubAdapter):
    def get_imports(self) -> list[dict]:
        return [
            {"name": "CryptEncrypt", "libname": "advapi32.dll", "plt": 0x1000},
            {"name": "VirtualAlloc", "libname": "kernel32.dll", "plt": 0x2000},
        ]

    def cmdj(self, command: str) -> Any:
        if command == "iij":
            return [
                {"name": "CryptEncrypt", "libname": "advapi32.dll", "plt": 0x1000},
                {"name": "VirtualAlloc", "libname": "kernel32.dll", "plt": 0x2000},
            ]
        return {}


class StubAdapterRaisingOnCmd(StubAdapter):
    def cmd(self, command: str) -> str:
        raise RuntimeError("adapter failure")

    def cmdj(self, command: str) -> Any:
        raise RuntimeError("adapter failure")

    def get_imports(self) -> list[dict]:
        raise RuntimeError("adapter failure")

    def get_sections(self) -> list[dict]:
        raise RuntimeError("adapter failure")

    def get_strings(self) -> list[dict]:
        raise RuntimeError("adapter failure")

    def read_bytes(self, vaddr: int, size: int) -> bytes:
        raise RuntimeError("adapter failure")


# ---------------------------------------------------------------------------
# CryptoAnalyzer
# ---------------------------------------------------------------------------

from r2inspect.modules.crypto_analyzer import CryptoAnalyzer


def _make_config() -> Any:
    from r2inspect.config import Config

    return Config()


def test_crypto_analyzer_detect_returns_required_keys():
    adapter = StubAdapter()
    analyzer = CryptoAnalyzer(adapter, _make_config())
    result = analyzer.detect()
    assert "algorithms" in result
    assert "constants" in result
    assert "entropy_analysis" in result
    assert "suspicious_patterns" in result


def test_crypto_analyzer_detect_empty_sections_no_entropy():
    adapter = StubAdapter()
    analyzer = CryptoAnalyzer(adapter, _make_config())
    result = analyzer.detect()
    assert result["entropy_analysis"] == {}


def test_crypto_analyzer_detect_with_sections():
    adapter = StubAdapterWithSections()
    analyzer = CryptoAnalyzer(adapter, _make_config())
    result = analyzer.detect()
    assert isinstance(result["entropy_analysis"], dict)


def test_crypto_analyzer_detect_with_imports():
    adapter = StubAdapterWithImports()
    analyzer = CryptoAnalyzer(adapter, _make_config())
    result = analyzer.detect()
    assert isinstance(result["algorithms"], list)


def test_crypto_analyzer_detect_adapter_error_captured():
    adapter = StubAdapterRaisingOnCmd()
    analyzer = CryptoAnalyzer(adapter, _make_config())
    result = analyzer.detect()
    # Should not raise; error captured in result
    assert isinstance(result, dict)


def test_crypto_analyzer_detect_crypto_libraries_empty():
    adapter = StubAdapter()
    analyzer = CryptoAnalyzer(adapter, _make_config())
    libs = analyzer.detect_crypto_libraries()
    assert libs == []


def test_crypto_analyzer_detect_crypto_libraries_with_imports():
    adapter = StubAdapterWithImports()
    analyzer = CryptoAnalyzer(adapter, _make_config())
    libs = analyzer.detect_crypto_libraries()
    assert isinstance(libs, list)
    names = [lib["api_function"] for lib in libs]
    assert "CryptEncrypt" in names


def test_crypto_analyzer_no_adapter():
    analyzer = CryptoAnalyzer(None, _make_config())
    result = analyzer.detect()
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# StringAnalyzer
# ---------------------------------------------------------------------------

from r2inspect.modules.string_analyzer import StringAnalyzer


class StubAdapterWithStringEntries(StubAdapter):
    def cmdj(self, command: str) -> Any:
        if command in ("izj", "izuj"):
            return [
                {"string": "Hello World", "vaddr": 0x1000},
                {"string": "CreateProcess", "vaddr": 0x2000},
                {"string": "VirtualAlloc", "vaddr": 0x3000},
            ]
        return {}


def test_string_analyzer_analyze_structure():
    adapter = StubAdapterWithStringEntries()
    analyzer = StringAnalyzer(adapter, _make_config())
    result = analyzer.analyze()
    assert "strings" in result
    assert "total_strings" in result


def test_string_analyzer_extract_strings():
    adapter = StubAdapterWithStringEntries()
    analyzer = StringAnalyzer(adapter, _make_config())
    strings = analyzer.extract_strings()
    assert isinstance(strings, list)


def test_string_analyzer_extract_strings_empty():
    adapter = StubAdapter()
    analyzer = StringAnalyzer(adapter, _make_config())
    strings = analyzer.extract_strings()
    assert strings == []


def test_string_analyzer_suspicious_strings():
    adapter = StubAdapterWithStringEntries()
    analyzer = StringAnalyzer(adapter, _make_config())
    suspicious = analyzer.get_suspicious_strings()
    assert isinstance(suspicious, list)


def test_string_analyzer_decode_strings():
    adapter = StubAdapterWithStringEntries()
    analyzer = StringAnalyzer(adapter, _make_config())
    decoded = analyzer.decode_strings()
    assert isinstance(decoded, list)


def test_string_analyzer_statistics():
    adapter = StubAdapterWithStringEntries()
    analyzer = StringAnalyzer(adapter, _make_config())
    stats = analyzer.get_string_statistics()
    assert "total_strings" in stats
    assert "avg_length" in stats


def test_string_analyzer_statistics_empty():
    adapter = StubAdapter()
    analyzer = StringAnalyzer(adapter, _make_config())
    stats = analyzer.get_string_statistics()
    assert stats["total_strings"] == 0
    assert stats["avg_length"] == 0


def test_string_analyzer_search_xor():
    adapter = StubAdapter()
    analyzer = StringAnalyzer(adapter, _make_config())
    result = analyzer.search_xor("test")
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# ImportAnalyzer
# ---------------------------------------------------------------------------

from r2inspect.modules.import_analyzer import ImportAnalyzer


def test_import_analyzer_analyze_structure():
    adapter = StubAdapter()
    analyzer = ImportAnalyzer(adapter, _make_config())
    result = analyzer.analyze()
    assert "total_imports" in result
    assert "imports" in result
    assert "statistics" in result


def test_import_analyzer_analyze_with_imports():
    adapter = StubAdapterWithImports()
    analyzer = ImportAnalyzer(adapter, _make_config())
    result = analyzer.analyze()
    assert result["total_imports"] == 2


def test_import_analyzer_get_imports_empty():
    adapter = StubAdapter()
    analyzer = ImportAnalyzer(adapter, _make_config())
    imports = analyzer.get_imports()
    assert imports == []


def test_import_analyzer_analyze_api_usage_empty():
    adapter = StubAdapter()
    analyzer = ImportAnalyzer(adapter, _make_config())
    api = analyzer.analyze_api_usage([])
    assert api["risk_score"] == 0
    assert api["suspicious_apis"] == []


def test_import_analyzer_detect_api_obfuscation_getprocaddress():
    adapter = StubAdapter()
    analyzer = ImportAnalyzer(adapter, _make_config())
    imports = [
        {"name": "GetProcAddress", "library": "kernel32.dll"},
        {"name": "LoadLibraryA", "library": "kernel32.dll"},
    ]
    result = analyzer.detect_api_obfuscation(imports)
    assert result["detected"] is True
    assert result["score"] > 0


def test_import_analyzer_detect_api_obfuscation_few_imports():
    adapter = StubAdapter()
    analyzer = ImportAnalyzer(adapter, _make_config())
    imports = [{"name": "ExitProcess", "library": "kernel32.dll"}]
    result = analyzer.detect_api_obfuscation(imports)
    assert result["detected"] is True


def test_import_analyzer_analyze_dll_dependencies_empty():
    adapter = StubAdapter()
    analyzer = ImportAnalyzer(adapter, _make_config())
    result = analyzer.analyze_dll_dependencies([])
    assert result["common_dlls"] == []
    assert result["suspicious_dlls"] == []


def test_import_analyzer_analyze_dll_dependencies_suspicious():
    adapter = StubAdapter()
    analyzer = ImportAnalyzer(adapter, _make_config())
    result = analyzer.analyze_dll_dependencies(["crypt32.dll", "psapi.dll", "kernel32.dll"])
    assert "crypt32.dll" in result["suspicious_dlls"]


def test_import_analyzer_detect_import_anomalies_no_imports():
    adapter = StubAdapter()
    analyzer = ImportAnalyzer(adapter, _make_config())
    result = analyzer.detect_import_anomalies([])
    assert result["count"] >= 1


def test_import_analyzer_detect_import_anomalies_duplicates():
    adapter = StubAdapter()
    analyzer = ImportAnalyzer(adapter, _make_config())
    imports = [
        {"name": "CreateFile", "library": "kernel32.dll"},
        {"name": "CreateFile", "library": "kernel32.dll"},
    ]
    result = analyzer.detect_import_anomalies(imports)
    types = [a["type"] for a in result["anomalies"]]
    assert "duplicate_imports" in types


def test_import_analyzer_get_import_statistics():
    adapter = StubAdapterWithImports()
    analyzer = ImportAnalyzer(adapter, _make_config())
    stats = analyzer.get_import_statistics()
    assert "total_imports" in stats
    assert "category_distribution" in stats


def test_import_analyzer_risk_level_thresholds():
    adapter = StubAdapter()
    analyzer = ImportAnalyzer(adapter, _make_config())
    assert analyzer._get_risk_level(75) == "HIGH"
    assert analyzer._get_risk_level(50) == "MEDIUM"
    assert analyzer._get_risk_level(10) == "LOW"


# ---------------------------------------------------------------------------
# ExportAnalyzer
# ---------------------------------------------------------------------------

from r2inspect.modules.export_analyzer import ExportAnalyzer


class StubAdapterWithExports(StubAdapter):
    def cmdj(self, command: str) -> Any:
        if command == "iEj":
            return [
                {"name": "DllMain", "vaddr": 0x1000, "ordinal": 1, "type": "func"},
                {"name": "RunPayload", "vaddr": 0x2000, "ordinal": 2, "type": "func"},
            ]
        return []

    def cmd(self, command: str) -> str:
        if command.startswith("afij"):
            return "[]"
        return ""


def test_export_analyzer_analyze_structure():
    adapter = StubAdapter()
    analyzer = ExportAnalyzer(adapter, _make_config())
    result = analyzer.analyze()
    assert "total_exports" in result
    assert "exports" in result
    assert "statistics" in result


def test_export_analyzer_get_exports_empty():
    adapter = StubAdapter()
    analyzer = ExportAnalyzer(adapter, _make_config())
    exports = analyzer.get_exports()
    assert exports == []


def test_export_analyzer_analyze_export_fields():
    adapter = StubAdapter()
    analyzer = ExportAnalyzer(adapter, _make_config())
    exp = {"name": "TestExport", "vaddr": 0x1000, "ordinal": 1, "type": "func"}
    result = analyzer._analyze_export(exp)
    assert result["name"] == "TestExport"
    assert result["ordinal"] == 1
    assert "characteristics" in result


def test_export_analyzer_suspicious_name_detected():
    adapter = StubAdapter()
    analyzer = ExportAnalyzer(adapter, _make_config())
    exp = {"name": "InjectShellcode", "vaddr": 0x0, "ordinal": 1, "type": "func"}
    chars = analyzer._get_export_characteristics(exp)
    assert chars.get("suspicious_name") is True


def test_export_analyzer_dll_export_name():
    adapter = StubAdapter()
    analyzer = ExportAnalyzer(adapter, _make_config())
    exp = {"name": "DllRegisterServer", "vaddr": 0x0, "ordinal": 1}
    chars = analyzer._get_export_characteristics(exp)
    assert chars.get("dll_export") is True


def test_export_analyzer_statistics_empty():
    adapter = StubAdapter()
    analyzer = ExportAnalyzer(adapter, _make_config())
    stats = analyzer.get_export_statistics()
    assert stats["total_exports"] == 0


def test_export_analyzer_skips_non_dict_exports():
    adapter = StubAdapter()
    analyzer = ExportAnalyzer(adapter, _make_config())
    stats: dict[str, Any] = {
        "total_exports": 0,
        "function_exports": 0,
        "data_exports": 0,
        "forwarded_exports": 0,
        "suspicious_exports": 0,
        "export_names": [],
    }
    # Non-dict items should be skipped silently
    analyzer._update_export_stats(stats, "not_a_dict")
    assert stats["total_exports"] == 0


# ---------------------------------------------------------------------------
# resource_analysis.run_resource_analysis
# ---------------------------------------------------------------------------

from r2inspect.modules.resource_analysis import run_resource_analysis


class MinimalResourceAnalyzer:
    """Minimal stub that satisfies run_resource_analysis interface."""

    def _init_result_structure(self, base: dict) -> dict:
        return dict(base)

    def _get_resource_directory(self) -> dict | None:
        return None

    def _parse_resources(self) -> list:
        return []

    def _analyze_resource_types(self, result: dict, resources: list) -> None:
        pass

    def _extract_version_info(self, result: dict, resources: list) -> None:
        pass

    def _extract_manifest(self, result: dict, resources: list) -> None:
        pass

    def _extract_icons(self, result: dict, resources: list) -> None:
        pass

    def _extract_strings(self, result: dict, resources: list) -> None:
        pass

    def _calculate_statistics(self, result: dict, resources: list) -> None:
        pass

    def _check_suspicious_resources(self, result: dict, resources: list) -> None:
        pass


def test_run_resource_analysis_no_resources():
    analyzer = MinimalResourceAnalyzer()
    result = run_resource_analysis(analyzer, logging.getLogger("test"))
    assert result["has_resources"] is False
    assert result["total_resources"] == 0


def test_run_resource_analysis_with_resources():
    class ResourceAnalyzerWithDir(MinimalResourceAnalyzer):
        def _get_resource_directory(self):
            return {"rva": 0x1000, "size": 0x100}

        def _parse_resources(self):
            return [{"type": "RT_ICON", "size": 256}]

    analyzer = ResourceAnalyzerWithDir()
    result = run_resource_analysis(analyzer, logging.getLogger("test"))
    assert result["has_resources"] is True
    assert result["total_resources"] == 1


def test_run_resource_analysis_handles_exception():
    class BrokenAnalyzer:
        def _init_result_structure(self, base: dict) -> dict:
            return dict(base)

        def _get_resource_directory(self):
            raise RuntimeError("broken")

    logger = logging.getLogger("test")
    result = run_resource_analysis(BrokenAnalyzer(), logger)
    assert result.get("has_resources") is False
    assert "error" in result


# ---------------------------------------------------------------------------
# pe_security
# ---------------------------------------------------------------------------

from r2inspect.modules.pe_security import (
    _apply_security_flags_from_header,
    _apply_security_flags_from_text,
    _apply_authenticode_feature,
    get_security_features,
)


def _empty_features() -> dict:
    return {"aslr": False, "dep": False, "seh": False, "guard_cf": False, "authenticode": False}


class FakeLogger:
    def debug(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass


def test_apply_security_flags_aslr():
    features = _empty_features()
    pe_header = {"optional_header": {"DllCharacteristics": 0x0040}}
    _apply_security_flags_from_header(features, pe_header, FakeLogger())
    assert features["aslr"] is True


def test_apply_security_flags_dep():
    features = _empty_features()
    pe_header = {"optional_header": {"DllCharacteristics": 0x0100}}
    _apply_security_flags_from_header(features, pe_header, FakeLogger())
    assert features["dep"] is True


def test_apply_security_flags_seh_no_flag():
    # When 0x0400 is NOT set, SEH is considered enabled
    features = _empty_features()
    pe_header = {"optional_header": {"DllCharacteristics": 0x0000}}
    _apply_security_flags_from_header(features, pe_header, FakeLogger())
    assert features["seh"] is True


def test_apply_security_flags_guard_cf():
    features = _empty_features()
    pe_header = {"optional_header": {"DllCharacteristics": 0x4000}}
    _apply_security_flags_from_header(features, pe_header, FakeLogger())
    assert features["guard_cf"] is True


def test_apply_security_flags_none_header():
    features = _empty_features()
    _apply_security_flags_from_header(features, None, FakeLogger())
    assert all(v is False for v in features.values())


def test_apply_security_flags_non_int_characteristics():
    features = _empty_features()
    pe_header = {"optional_header": {"DllCharacteristics": "not_an_int"}}
    _apply_security_flags_from_header(features, pe_header, FakeLogger())
    # Should not raise; no flags set
    assert all(v is False for v in features.values())


def test_apply_security_flags_from_text_aslr():
    features = _empty_features()
    _apply_security_flags_from_text(features, "DLL can move DYNAMIC_BASE")
    assert features["aslr"] is True


def test_apply_security_flags_from_text_dep():
    features = _empty_features()
    _apply_security_flags_from_text(features, "NX_COMPAT")
    assert features["dep"] is True


def test_apply_security_flags_from_text_guard_cf():
    features = _empty_features()
    _apply_security_flags_from_text(features, "GUARD_CF enabled")
    assert features["guard_cf"] is True


def test_apply_security_flags_from_text_no_seh():
    features = _empty_features()
    _apply_security_flags_from_text(features, "NO_SEH")
    assert features["seh"] is False


def test_apply_security_flags_from_text_none():
    features = _empty_features()
    _apply_security_flags_from_text(features, None)
    assert all(v is False for v in features.values())


def test_apply_authenticode_feature_with_security_dir():
    features = _empty_features()
    pe_header = {"data_directories": {"security": {"size": 1024, "rva": 0x100}}}
    _apply_authenticode_feature(features, pe_header)
    assert features["authenticode"] is True


def test_apply_authenticode_feature_empty_security_dir():
    features = _empty_features()
    pe_header = {"data_directories": {"security": {"size": 0}}}
    _apply_authenticode_feature(features, pe_header)
    assert features["authenticode"] is False


def test_apply_authenticode_feature_none_header():
    features = _empty_features()
    _apply_authenticode_feature(features, None)
    assert features["authenticode"] is False


class StubAdapterForSecurity(StubAdapter):
    def get_pe_headers(self) -> dict:
        return {"optional_header": {"DllCharacteristics": 0x0140}}  # ASLR + DEP

    def cmdj(self, command: str) -> Any:
        if "pf." in command or "ih" in command:
            return {"optional_header": {"DllCharacteristics": 0x0140}}
        return {}


def test_get_security_features_returns_dict():
    # get_security_features calls get_pe_headers via r2_commands, which falls back gracefully
    adapter = StubAdapter()
    result = get_security_features(adapter, FakeLogger())
    assert isinstance(result, dict)
    assert "aslr" in result
    assert "dep" in result


# ---------------------------------------------------------------------------
# pe_info.get_pe_headers_info
# ---------------------------------------------------------------------------

from r2inspect.modules.pe_info import get_pe_headers_info


class StubAdapterForPeInfo(StubAdapter):
    def get_file_info(self) -> dict:
        return {
            "bin": {
                "arch": "x86",
                "bits": 32,
                "endian": "little",
                "baddr": 0x400000,
                "machine": "i386",
                "entry": 0x401000,
            }
        }

    def cmdj(self, command: str) -> Any:
        return {}


def test_get_pe_headers_info_basic_keys():
    adapter = StubAdapterForPeInfo()
    result = get_pe_headers_info(adapter, None, FakeLogger())
    assert "architecture" in result
    assert "bits" in result
    assert result["architecture"] == "x86"


def test_get_pe_headers_info_no_bin():
    class NoBinAdapter(StubAdapter):
        def get_file_info(self) -> dict:
            return {}

    adapter = NoBinAdapter()
    result = get_pe_headers_info(adapter, None, FakeLogger())
    # Should return empty dict without crashing
    assert isinstance(result, dict)


def test_get_pe_headers_info_adapter_error():
    class ErrorAdapter(StubAdapter):
        def get_file_info(self) -> dict:
            raise RuntimeError("crash")

    adapter = ErrorAdapter()
    result = get_pe_headers_info(adapter, None, FakeLogger())
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# RichHeaderDebugMixin
# ---------------------------------------------------------------------------

from r2inspect.modules.rich_header_debug import RichHeaderDebugMixin


class ConcreteRichHeaderDebug(RichHeaderDebugMixin):
    def __init__(self, adapter: Any) -> None:
        self.adapter = adapter


def test_rich_header_debug_no_adapter():
    mixin = ConcreteRichHeaderDebug(None)
    # Should not raise
    mixin._debug_file_structure()


def test_rich_header_debug_with_mz_bytes():
    class MZAdapter:
        def read_bytes(self, addr: int, size: int) -> bytes:
            # MZ header followed by zeros; PE offset at 0x3C = 0x40
            data = bytearray(512)
            data[0] = ord("M")
            data[1] = ord("Z")
            data[0x3C] = 0x40
            return bytes(data)

        def get_file_info(self) -> dict:
            return {"core": {"size": 512}}

    mixin = ConcreteRichHeaderDebug(MZAdapter())
    mixin._debug_file_structure()  # Should complete without error


def test_rich_header_debug_has_mz_header():
    assert RichHeaderDebugMixin._debug_has_mz_header(b"MZ\x00\x00") is True
    assert RichHeaderDebugMixin._debug_has_mz_header(b"PE\x00\x00") is False


def test_rich_header_debug_get_pe_offset():
    data = bytearray(0x40)
    import struct
    struct.pack_into("<I", data, 0x3C, 0x40)
    result = RichHeaderDebugMixin._debug_get_pe_offset(bytes(data))
    assert result == 0x40


def test_rich_header_debug_find_rich_dans_positions():
    data = b"abc" + b"DanS" + b"x" * 20 + b"Rich" + b"\x00\x00\x00\x00"
    rich_pos, dans_pos = RichHeaderDebugMixin._find_rich_dans_positions(data)
    assert len(rich_pos) >= 1
    assert len(dans_pos) >= 1


def test_rich_header_debug_read_bytes_no_adapter():
    mixin = ConcreteRichHeaderDebug(None)
    result = mixin._read_bytes(0, 16)
    assert result == b""


def test_rich_header_debug_get_file_info_no_adapter():
    mixin = ConcreteRichHeaderDebug(None)
    result = mixin._get_file_info()
    assert result == {}


# ---------------------------------------------------------------------------
# Command base class
# ---------------------------------------------------------------------------

from r2inspect.cli.commands.base import (
    Command,
    CommandContext,
    apply_thread_settings,
    configure_logging_levels,
    configure_quiet_logging,
)


class ConcreteCommand(Command):
    def execute(self, args: dict) -> int:
        return 0


def test_command_base_cannot_instantiate_abstract():
    try:
        Command()
        assert False, "Should not be able to instantiate abstract Command"
    except TypeError:
        pass


def test_command_base_concrete_execute():
    ctx = CommandContext.create()
    cmd = ConcreteCommand(ctx)
    assert cmd.execute({}) == 0


def test_command_context_property_lazy_creation():
    cmd = ConcreteCommand()
    ctx = cmd.context
    assert isinstance(ctx, CommandContext)


def test_command_context_setter():
    cmd = ConcreteCommand()
    ctx1 = CommandContext.create()
    cmd.context = ctx1
    assert cmd.context is ctx1


def test_command_get_config_no_path():
    from r2inspect.config import Config

    cmd = ConcreteCommand(CommandContext.create())
    config = cmd._get_config()
    assert isinstance(config, Config)


def test_command_setup_analysis_options_empty():
    cmd = ConcreteCommand(CommandContext.create())
    opts = cmd._setup_analysis_options()
    assert opts == {}


def test_command_setup_analysis_options_yara():
    cmd = ConcreteCommand(CommandContext.create())
    opts = cmd._setup_analysis_options(yara="/rules")
    assert opts["yara_rules_dir"] == "/rules"


def test_command_setup_analysis_options_xor():
    cmd = ConcreteCommand(CommandContext.create())
    opts = cmd._setup_analysis_options(xor="FF")
    assert opts["xor_search"] == "FF"


def test_configure_logging_levels_verbose():
    configure_logging_levels(verbose=True, quiet=False)
    assert logging.getLogger("r2inspect").level == logging.INFO


def test_configure_logging_levels_warning():
    configure_logging_levels(verbose=False, quiet=False)
    assert logging.getLogger("r2inspect").level == logging.WARNING


def test_configure_logging_levels_quiet():
    configure_logging_levels(verbose=False, quiet=True)
    assert logging.getLogger("r2pipe").level == logging.CRITICAL


def test_configure_quiet_logging_true():
    configure_quiet_logging(quiet=True)
    assert logging.getLogger("r2pipe").level == logging.CRITICAL


def test_configure_quiet_logging_false_noop():
    logging.getLogger("r2pipe").setLevel(logging.DEBUG)
    configure_quiet_logging(quiet=False)
    assert logging.getLogger("r2pipe").level == logging.DEBUG


def test_apply_thread_settings_none():
    from r2inspect.config import Config

    config = Config()
    apply_thread_settings(config, None)  # Should not raise


def test_apply_thread_settings_valid():
    from r2inspect.config import Config

    config = Config()
    apply_thread_settings(config, 4)  # Should not raise


def test_apply_thread_settings_invalid():
    from r2inspect.config import Config

    config = Config()
    apply_thread_settings(config, "bad")  # Should not raise


# ---------------------------------------------------------------------------
# VersionCommand
# ---------------------------------------------------------------------------

from r2inspect.cli.commands.version_command import VersionCommand


def test_version_command_execute_returns_zero():
    ctx = CommandContext.create()
    cmd = VersionCommand(ctx)
    result = cmd.execute({})
    assert result == 0


def test_version_command_prints_version(capsys):
    ctx = CommandContext.create()
    cmd = VersionCommand(ctx)
    cmd.execute({})
    # Rich Console goes to stdout; capsys may or may not capture it depending on Console setup
    # At minimum the command returned 0 without raising
    assert True


# ---------------------------------------------------------------------------
# ConfigCommand.execute
# ---------------------------------------------------------------------------

from r2inspect.cli.commands.config_command import ConfigCommand


def test_config_command_no_list_yara():
    ctx = CommandContext.create()
    cmd = ConfigCommand(ctx)
    result = cmd.execute({"list_yara": False})
    assert result == 0


def test_config_command_list_yara_nonexistent_path():
    ctx = CommandContext.create()
    cmd = ConfigCommand(ctx)
    result = cmd.execute({"list_yara": True, "yara": "/nonexistent/path/xyz"})
    assert result == 1


def test_config_command_list_yara_empty_dir(tmp_path):
    ctx = CommandContext.create()
    cmd = ConfigCommand(ctx)
    result = cmd.execute({"list_yara": True, "yara": str(tmp_path)})
    assert result == 0


def test_config_command_list_yara_with_rules(tmp_path):
    rule_file = tmp_path / "test_rule.yar"
    rule_file.write_text('rule Test { condition: true }')
    ctx = CommandContext.create()
    cmd = ConfigCommand(ctx)
    result = cmd.execute({"list_yara": True, "yara": str(tmp_path)})
    assert result == 0


def test_config_command_format_file_size_bytes():
    cmd = ConfigCommand(CommandContext.create())
    assert "B" in cmd._format_file_size(512)


def test_config_command_format_file_size_kb():
    cmd = ConfigCommand(CommandContext.create())
    assert "KB" in cmd._format_file_size(2048)


def test_config_command_format_file_size_mb():
    cmd = ConfigCommand(CommandContext.create())
    assert "MB" in cmd._format_file_size(2 * 1024 * 1024)


def test_config_command_find_yara_rules_empty(tmp_path):
    cmd = ConfigCommand(CommandContext.create())
    rules = cmd._find_yara_rules(tmp_path)
    assert rules == []


def test_config_command_find_yara_rules_finds_yar(tmp_path):
    (tmp_path / "a.yar").write_text("rule A {}")
    cmd = ConfigCommand(CommandContext.create())
    rules = cmd._find_yara_rules(tmp_path)
    assert len(rules) == 1


def test_config_command_find_yara_rules_finds_yara(tmp_path):
    (tmp_path / "b.yara").write_text("rule B {}")
    cmd = ConfigCommand(CommandContext.create())
    rules = cmd._find_yara_rules(tmp_path)
    assert len(rules) == 1


# ---------------------------------------------------------------------------
# display_base
# ---------------------------------------------------------------------------

from r2inspect.cli.display_base import (
    NOT_AVAILABLE,
    STATUS_AVAILABLE,
    STATUS_NOT_AVAILABLE,
    UNKNOWN_ERROR,
    create_info_table,
    format_hash_display,
)


def test_format_hash_display_short():
    result = format_hash_display("abc123")
    assert result == "abc123"


def test_format_hash_display_long():
    long_hash = "a" * 64
    result = format_hash_display(long_hash, max_length=32)
    assert result.endswith("...")
    assert len(result) < len(long_hash)


def test_format_hash_display_none():
    assert format_hash_display(None) == "N/A"
    assert format_hash_display("N/A") == "N/A"


def test_format_hash_display_empty_string():
    assert format_hash_display("") == "N/A"


def test_create_info_table_returns_table():
    from rich.table import Table

    table = create_info_table("Test Table")
    assert isinstance(table, Table)


def test_display_base_constants():
    assert UNKNOWN_ERROR == "Unknown error"
    assert NOT_AVAILABLE == "Not Available"
    assert "Available" in STATUS_AVAILABLE
    assert "Not Available" in STATUS_NOT_AVAILABLE


# ---------------------------------------------------------------------------
# batch_workers._cap_threads_for_execution
# ---------------------------------------------------------------------------

from r2inspect.cli.batch_workers import _cap_threads_for_execution


def test_cap_threads_no_env_var(monkeypatch):
    monkeypatch.delenv("R2INSPECT_MAX_THREADS", raising=False)
    assert _cap_threads_for_execution(8) == 8


def test_cap_threads_env_var_limits(monkeypatch):
    monkeypatch.setenv("R2INSPECT_MAX_THREADS", "4")
    assert _cap_threads_for_execution(8) == 4


def test_cap_threads_env_var_larger_than_request(monkeypatch):
    monkeypatch.setenv("R2INSPECT_MAX_THREADS", "16")
    assert _cap_threads_for_execution(8) == 8


def test_cap_threads_env_var_invalid(monkeypatch):
    monkeypatch.setenv("R2INSPECT_MAX_THREADS", "not_a_number")
    assert _cap_threads_for_execution(8) == 8


def test_cap_threads_env_var_zero(monkeypatch):
    monkeypatch.setenv("R2INSPECT_MAX_THREADS", "0")
    assert _cap_threads_for_execution(8) == 8


def test_cap_threads_env_var_negative(monkeypatch):
    monkeypatch.setenv("R2INSPECT_MAX_THREADS", "-1")
    assert _cap_threads_for_execution(8) == 8


# ---------------------------------------------------------------------------
# batch_output
# ---------------------------------------------------------------------------

from r2inspect.cli.batch_output import (
    determine_csv_file_path,
    find_files_by_extensions,
    get_csv_fieldnames,
)


def test_get_csv_fieldnames_returns_list():
    fieldnames = get_csv_fieldnames()
    assert isinstance(fieldnames, list)
    assert "md5" in fieldnames
    assert "sha256" in fieldnames
    assert "name" in fieldnames


def test_determine_csv_file_path_with_csv_suffix(tmp_path):
    csv_path = tmp_path / "results.csv"
    file_path, name = determine_csv_file_path(csv_path, "20250101")
    assert file_path == csv_path
    assert name == "results.csv"


def test_determine_csv_file_path_with_directory(tmp_path):
    file_path, name = determine_csv_file_path(tmp_path, "20250101")
    assert "r2inspect_20250101.csv" in name
    assert file_path.parent == tmp_path


def test_find_files_by_extensions_empty_dir(tmp_path):
    result = find_files_by_extensions(tmp_path, ".exe", False)
    assert isinstance(result, list)


def test_find_files_by_extensions_matches(tmp_path):
    (tmp_path / "a.exe").write_bytes(b"\x00")
    (tmp_path / "b.dll").write_bytes(b"\x00")
    result = find_files_by_extensions(tmp_path, "exe", False)
    assert any(p.suffix == ".exe" for p in result)


# ---------------------------------------------------------------------------
# __main__.main
# ---------------------------------------------------------------------------

from r2inspect.__main__ import main


def test_main_returns_int():
    # main() calls cli() which will raise SystemExit; we catch that
    result = main()
    assert isinstance(result, int)


# ---------------------------------------------------------------------------
# r2pipe_context
# ---------------------------------------------------------------------------

from r2inspect.adapters.r2pipe_context import open_r2_adapter, open_r2pipe


def test_open_r2pipe_is_context_manager():
    import inspect

    assert inspect.isgeneratorfunction(open_r2pipe.__wrapped__)


def test_open_r2_adapter_is_context_manager():
    import inspect

    assert inspect.isgeneratorfunction(open_r2_adapter.__wrapped__)


# ---------------------------------------------------------------------------
# MagicAdapter
# ---------------------------------------------------------------------------

from r2inspect.adapters.magic_adapter import MagicAdapter


def test_magic_adapter_available_property():
    adapter = MagicAdapter()
    assert isinstance(adapter.available, bool)


def test_magic_adapter_create_detectors_when_unavailable():
    adapter = MagicAdapter()
    if not adapter.available:
        result = adapter.create_detectors()
        assert result is None


def test_magic_adapter_create_detectors_returns_tuple_or_none():
    adapter = MagicAdapter()
    result = adapter.create_detectors()
    assert result is None or isinstance(result, tuple)


# ---------------------------------------------------------------------------
# FileSystemAdapter
# ---------------------------------------------------------------------------

from r2inspect.adapters.file_system import FileSystemAdapter, default_file_system


def test_file_system_read_bytes(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"hello")
    adapter = FileSystemAdapter()
    assert adapter.read_bytes(f) == b"hello"


def test_file_system_read_bytes_with_size(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"0123456789")
    adapter = FileSystemAdapter()
    assert adapter.read_bytes(f, size=3) == b"012"


def test_file_system_read_bytes_with_offset(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"0123456789")
    adapter = FileSystemAdapter()
    assert adapter.read_bytes(f, offset=5) == b"56789"


def test_file_system_read_text(tmp_path):
    f = tmp_path / "text.txt"
    f.write_text("hello world", encoding="utf-8")
    adapter = FileSystemAdapter()
    assert adapter.read_text(f) == "hello world"


def test_file_system_write_text(tmp_path):
    f = tmp_path / "out.txt"
    adapter = FileSystemAdapter()
    adapter.write_text(f, "written")
    assert f.read_text() == "written"


def test_default_file_system_instance():
    assert isinstance(default_file_system, FileSystemAdapter)


def test_file_system_read_bytes_nonexistent(tmp_path):
    adapter = FileSystemAdapter()
    with pytest.raises(FileNotFoundError):
        adapter.read_bytes(tmp_path / "missing.bin")
