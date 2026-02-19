from __future__ import annotations

from r2inspect.modules.anti_analysis import AntiAnalysisDetector


class _FullAdapter:
    """Adapter that returns data covering all anti-analysis branches."""

    def get_imports(self) -> list[dict]:
        return [
            {"name": "IsDebuggerPresent", "plt": 0x1000, "libname": "kernel32.dll"},
            {"name": "QueryPerformanceCounter", "plt": 0x2000, "libname": "kernel32.dll"},
            {"name": "Sleep", "plt": 0x3000, "libname": "kernel32.dll"},
            {"name": "VirtualAlloc", "plt": 0x4000, "libname": "kernel32.dll"},
            {"name": "CreateRemoteThread", "plt": 0x5000, "libname": "kernel32.dll"},
        ]

    def get_strings(self) -> list[dict]:
        return [
            {"string": "VMware SVGA II", "vaddr": 0x6000},
            {"string": "VBoxGuest", "vaddr": 0x7000},
            {"string": "SandboxDetected", "vaddr": 0x8000},
        ]

    def search_text(self, pattern: str) -> str:
        if pattern == "fs:[0x30]":
            return "0x401000\n0x401050"
        if pattern == "rdtsc":
            return "0x402000\n0x402100\n0x402200"
        if pattern == "cc":
            return "\n".join([f"0x{i:x}" for i in range(10)])
        if pattern == "cpuid":
            return "0x403000"
        return ""

    def search_hex(self, _pattern: str) -> str:
        return ""

    def cmd(self, command: str) -> str:
        if "iz~mac" in command:
            return "mac_address"
        if "ii~Sleep" in command or "ii~Delay" in command:
            return "Sleep"
        if "ii~FindFirst" in command:
            return "FindFirstFileA"
        if "iz~HKEY.*VMware" in command or "HKEY" in command:
            return ""
        return ""

    def cmdj(self, _command: str) -> list:
        return []


class _EmptyAdapter:
    """Adapter that returns no data."""

    def get_imports(self) -> list:
        return []

    def get_strings(self) -> list:
        return []

    def search_text(self, _pattern: str) -> str:
        return ""

    def search_hex(self, _pattern: str) -> str:
        return ""

    def cmd(self, _command: str) -> str:
        return ""

    def cmdj(self, _command: str) -> list:
        return []


class _DictImportAdapter:
    """Adapter returning a dict (not list) from get_imports."""

    def get_imports(self):
        return {"name": "VirtualAlloc", "plt": 0x1000, "libname": "kernel32.dll"}

    def get_strings(self) -> list:
        return []

    def search_text(self, _pattern: str) -> str:
        return ""

    def search_hex(self, _pattern: str) -> str:
        return ""

    def cmd(self, _command: str) -> str:
        return ""

    def cmdj(self, _command: str) -> list:
        return []


def test_detect_with_full_adapter_returns_complete_result() -> None:
    detector = AntiAnalysisDetector(_FullAdapter())
    result = detector.detect()
    assert "anti_debug" in result
    assert "anti_vm" in result
    assert "anti_sandbox" in result
    assert "evasion_techniques" in result
    assert "suspicious_apis" in result
    assert "timing_checks" in result
    assert "environment_checks" in result
    assert "detection_details" in result


def test_detect_anti_debug_with_peb_access() -> None:
    detector = AntiAnalysisDetector(_FullAdapter())
    result = detector._detect_anti_debug_detailed()
    assert result["detected"] is True
    types = [e["type"] for e in result["evidence"]]
    assert "PEB Access" in types


def test_detect_anti_debug_with_int3_count() -> None:
    detector = AntiAnalysisDetector(_FullAdapter())
    result = detector._detect_anti_debug_detailed()
    assert result["detected"] is True
    types = [e["type"] for e in result["evidence"]]
    assert "Breakpoint Detection" in types


def test_detect_anti_debug_with_rdtsc() -> None:
    detector = AntiAnalysisDetector(_FullAdapter())
    result = detector._detect_anti_debug_detailed()
    types = [e["type"] for e in result["evidence"]]
    assert "Timing Check" in types


def test_detect_anti_vm_with_vm_strings() -> None:
    detector = AntiAnalysisDetector(_FullAdapter())
    result = detector._detect_anti_vm_detailed()
    assert result["detected"] is True


def test_detect_anti_sandbox_with_sandbox_strings() -> None:
    detector = AntiAnalysisDetector(_FullAdapter())
    result = detector._detect_anti_sandbox_detailed()
    assert result["detected"] is True


def test_detect_timing_checks_with_rdtsc() -> None:
    detector = AntiAnalysisDetector(_FullAdapter())
    result = detector._detect_timing_checks_detailed()
    assert result["detected"] is True
    types = [e["type"] for e in result["evidence"]]
    assert "RDTSC Instruction" in types


def test_detect_environment_checks_returns_list() -> None:
    detector = AntiAnalysisDetector(_FullAdapter())
    checks = detector._detect_environment_checks()
    assert isinstance(checks, list)


def test_search_opcode_calls_adapter() -> None:
    detector = AntiAnalysisDetector(_FullAdapter())
    result = detector._search_opcode("rdtsc")
    assert "0x402000" in result


def test_coerce_dict_list_with_list() -> None:
    result = AntiAnalysisDetector._coerce_dict_list([{"a": 1}, {"b": 2}])
    assert len(result) == 2


def test_coerce_dict_list_with_dict() -> None:
    result = AntiAnalysisDetector._coerce_dict_list({"name": "VirtualAlloc"})
    assert len(result) == 1
    assert result[0]["name"] == "VirtualAlloc"


def test_coerce_dict_list_with_none() -> None:
    result = AntiAnalysisDetector._coerce_dict_list(None)
    assert result == []


def test_coerce_dict_list_filters_non_dicts() -> None:
    result = AntiAnalysisDetector._coerce_dict_list([{"a": 1}, "string", 42, None])
    assert len(result) == 1


def test_detect_with_empty_adapter_no_error() -> None:
    detector = AntiAnalysisDetector(_EmptyAdapter())
    result = detector.detect()
    assert result["anti_debug"] is False
    assert result["anti_vm"] is False
    assert result["anti_sandbox"] is False


def test_get_imports_via_adapter_method() -> None:
    detector = AntiAnalysisDetector(_FullAdapter())
    imports = detector._get_imports()
    assert isinstance(imports, list)
    assert len(imports) > 0


def test_get_strings_via_adapter_method() -> None:
    detector = AntiAnalysisDetector(_FullAdapter())
    strings = detector._get_strings()
    assert isinstance(strings, list)
    assert len(strings) > 0


def test_find_suspicious_apis_returns_list() -> None:
    detector = AntiAnalysisDetector(_FullAdapter())
    suspicious = detector._find_suspicious_apis()
    assert isinstance(suspicious, list)


def test_detect_evasion_techniques_returns_list() -> None:
    detector = AntiAnalysisDetector(_FullAdapter())
    techniques = detector._detect_evasion_techniques()
    assert isinstance(techniques, list)


def test_detect_with_dict_import_adapter() -> None:
    detector = AntiAnalysisDetector(_DictImportAdapter())
    result = detector.detect()
    assert "anti_debug" in result
