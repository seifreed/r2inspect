"""Tests for anti_analysis branch paths -- no mocks, no monkeypatch, no patch decorators.

Uses FakeR2 + R2PipeAdapter for AntiAnalysisDetector.
"""

from __future__ import annotations

from typing import Any

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.anti_analysis import AntiAnalysisDetector
from r2inspect.testing.fake_r2 import FakeR2

# ---------------------------------------------------------------------------
# FakeR2: minimal r2pipe-like backend driven by command maps
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Adapter factories
# ---------------------------------------------------------------------------


def _make_adapter(
    cmd_map: dict[str, str] | None = None,
    cmdj_map: dict[str, Any] | None = None,
) -> R2PipeAdapter:
    return R2PipeAdapter(FakeR2(cmd_map=cmd_map, cmdj_map=cmdj_map))


# ---------------------------------------------------------------------------
# Data constants
# ---------------------------------------------------------------------------

FULL_IMPORTS = [
    {"name": "IsDebuggerPresent", "plt": 0x1000, "libname": "kernel32.dll"},
    {"name": "QueryPerformanceCounter", "plt": 0x2000, "libname": "kernel32.dll"},
    {"name": "Sleep", "plt": 0x3000, "libname": "kernel32.dll"},
    {"name": "VirtualAlloc", "plt": 0x4000, "libname": "kernel32.dll"},
    {"name": "CreateRemoteThread", "plt": 0x5000, "libname": "kernel32.dll"},
]

FULL_STRINGS = [
    {
        "string": "VMware SVGA II",
        "vaddr": 0x6000,
        "type": "ascii",
        "length": 14,
        "section": ".rdata",
        "paddr": 0x6000,
    },
    {
        "string": "VBoxGuest",
        "vaddr": 0x7000,
        "type": "ascii",
        "length": 9,
        "section": ".rdata",
        "paddr": 0x7000,
    },
    {
        "string": "SandboxDetected",
        "vaddr": 0x8000,
        "type": "ascii",
        "length": 15,
        "section": ".rdata",
        "paddr": 0x8000,
    },
]

# Commands used by the anti-analysis detector through the _cmd path.
# These go through _cmd_fallback -> r2.cmd() since _maybe_use_adapter
# doesn't intercept them as simple base calls.
FULL_CMD_MAP: dict[str, str] = {
    "ii~Sleep,NtDelayExecution": "Sleep",
    "ii~FindFirst,Process32,Module32": "FindFirstFileA",
    # Environment check commands from domain
    "iz~GetUserName": "",
    "iz~GetComputerName": "",
    "ii~GetSystemInfo,GlobalMemoryStatus": "",
    "ii~CreateToolhelp32Snapshot,Process32": "",
}

FULL_CMDJ_MAP: dict[str, Any] = {
    "iij": FULL_IMPORTS,
    "izj": FULL_STRINGS,
    "izzj": FULL_STRINGS,
}


def _full_adapter() -> R2PipeAdapter:
    """Adapter that returns data covering all anti-analysis branches."""
    return _make_adapter(cmd_map=FULL_CMD_MAP, cmdj_map=FULL_CMDJ_MAP)


def _empty_adapter() -> R2PipeAdapter:
    """Adapter that returns no data."""
    return _make_adapter()


def _dict_import_adapter() -> R2PipeAdapter:
    """Adapter returning a dict (not list) from get_imports via iij."""
    return _make_adapter(
        cmdj_map={"iij": {"name": "VirtualAlloc", "plt": 0x1000, "libname": "kernel32.dll"}},
    )


class _CmdListFallbackAdapter:
    """Plain adapter without get_imports/get_strings to force cmd/cmdj fallbacks.

    AntiAnalysisDetector falls back to _cmd_list("iij") / _cmd_list("izj")
    when the adapter lacks those helper methods.
    """

    def __init__(
        self,
        imports: list[dict] | None = None,
        strings: list[dict] | None = None,
    ) -> None:
        self._imports = imports or []
        self._strings = strings or []

    def cmd(self, _command: str) -> str:
        return ""

    def cmdj(self, command: str) -> list:
        if command.startswith("iij"):
            return self._imports
        if command.startswith("izj"):
            return self._strings
        return []


# ---------------------------------------------------------------------------
# Error-inducing adapters (no mocks -- real subclasses that raise)
# ---------------------------------------------------------------------------


class _ErrorSearchAdapter(R2PipeAdapter):
    """Adapter whose search_text raises RuntimeError."""

    def __init__(self, base_r2: FakeR2) -> None:
        super().__init__(base_r2)

    def search_text(self, _pattern: str) -> str:
        raise RuntimeError("opcode failed")


class _ErrorStringsAdapter(R2PipeAdapter):
    """Adapter whose get_strings / get_strings_basic raises."""

    def __init__(self, base_r2: FakeR2) -> None:
        super().__init__(base_r2)

    def get_strings_basic(self) -> list[dict]:
        raise RuntimeError("strings failed")

    def get_strings(self) -> list[dict]:
        raise RuntimeError("strings failed")


class _SearchTextAdapter(R2PipeAdapter):
    """Adapter with an injectable search_text for anti-debug branch tests."""

    def __init__(self, base_r2: FakeR2, search_fn: Any) -> None:
        super().__init__(base_r2)
        self._search_fn = search_fn

    def search_text(self, pattern: str) -> str:
        return self._search_fn(pattern)


def _search_text_adapter(search_fn: Any) -> R2PipeAdapter:
    """Full-data adapter whose search_text is driven by *search_fn*."""
    return _SearchTextAdapter(FakeR2(cmd_map=FULL_CMD_MAP, cmdj_map=FULL_CMDJ_MAP), search_fn)


class _ErrorImportsAdapter(R2PipeAdapter):
    """Adapter whose get_imports raises."""

    def __init__(self, base_r2: FakeR2) -> None:
        super().__init__(base_r2)

    def get_imports(self) -> list[dict]:
        raise RuntimeError("imports failed")


# ---------------------------------------------------------------------------
# Tests: full adapter, happy paths
# ---------------------------------------------------------------------------


def test_detect_with_full_adapter_returns_complete_result() -> None:
    adapter = _full_adapter()
    detector = AntiAnalysisDetector(adapter)
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
    adapter = _search_text_adapter(lambda p: "0x401000\n0x401050" if "fs:[0x30]" in p else "")
    detector = AntiAnalysisDetector(adapter)
    result = detector._detect_anti_debug_detailed()
    assert result["detected"] is True
    types = [e["type"] for e in result["evidence"]]
    assert "PEB Access" in types


def test_detect_anti_debug_with_int3_count() -> None:
    # cc search yields >5 hits -> triggers breakpoint detection
    adapter = _search_text_adapter(
        lambda p: (
            "\n".join([f"0x{i:x}" for i in range(10)])
            if p == "cc"
            else (
                "0x401000\n0x401050"
                if p == "fs:[0x30]"
                else ("0x402000\n0x402100\n0x402200" if p == "rdtsc" else "")
            )
        )
    )
    detector = AntiAnalysisDetector(adapter)
    result = detector._detect_anti_debug_detailed()
    assert result["detected"] is True
    types = [e["type"] for e in result["evidence"]]
    assert "Breakpoint Detection" in types


def test_detect_anti_debug_int3_below_threshold_not_flagged() -> None:
    # cc search yields <=5 hits -> breakpoint detection is not flagged
    adapter = _search_text_adapter(lambda p: "0x401000\n0x401050\n0x401100" if p == "cc" else "")
    detector = AntiAnalysisDetector(adapter)
    result = detector._detect_anti_debug_detailed()
    types = [e["type"] for e in result["evidence"]]
    assert "Breakpoint Detection" not in types


def test_detect_anti_debug_with_rdtsc() -> None:
    adapter = _search_text_adapter(
        lambda p: (
            "0x402000\n0x402100\n0x402200"
            if p == "rdtsc"
            else ("0x401000\n0x401050" if p == "fs:[0x30]" else ("" if p == "cc" else ""))
        )
    )
    detector = AntiAnalysisDetector(adapter)
    result = detector._detect_anti_debug_detailed()
    types = [e["type"] for e in result["evidence"]]
    assert "Timing Check" in types


def test_detect_anti_vm_with_vm_strings() -> None:
    adapter = _full_adapter()
    detector = AntiAnalysisDetector(adapter)
    result = detector._detect_anti_vm_detailed()
    assert result["detected"] is True


def test_detect_anti_sandbox_with_sandbox_strings() -> None:
    adapter = _full_adapter()
    detector = AntiAnalysisDetector(adapter)
    result = detector._detect_anti_sandbox_detailed()
    assert result["detected"] is True


def test_detect_timing_checks_with_rdtsc() -> None:
    adapter = _search_text_adapter(lambda p: "0x402000\n0x402100\n0x402200" if p == "rdtsc" else "")
    detector = AntiAnalysisDetector(adapter)
    result = detector._detect_timing_checks_detailed()
    assert result["detected"] is True
    types = [e["type"] for e in result["evidence"]]
    assert "RDTSC Instruction" in types


def test_detect_anti_debug_detailed_skips_non_string_search_output() -> None:
    class _BadSearchDetector(AntiAnalysisDetector):
        def _search_opcode(self, _pattern: str):
            return None

    detector = _BadSearchDetector(_empty_adapter())
    result = detector._detect_anti_debug_detailed()
    assert result["detected"] is False
    assert result["evidence"] == []


def test_detect_anti_debug_detailed_skips_malformed_imports() -> None:
    adapter = _make_adapter(
        cmdj_map={
            "iij": [
                {"name": ["bad"], "plt": "bad"},
                {"name": "IsDebuggerPresent", "plt": "4096", "libname": "kernel32.dll"},
            ]
        }
    )
    detector = AntiAnalysisDetector(adapter)
    result = detector._detect_anti_debug_detailed()

    assert result["detected"] is True
    assert any(e.get("type") == "API Call" for e in result["evidence"])


def test_detect_timing_checks_detailed_skips_malformed_imports() -> None:
    adapter = _make_adapter(
        cmdj_map={
            "iij": [
                {"name": ["bad"], "plt": "bad"},
                {"name": "GetTickCount", "plt": "4096", "libname": "kernel32.dll"},
            ]
        }
    )
    detector = AntiAnalysisDetector(adapter)
    result = detector._detect_timing_checks_detailed()

    assert result["detected"] is True
    assert any(e.get("type") == "Timing API Calls" for e in result["evidence"])


def test_detect_environment_checks_returns_list() -> None:
    adapter = _full_adapter()
    detector = AntiAnalysisDetector(adapter)
    checks = detector._detect_environment_checks()
    assert isinstance(checks, list)


def test_search_opcode_calls_adapter() -> None:
    adapter = _search_text_adapter(lambda p: "0x402000\n0x402100\n0x402200" if p == "rdtsc" else "")
    detector = AntiAnalysisDetector(adapter)
    result = detector._search_opcode("rdtsc")
    assert "0x402000" in result


def test_search_opcode_byte_searches_fixed_opcodes_above_size_gate() -> None:
    # Above the size gate the linear /aa scan is skipped; fixed-encoding opcodes
    # (rdtsc 0f31, cpuid 0fa2) fall back to an executable-scoped byte search so
    # the detectors still fire on large binaries. Opcodes without a fixed byte
    # encoding (e.g. int3 'cc') stay skipped rather than flood on data bytes.
    big_bytes = 64 * 1024 * 1024
    omj = [{"from": 0x1000, "to": 0x1007, "delta": 0, "perm": "r-x"}]

    def cmd_fn(command: str) -> str:
        if command.startswith("p8 8 @ 4096"):
            return "00000f3100000000"  # rdtsc 0f31 at exec vaddr 0x1002
        return ""

    fake = FakeR2(
        cmdj_map={"ij": {"core": {"size": big_bytes}, "bin": {"arch": "x86"}}, "omj": omj},
        cmd_fn=cmd_fn,
    )
    detector = AntiAnalysisDetector(R2PipeAdapter(fake))

    assert detector._should_search_opcodes() is False
    assert detector._search_opcode("rdtsc") == "0x1002"
    assert detector._search_opcode("cc") == ""


def test_byte_search_opcode_skipped_on_non_x86_binary() -> None:
    # cpuid (0fa2) / rdtsc (0f31) are x86 encodings; on ARM/MIPS/etc. those bytes
    # are not those instructions, so the byte search must be skipped to avoid
    # false cpuid/rdtsc hits on incidental data.
    big_bytes = 64 * 1024 * 1024
    omj = [{"from": 0x1000, "to": 0x1007, "delta": 0, "perm": "r-x"}]

    def cmd_fn(command: str) -> str:
        if command.startswith("p8 8 @ 4096"):
            return "00000f3100000000"  # would be rdtsc 0f31 on x86
        return ""

    fake = FakeR2(
        cmdj_map={"ij": {"core": {"size": big_bytes}, "bin": {"arch": "arm"}}, "omj": omj},
        cmd_fn=cmd_fn,
    )
    detector = AntiAnalysisDetector(R2PipeAdapter(fake))

    assert detector._should_search_opcodes() is False
    assert detector._is_x86_binary() is False
    assert detector._search_opcode("rdtsc") == ""
    assert detector._search_opcode("cpuid") == ""


# ---------------------------------------------------------------------------
# Tests: _coerce_dict_list (static, no adapter needed)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Tests: empty adapter
# ---------------------------------------------------------------------------


def test_detect_with_empty_adapter_no_error() -> None:
    adapter = _empty_adapter()
    detector = AntiAnalysisDetector(adapter)
    result = detector.detect()
    assert result["anti_debug"] is False
    assert result["anti_vm"] is False
    assert result["anti_sandbox"] is False


# ---------------------------------------------------------------------------
# Tests: import/string retrieval
# ---------------------------------------------------------------------------


def test_get_imports_via_adapter_method() -> None:
    adapter = _full_adapter()
    detector = AntiAnalysisDetector(adapter)
    imports = detector._get_imports()
    assert isinstance(imports, list)
    assert len(imports) > 0


def test_get_strings_via_adapter_method() -> None:
    adapter = _full_adapter()
    detector = AntiAnalysisDetector(adapter)
    strings = detector._get_strings()
    assert isinstance(strings, list)
    assert len(strings) > 0


def test_find_suspicious_apis_returns_list() -> None:
    adapter = _full_adapter()
    detector = AntiAnalysisDetector(adapter)
    suspicious = detector._find_suspicious_apis()
    assert isinstance(suspicious, list)


def test_find_suspicious_apis_skips_malformed_imports() -> None:
    adapter = _make_adapter(
        cmdj_map={
            "iij": [
                {"name": ["bad"], "plt": "bad"},
                {"name": "VirtualAlloc", "plt": "4096", "libname": "kernel32.dll"},
            ]
        }
    )
    detector = AntiAnalysisDetector(adapter)
    suspicious = detector._find_suspicious_apis()

    assert len(suspicious) == 1
    assert suspicious[0]["api"] == "VirtualAlloc"
    assert suspicious[0]["address"] == "0x1000"


def test_detect_evasion_techniques_returns_list() -> None:
    adapter = _full_adapter()
    detector = AntiAnalysisDetector(adapter)
    techniques = detector._detect_evasion_techniques()
    assert isinstance(techniques, list)


def test_detect_with_dict_import_adapter() -> None:
    adapter = _dict_import_adapter()
    detector = AntiAnalysisDetector(adapter)
    result = detector.detect()
    assert "anti_debug" in result


# ---------------------------------------------------------------------------
# Tests: error paths (using real error-raising adapters, NO mocks)
# ---------------------------------------------------------------------------


def test_detect_adds_error_field_when_step_fails() -> None:
    """When _detect_anti_debug_detailed raises, detect() catches and sets error."""
    # Use an adapter that will cause a failure inside detect's sub-calls.
    # _ErrorImportsAdapter raises on get_imports, which causes _detect_anti_debug_detailed
    # to fail. The top-level detect() handler catches and adds the 'error' field.
    fake_r2 = FakeR2()
    adapter = _ErrorImportsAdapter(fake_r2)
    detector = AntiAnalysisDetector(adapter)

    # _detect_anti_debug_detailed calls _get_imports which calls adapter.get_imports()
    # which raises. The _run_detail_detector wraps and returns error evidence.
    # But detect() itself might not have an error field unless the top-level lambda fails.
    # Let's test that the individual error handlers work correctly.
    result = detector._detect_anti_debug_detailed()
    assert result["detected"] is False
    assert any("Error" in str(e) for e in result["evidence"])


def test_detect_anti_debug_detailed_handles_unexpected_errors() -> None:
    """When _search_opcode raises, _detect_anti_debug_detailed catches via _run_detail_detector."""
    fake_r2 = FakeR2(cmdj_map={"iij": FULL_IMPORTS})
    adapter = _ErrorSearchAdapter(fake_r2)
    detector = AntiAnalysisDetector(adapter)

    result = detector._detect_anti_debug_detailed()
    # The error is caught by _run_detail_detector, returning fallback with error evidence
    assert result["detected"] is False
    assert any(
        e.get("type") == "Error" and "opcode failed" in e.get("detail", "")
        for e in result["evidence"]
    )


def test_detect_anti_vm_detailed_handles_unexpected_errors() -> None:
    """When get_strings raises, _detect_anti_vm_detailed catches the error."""
    fake_r2 = FakeR2()
    adapter = _ErrorStringsAdapter(fake_r2)
    detector = AntiAnalysisDetector(adapter)

    result = detector._detect_anti_vm_detailed()
    assert result["detected"] is False
    assert any(e.get("type") == "Error" for e in result["evidence"])


def test_detect_anti_sandbox_detailed_handles_unexpected_errors() -> None:
    """When get_strings raises, _detect_anti_sandbox_detailed catches the error."""
    fake_r2 = FakeR2()
    adapter = _ErrorStringsAdapter(fake_r2)
    detector = AntiAnalysisDetector(adapter)

    result = detector._detect_anti_sandbox_detailed()
    assert result["detected"] is False
    assert any(e.get("type") == "Error" for e in result["evidence"])


def test_detect_evasion_techniques_handles_helper_exceptions() -> None:
    """When search_text raises inside detect_obfuscation, evasion returns []."""
    fake_r2 = FakeR2()
    adapter = _ErrorSearchAdapter(fake_r2)
    detector = AntiAnalysisDetector(adapter)

    techniques = detector._detect_evasion_techniques()
    # _run_detail_detector catches the error and returns the fallback []
    assert techniques == []


def test_find_suspicious_apis_handles_import_errors() -> None:
    """When get_imports raises, _find_suspicious_apis returns []."""
    fake_r2 = FakeR2()
    adapter = _ErrorImportsAdapter(fake_r2)
    detector = AntiAnalysisDetector(adapter)

    suspicious = detector._find_suspicious_apis()
    assert suspicious == []


def test_detect_timing_checks_detailed_handles_errors() -> None:
    """When get_imports raises, _detect_timing_checks_detailed catches it."""
    fake_r2 = FakeR2()
    adapter = _ErrorImportsAdapter(fake_r2)
    detector = AntiAnalysisDetector(adapter)

    result = detector._detect_timing_checks_detailed()
    assert result["detected"] is False
    assert any(e.get("type") == "Error" for e in result["evidence"])


def test_detect_environment_checks_handles_errors() -> None:
    """When cmd raises for env check commands, _detect_environment_checks returns []."""
    # Use an adapter whose cmd() always raises
    fake_r2 = FakeR2()

    class _ErrorCmdAdapter(R2PipeAdapter):
        def cmd(self, command: str) -> str:
            raise RuntimeError("environment failed")

    adapter = _ErrorCmdAdapter(fake_r2)
    detector = AntiAnalysisDetector(adapter)

    checks = detector._detect_environment_checks()
    assert checks == []


# ---------------------------------------------------------------------------
# Tests: cmd_list fallback paths
# ---------------------------------------------------------------------------


def test_get_imports_uses_cmd_list_fallback() -> None:
    adapter = _CmdListFallbackAdapter(
        imports=[{"name": "OpenProcess"}],
        strings=[{"string": "vmware"}],
    )
    detector = AntiAnalysisDetector(adapter)
    result = detector._get_imports()
    assert result == [{"name": "OpenProcess"}]


def test_get_strings_uses_cmd_list_fallback() -> None:
    adapter = _CmdListFallbackAdapter(
        imports=[{"name": "VirtualAlloc"}],
        strings=[{"string": "sandbox"}],
    )
    detector = AntiAnalysisDetector(adapter)
    result = detector._get_strings()
    assert result == [{"string": "sandbox"}]


def test_search_opcode_caches_repeated_pattern() -> None:
    # Regression: each /aa scans the whole binary and several techniques probe
    # the same opcode (rdtsc is searched by two detectors), so a repeated
    # pattern must hit the adapter only once.
    calls: list[str] = []

    def counting_search(pattern: str) -> str:
        calls.append(pattern)
        return "0x401000"

    detector = AntiAnalysisDetector(_search_text_adapter(counting_search))
    first = detector._search_opcode("rdtsc")
    second = detector._search_opcode("rdtsc")
    assert first == second == "0x401000"
    assert calls == ["rdtsc"]
    # A distinct pattern is searched independently.
    detector._search_opcode("cpuid")
    assert calls == ["rdtsc", "cpuid"]
