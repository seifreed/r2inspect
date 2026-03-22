from __future__ import annotations

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.anti_analysis import AntiAnalysisDetector
from r2inspect.testing.fake_r2 import FakeR2


def _make_detector(imports=None, strings=None, cmd_map=None):
    """Create an AntiAnalysisDetector with a real R2PipeAdapter backed by FakeR2."""
    cmdj_map = {}
    if imports is not None:
        cmdj_map["iij"] = imports
    else:
        cmdj_map["iij"] = []
    if strings is not None:
        cmdj_map["izzj"] = strings
    else:
        cmdj_map["izzj"] = []

    fake = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map or {})
    adapter = R2PipeAdapter(fake)
    return AntiAnalysisDetector(adapter, None)


def test_anti_debug_with_is_debugger_present_api():
    detector = _make_detector(
        imports=[{"name": "IsDebuggerPresent", "plt": 0x1000, "libname": "kernel32.dll"}],
    )
    result = detector.detect()

    assert result["anti_debug"] is True
    assert any(
        "IsDebuggerPresent" in str(e) for e in result["detection_details"]["anti_debug_evidence"]
    )


def test_anti_debug_with_check_remote_debugger_api():
    detector = _make_detector(
        imports=[{"name": "CheckRemoteDebuggerPresent", "plt": 0x2000, "libname": "kernel32.dll"}],
    )
    result = detector.detect()

    assert result["anti_debug"] is True


def test_anti_debug_with_nt_query_information():
    detector = _make_detector(
        imports=[{"name": "NtQueryInformationProcess", "plt": 0x3000, "libname": "ntdll.dll"}],
    )
    result = detector.detect()

    assert result["anti_debug"] is True


def test_anti_vm_with_vmware_strings():
    detector = _make_detector(
        strings=[
            {
                "string": "VMware",
                "vaddr": 0x1000,
                "type": "ascii",
                "length": 6,
                "section": ".data",
                "paddr": 0x1000,
            },
            {
                "string": "vmtoolsd.exe",
                "vaddr": 0x2000,
                "type": "ascii",
                "length": 12,
                "section": ".data",
                "paddr": 0x2000,
            },
        ],
    )
    result = detector.detect()

    assert result["anti_vm"] is True
    assert any(
        "VM Artifact Strings" in str(e) for e in result["detection_details"]["anti_vm_evidence"]
    )


def test_anti_vm_with_virtualbox_strings():
    detector = _make_detector(
        strings=[
            {
                "string": "VirtualBox",
                "vaddr": 0x1000,
                "type": "ascii",
                "length": 10,
                "section": ".data",
                "paddr": 0x1000,
            },
            {
                "string": "VBoxService",
                "vaddr": 0x2000,
                "type": "ascii",
                "length": 11,
                "section": ".data",
                "paddr": 0x2000,
            },
        ],
    )
    result = detector.detect()

    assert result["anti_vm"] is True


def test_anti_sandbox_with_cuckoo_string():
    detector = _make_detector(
        strings=[
            {
                "string": "cuckoo",
                "vaddr": 0x1000,
                "type": "ascii",
                "length": 6,
                "section": ".data",
                "paddr": 0x1000,
            }
        ],
    )
    result = detector.detect()

    assert result["anti_sandbox"] is True


def test_anti_sandbox_with_sandbox_indicator():
    detector = _make_detector(
        strings=[
            {
                "string": "sandbox",
                "vaddr": 0x1000,
                "type": "ascii",
                "length": 7,
                "section": ".data",
                "paddr": 0x1000,
            },
            {
                "string": "virus.exe",
                "vaddr": 0x2000,
                "type": "ascii",
                "length": 9,
                "section": ".data",
                "paddr": 0x2000,
            },
        ],
    )
    result = detector.detect()

    assert result["anti_sandbox"] is True
    assert any(
        "Sandbox Indicator Strings" in str(e)
        for e in result["detection_details"]["anti_sandbox_evidence"]
    )


def test_timing_checks_with_get_tick_count():
    detector = _make_detector(
        imports=[{"name": "GetTickCount", "plt": 0x1000, "libname": "kernel32.dll"}],
    )
    result = detector.detect()

    assert result["timing_checks"] is True
    assert any("Timing API Calls" in str(e) for e in result["detection_details"]["timing_evidence"])


def test_anti_analysis_evidence_accepts_library_key() -> None:
    detector = _make_detector(
        imports=[
            {"name": "IsDebuggerPresent", "plt": 0x1000, "library": "kernel32.dll"},
            {"name": "GetTickCount", "plt": 0x2000, "library": "kernel32.dll"},
        ],
    )
    result = detector.detect()

    anti_debug_evidence = result["detection_details"]["anti_debug_evidence"]
    timing_evidence = result["detection_details"]["timing_evidence"][0]["apis"]

    assert anti_debug_evidence[0]["library"] == "kernel32.dll"
    assert timing_evidence[0]["library"] == "kernel32.dll"


def test_timing_checks_with_query_performance_counter():
    detector = _make_detector(
        imports=[{"name": "QueryPerformanceCounter", "plt": 0x2000, "libname": "kernel32.dll"}],
    )
    result = detector.detect()

    assert result["timing_checks"] is True


def test_suspicious_api_virtual_alloc():
    detector = _make_detector(
        imports=[{"name": "VirtualAlloc", "plt": 0x1000, "libname": "kernel32.dll"}],
    )
    result = detector.detect()

    assert len(result["suspicious_apis"]) > 0


def test_suspicious_api_create_process():
    detector = _make_detector(
        imports=[{"name": "CreateProcess", "plt": 0x2000, "libname": "kernel32.dll"}],
    )
    result = detector.detect()

    assert len(result["suspicious_apis"]) > 0


def test_suspicious_api_registry_operations():
    detector = _make_detector(
        imports=[
            {"name": "RegSetValue", "plt": 0x3000, "libname": "advapi32.dll"},
            {"name": "RegOpenKey", "plt": 0x3100, "libname": "advapi32.dll"},
        ],
    )
    result = detector.detect()

    assert len(result["suspicious_apis"]) >= 2


def test_suspicious_api_network_operations():
    detector = _make_detector(
        imports=[
            {"name": "socket", "plt": 0x4000, "libname": "ws2_32.dll"},
            {"name": "connect", "plt": 0x4100, "libname": "ws2_32.dll"},
        ],
    )
    result = detector.detect()

    assert len(result["suspicious_apis"]) >= 2


def test_injection_apis_detection():
    detector = _make_detector(
        imports=[
            {"name": "VirtualAllocEx", "plt": 0x1000, "libname": "kernel32.dll"},
            {"name": "WriteProcessMemory", "plt": 0x2000, "libname": "kernel32.dll"},
            {"name": "CreateRemoteThread", "plt": 0x3000, "libname": "kernel32.dll"},
        ],
    )
    result = detector.detect()

    assert len(result["evasion_techniques"]) > 0 or len(result["suspicious_apis"]) > 0


def test_no_anti_analysis_detected():
    detector = _make_detector(
        imports=[{"name": "printf", "plt": 0x1000, "libname": "msvcrt.dll"}],
        strings=[
            {
                "string": "Hello World",
                "vaddr": 0x1000,
                "type": "ascii",
                "length": 11,
                "section": ".data",
                "paddr": 0x1000,
            }
        ],
    )
    result = detector.detect()

    assert result["anti_debug"] is False
    assert result["anti_vm"] is False
    assert result["anti_sandbox"] is False
    assert result["timing_checks"] is False


def test_multiple_anti_debug_apis():
    detector = _make_detector(
        imports=[
            {"name": "IsDebuggerPresent", "plt": 0x1000, "libname": "kernel32.dll"},
            {"name": "CheckRemoteDebuggerPresent", "plt": 0x2000, "libname": "kernel32.dll"},
            {"name": "NtQueryInformationProcess", "plt": 0x3000, "libname": "ntdll.dll"},
            {"name": "OutputDebugStringA", "plt": 0x4000, "libname": "kernel32.dll"},
        ],
    )
    result = detector.detect()

    assert result["anti_debug"] is True
    assert len(result["detection_details"]["anti_debug_evidence"]) > 0


def test_combined_anti_vm_indicators():
    detector = _make_detector(
        strings=[
            {
                "string": "VMware",
                "vaddr": 0x1000,
                "type": "ascii",
                "length": 6,
                "section": ".data",
                "paddr": 0x1000,
            },
            {
                "string": "VirtualBox",
                "vaddr": 0x2000,
                "type": "ascii",
                "length": 10,
                "section": ".data",
                "paddr": 0x2000,
            },
            {
                "string": "qemu",
                "vaddr": 0x3000,
                "type": "ascii",
                "length": 4,
                "section": ".data",
                "paddr": 0x3000,
            },
            {
                "string": "bochs",
                "vaddr": 0x4000,
                "type": "ascii",
                "length": 5,
                "section": ".data",
                "paddr": 0x4000,
            },
        ],
    )
    result = detector.detect()

    assert result["anti_vm"] is True
    evidence = result["detection_details"]["anti_vm_evidence"]
    vm_strings_evidence = [e for e in evidence if e.get("type") == "VM Artifact Strings"]
    assert len(vm_strings_evidence) > 0


def test_combined_evasion_techniques():
    detector = _make_detector(
        imports=[
            {"name": "IsDebuggerPresent", "plt": 0x1000, "libname": "kernel32.dll"},
            {"name": "GetTickCount", "plt": 0x2000, "libname": "kernel32.dll"},
            {"name": "VirtualAllocEx", "plt": 0x3000, "libname": "kernel32.dll"},
        ],
        strings=[
            {
                "string": "VMware",
                "vaddr": 0x1000,
                "type": "ascii",
                "length": 6,
                "section": ".data",
                "paddr": 0x1000,
            },
            {
                "string": "sandbox",
                "vaddr": 0x2000,
                "type": "ascii",
                "length": 7,
                "section": ".data",
                "paddr": 0x2000,
            },
        ],
    )
    result = detector.detect()

    assert result["anti_debug"] is True
    assert result["anti_vm"] is True
    assert result["anti_sandbox"] is True
    assert result["timing_checks"] is True
    assert len(result["suspicious_apis"]) > 0


def test_empty_imports():
    detector = _make_detector()
    result = detector.detect()

    assert result["anti_debug"] is False
    assert result["timing_checks"] is False
    assert len(result["suspicious_apis"]) == 0


def test_detection_details_structure():
    detector = _make_detector()
    result = detector.detect()

    assert "detection_details" in result
    details = result["detection_details"]
    assert "anti_debug_evidence" in details
    assert "anti_vm_evidence" in details
    assert "anti_sandbox_evidence" in details
    assert "timing_evidence" in details
