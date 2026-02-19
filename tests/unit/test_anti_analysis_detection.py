from __future__ import annotations

from unittest.mock import Mock

from r2inspect.modules.anti_analysis import AntiAnalysisDetector


def test_anti_debug_with_is_debugger_present_api():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[
        {"name": "IsDebuggerPresent", "plt": 0x1000, "libname": "kernel32.dll"}
    ])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert result["anti_debug"] is True
    assert any("IsDebuggerPresent" in str(e) for e in result["detection_details"]["anti_debug_evidence"])


def test_anti_debug_with_check_remote_debugger_api():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[
        {"name": "CheckRemoteDebuggerPresent", "plt": 0x2000, "libname": "kernel32.dll"}
    ])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert result["anti_debug"] is True


def test_anti_debug_with_nt_query_information():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[
        {"name": "NtQueryInformationProcess", "plt": 0x3000, "libname": "ntdll.dll"}
    ])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert result["anti_debug"] is True


def test_anti_vm_with_vmware_strings():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[
        {"string": "VMware", "vaddr": 0x1000},
        {"string": "vmtoolsd.exe", "vaddr": 0x2000}
    ])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert result["anti_vm"] is True
    assert any("VM Artifact Strings" in str(e) for e in result["detection_details"]["anti_vm_evidence"])


def test_anti_vm_with_virtualbox_strings():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[
        {"string": "VirtualBox", "vaddr": 0x1000},
        {"string": "VBoxService", "vaddr": 0x2000}
    ])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert result["anti_vm"] is True


def test_anti_sandbox_with_cuckoo_string():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[
        {"string": "cuckoo", "vaddr": 0x1000}
    ])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert result["anti_sandbox"] is True


def test_anti_sandbox_with_sandbox_indicator():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[
        {"string": "sandbox", "vaddr": 0x1000},
        {"string": "virus.exe", "vaddr": 0x2000}
    ])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert result["anti_sandbox"] is True
    assert any("Sandbox Indicator Strings" in str(e) for e in result["detection_details"]["anti_sandbox_evidence"])


def test_timing_checks_with_get_tick_count():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[
        {"name": "GetTickCount", "plt": 0x1000, "libname": "kernel32.dll"}
    ])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert result["timing_checks"] is True
    assert any("Timing API Calls" in str(e) for e in result["detection_details"]["timing_evidence"])


def test_timing_checks_with_query_performance_counter():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[
        {"name": "QueryPerformanceCounter", "plt": 0x2000, "libname": "kernel32.dll"}
    ])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert result["timing_checks"] is True


def test_suspicious_api_virtual_alloc():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[
        {"name": "VirtualAlloc", "plt": 0x1000, "libname": "kernel32.dll"}
    ])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert len(result["suspicious_apis"]) > 0


def test_suspicious_api_create_process():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[
        {"name": "CreateProcess", "plt": 0x2000, "libname": "kernel32.dll"}
    ])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert len(result["suspicious_apis"]) > 0


def test_suspicious_api_registry_operations():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[
        {"name": "RegSetValue", "plt": 0x3000, "libname": "advapi32.dll"},
        {"name": "RegOpenKey", "plt": 0x3100, "libname": "advapi32.dll"}
    ])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert len(result["suspicious_apis"]) >= 2


def test_suspicious_api_network_operations():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[
        {"name": "socket", "plt": 0x4000, "libname": "ws2_32.dll"},
        {"name": "connect", "plt": 0x4100, "libname": "ws2_32.dll"}
    ])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert len(result["suspicious_apis"]) >= 2


def test_injection_apis_detection():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[
        {"name": "VirtualAllocEx", "plt": 0x1000, "libname": "kernel32.dll"},
        {"name": "WriteProcessMemory", "plt": 0x2000, "libname": "kernel32.dll"},
        {"name": "CreateRemoteThread", "plt": 0x3000, "libname": "kernel32.dll"}
    ])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert len(result["evasion_techniques"]) > 0 or len(result["suspicious_apis"]) > 0


def test_no_anti_analysis_detected():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[
        {"name": "printf", "plt": 0x1000, "libname": "msvcrt.dll"}
    ])
    adapter.get_strings = Mock(return_value=[
        {"string": "Hello World", "vaddr": 0x1000}
    ])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert result["anti_debug"] is False
    assert result["anti_vm"] is False
    assert result["anti_sandbox"] is False
    assert result["timing_checks"] is False


def test_multiple_anti_debug_apis():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[
        {"name": "IsDebuggerPresent", "plt": 0x1000, "libname": "kernel32.dll"},
        {"name": "CheckRemoteDebuggerPresent", "plt": 0x2000, "libname": "kernel32.dll"},
        {"name": "NtQueryInformationProcess", "plt": 0x3000, "libname": "ntdll.dll"},
        {"name": "OutputDebugStringA", "plt": 0x4000, "libname": "kernel32.dll"}
    ])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert result["anti_debug"] is True
    assert len(result["detection_details"]["anti_debug_evidence"]) > 0


def test_combined_anti_vm_indicators():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[
        {"string": "VMware", "vaddr": 0x1000},
        {"string": "VirtualBox", "vaddr": 0x2000},
        {"string": "qemu", "vaddr": 0x3000},
        {"string": "bochs", "vaddr": 0x4000}
    ])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert result["anti_vm"] is True
    evidence = result["detection_details"]["anti_vm_evidence"]
    vm_strings_evidence = [e for e in evidence if e.get("type") == "VM Artifact Strings"]
    assert len(vm_strings_evidence) > 0


def test_combined_evasion_techniques():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[
        {"name": "IsDebuggerPresent", "plt": 0x1000, "libname": "kernel32.dll"},
        {"name": "GetTickCount", "plt": 0x2000, "libname": "kernel32.dll"},
        {"name": "VirtualAllocEx", "plt": 0x3000, "libname": "kernel32.dll"}
    ])
    adapter.get_strings = Mock(return_value=[
        {"string": "VMware", "vaddr": 0x1000},
        {"string": "sandbox", "vaddr": 0x2000}
    ])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert result["anti_debug"] is True
    assert result["anti_vm"] is True
    assert result["anti_sandbox"] is True
    assert result["timing_checks"] is True
    assert len(result["suspicious_apis"]) > 0


def test_empty_imports():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert result["anti_debug"] is False
    assert result["timing_checks"] is False
    assert len(result["suspicious_apis"]) == 0


def test_detection_details_structure():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value=[])
    adapter.cmd = Mock(return_value="")
    
    detector = AntiAnalysisDetector(adapter, None)
    result = detector.detect()
    
    assert "detection_details" in result
    details = result["detection_details"]
    assert "anti_debug_evidence" in details
    assert "anti_vm_evidence" in details
    assert "anti_sandbox_evidence" in details
    assert "timing_evidence" in details
