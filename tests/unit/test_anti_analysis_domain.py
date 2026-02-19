#!/usr/bin/env python3
"""Comprehensive tests for anti_analysis_domain module."""

from r2inspect.modules.anti_analysis_domain import (
    ANTI_DEBUG_APIS,
    ENVIRONMENT_CHECK_COMMANDS,
    INJECTION_APIS,
    SANDBOX_INDICATORS,
    SUSPICIOUS_API_CATEGORIES,
    TIMING_APIS,
    VM_ARTIFACTS,
)


def test_anti_debug_apis_not_empty():
    assert len(ANTI_DEBUG_APIS) > 0


def test_anti_debug_apis_contains_expected():
    assert "IsDebuggerPresent" in ANTI_DEBUG_APIS
    assert "CheckRemoteDebuggerPresent" in ANTI_DEBUG_APIS
    assert "NtQueryInformationProcess" in ANTI_DEBUG_APIS
    assert "ZwQueryInformationProcess" in ANTI_DEBUG_APIS


def test_anti_debug_apis_timing_functions():
    assert "GetTickCount" in ANTI_DEBUG_APIS
    assert "QueryPerformanceCounter" in ANTI_DEBUG_APIS


def test_anti_debug_apis_output_functions():
    assert "OutputDebugStringA" in ANTI_DEBUG_APIS
    assert "OutputDebugStringW" in ANTI_DEBUG_APIS


def test_anti_debug_apis_thread_functions():
    assert "NtSetInformationThread" in ANTI_DEBUG_APIS
    assert "SetThreadHideFromDebugger" in ANTI_DEBUG_APIS


def test_anti_debug_apis_all_strings():
    for api in ANTI_DEBUG_APIS:
        assert isinstance(api, str)
        assert len(api) > 0


def test_vm_artifacts_not_empty():
    assert len(VM_ARTIFACTS) > 0


def test_vm_artifacts_vmware():
    assert "VMware" in VM_ARTIFACTS
    assert "vmtoolsd" in VM_ARTIFACTS
    assert "vmwaretray" in VM_ARTIFACTS
    assert "vmwareuser" in VM_ARTIFACTS


def test_vm_artifacts_virtualbox():
    assert "VirtualBox" in VM_ARTIFACTS
    assert "vbox" in VM_ARTIFACTS
    assert "VBoxService" in VM_ARTIFACTS
    assert "VBoxTray" in VM_ARTIFACTS


def test_vm_artifacts_other_vms():
    assert "qemu" in VM_ARTIFACTS
    assert "bochs" in VM_ARTIFACTS
    assert "xenservice" in VM_ARTIFACTS


def test_vm_artifacts_analysis_tools():
    assert "sandboxie" in VM_ARTIFACTS
    assert "wireshark" in VM_ARTIFACTS
    assert "fiddler" in VM_ARTIFACTS
    assert "regmon" in VM_ARTIFACTS
    assert "procmon" in VM_ARTIFACTS


def test_vm_artifacts_file_extensions():
    assert "vmx" in VM_ARTIFACTS
    assert "vhd" in VM_ARTIFACTS


def test_vm_artifacts_all_strings():
    for artifact in VM_ARTIFACTS:
        assert isinstance(artifact, str)
        assert len(artifact) > 0


def test_sandbox_indicators_not_empty():
    assert len(SANDBOX_INDICATORS) > 0


def test_sandbox_indicators_generic():
    assert "sample" in SANDBOX_INDICATORS
    assert "virus" in SANDBOX_INDICATORS
    assert "malware" in SANDBOX_INDICATORS
    assert "sandbox" in SANDBOX_INDICATORS


def test_sandbox_indicators_specific():
    assert "cuckoo" in SANDBOX_INDICATORS
    assert "anubis" in SANDBOX_INDICATORS
    assert "joesandbox" in SANDBOX_INDICATORS
    assert "threatanalyzer" in SANDBOX_INDICATORS


def test_sandbox_indicators_additional():
    assert "gfilogger" in SANDBOX_INDICATORS
    assert "cwsandbox" in SANDBOX_INDICATORS


def test_sandbox_indicators_all_strings():
    for indicator in SANDBOX_INDICATORS:
        assert isinstance(indicator, str)
        assert len(indicator) > 0


def test_injection_apis_not_empty():
    assert len(INJECTION_APIS) > 0


def test_injection_apis_contains_expected():
    assert "VirtualAllocEx" in INJECTION_APIS
    assert "WriteProcessMemory" in INJECTION_APIS
    assert "CreateRemoteThread" in INJECTION_APIS


def test_injection_apis_all_strings():
    for api in INJECTION_APIS:
        assert isinstance(api, str)
        assert len(api) > 0


def test_suspicious_api_categories_not_empty():
    assert len(SUSPICIOUS_API_CATEGORIES) > 0


def test_suspicious_api_categories_process_thread():
    assert "Process/Thread" in SUSPICIOUS_API_CATEGORIES
    apis = SUSPICIOUS_API_CATEGORIES["Process/Thread"]
    assert "CreateProcess" in apis
    assert "CreateThread" in apis
    assert "OpenProcess" in apis
    assert "TerminateProcess" in apis


def test_suspicious_api_categories_memory():
    assert "Memory" in SUSPICIOUS_API_CATEGORIES
    apis = SUSPICIOUS_API_CATEGORIES["Memory"]
    assert "VirtualAlloc" in apis
    assert "VirtualProtect" in apis
    assert "HeapAlloc" in apis
    assert "MapViewOfFile" in apis


def test_suspicious_api_categories_file_system():
    assert "File System" in SUSPICIOUS_API_CATEGORIES
    apis = SUSPICIOUS_API_CATEGORIES["File System"]
    assert "CreateFile" in apis
    assert "DeleteFile" in apis
    assert "MoveFile" in apis
    assert "FindFirstFile" in apis


def test_suspicious_api_categories_registry():
    assert "Registry" in SUSPICIOUS_API_CATEGORIES
    apis = SUSPICIOUS_API_CATEGORIES["Registry"]
    assert "RegOpenKey" in apis
    assert "RegSetValue" in apis
    assert "RegDeleteKey" in apis
    assert "RegEnumKey" in apis


def test_suspicious_api_categories_network():
    assert "Network" in SUSPICIOUS_API_CATEGORIES
    apis = SUSPICIOUS_API_CATEGORIES["Network"]
    assert "WSAStartup" in apis
    assert "socket" in apis
    assert "connect" in apis
    assert "HttpOpenRequest" in apis


def test_suspicious_api_categories_crypto():
    assert "Crypto" in SUSPICIOUS_API_CATEGORIES
    apis = SUSPICIOUS_API_CATEGORIES["Crypto"]
    assert "CryptAcquireContext" in apis
    assert "CryptCreateHash" in apis
    assert "CryptEncrypt" in apis


def test_suspicious_api_categories_service():
    assert "Service" in SUSPICIOUS_API_CATEGORIES
    apis = SUSPICIOUS_API_CATEGORIES["Service"]
    assert "CreateService" in apis
    assert "StartService" in apis
    assert "OpenSCManager" in apis


def test_suspicious_api_categories_all_lists():
    for category, apis in SUSPICIOUS_API_CATEGORIES.items():
        assert isinstance(category, str)
        assert isinstance(apis, list)
        assert len(apis) > 0


def test_timing_apis_not_empty():
    assert len(TIMING_APIS) > 0


def test_timing_apis_contains_expected():
    assert "GetTickCount" in TIMING_APIS
    assert "QueryPerformanceCounter" in TIMING_APIS
    assert "timeGetTime" in TIMING_APIS
    assert "GetSystemTimeAsFileTime" in TIMING_APIS
    assert "NtQuerySystemTime" in TIMING_APIS


def test_timing_apis_descriptions():
    assert TIMING_APIS["GetTickCount"] == "Basic timing check"
    assert TIMING_APIS["QueryPerformanceCounter"] == "High-resolution timing"
    assert TIMING_APIS["timeGetTime"] == "Multimedia timer"
    assert TIMING_APIS["GetSystemTimeAsFileTime"] == "File time check"
    assert TIMING_APIS["NtQuerySystemTime"] == "Native timing check"


def test_timing_apis_all_have_descriptions():
    for api, description in TIMING_APIS.items():
        assert isinstance(api, str)
        assert isinstance(description, str)
        assert len(description) > 0


def test_environment_check_commands_not_empty():
    assert len(ENVIRONMENT_CHECK_COMMANDS) > 0


def test_environment_check_commands_structure():
    for cmd, name, description in ENVIRONMENT_CHECK_COMMANDS:
        assert isinstance(cmd, str)
        assert isinstance(name, str)
        assert isinstance(description, str)
        assert len(cmd) > 0
        assert len(name) > 0
        assert len(description) > 0


def test_environment_check_commands_username():
    commands = [cmd for cmd, name, desc in ENVIRONMENT_CHECK_COMMANDS if "Username" in name]
    assert len(commands) > 0


def test_environment_check_commands_computer_name():
    commands = [cmd for cmd, name, desc in ENVIRONMENT_CHECK_COMMANDS if "Computer Name" in name]
    assert len(commands) > 0


def test_environment_check_commands_system_info():
    commands = [cmd for cmd, name, desc in ENVIRONMENT_CHECK_COMMANDS if "System Info" in name]
    assert len(commands) > 0


def test_environment_check_commands_process_enum():
    commands = [cmd for cmd, name, desc in ENVIRONMENT_CHECK_COMMANDS if "Process Enumeration" in name]
    assert len(commands) > 0


def test_anti_debug_apis_unique():
    assert len(ANTI_DEBUG_APIS) == len(set(ANTI_DEBUG_APIS))


def test_vm_artifacts_unique():
    assert len(VM_ARTIFACTS) == len(set(VM_ARTIFACTS))


def test_sandbox_indicators_unique():
    assert len(SANDBOX_INDICATORS) == len(set(SANDBOX_INDICATORS))


def test_injection_apis_unique():
    assert len(INJECTION_APIS) == len(set(INJECTION_APIS))


def test_timing_apis_unique():
    assert len(TIMING_APIS) == len(set(TIMING_APIS.keys()))


def test_suspicious_api_categories_no_duplicates():
    all_apis = []
    for apis in SUSPICIOUS_API_CATEGORIES.values():
        all_apis.extend(apis)
    assert len(all_apis) == len(set(all_apis))


def test_anti_debug_apis_count():
    assert len(ANTI_DEBUG_APIS) >= 10


def test_vm_artifacts_count():
    assert len(VM_ARTIFACTS) >= 15


def test_sandbox_indicators_count():
    assert len(SANDBOX_INDICATORS) >= 8


def test_injection_apis_count():
    assert len(INJECTION_APIS) == 3


def test_timing_apis_count():
    assert len(TIMING_APIS) == 5


def test_suspicious_api_categories_count():
    assert len(SUSPICIOUS_API_CATEGORIES) == 7


def test_environment_check_commands_count():
    assert len(ENVIRONMENT_CHECK_COMMANDS) == 4


def test_anti_debug_apis_no_empty_strings():
    for api in ANTI_DEBUG_APIS:
        assert api.strip() == api
        assert len(api) > 0


def test_vm_artifacts_no_empty_strings():
    for artifact in VM_ARTIFACTS:
        assert artifact.strip() == artifact
        assert len(artifact) > 0


def test_sandbox_indicators_no_empty_strings():
    for indicator in SANDBOX_INDICATORS:
        assert indicator.strip() == indicator
        assert len(indicator) > 0


def test_injection_apis_no_empty_strings():
    for api in INJECTION_APIS:
        assert api.strip() == api
        assert len(api) > 0


def test_suspicious_api_categories_values_are_lists():
    for category, apis in SUSPICIOUS_API_CATEGORIES.items():
        assert isinstance(apis, list)
        for api in apis:
            assert isinstance(api, str)


def test_timing_apis_values_are_strings():
    for api, description in TIMING_APIS.items():
        assert isinstance(description, str)
        assert len(description) > 0


def test_environment_check_commands_tuples():
    for entry in ENVIRONMENT_CHECK_COMMANDS:
        assert isinstance(entry, tuple)
        assert len(entry) == 3


def test_anti_debug_apis_nt_functions():
    nt_apis = [api for api in ANTI_DEBUG_APIS if api.startswith("Nt") or api.startswith("Zw")]
    assert len(nt_apis) >= 3


def test_vm_artifacts_case_variations():
    lower_artifacts = [a.lower() for a in VM_ARTIFACTS]
    assert len(lower_artifacts) >= len(VM_ARTIFACTS) - 5


def test_suspicious_api_categories_memory_apis():
    memory_apis = SUSPICIOUS_API_CATEGORIES.get("Memory", [])
    assert len(memory_apis) >= 4


def test_suspicious_api_categories_network_apis():
    network_apis = SUSPICIOUS_API_CATEGORIES.get("Network", [])
    assert len(network_apis) >= 4


def test_suspicious_api_categories_registry_apis():
    registry_apis = SUSPICIOUS_API_CATEGORIES.get("Registry", [])
    assert len(registry_apis) >= 4
