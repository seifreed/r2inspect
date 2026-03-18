"""Domain constants for anti-analysis detection."""

ANTI_DEBUG_APIS = [
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "ZwQueryInformationProcess",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "GetTickCount",
    "QueryPerformanceCounter",
    "NtSetInformationThread",
    "SetThreadHideFromDebugger",
    "NtQueryObject",
    "NtClose",
]

VM_ARTIFACTS = [
    "VMware",
    "VirtualBox",
    "vbox",
    "vmtoolsd",
    "vmwaretray",
    "vmwareuser",
    "VBoxService",
    "VBoxTray",
    "xenservice",
    "qemu",
    "bochs",
    "sandboxie",
    "wireshark",
    "fiddler",
    "regmon",
    "procmon",
    "vmx",
    "vhd",
]

SANDBOX_INDICATORS = [
    "sample",
    "virus",
    "malware",
    "sandbox",
    "cuckoo",
    "anubis",
    "joesandbox",
    "threatanalyzer",
    "gfilogger",
    "cwsandbox",
]

INJECTION_APIS = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]

SUSPICIOUS_API_CATEGORIES: dict[str, list[str]] = {
    "Process/Thread": [
        "CreateProcess",
        "CreateThread",
        "OpenProcess",
        "TerminateProcess",
    ],
    "Memory": [
        "VirtualAlloc",
        "VirtualProtect",
        "HeapAlloc",
        "MapViewOfFile",
    ],
    "File System": [
        "CreateFile",
        "DeleteFile",
        "MoveFile",
        "FindFirstFile",
    ],
    "Registry": [
        "RegOpenKey",
        "RegSetValue",
        "RegDeleteKey",
        "RegEnumKey",
    ],
    "Network": ["WSAStartup", "socket", "connect", "HttpOpenRequest"],
    "Crypto": ["CryptAcquireContext", "CryptCreateHash", "CryptEncrypt"],
    "Service": ["CreateService", "StartService", "OpenSCManager"],
}

TIMING_APIS = {
    "GetTickCount": "Basic timing check",
    "QueryPerformanceCounter": "High-resolution timing",
    "timeGetTime": "Multimedia timer",
    "GetSystemTimeAsFileTime": "File time check",
    "NtQuerySystemTime": "Native timing check",
}

ENVIRONMENT_CHECK_COMMANDS = [
    ("iz~GetUserName|iz~USER", "Username Check", "Username enumeration detected"),
    (
        "iz~GetComputerName|iz~COMPUTERNAME",
        "Computer Name Check",
        "Computer name enumeration detected",
    ),
    (
        "ii~GetSystemInfo|ii~GlobalMemoryStatus",
        "System Info Check",
        "System information queries detected",
    ),
    (
        "ii~CreateToolhelp32Snapshot|ii~Process32",
        "Process Enumeration",
        "Process enumeration detected",
    ),
]
