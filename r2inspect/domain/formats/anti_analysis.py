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

# General-purpose timing APIs that are used by virtually every program (frame
# timing, performance measurement, RNG seeding). They CAN drive a timing-based
# anti-debug check, but their mere import is not evidence of one -- so they are
# recorded as informational ("weak") rather than asserting anti-debug.
WEAK_ANTI_DEBUG_APIS = {
    "GetTickCount",
    "GetTickCount64",
    "QueryPerformanceCounter",
}

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

# VM-vendor MAC-address OUI prefixes (colon form). A binary that hardcodes one
# of these is fingerprinting the host NIC to spot a hypervisor. Matched with
# word boundaries, NOT a bare "mac" substring -- that hit benign tokens like
# "machine", "dl-machine", "hmac"/"hmac.HMAC", and "Cinemachine".
VM_MAC_OUIS = [
    "00:05:69",  # VMware
    "00:0c:29",  # VMware
    "00:1c:14",  # VMware
    "00:50:56",  # VMware
    "08:00:27",  # VirtualBox
    "00:15:5d",  # Hyper-V
    "00:1c:42",  # Parallels
    "00:16:3e",  # Xen
    "52:54:00",  # QEMU / KVM
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
    # r2's ~ grep ORs with ',' (not '|', a shell pipe). The dropped second
    # terms ("USER"/"COMPUTERNAME") were dead AND too loose to enable safely
    # (they match ordinary strings), so keep only the specific API-name probe.
    ("iz~GetUserName", "Username Check", "Username enumeration detected"),
    (
        "iz~GetComputerName",
        "Computer Name Check",
        "Computer name enumeration detected",
    ),
    (
        "ii~GetSystemInfo,GlobalMemoryStatus",
        "System Info Check",
        "System information queries detected",
    ),
    (
        "ii~CreateToolhelp32Snapshot,Process32",
        "Process Enumeration",
        "Process enumeration detected",
    ),
]
