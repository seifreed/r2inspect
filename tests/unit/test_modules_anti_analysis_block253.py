from r2inspect.modules.anti_analysis import AntiAnalysisDetector


class DummyAdapter:
    def __init__(self):
        self._imports = [
            {"name": "IsDebuggerPresent", "plt": 1, "libname": "kernel32"},
            {"name": "GetTickCount", "plt": 2, "libname": "kernel32"},
            {"name": "VirtualAllocEx", "plt": 3, "libname": "kernel32"},
            {"name": "WriteProcessMemory", "plt": 4, "libname": "kernel32"},
        ]
        self._strings = [
            {"string": "VMware", "vaddr": 10},
            {"string": "sandbox", "vaddr": 20},
        ]

    def get_imports(self):
        return self._imports

    def get_strings(self):
        return self._strings

    def search_text(self, pattern: str):
        if pattern == "fs:[0x30]":
            return "0x1000"
        if pattern == "cc":
            return "0x2000\n0x2001\n0x2002\n0x2003\n0x2004\n0x2005"
        if pattern == "rdtsc":
            return "0x3000"
        if pattern == "jmp":
            return "\n".join(["0x1"] * 101)
        if pattern == "call":
            return "\n".join(["0x1"] * 201)
        return ""

    def search_hex(self, pattern: str):
        return ""

    def get_strings_filtered(self, _command: str):
        return "hit"

    def cmd(self, command: str):
        if command.startswith("iz~mac"):
            return "mac"
        if command.startswith("iz~HKEY"):
            return "hkey"
        if command.startswith("ii~Sleep"):
            return "Sleep"
        if command.startswith("ii~FindFirst"):
            return "FindFirst"
        if command.startswith("/c mov"):
            return "mov cs"
        if command.startswith("iz~hash"):
            return "hash"
        if command.startswith("iz~GetUserName") or command.startswith("iz~USER"):
            return "user"
        if command.startswith("iz~GetComputerName") or command.startswith("iz~COMPUTERNAME"):
            return "pc"
        if command.startswith("ii~GetSystemInfo"):
            return "sys"
        if command.startswith("ii~CreateToolhelp32Snapshot"):
            return "proc"
        return ""

    def cmdj(self, _command: str):
        return []


def test_anti_analysis_detector_full_flow():
    detector = AntiAnalysisDetector(DummyAdapter())
    result = detector.detect()

    assert result["anti_debug"] is True
    assert result["anti_vm"] is True
    assert result["anti_sandbox"] is True
    assert result["timing_checks"] is True

    assert result["evasion_techniques"]
    assert result["suspicious_apis"]
    assert result["environment_checks"]
