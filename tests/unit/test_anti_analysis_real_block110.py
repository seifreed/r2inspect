from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.anti_analysis import AntiAnalysisDetector


class MinimalAdapter:
    def get_imports(self):
        return [{"name": "IsDebuggerPresent", "plt": 1, "libname": "kernel32"}]

    def get_strings(self):
        return [{"string": "VMware", "vaddr": 10}]

    def search_text(self, pattern: str):
        if pattern == "fs:[0x30]":
            return "0x1000"
        if pattern == "rdtsc":
            return "0x2000"
        return ""

    def search_hex(self, _pattern: str):
        return ""

    def get_strings_filtered(self, _command: str):
        return ""

    def cmd(self, command: str):
        if command.startswith("iz~mac"):
            return "mac"
        if command.startswith("ii~Sleep"):
            return "Sleep"
        return ""

    def cmdj(self, _command: str):
        return []


def test_anti_analysis_detector_real_fixture():
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    adapter = None
    r2 = None
    try:
        r2 = r2pipe.open(str(sample), flags=["-2"])
        adapter = R2PipeAdapter(r2)
    except OSError:
        adapter = MinimalAdapter()

    detector = AntiAnalysisDetector(adapter, config=None)
    result = detector.detect()
    assert "anti_debug" in result
    assert "anti_vm" in result
    assert "anti_sandbox" in result
    assert "detection_details" in result
    assert isinstance(result.get("suspicious_apis"), list)
    assert isinstance(result.get("evasion_techniques"), list)

    if r2 is not None:
        r2.quit()
