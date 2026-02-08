from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer


class MinimalAdapter:
    def cmd(self, _command: str):
        return ""

    def cmdj(self, _command: str):
        return {}


def test_authenticode_analyzer_basic():
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    adapter = None
    r2 = None
    try:
        r2 = r2pipe.open(str(sample), flags=["-2"])
        adapter = R2PipeAdapter(r2)
    except OSError:
        adapter = MinimalAdapter()

    analyzer = AuthenticodeAnalyzer(adapter)
    result = analyzer.analyze()
    assert "has_signature" in result
    assert "signature_valid" in result
    assert "available" in result

    if r2 is not None:
        r2.quit()
