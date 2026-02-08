from __future__ import annotations

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer

PE_FIXTURE = "samples/fixtures/hello_pe.exe"


def test_authenticode_analyzer_real_fixture_details() -> None:
    r2 = r2pipe.open(PE_FIXTURE)
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = AuthenticodeAnalyzer(adapter)
        result = analyzer.analyze()
    finally:
        r2.quit()

    assert "has_signature" in result
    assert "signature_valid" in result
    assert "certificates" in result
    assert "errors" in result
