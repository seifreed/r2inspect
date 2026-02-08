from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.compiler_detector import CompilerDetector


class _Config:
    pass


def test_compiler_detector_real_fixture():
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    r2 = r2pipe.open(str(sample), flags=["-2"])
    try:
        adapter = R2PipeAdapter(r2)
        detector = CompilerDetector(adapter, _Config())
        result = detector.detect_compiler()
        assert "compiler" in result
        assert "confidence" in result
        assert 0.0 <= result.get("confidence", 0.0) <= 1.0
        assert "details" in result
        assert "signatures_found" in result
    finally:
        r2.quit()
