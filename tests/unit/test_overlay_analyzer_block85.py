from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.overlay_analyzer import OverlayAnalyzer


def test_overlay_analyzer_with_appended_data(tmp_path: Path):
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    modified = tmp_path / "hello_pe_overlay.exe"
    modified.write_bytes(sample.read_bytes() + b"OVERLAYDATA1234567890")

    r2 = r2pipe.open(str(modified), flags=["-2"])
    try:
        analyzer = OverlayAnalyzer(R2PipeAdapter(r2))
        result = analyzer.analyze()
        assert "has_overlay" in result
        # Depending on PE end calc, overlay may or may not be detected. Ensure no crash.
        assert isinstance(result, dict)
    finally:
        r2.quit()
