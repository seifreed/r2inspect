from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.modules.packer_detector import PackerDetector


def test_packer_detector_basic(tmp_path: Path):
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    config = Config(str(tmp_path / "config.json"))
    r2 = r2pipe.open(str(sample), flags=["-2"])
    try:
        detector = PackerDetector(R2PipeAdapter(r2), config)
        result = detector.detect()
        assert "is_packed" in result
        assert "confidence" in result
    finally:
        r2.quit()
