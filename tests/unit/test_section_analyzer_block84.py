from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.modules.section_analyzer import SectionAnalyzer


def test_section_analyzer_basic(tmp_path: Path):
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    config = Config(str(tmp_path / "config.json"))
    r2 = r2pipe.open(str(sample), flags=["-2"])
    adapter = R2PipeAdapter(r2)
    try:
        analyzer = SectionAnalyzer(adapter=adapter, config=config)
        result = analyzer.analyze()
        assert "sections" in result
        assert result["available"] in {True, False}

        # Exercise helpers
        flags = analyzer._decode_pe_characteristics(0x01000000 | 0x02000000)
        assert "IMAGE_SCN_MEM_EXECUTE" in flags
        assert "IMAGE_SCN_MEM_READ" in flags

        assert analyzer._calculate_size_ratio({"virtual_size": 10, "raw_size": 0}) == 0.0
        characteristics = {"expected_entropy": "1.0-2.0"}
        analysis = {"entropy": 5.0}
        analyzer._check_entropy_anomaly(characteristics, analysis)
        assert characteristics.get("entropy_anomaly") is True
    finally:
        r2.quit()
