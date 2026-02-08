from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.modules.export_analyzer import ExportAnalyzer


def test_export_analyzer_helpers(tmp_path: Path):
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    config = Config(str(tmp_path / "config.json"))
    r2 = r2pipe.open(str(sample), flags=["-2"])
    adapter = R2PipeAdapter(r2)
    try:
        r2.cmd("aaa")
        analyzer = ExportAnalyzer(adapter=adapter, config=config)

        # Use a function address for characteristics
        funcs = r2.cmdj("aflj") or []
        if funcs:
            first = funcs[0]
            vaddr = first.get("offset") or first.get("addr") or 0
        else:
            vaddr = 0

        exp = {"name": "install_me", "vaddr": vaddr}
        characteristics = analyzer._get_export_characteristics(exp)
        assert characteristics.get("suspicious_name") is True

        stats = {
            "total_exports": 0,
            "function_exports": 0,
            "data_exports": 0,
            "forwarded_exports": 0,
            "suspicious_exports": 0,
            "export_names": [],
        }
        analyzer._update_export_stats(
            stats, {"name": "x", "characteristics": {"is_function": True}}
        )
        assert stats["function_exports"] == 1
    finally:
        r2.quit()
