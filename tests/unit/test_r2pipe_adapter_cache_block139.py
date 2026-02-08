from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter


def test_r2pipe_adapter_cached_query_reuses_cache():
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    r2 = r2pipe.open(str(sample), flags=["-2"])
    try:
        adapter = R2PipeAdapter(r2)
        first = adapter.get_sections()
        second = adapter.get_sections()
        assert first == second
        assert "iSj" in adapter._cache
    finally:
        r2.quit()
