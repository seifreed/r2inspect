from __future__ import annotations

from pathlib import Path

import pytest
import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter


def test_r2pipe_adapter_edge_cases_real_fixture():
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    r2 = r2pipe.open(str(sample), flags=["-2"])
    try:
        adapter = R2PipeAdapter(r2)

        assert adapter.execute_command("") is None

        with pytest.raises(ValueError):
            adapter.read_bytes(0, 0)

        with pytest.raises(ValueError):
            adapter.read_bytes(-1, 4)
    finally:
        r2.quit()
