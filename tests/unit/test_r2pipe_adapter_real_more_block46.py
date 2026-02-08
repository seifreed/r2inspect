from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter


@pytest.fixture(scope="module")
def adapter():
    r2pipe = pytest.importorskip("r2pipe")
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample missing")
    r2 = r2pipe.open(str(sample))
    adapter = R2PipeAdapter(r2)
    try:
        yield adapter
    finally:
        r2.quit()


def test_cached_query_defaults(adapter: R2PipeAdapter):
    sections = adapter._cached_query("iSj", "list")
    assert isinstance(sections, list)

    info = adapter._cached_query("ij", "dict")
    assert isinstance(info, dict)

    # cached path
    _ = adapter._cached_query("ij", "dict")
    assert "ij" in adapter._cache


def test_execute_command_text(adapter: R2PipeAdapter):
    text = adapter.execute_command("?v 1+1")
    assert isinstance(text, str)
