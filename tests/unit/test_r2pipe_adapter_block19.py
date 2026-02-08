from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter


@pytest.fixture(scope="module")
def r2_adapter():
    r2pipe = pytest.importorskip("r2pipe")
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")
    r2 = r2pipe.open(str(sample))
    adapter = R2PipeAdapter(r2)
    try:
        yield adapter
    finally:
        r2.quit()


def test_adapter_basic_queries(r2_adapter: R2PipeAdapter):
    info = r2_adapter.get_file_info()
    assert isinstance(info, dict)

    sections = r2_adapter.get_sections()
    assert isinstance(sections, list)
    assert "iSj" in r2_adapter._cache

    imports = r2_adapter.get_imports()
    assert isinstance(imports, list)

    exports = r2_adapter.get_exports()
    assert isinstance(exports, list)

    symbols = r2_adapter.get_symbols()
    assert isinstance(symbols, list)

    strings = r2_adapter.get_strings()
    assert isinstance(strings, list)


def test_adapter_functions_and_read_bytes(r2_adapter: R2PipeAdapter):
    r2_adapter.execute_command("aa")
    funcs = r2_adapter.get_functions()
    assert isinstance(funcs, list)

    data = r2_adapter.read_bytes(0, 2)
    assert isinstance(data, bytes)
    assert len(data) == 2

    with pytest.raises(ValueError):
        r2_adapter.read_bytes(-1, 2)

    with pytest.raises(ValueError):
        r2_adapter.read_bytes(0, 0)


def test_adapter_execute_command_paths(r2_adapter: R2PipeAdapter):
    assert r2_adapter.execute_command("") is None

    result = r2_adapter.execute_command("ij")
    assert isinstance(result, dict)

    result_list = r2_adapter.execute_command("iSj")
    assert isinstance(result_list, list)

    text = r2_adapter.execute_command("iI")
    assert isinstance(text, str)

    assert "R2PipeAdapter" in repr(r2_adapter)
    assert str(r2_adapter) == "R2PipeAdapter for radare2 binary analysis"
