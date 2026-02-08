from __future__ import annotations

from pathlib import Path

import pytest
import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter


def _sample_path() -> Path:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")
    return sample


def test_r2pipe_adapter_real_methods():
    sample = _sample_path()
    r2 = r2pipe.open(str(sample))
    try:
        adapter = R2PipeAdapter(r2)
        info = adapter.get_file_info()
        assert isinstance(info, dict)

        sections = adapter.get_sections()
        assert isinstance(sections, list)

        # Cached query path
        sections_again = adapter.get_sections()
        assert sections_again == sections

        imports = adapter.get_imports()
        exports = adapter.get_exports()
        symbols = adapter.get_symbols()
        strings = adapter.get_strings()
        functions = adapter.get_functions()

        assert isinstance(imports, list)
        assert isinstance(exports, list)
        assert isinstance(symbols, list)
        assert isinstance(strings, list)
        assert isinstance(functions, list)

        # Read bytes from start of file
        data = adapter.read_bytes(0, 4)
        assert isinstance(data, bytes)
        assert len(data) == 4

        # Execute JSON and text commands
        result_json = adapter.execute_command("ij")
        assert isinstance(result_json, dict)
        result_text = adapter.execute_command("pd 1")
        assert isinstance(result_text, str)

        # Empty command returns None
        assert adapter.execute_command("") is None

        # Invalid size triggers ValueError
        with pytest.raises(ValueError):
            adapter.read_bytes(0, 0)

        with pytest.raises(ValueError):
            adapter.read_bytes(-1, 4)
    finally:
        r2.quit()
