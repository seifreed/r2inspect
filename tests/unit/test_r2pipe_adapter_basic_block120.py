from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.interfaces.binary_analyzer import BinaryAnalyzerInterface


def test_r2pipe_adapter_basic_real_fixture():
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    r2 = r2pipe.open(str(sample), flags=["-2"])
    try:
        adapter = R2PipeAdapter(r2)
        assert isinstance(adapter, BinaryAnalyzerInterface)

        info = adapter.get_file_info()
        assert isinstance(info, dict)

        sections = adapter.get_sections()
        assert isinstance(sections, list)

        imports = adapter.get_imports()
        assert isinstance(imports, list)

        exports = adapter.get_exports()
        assert isinstance(exports, list)

        symbols = adapter.get_symbols()
        assert isinstance(symbols, list)

        # execute_command json/text
        info_cmd = adapter.execute_command("ij")
        assert isinstance(info_cmd, dict)
        text_cmd = adapter.execute_command("i")
        assert isinstance(text_cmd, str)

        # read some bytes (may be empty depending on address)
        data = adapter.read_bytes(0, 4)
        assert isinstance(data, bytes | bytearray)
    finally:
        r2.quit()
