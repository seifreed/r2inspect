from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.core.r2_session import R2Session
from r2inspect.utils import command_helpers


@pytest.fixture
def adapter(samples_dir: Path) -> R2PipeAdapter:
    path = samples_dir / "hello_pe.exe"
    session = R2Session(str(path))
    r2 = session.open(file_size_mb=path.stat().st_size / (1024 * 1024))
    adapter = R2PipeAdapter(r2)
    yield adapter
    session.close()


@pytest.mark.requires_r2
def test_command_helpers_search_and_info(adapter: R2PipeAdapter) -> None:
    assert isinstance(command_helpers.cmdj(adapter, None, "ij", {}), dict)
    assert isinstance(command_helpers.cmd(adapter, None, "i"), str)
    assert isinstance(command_helpers.cmdj(adapter, None, "/xj 90", []), list)
    assert isinstance(command_helpers.cmd(adapter, None, "/x 90"), str)
    assert isinstance(command_helpers.cmd(adapter, None, "/c test"), str)


@pytest.mark.requires_r2
def test_command_helpers_disasm_and_bytes(adapter: R2PipeAdapter) -> None:
    entry = adapter.get_entry_info()
    address = entry[0].get("vaddr", 0) if entry else 0
    assert isinstance(command_helpers.cmdj(adapter, None, f"aflj @ {address}", []), list)
    assert isinstance(command_helpers.cmdj(adapter, None, f"afij @ {address}", []), list)
    assert isinstance(command_helpers.cmdj(adapter, None, f"pdfj @ {address}", []), dict)
    assert isinstance(command_helpers.cmdj(adapter, None, f"pdj 8 @ {address}", []), list)
    assert isinstance(command_helpers.cmd(adapter, None, f"pi 4 @ {address}"), str)
    hex_bytes = command_helpers.cmd(adapter, None, f"p8 4 @ {address}")
    assert isinstance(hex_bytes, str)
    assert hex_bytes == "" or len(hex_bytes) == 8
    byte_list = command_helpers.cmdj(adapter, None, f"p8j 4 @ {address}", [])
    assert isinstance(byte_list, list)


def test_command_helpers_default_fallbacks() -> None:
    assert command_helpers.cmd(None, None, "i") == ""
    assert command_helpers.cmdj(None, None, "ij", {"x": 1}) == {"x": 1}
    assert command_helpers.cmd_list(None, None, "ij") == []
