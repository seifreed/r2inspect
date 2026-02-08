from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.config import Config
from r2inspect.factory import create_inspector
from r2inspect.utils import command_helpers

pytestmark = pytest.mark.requires_r2

FIXTURE_DIR = Path("samples/fixtures")


def test_command_helpers_disasm_and_bytes(tmp_path: Path) -> None:
    config = Config(str(tmp_path / "r2inspect_cmd_helpers.json"))
    with create_inspector(
        filename=str(FIXTURE_DIR / "hello_pe.exe"),
        config=config,
        verbose=False,
    ) as inspector:
        adapter = inspector.adapter
        disasm = command_helpers.cmdj(adapter, None, "pdfj @ 0x0", default=None)
        assert disasm is not None

        bytes_hex = command_helpers.cmd(adapter, None, "p8 4 @ 0x0")
        assert isinstance(bytes_hex, str)

        bytes_list = command_helpers.cmdj(adapter, None, "p8j 4 @ 0x0", default=None)
        assert isinstance(bytes_list, list)

        cfg = command_helpers.cmdj(adapter, None, "agj @ 0x0", default=None)
        assert cfg is not None


def test_command_helpers_handle_bytes_return_none() -> None:
    assert command_helpers._handle_bytes(adapter=None, base="px", address=0) is None
