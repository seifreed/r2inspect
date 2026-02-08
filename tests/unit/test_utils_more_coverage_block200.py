from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.core.r2_session import R2Session
from r2inspect.utils import command_helpers as ch
from r2inspect.utils import hashing
from r2inspect.utils import logger as logger_utils
from r2inspect.utils.r2_suppress import _parse_raw_result, silent_cmdj
from r2inspect.utils.ssdeep_loader import get_ssdeep


@pytest.fixture
def r2_adapter(samples_dir: Path) -> R2PipeAdapter:
    target = samples_dir / "hello_pe.exe"
    session = R2Session(str(target))
    r2 = session.open(file_size_mb=target.stat().st_size / (1024 * 1024))
    adapter = R2PipeAdapter(r2)
    yield adapter
    session.close()


def _install_fake_module(tmp_path: Path, contents: str) -> None:
    module_path = tmp_path / "ssdeep.py"
    module_path.write_text(contents, encoding="utf-8")


def _reset_ssdeep_loader() -> None:
    import r2inspect.utils.ssdeep_loader as loader

    loader._ssdeep_module = None
    if "ssdeep" in sys.modules:
        del sys.modules["ssdeep"]
    importlib.invalidate_caches()


def test_get_ssdeep_success_and_failure(tmp_path: Path) -> None:
    _reset_ssdeep_loader()

    _install_fake_module(
        tmp_path,
        "def hash_from_file(path):\n    return 'ok'\n",
    )
    sys.path.insert(0, str(tmp_path))
    try:
        module = get_ssdeep()
        assert module is not None
        assert module.hash_from_file("/dev/null") == "ok"
    finally:
        sys.path.remove(str(tmp_path))

    _reset_ssdeep_loader()
    _install_fake_module(tmp_path, "raise RuntimeError('boom')\n")
    sys.path.insert(0, str(tmp_path))
    try:
        module = get_ssdeep()
        assert module is None
    finally:
        sys.path.remove(str(tmp_path))


def test_calculate_imphash_handles_bad_inputs() -> None:
    assert hashing.calculate_imphash([]) is None
    assert hashing.calculate_imphash(["not-a-dict"]) is None


def test_calculate_ssdeep_error_path(tmp_path: Path) -> None:
    _reset_ssdeep_loader()
    _install_fake_module(
        tmp_path,
        "def hash_from_file(path):\n    raise RuntimeError('fail')\n",
    )
    sys.path.insert(0, str(tmp_path))
    try:
        assert hashing.calculate_ssdeep("/dev/null") is None
    finally:
        sys.path.remove(str(tmp_path))


def test_logger_setup_variants(tmp_path: Path) -> None:
    log = logger_utils.setup_logger(name="r2inspect_test_logger", thread_safe=True)
    assert log.handlers

    log2 = logger_utils.setup_logger(name="r2inspect_test_logger2", thread_safe=False)
    assert log2.handlers

    # Force fallback path by using non-writable HOME
    no_write_home = tmp_path / "home"
    no_write_home.mkdir()
    no_write_home.chmod(0o500)
    old_home = os.environ.get("HOME")
    os.environ["HOME"] = str(no_write_home)
    try:
        log3 = logger_utils.setup_logger(name="r2inspect_test_logger3", thread_safe=True)
        assert log3.handlers
    finally:
        if old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = old_home
        no_write_home.chmod(0o700)


@pytest.mark.requires_r2
def test_r2_suppress_and_parse(r2_adapter: R2PipeAdapter) -> None:
    assert silent_cmdj(None, "ij", {"ok": True}) == {"ok": True}

    # Use a command that is not JSON to trigger parse fallback
    result = silent_cmdj(r2_adapter._r2, "pd 1", None)
    assert result is None or isinstance(result, (str, list, dict))

    assert _parse_raw_result("not json") == "not json"
    assert _parse_raw_result("{}") == {}


@pytest.mark.requires_r2
def test_command_helpers_paths(r2_adapter: R2PipeAdapter) -> None:
    base, addr = ch._parse_address("pd @")
    assert base == "pd"
    assert addr is None
    base, addr = ch._parse_address("pd @ nope")
    assert base == "pd"
    assert addr is None

    assert ch._parse_size("pdj xx") is None

    entry_info = r2_adapter.get_entry_info() or []
    address = entry_info[0]["vaddr"] if entry_info else 0

    # Search handlers
    assert ch._handle_search(r2_adapter, "/x 90") is not None
    assert ch._handle_search(r2_adapter, "/c test") is not None
    assert ch._handle_search(r2_adapter, "/xj 90") is not None

    # Simple handlers
    assert ch._handle_simple(r2_adapter, "iz~", "iz~test", address) is not None
    assert ch._handle_simple(r2_adapter, "aflj", "aflj", address) is not None
    assert ch._handle_simple(r2_adapter, "afij", f"afij @ {address}", address) is not None

    # Disasm handlers
    assert ch._handle_disasm(r2_adapter, "pdfj", address) is not None
    assert ch._handle_disasm(r2_adapter, "pdj 5", address) is not None
    assert ch._handle_disasm(r2_adapter, "pi 5", address) is not None
    assert ch._handle_disasm(r2_adapter, "agj", address) is not None

    # Bytes handlers
    assert ch._handle_bytes(r2_adapter, "p8j 4", address) is not None
    assert ch._handle_bytes(r2_adapter, "p8 4", address) is not None
    assert ch._handle_bytes(r2_adapter, "pxj 4", address) is not None

    assert ch._maybe_use_adapter(None, "ij") is None
