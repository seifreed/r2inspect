"""Unit coverage for the dependency-free ELF program-header scan that guards
telfhash 0.9.8's PT_LOAD infinite loop (r2inspect/modules/telfhash_guard.py)."""

from __future__ import annotations

import struct
from pathlib import Path

from r2inspect.modules.telfhash_guard import (
    MAX_PROGRAM_HEADER_TABLE_BYTES,
    _resolve_telfhash_timeout,
    _telfhash_safe_to_call,
)
from tests.helpers.env import env_vars


def _elf64(*, e_phoff: int, e_phentsize: int, e_phnum: int, ei_data: int = 1) -> bytes:
    endian = "<" if ei_data == 1 else ">"
    head = bytearray(64)
    head[0:4] = b"\x7fELF"
    head[4] = 2  # 64-bit
    head[5] = ei_data
    struct.pack_into(endian + "Q", head, 0x20, e_phoff)
    struct.pack_into(endian + "H", head, 0x36, e_phentsize)
    struct.pack_into(endian + "H", head, 0x38, e_phnum)
    return bytes(head)


def _elf32(*, e_phoff: int, e_phentsize: int, e_phnum: int) -> bytes:
    head = bytearray(64)
    head[0:4] = b"\x7fELF"
    head[4] = 1  # 32-bit
    head[5] = 1  # little-endian
    struct.pack_into("<I", head, 0x1C, e_phoff)
    struct.pack_into("<H", head, 0x2A, e_phentsize)
    struct.pack_into("<H", head, 0x2C, e_phnum)
    return bytes(head)


def _ph_entry(p_type: int, size: int) -> bytes:
    entry = bytearray(size)
    struct.pack_into("<I", entry, 0, p_type)
    return bytes(entry)


def test_resolve_telfhash_timeout_invalid_override() -> None:
    with env_vars(R2INSPECT_TELFHASH_TIMEOUT_SECONDS="bad-value"):
        assert _resolve_telfhash_timeout() > 0


def _write(tmp_path: Path, data: bytes) -> str:
    target = tmp_path / "sample.elf"
    target.write_bytes(data)
    return str(target)


def test_non_elf_is_safe(tmp_path: Path) -> None:
    assert _telfhash_safe_to_call(_write(tmp_path, b"MZ" + b"\x00" * 100)) is True


def test_bad_ei_class_is_safe(tmp_path: Path) -> None:
    head = bytearray(_elf64(e_phoff=64, e_phentsize=56, e_phnum=1))
    head[4] = 9  # invalid EI_CLASS
    assert _telfhash_safe_to_call(_write(tmp_path, bytes(head))) is True


def test_elf64_with_pt_load_is_safe(tmp_path: Path) -> None:
    data = _elf64(e_phoff=64, e_phentsize=56, e_phnum=1) + _ph_entry(1, 56)
    assert _telfhash_safe_to_call(_write(tmp_path, data)) is True


def test_elf64_without_pt_load_is_unsafe(tmp_path: Path) -> None:
    data = _elf64(e_phoff=64, e_phentsize=56, e_phnum=1) + _ph_entry(2, 56)
    assert _telfhash_safe_to_call(_write(tmp_path, data)) is False


def test_elf64_without_program_headers_is_unsafe(tmp_path: Path) -> None:
    assert (
        _telfhash_safe_to_call(_write(tmp_path, _elf64(e_phoff=0, e_phentsize=56, e_phnum=0)))
        is False
    )


def test_elf32_with_pt_load_is_safe(tmp_path: Path) -> None:
    data = _elf32(e_phoff=64, e_phentsize=32, e_phnum=1) + _ph_entry(1, 32)
    assert _telfhash_safe_to_call(_write(tmp_path, data)) is True


def test_truncated_program_header_table_is_unsafe(tmp_path: Path) -> None:
    # e_phnum claims five entries but only two bytes follow, so the scan hits
    # the off+4 > len(table) break without ever seeing a PT_LOAD.
    data = _elf64(e_phoff=64, e_phentsize=56, e_phnum=5) + b"\x01\x00"
    assert _telfhash_safe_to_call(_write(tmp_path, data)) is False


def test_unreadable_path_is_safe(tmp_path: Path) -> None:
    assert _telfhash_safe_to_call(str(tmp_path / "does-not-exist.elf")) is True


def test_program_header_table_read_is_capped(tmp_path: Path) -> None:
    """A crafted ELF whose e_phnum*e_phentsize claims more than the cap must not
    read the whole oversized table: a PT_LOAD entry placed beyond the cap is not
    scanned, so the guard reports the input as unsafe (telfhash skipped). Before
    the read was capped, the full ~1 MiB table was loaded and the entry found."""
    entsize = 56
    entries_in_cap = MAX_PROGRAM_HEADER_TABLE_BYTES // entsize
    e_phnum = entries_in_cap + 5  # claims more entries than fit in the cap
    table = bytearray(e_phnum * entsize)  # all PT_NULL (0) ...
    struct.pack_into("<I", table, (e_phnum - 1) * entsize, 1)  # ... except a PT_LOAD past the cap
    data = _elf64(e_phoff=64, e_phentsize=entsize, e_phnum=e_phnum) + bytes(table)
    assert _telfhash_safe_to_call(_write(tmp_path, data)) is False


def test_pt_load_within_cap_still_detected(tmp_path: Path) -> None:
    """The cap must not regress the normal case: a PT_LOAD in the first entry is
    still found even when e_phnum claims a huge table."""
    entsize = 56
    e_phnum = (MAX_PROGRAM_HEADER_TABLE_BYTES // entsize) + 5
    table = bytearray(e_phnum * entsize)
    struct.pack_into("<I", table, 0, 1)  # PT_LOAD at entry 0 (within the cap)
    data = _elf64(e_phoff=64, e_phentsize=entsize, e_phnum=e_phnum) + bytes(table)
    assert _telfhash_safe_to_call(_write(tmp_path, data)) is True
