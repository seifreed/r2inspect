"""Safe wrapper around the telfhash library.

telfhash 0.9.8 has an infinite loop (``while elf.iter_segments():`` in
``elf_get_imagebase``) that never terminates for ELF inputs without a PT_LOAD
segment — exactly the malformed/crafted binaries a malware analyzer is fed.
An unbounded call would hang the whole analysis, so every call goes through
``_safe_telfhash`` which combines a dependency-free PT_LOAD guard with a
worker-thread timeout (same idiom as ``run_cmd_with_timeout``).
"""

from __future__ import annotations

import os
import struct
from typing import Any

# Try to import telfhash library
try:
    from telfhash import telfhash

    TELFHASH_AVAILABLE = True
except ImportError:
    TELFHASH_AVAILABLE = False

from ..infrastructure.logging import get_logger
from ..infrastructure.timeout_runner import run_with_timeout

logger = get_logger(__name__)

TELFHASH_TIMEOUT_SECONDS = 30.0


def _resolve_telfhash_timeout() -> float:
    """Resolve the telfhash timeout, allowing an env override for fast tests."""
    raw = os.environ.get("R2INSPECT_TELFHASH_TIMEOUT_SECONDS", "").strip()
    if raw:
        try:
            value = float(raw)
            if value > 0:
                return value
        except ValueError:
            pass
    return TELFHASH_TIMEOUT_SECONDS


def _elf_header_layout(head: bytes) -> tuple[int, str] | None:
    """Return (ei_class, struct-endianness) for a parseable ELF header, else None.

    None means telfhash will error/return fast (non-ELF or pyelftools-rejected
    header), so it is safe to call without looping.
    """
    if len(head) < 64 or head[:4] != b"\x7fELF":
        return None  # not an ELF -> telfhash errors fast, no loop
    ei_class, ei_data = head[4], head[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None  # pyelftools rejects -> fast error, no loop
    return ei_class, "<" if ei_data == 1 else ">"


def _program_header_location(head: bytes, ei_class: int, endian: str) -> tuple[int, int, int]:
    """Return (e_phoff, e_phentsize, e_phnum) for a 32- or 64-bit ELF header."""
    if ei_class == 2:
        e_phoff = struct.unpack_from(endian + "Q", head, 0x20)[0]
        e_phentsize = struct.unpack_from(endian + "H", head, 0x36)[0]
        e_phnum = struct.unpack_from(endian + "H", head, 0x38)[0]
    else:
        e_phoff = struct.unpack_from(endian + "I", head, 0x1C)[0]
        e_phentsize = struct.unpack_from(endian + "H", head, 0x2A)[0]
        e_phnum = struct.unpack_from(endian + "H", head, 0x2C)[0]
    return e_phoff, e_phentsize, e_phnum


def _has_pt_load_segment(table: bytes, e_phnum: int, e_phentsize: int, endian: str) -> bool:
    for i in range(e_phnum):
        off = i * e_phentsize
        if off + 4 > len(table):
            break
        if struct.unpack_from(endian + "I", table, off)[0] == 1:  # PT_LOAD
            return True
    return False


def _telfhash_safe_to_call(filepath: str) -> bool:
    """Return False only for inputs that trigger telfhash 0.9.8's hang.

    telfhash 0.9.8's ``elf_get_imagebase`` does ``while elf.iter_segments():``
    and only terminates by *returning* when it finds a PT_LOAD segment. For a
    structurally-valid ELF (one pyelftools will parse) that has zero PT_LOAD
    segments it spins forever in a CPU-bound, uninterruptible loop that a
    thread timeout cannot reclaim. So the only safe approach is to not feed
    telfhash that exact input.

    Returns True (safe to call) for everything else — unreadable paths,
    non-ELF files, and structurally-invalid ELF headers — because pyelftools
    rejects those and telfhash returns/raises quickly without looping. This is
    a dependency-free program-header scan (PT_LOAD == 1).
    """
    try:
        with open(filepath, "rb") as fh:
            head = fh.read(64)
            layout = _elf_header_layout(head)
            if layout is None:
                return True
            ei_class, endian = layout
            e_phoff, e_phentsize, e_phnum = _program_header_location(head, ei_class, endian)
            # Valid ELF header with no usable program-header table: the loop
            # never finds PT_LOAD and never terminates.
            if e_phoff == 0 or e_phnum == 0 or e_phentsize < 4:
                return False
            fh.seek(e_phoff)
            table = fh.read(e_phnum * e_phentsize)
            # valid ELF, program headers, but no PT_LOAD -> telfhash loops
            return _has_pt_load_segment(table, e_phnum, e_phentsize, endian)
    except OSError:
        return True  # cannot read -> not the infinite-loop case


def _telfhash_with_timeout(filepath: str, timeout: float | None = None) -> Any:
    """Run ``telfhash(filepath)`` with a hard timeout.

    The PT_LOAD guard above prevents the common infinite-loop trigger; this
    timeout is defense-in-depth for any other slow path. The abandoned worker
    is a daemon thread so it cannot keep the process alive.
    """
    if timeout is None:
        timeout = _resolve_telfhash_timeout()
    completed, value, error = run_with_timeout(lambda: telfhash(filepath), timeout)
    if not completed:
        raise TimeoutError(
            f"telfhash timed out after {timeout:.1f}s for {filepath} "
            "(likely the telfhash 0.9.8 iter_segments infinite loop)"
        )
    if error is not None:
        raise error
    return value


def _safe_telfhash(filepath: str) -> Any:
    """Single guarded entry point for telfhash.

    Returns ``[]`` (telfhash's own "no result" shape) for inputs that would
    trigger the library's infinite loop, otherwise runs it under the timeout.
    Every telfhash call site must go through this.
    """
    if not _telfhash_safe_to_call(filepath):
        logger.debug(
            "Skipping telfhash for %s: structurally-valid ELF without a "
            "PT_LOAD segment (telfhash 0.9.8 would infinite-loop)",
            filepath,
        )
        return []
    return _telfhash_with_timeout(filepath)
