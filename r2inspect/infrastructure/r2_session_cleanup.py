#!/usr/bin/env python3
"""Cleanup and safe-mode helpers for r2 sessions."""

from __future__ import annotations

import logging
import platform
import struct
import time
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import psutil

_log = logging.getLogger(__name__)


_FAT_MACHO_CPUTYPE_ARCH = {
    7: "x86",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "arm64",
}


def _fat_macho_header_layout(header: bytes) -> tuple[str, int] | None:
    """Return (struct format, nfat_arch) for a fat Mach-O 8-byte header, else None."""
    if len(header) < 8:
        return None
    magic_be = struct.unpack(">I", header[:4])[0]
    if magic_be == 0xCAFEBABE:
        return ">IIIII", struct.unpack(">I", header[4:8])[0]
    if magic_be == 0xBEBAFECA:
        return "<IIIII", struct.unpack("<I", header[4:8])[0]
    return None


def detect_fat_macho_arches(filename: str) -> set[str]:
    path = Path(filename)
    try:
        with open(path, "rb") as handle:
            layout = _fat_macho_header_layout(handle.read(8))
            if layout is None:
                return set()
            entry_unpack, nfat_arch = layout
            arches: set[str] = set()
            for _ in range(nfat_arch):
                arch_data = handle.read(20)
                if len(arch_data) < 20:
                    break
                cputype = struct.unpack(entry_unpack, arch_data)[0]
                arch = _FAT_MACHO_CPUTYPE_ARCH.get(cputype)
                if arch is not None:
                    arches.add(arch)
            return arches
    except OSError:
        return set()


def select_r2_flags(
    session: Any, *, logger: Any, machine_fn: Callable[[], str] | None = None
) -> list[str]:
    # -N skips the user/system radare2rc: analysis must be deterministic and
    # must never inherit an analyst rc that (e.g. cfg.debug=true) would
    # debug-launch the sample on open. The conditional -NN branches below are
    # a strict superset and remain correct alongside -N.
    flags = ["-2", "-N"]
    if session._is_test_mode:
        flags.append("-M")
    if os.environ.get("R2INSPECT_DISABLE_PLUGINS", "").strip():
        flags.append("-NN")
    # Detect fat Mach-O by magic regardless of extension — malware routinely
    # ships fat Mach-O payloads under misleading names like `.bin` or no
    # suffix. The magic check is an 8-byte read and returns set() for any
    # non-fat input, so it is safe to run unconditionally.
    arches = detect_fat_macho_arches(session.filename)
    path = Path(session.filename)
    is_macho_by_ext = path.suffix.lower() in {".macho", ".dylib"}
    if arches or is_macho_by_ext:
        if "-NN" not in flags:
            flags.append("-NN")
        host = (machine_fn if machine_fn is not None else platform.machine)().lower()
        if "arm64" in arches and "arm" in host:
            flags.extend(["-a", "arm", "-b", "64"])
        elif "x86_64" in arches:
            flags.extend(["-a", "x86", "-b", "64"])
    logger.debug("Selected r2 flags: %s", flags)
    return flags


def _escalate_kill(proc: Any, timeout: float) -> None:
    """Wait for a terminated proc; SIGKILL it if SIGTERM did not land.

    A radare2 wedged in a CPU-bound, uninterruptible loop ignores SIGTERM and
    would keep burning a core after a safe-mode reopen. Escalate to kill(),
    matching ``force_close_process``.
    """
    try:
        proc.wait(timeout=timeout)
    except psutil.TimeoutExpired:
        try:
            proc.kill()
        except Exception as exc:
            _log.debug("Failed to kill radare2 process: %s", exc)
    except Exception as exc:
        _log.debug("Failed to wait on radare2 process: %s", exc)


def terminate_radare2_processes(
    filename: str, *, process_iter: Callable[..., Any] | None = None, kill_timeout: float = 1.0
) -> None:
    iterator = process_iter if process_iter is not None else psutil.process_iter
    terminated: list[Any] = []
    for proc in iterator(["name", "cmdline"]):
        try:
            info = proc.info
            if info.get("name") != "radare2":
                continue
            cmdline = info.get("cmdline") or []
            # Match the filename as a whole argv element, not a substring:
            # r2pipe passes session.filename verbatim as its own argv entry, so
            # a substring test would also kill unrelated radare2 sessions whose
            # path merely contains this one (e.g. "a.bin" inside "a.bin.packed"
            # or "lib.so" inside "mylib.so").
            if any(filename == part for part in cmdline):
                proc.terminate()
                terminated.append(proc)
        except Exception as exc:
            _log.debug("Failed to inspect/terminate radare2 process: %s", exc)
            continue
    for proc in terminated:
        _escalate_kill(proc, kill_timeout)


def reopen_safe_mode(session: Any, *, reopen_timeout: float = 30.0) -> Any:
    session.close()
    terminate_radare2_processes(session.filename)
    time.sleep(0.1)
    try:
        from .r2_session_timeouts import open_with_timeout
        import logging

        _logger = logging.getLogger(__name__)
        open_with_timeout(session, ["-2", "-n"], reopen_timeout, logger=_logger)
    except TimeoutError:
        session.r2 = None
        session._cleanup_required = False
        raise
    except Exception:
        session.r2 = None
        session._cleanup_required = False
        raise
    session._cleanup_required = True
    return session.r2


def force_close_process(r2_instance: Any) -> None:
    process = getattr(r2_instance, "process", None)
    if process is None:
        return

    # Close the stdio pipes explicitly: relying on GC leaks file descriptors
    # across a batch run, eventually exhausting the process FD limit.
    for stream_name in ("stdin", "stdout", "stderr"):
        stream = getattr(process, stream_name, None)
        if stream is None:
            continue
        try:
            stream.close()
        except Exception as exc:
            _log.debug("Failed to close r2 %s: %s", stream_name, exc)

    # Reap the process so it does not linger as a zombie; wait() after
    # terminate() releases the OS process table entry.
    try:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=1.0)
    except Exception as exc:
        _log.debug("Failed to terminate r2 process: %s", exc)
        try:
            if process.poll() is None:
                process.kill()
        except Exception as kill_error:
            _log.debug("Failed to kill r2 process: %s", kill_error)
