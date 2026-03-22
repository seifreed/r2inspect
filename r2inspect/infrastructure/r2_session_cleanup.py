#!/usr/bin/env python3
"""Cleanup and safe-mode helpers for r2 sessions."""

from __future__ import annotations

import platform
import struct
import time
import os
from pathlib import Path
from typing import Any

import psutil
import r2pipe


def detect_fat_macho_arches(filename: str) -> set[str]:
    path = Path(filename)
    try:
        with open(path, "rb") as handle:
            header = handle.read(8)
            if len(header) < 8:
                return set()
            magic_be = struct.unpack(">I", header[:4])[0]
            if magic_be == 0xCAFEBABE:
                entry_unpack = ">IIIII"
                nfat_arch = struct.unpack(">I", header[4:8])[0]
            elif magic_be == 0xBEBAFECA:
                entry_unpack = "<IIIII"
                nfat_arch = struct.unpack("<I", header[4:8])[0]
            else:
                return set()
            arches: set[str] = set()
            for _ in range(nfat_arch):
                arch_data = handle.read(20)
                if len(arch_data) < 20:
                    break
                cputype = struct.unpack(entry_unpack, arch_data)[0]
                if cputype in {7, 0x01000007}:
                    arches.add("x86_64" if cputype == 0x01000007 else "x86")
                elif cputype in {12, 0x0100000C}:
                    arches.add("arm64" if cputype == 0x0100000C else "arm")
            return arches
    except OSError:
        return set()


def select_r2_flags(session: Any, *, logger: Any) -> list[str]:
    flags = ["-2"]
    if session._is_test_mode:
        flags.append("-M")
    if os.environ.get("R2INSPECT_DISABLE_PLUGINS", "").strip():
        flags.append("-NN")
    path = Path(session.filename)
    if path.suffix.lower() in {".macho", ".dylib"}:
        arches = detect_fat_macho_arches(session.filename)
        host = platform.machine().lower()
        if "-NN" not in flags:
            flags.append("-NN")
        if "arm64" in arches and "arm" in host:
            flags.extend(["-a", "arm", "-b", "64"])
        elif "x86_64" in arches:
            flags.extend(["-a", "x86", "-b", "64"])
    logger.debug("Selected r2 flags: %s", flags)
    return flags


def terminate_radare2_processes(filename: str) -> None:
    for proc in psutil.process_iter(["name", "cmdline"]):
        try:
            info = proc.info
            if info.get("name") != "radare2":
                continue
            cmdline = info.get("cmdline") or []
            if any(filename in part for part in cmdline):
                proc.terminate()
        except Exception:
            continue


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
    try:
        process.terminate()
    except Exception:
        pass
