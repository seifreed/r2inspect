"""Runtime helpers for SSDeep hashing and comparison."""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
import tempfile
from pathlib import Path
from typing import Any, cast


def resolve_ssdeep_binary() -> str | None:
    return shutil.which("ssdeep")


def compare_with_library(hash1: str, hash2: str, get_ssdeep_fn: Any, logger: Any) -> int | None:
    ssdeep_module = get_ssdeep_fn()
    if ssdeep_module is None:
        return None
    try:
        return cast(int, ssdeep_module.compare(hash1, hash2))
    except Exception as exc:
        logger.warning("SSDeep comparison failed with library: %s", exc)
        return None


def compare_with_binary(
    hash1: str,
    hash2: str,
    resolve_binary_fn: Any,
    write_temp_hash_file_fn: Any,
    logger: Any,
) -> int | None:
    temp_dir = None
    try:
        temp_dir = tempfile.TemporaryDirectory(prefix="r2inspect_ssdeep_")
        temp_dir_path = Path(temp_dir.name)

        temp_file1 = temp_dir_path / "hash1.txt"
        temp_file2 = temp_dir_path / "hash2.txt"

        write_temp_hash_file_fn(temp_file1, f"{hash1},file1\n")
        write_temp_hash_file_fn(temp_file2, f"{hash2},file2\n")

        ssdeep_path = resolve_binary_fn()
        if not ssdeep_path:
            return None
        result = subprocess.run(
            [ssdeep_path, "-k", str(temp_file1), str(temp_file2)],
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
            check=False,
        )

        if result.returncode == 0:
            return parse_ssdeep_output(result.stdout)

    except Exception as exc:
        logger.warning("SSDeep comparison failed with binary: %s", exc)
    finally:
        if temp_dir is not None:
            try:
                temp_dir.cleanup()
            except Exception as exc:
                logger.warning("Failed to cleanup temporary directory: %s", exc)

    return None


def write_temp_hash_file(path: Path, content: str) -> None:
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        mode=0o600,
    )
    try:
        os.write(fd, content.encode())
    finally:
        os.close(fd)


def parse_ssdeep_output(output: str) -> int | None:
    for line in output.split("\n"):
        if "matches" in line and "(" in line and ")" in line:
            start = line.rfind("(")
            end = line.rfind(")")
            if start != -1 and end != -1 and start < end:
                try:
                    return int(line[start + 1 : end])
                except ValueError:
                    continue
    return None


def is_available(get_ssdeep_fn: Any, resolve_binary_fn: Any) -> bool:
    if get_ssdeep_fn() is not None:
        return True

    try:
        ssdeep_path = resolve_binary_fn()
        if not ssdeep_path:
            return False
        result = subprocess.run(
            [ssdeep_path, "-V"],
            capture_output=True,
            text=True,
            timeout=5,
            shell=False,
            check=False,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False
