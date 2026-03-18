#!/usr/bin/env python3
"""Helpers for syncing shared sample fixtures across local and CI runs."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

FIXTURE_NAMES = (
    "hello_pe.exe",
    "hello_elf",
    "hello_macho",
    "hello_macho_stripped",
    "edge_tiny.bin",
    "edge_packed.bin",
    "edge_bad_pe.bin",
    "edge_high_entropy.bin",
)

LAYOUT_CANDIDATES: tuple[dict[str, str], ...] = (
    {
        "hello_pe.exe": "fixtures/hello_pe.exe",
        "hello_elf": "fixtures/hello_elf",
        "hello_macho": "fixtures/hello_macho",
        "hello_macho_stripped": "fixtures/hello_macho_stripped",
        "edge_tiny.bin": "fixtures/edge_tiny.bin",
        "edge_packed.bin": "fixtures/edge_packed.bin",
        "edge_bad_pe.bin": "fixtures/edge_bad_pe.bin",
        "edge_high_entropy.bin": "fixtures/edge_high_entropy.bin",
    },
    {
        "hello_pe.exe": "pe/hello_pe.exe",
        "hello_elf": "elf/hello_elf",
        "hello_macho": "mach0/hello_macho",
        "hello_macho_stripped": "mach0/hello_macho_stripped",
        "edge_tiny.bin": "edge/edge_tiny.bin",
        "edge_packed.bin": "edge/edge_packed.bin",
        "edge_bad_pe.bin": "edge/edge_bad_pe.bin",
        "edge_high_entropy.bin": "edge/edge_high_entropy.bin",
    },
    {
        "hello_pe.exe": "hello_pe.exe",
        "hello_elf": "hello_elf",
        "hello_macho": "hello_macho",
        "hello_macho_stripped": "hello_macho_stripped",
        "edge_tiny.bin": "edge_tiny.bin",
        "edge_packed.bin": "edge_packed.bin",
        "edge_bad_pe.bin": "edge_bad_pe.bin",
        "edge_high_entropy.bin": "edge_high_entropy.bin",
    },
)


def _infer_file_format(path: Path) -> str:
    data = path.read_bytes()[:4]
    if data.startswith(b"MZ"):
        return "PE"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data in {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    }:
        return "MACHO"
    return "Unknown"


def _build_expected_payload(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
    sha1 = hashlib.sha1(data, usedforsecurity=False).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    file_format = _infer_file_format(path)
    return {
        "file_format": file_format,
        "name": path.name,
        "size": path.stat().st_size,
        "hashes": {"md5": md5, "sha1": sha1, "sha256": sha256},
        "file_info": {
            "name": path.name,
            "path": str(path),
            "size": path.stat().st_size,
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "file_type": file_format,
        },
        "hashing": {},
        "security": {},
    }


def ensure_expected_snapshots(fixtures_dir: Path) -> None:
    expected_dir = fixtures_dir / "expected"
    expected_dir.mkdir(parents=True, exist_ok=True)
    snapshot_names = (
        "hello_pe.exe",
        "hello_elf",
        "hello_macho",
        "edge_packed.bin",
        "edge_tiny.bin",
        "edge_bad_pe.bin",
        "edge_high_entropy.bin",
    )
    for file_name in snapshot_names:
        fixture_path = fixtures_dir / file_name
        if not fixture_path.exists():
            continue
        payload = _build_expected_payload(fixture_path)
        out_name = file_name.replace(".exe", "").replace(".bin", "") + ".json"
        (expected_dir / out_name).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def resolve_fixture_source_root(repo_root: Path, configured: str | None = None) -> Path | None:
    candidate_roots: list[Path] = []
    configured_value = (
        configured if configured is not None else os.getenv("R2INSPECT_TEST_BINARIES_DIR", "")
    ).strip()
    if configured_value:
        candidate_roots.append(Path(configured_value))
    candidate_roots.append(repo_root.parent / "r2inspect-test-binaries")
    candidate_roots.append(repo_root / "samples" / "fixtures")

    for candidate in candidate_roots:
        if not candidate.exists():
            continue
        if _resolve_layout(candidate) is not None:
            return candidate

    return None


def _resolve_layout(source_root: Path) -> dict[str, Path] | None:
    for layout in LAYOUT_CANDIDATES:
        mapping = {name: source_root / relative for name, relative in layout.items()}
        if (mapping["hello_pe.exe"]).exists():
            return mapping
    return None


def sync_sample_fixtures(
    target_dir: Path, source_root: Path, *, copy_files: bool = False
) -> list[Path]:
    mapping = _resolve_layout(source_root)
    if mapping is None:
        raise FileNotFoundError(f"No supported fixture layout found under {source_root}")

    target_dir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []

    for target_name, source_path in mapping.items():
        if not source_path.exists():
            continue

        target_path = target_dir / target_name
        if target_path.is_symlink() or target_path.exists():
            if target_path.is_symlink() and not target_path.exists():
                target_path.unlink()
            else:
                continue

        if copy_files:
            target_path.write_bytes(source_path.read_bytes())
        else:
            try:
                target_path.symlink_to(source_path.resolve())
            except OSError:
                target_path.write_bytes(source_path.read_bytes())
        created.append(target_path)

    expected_dir = target_dir / "expected"
    if expected_dir.is_symlink():
        expected_dir.unlink()
    ensure_expected_snapshots(target_dir)
    created.append(expected_dir)
    return created
