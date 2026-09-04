from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .rule_packs import (
    RulePackManifest,
    load_verified_manifest,
    manifest_digest,
    public_key_id,
    verify_rule_pack,
)

PUBLIC_KEY_FILE = ".r2inspect-public-key"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_RULE_SUFFIXES = {".yar", ".yara", ".rule", ".rules"}


def _validate_identifier(value: str, label: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"invalid {label}: {value}")
    return value


def _write_manifest(directory: Path, manifest: RulePackManifest) -> Path:
    path = directory / "manifest.json"
    path.write_text(
        json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path


def build_rule_pack(directory: Path, *, pack_id: str, version: str) -> RulePackManifest:
    root = directory.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"rule pack directory is not a directory: {directory}")
    files: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        resolved = path.resolve(strict=False)
        if not path.is_file() or not resolved.is_relative_to(root):
            continue
        if path.suffix.lower() in _RULE_SUFFIXES:
            files[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not files:
        raise ValueError("rule pack contains no YARA rule files")
    manifest = RulePackManifest(
        pack_id=_validate_identifier(pack_id, "pack ID"),
        version=_validate_identifier(version, "pack version"),
        files=files,
    )
    _write_manifest(root, manifest)
    return manifest


def _load_private_key(private_key: bytes) -> Ed25519PrivateKey:
    key = (
        serialization.load_pem_private_key(private_key, password=None)
        if private_key.startswith(b"-----")
        else Ed25519PrivateKey.from_private_bytes(private_key)
    )
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key is not Ed25519")
    return key


def sign_rule_pack(directory: Path, private_key: bytes) -> RulePackManifest:
    manifest = load_verified_manifest(directory)
    key = _load_private_key(private_key)
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    unsigned = replace(manifest, signing_key_id=public_key_id(public), signature=None)
    signed = replace(
        unsigned, signature=base64.b64encode(key.sign(unsigned.signing_payload())).decode()
    )
    _write_manifest(directory, signed)
    return signed


def default_rule_pack_root() -> Path:
    configured = os.environ.get("R2INSPECT_RULE_PACKS_DIR")
    if configured:
        return Path(configured).expanduser()
    data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return data_home / "r2inspect" / "rule-packs"


def install_rule_pack(
    source: Path,
    public_key: bytes,
    *,
    root: Path | None = None,
    replace_existing: bool = False,
) -> tuple[RulePackManifest, Path]:
    source = source.resolve(strict=True)
    manifest = verify_rule_pack(source, public_key=public_key)
    pack_id = _validate_identifier(manifest.pack_id, "pack ID")
    version = _validate_identifier(manifest.version, "pack version")
    install_root = (root or default_rule_pack_root()).expanduser().resolve()
    pack_root = install_root / pack_id
    pack_root.mkdir(parents=True, exist_ok=True)
    resolved_pack_root = pack_root.resolve()
    if not resolved_pack_root.is_relative_to(install_root):
        raise ValueError("rule pack install path escapes its root")
    destination = resolved_pack_root / version
    if destination.exists() and not destination.is_dir():
        raise ValueError(f"rule pack destination is not a directory: {destination}")
    if destination.exists() and not replace_existing:
        raise ValueError(f"rule pack is already installed: {pack_id} {version}")

    temporary = Path(tempfile.mkdtemp(prefix=".install-", dir=destination.parent))
    try:
        for relative in ["manifest.json", *manifest.files]:
            target = temporary / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / relative, target)
        (temporary / PUBLIC_KEY_FILE).write_bytes(public_key)
        verify_rule_pack(temporary, public_key=public_key)
        if destination.exists():
            backup = temporary.with_name(f"{temporary.name}.previous")
            destination.rename(backup)
            try:
                temporary.rename(destination)
            except Exception:
                backup.rename(destination)
                raise
            shutil.rmtree(backup)
        else:
            temporary.rename(destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return manifest, destination


def list_rule_packs(root: Path | None = None) -> list[dict[str, Any]]:
    install_root = (root or default_rule_pack_root()).expanduser()
    if not install_root.is_dir():
        return []
    packs: list[dict[str, Any]] = []
    for path in sorted(install_root.glob("*/*/manifest.json")):
        try:
            manifest = RulePackManifest.load(path)
            packs.append(
                {
                    "pack_id": manifest.pack_id,
                    "pack_version": manifest.version,
                    "manifest_digest": manifest_digest(path.parent),
                    "signing_key_id": manifest.signing_key_id,
                    "rule_count": len(manifest.files),
                    "path": str(path.parent),
                }
            )
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            continue
    return packs
