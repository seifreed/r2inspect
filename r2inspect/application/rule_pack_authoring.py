"""Build and sign integrity-checked YARA rule packs."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..infrastructure.logging import get_logger
from .rule_packs import RulePackManifest, load_verified_manifest, public_key_id

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_RULE_SUFFIXES = {".yar", ".yara", ".rule", ".rules"}
logger = get_logger(__name__)


def _log_rule_pack(
    event_name: str, message: str, manifest: RulePackManifest, outcome: str, **fields: Any
) -> None:
    logger.info(
        message,
        extra={
            "event_name": event_name,
            "pack_id": manifest.pack_id,
            "pack_version": manifest.version,
            "outcome": outcome,
            **fields,
        },
    )


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
        if (
            path.is_file()
            and resolved.is_relative_to(root)
            and path.suffix.lower() in _RULE_SUFFIXES
        ):
            files[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not files:
        raise ValueError("rule pack contains no YARA rule files")
    manifest = RulePackManifest(
        pack_id=_validate_identifier(pack_id, "pack ID"),
        version=_validate_identifier(version, "pack version"),
        files=files,
    )
    _write_manifest(root, manifest)
    _log_rule_pack(
        "rule_pack.built", "Rule pack manifest built", manifest, "success", rule_count=len(files)
    )
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
    _log_rule_pack(
        "rule_pack.signed",
        "Rule pack signed",
        signed,
        "success",
        signing_key_id=signed.signing_key_id,
    )
    return signed


__all__ = ["build_rule_pack", "sign_rule_pack"]
