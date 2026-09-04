"""Versioned, integrity-checked YARA rule packs."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


@dataclass(frozen=True)
class RulePackManifest:
    pack_id: str
    version: str
    files: dict[str, str]
    signing_key_id: str | None = None
    signature: str | None = None

    @classmethod
    def load(cls, path: Path) -> RulePackManifest:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
            raise ValueError("invalid rule pack manifest")
        try:
            manifest = cls(
                pack_id=str(data["pack_id"]),
                version=str(data["version"]),
                files={str(name): str(digest) for name, digest in data["files"].items()},
                signing_key_id=data.get("signing_key_id"),
                signature=data.get("signature"),
            )
        except (KeyError, TypeError) as exc:
            raise ValueError("invalid rule pack manifest") from exc
        if not manifest.pack_id or not manifest.version or not manifest.files:
            raise ValueError("invalid rule pack manifest")
        return manifest

    def signing_payload(self) -> bytes:
        payload = {"pack_id": self.pack_id, "version": self.version, "files": self.files}
        if self.signing_key_id:
            payload["signing_key_id"] = self.signing_key_id
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "pack_id": self.pack_id,
            "version": self.version,
            "files": self.files,
        }
        if self.signing_key_id:
            payload["signing_key_id"] = self.signing_key_id
        if self.signature:
            payload["signature"] = self.signature
        return payload


def _load_public_key(public_key: bytes) -> Ed25519PublicKey:
    key = (
        serialization.load_pem_public_key(public_key)
        if public_key.startswith(b"-----")
        else Ed25519PublicKey.from_public_bytes(public_key)
    )
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key is not Ed25519")
    return key


def public_key_id(public_key: bytes) -> str:
    raw = _load_public_key(public_key).public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def manifest_digest(directory: Path) -> str:
    return hashlib.sha256((directory / "manifest.json").read_bytes()).hexdigest()


def load_verified_manifest(directory: Path) -> RulePackManifest:
    root = directory.resolve(strict=True)
    manifest_path = (root / "manifest.json").resolve(strict=False)
    if not manifest_path.is_relative_to(root) or not manifest_path.is_file():
        raise ValueError("rule pack manifest is missing or escapes its directory")
    manifest = RulePackManifest.load(manifest_path)
    for relative, expected in manifest.files.items():
        path = (root / relative).resolve(strict=False)
        if path == root or not path.is_relative_to(root):
            raise ValueError(f"rule pack path escapes its directory: {relative}")
        if not path.is_file():
            raise ValueError(f"rule pack file is missing: {relative}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected:
            raise ValueError(f"rule pack checksum mismatch: {relative}")
    return manifest


def verify_rule_pack(
    directory: Path,
    *,
    public_key: bytes | None = None,
    require_signature: bool = True,
) -> RulePackManifest:
    manifest = load_verified_manifest(directory)
    if require_signature and not manifest.signature:
        raise ValueError("rule pack manifest is unsigned")
    if manifest.signature:
        if public_key is None:
            raise ValueError("a public key is required to verify the rule pack signature")
        try:
            key = _load_public_key(public_key)
            key_id = public_key_id(public_key)
            if manifest.signing_key_id and manifest.signing_key_id != key_id:
                raise ValueError("rule pack signing key ID does not match")
            key.verify(
                base64.b64decode(manifest.signature, validate=True), manifest.signing_payload()
            )
        except Exception as exc:
            raise ValueError("rule pack signature verification failed") from exc
    return manifest


def verify_main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Verify an r2inspect rule pack")
    parser.add_argument("directory", type=Path)
    parser.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args()
    manifest = verify_rule_pack(args.directory, public_key=args.public_key.read_bytes())
    print(f"{manifest.pack_id} {manifest.version}: verified")


__all__ = [
    "RulePackManifest",
    "load_verified_manifest",
    "manifest_digest",
    "public_key_id",
    "verify_main",
    "verify_rule_pack",
]
