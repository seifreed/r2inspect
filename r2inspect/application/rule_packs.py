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
    signature: str | None = None

    @classmethod
    def load(cls, path: Path) -> RulePackManifest:
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            pack_id=str(data["pack_id"]),
            version=str(data["version"]),
            files={str(name): str(digest) for name, digest in data["files"].items()},
            signature=data.get("signature"),
        )

    def signing_payload(self) -> bytes:
        return json.dumps(
            {"pack_id": self.pack_id, "version": self.version, "files": self.files},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


def verify_rule_pack(
    directory: Path,
    *,
    public_key: bytes | None = None,
    require_signature: bool = True,
) -> RulePackManifest:
    manifest = RulePackManifest.load(directory / "manifest.json")
    for relative, expected in manifest.files.items():
        path = directory / relative
        if not path.is_file():
            raise ValueError(f"rule pack file is missing: {relative}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected:
            raise ValueError(f"rule pack checksum mismatch: {relative}")
    if require_signature and not manifest.signature:
        raise ValueError("rule pack manifest is unsigned")
    if manifest.signature:
        if public_key is None:
            raise ValueError("a public key is required to verify the rule pack signature")
        try:
            key = (
                serialization.load_pem_public_key(public_key)
                if public_key.startswith(b"-----")
                else Ed25519PublicKey.from_public_bytes(public_key)
            )
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError("public key is not Ed25519")
            key.verify(base64.b64decode(manifest.signature), manifest.signing_payload())
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


__all__ = ["RulePackManifest", "verify_main", "verify_rule_pack"]
