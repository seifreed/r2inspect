"""Signed-pack verification and cache digests for YARA rules."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from ..application.rule_pack_operations import PUBLIC_KEY_FILE
from ..application.rule_packs import manifest_digest, public_key_id, verify_rule_pack

_RULE_SUFFIXES = {".yar", ".yara", ".rule", ".rules"}


def rules_content_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        root = path.resolve(strict=True)
    except OSError:
        return ""
    candidates = [root] if root.is_file() else sorted(root.rglob("*"))
    for candidate in candidates:
        resolved = candidate.resolve(strict=False)
        if not candidate.is_file() or candidate.suffix.lower() not in _RULE_SUFFIXES:
            continue
        if root.is_dir() and not resolved.is_relative_to(root):
            continue
        relative = candidate.name if root.is_file() else candidate.relative_to(root).as_posix()
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(candidate.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def verify_rules_path(path: Path) -> tuple[dict[str, Any] | None, str]:
    manifest_path = path / "manifest.json"
    if not path.is_dir() or not manifest_path.is_file():
        return None, rules_content_digest(path)
    configured_key = os.environ.get("R2INSPECT_RULE_PACK_PUBLIC_KEY")
    key_path = Path(configured_key).expanduser() if configured_key else path / PUBLIC_KEY_FILE
    if not key_path.is_file():
        raise ValueError("signed rule pack requires an installed or configured public key")
    public_key = key_path.read_bytes()
    manifest = verify_rule_pack(path, public_key=public_key)
    digest = manifest_digest(path)
    return (
        {
            "pack_id": manifest.pack_id,
            "pack_version": manifest.version,
            "manifest_digest": digest,
            "signing_key_id": manifest.signing_key_id or public_key_id(public_key),
            "rule_count": len(manifest.files),
            "loaded_rules": len(manifest.files),
            "failed_rules": 0,
        },
        digest,
    )


def update_rule_counts(metadata: dict[str, Any] | None, loaded: int) -> None:
    if metadata is None:
        return
    total = int(metadata["rule_count"])
    metadata["loaded_rules"] = loaded
    metadata["failed_rules"] = max(total - loaded, 0)


def prepare_rules_path(analyzer: Any, path: Path, logger: Any) -> bool:
    try:
        analyzer.rule_pack_metadata, analyzer._rule_cache_digest = verify_rules_path(path)
    except (OSError, ValueError) as exc:
        analyzer.last_status = "failed"
        analyzer.last_error = str(exc)
        logger.error("YARA rule pack verification failed: %s", exc)
        return False
    return True


__all__ = [
    "prepare_rules_path",
    "rules_content_digest",
    "update_rule_counts",
    "verify_rules_path",
]
