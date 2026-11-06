"""Install and enumerate integrity-checked YARA rule packs."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from ..infrastructure.logging import get_logger
from .rule_pack_authoring import (
    _log_rule_pack,
    _validate_identifier,
    build_rule_pack,
    sign_rule_pack,
)
from .rule_packs import RulePackManifest, manifest_digest, verify_rule_pack

PUBLIC_KEY_FILE = ".r2inspect-public-key"
logger = get_logger(__name__)


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
    _log_rule_pack(
        "rule_pack.installed",
        "Rule pack installed",
        manifest,
        "replaced" if replace_existing else "installed",
        signing_key_id=manifest.signing_key_id,
    )
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
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            logger.warning(
                "Ignoring invalid installed rule pack",
                extra={
                    "event_name": "rule_pack.invalid_installation",
                    "error_type": type(exc).__name__,
                    "outcome": "ignored",
                },
            )
    return packs


__all__ = [
    "PUBLIC_KEY_FILE",
    "build_rule_pack",
    "default_rule_pack_root",
    "install_rule_pack",
    "list_rule_packs",
    "sign_rule_pack",
]
