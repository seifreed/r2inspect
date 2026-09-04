"""Rule-pack management CLI."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

import click

from ..application.rule_pack_operations import (
    build_rule_pack,
    install_rule_pack,
    list_rule_packs,
    sign_rule_pack,
)
from ..application.rule_packs import manifest_digest, public_key_id, verify_rule_pack

T = TypeVar("T")


def _call(operation: Callable[[], T]) -> T:
    try:
        return operation()
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise click.ClickException(str(exc)) from exc


def _summary(manifest: Any, directory: Path, public_key: bytes | None = None) -> dict[str, Any]:
    return {
        "pack_id": manifest.pack_id,
        "pack_version": manifest.version,
        "manifest_digest": manifest_digest(directory),
        "signing_key_id": manifest.signing_key_id
        or (public_key_id(public_key) if public_key else None),
        "rule_count": len(manifest.files),
        "loaded_rules": len(manifest.files),
        "failed_rules": 0,
    }


def _echo(payload: dict[str, Any] | list[dict[str, Any]]) -> None:
    click.echo(json.dumps(payload, indent=2, sort_keys=True))


@click.group(name="rules")
def rules_cli() -> None:
    """Build, sign, verify, and install YARA rule packs."""


@rules_cli.command("build")
@click.argument("directory", type=click.Path(path_type=Path, exists=True, file_okay=False))
@click.option("--pack-id", required=True)
@click.option("--version", "pack_version", required=True)
def build_command(directory: Path, pack_id: str, pack_version: str) -> None:
    manifest = _call(lambda: build_rule_pack(directory, pack_id=pack_id, version=pack_version))
    _echo(_summary(manifest, directory))


@rules_cli.command("sign")
@click.argument("directory", type=click.Path(path_type=Path, exists=True, file_okay=False))
@click.option(
    "--private-key", type=click.Path(path_type=Path, exists=True, dir_okay=False), required=True
)
def sign_command(directory: Path, private_key: Path) -> None:
    manifest = _call(lambda: sign_rule_pack(directory, private_key.read_bytes()))
    _echo(_summary(manifest, directory))


@rules_cli.command("verify")
@click.argument("directory", type=click.Path(path_type=Path, exists=True, file_okay=False))
@click.option(
    "--public-key", type=click.Path(path_type=Path, exists=True, dir_okay=False), required=True
)
def verify_command(directory: Path, public_key: Path) -> None:
    key = public_key.read_bytes()
    manifest = _call(lambda: verify_rule_pack(directory, public_key=key))
    _echo(_summary(manifest, directory, key))


def _install(directory: Path, public_key: Path, root: Path | None, *, update: bool) -> None:
    key = public_key.read_bytes()
    manifest, destination = _call(
        lambda: install_rule_pack(
            directory,
            key,
            root=root,
            replace_existing=update,
        )
    )
    payload = _summary(manifest, destination, key)
    payload["path"] = str(destination)
    _echo(payload)


def _install_options(function: Callable[..., Any]) -> Callable[..., Any]:
    function = click.option("--root", type=click.Path(path_type=Path, file_okay=False))(function)
    function = click.option(
        "--public-key", type=click.Path(path_type=Path, exists=True, dir_okay=False), required=True
    )(function)
    return click.argument(
        "directory", type=click.Path(path_type=Path, exists=True, file_okay=False)
    )(function)


@rules_cli.command("install")
@_install_options
def install_command(directory: Path, public_key: Path, root: Path | None) -> None:
    _install(directory, public_key, root, update=False)


@rules_cli.command("update")
@_install_options
def update_command(directory: Path, public_key: Path, root: Path | None) -> None:
    _install(directory, public_key, root, update=True)


@rules_cli.command("list")
@click.option("--root", type=click.Path(path_type=Path, file_okay=False))
def list_command(root: Path | None) -> None:
    _echo(_call(lambda: list_rule_packs(root)))


__all__ = ["rules_cli"]
