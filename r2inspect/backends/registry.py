"""Resolve builtin and entry-point supplied binary backends."""

from __future__ import annotations

from importlib.metadata import entry_points
from collections.abc import Callable
from typing import Any

from .core_backend import build_core_backend

BackendFactory = Callable[..., Any]


def _entrypoint_backends() -> dict[str, BackendFactory]:
    discovered: dict[str, BackendFactory] = {}
    for entrypoint in entry_points(group="r2inspect.backends"):
        try:
            loaded = entrypoint.load()
        except Exception:
            loaded = None
        if loaded is not None:
            discovered[entrypoint.name] = loaded
    return discovered


def available_backends() -> tuple[str, ...]:
    return ("r2", "pe-core", "elf-core", "macho-core", "consensus", *sorted(_entrypoint_backends()))


def resolve_backend(name: str) -> BackendFactory | None:
    if name in {"pe-core", "elf-core", "macho-core"}:
        return lambda filename, **kwargs: build_core_backend(filename, backend=name, **kwargs)
    return _entrypoint_backends().get(name)


__all__ = ["available_backends", "resolve_backend"]
