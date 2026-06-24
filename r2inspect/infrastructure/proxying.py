"""Minimal lazy proxy helpers."""

from __future__ import annotations

import importlib
from collections.abc import Callable
from typing import Any


class LazyProxy:
    def __init__(self, getter: Callable[[], Any]) -> None:
        object.__setattr__(self, "_getter", getter)

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_getter")(), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_getter")(), name, value)


def resolve_lazy_attr(
    name: str, mapping: dict[str, tuple[str, str | None]], module_name: str
) -> Any:
    if name not in mapping:
        raise AttributeError(f"module {module_name!r} has no attribute {name!r}")
    target_module, attr = mapping[name]
    module = importlib.import_module(target_module)
    return module if attr is None else getattr(module, attr)


def make_module_getattr(
    mapping: dict[str, tuple[str, str | None]], module_name: str
) -> Callable[[str], Any]:
    def _getattr(name: str) -> Any:
        return resolve_lazy_attr(name, mapping, module_name)

    return _getattr
