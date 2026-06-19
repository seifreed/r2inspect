"""Minimal lazy proxy helpers."""

from __future__ import annotations

from typing import Any, Callable


class LazyProxy:
    def __init__(self, getter: Callable[[], Any]) -> None:
        object.__setattr__(self, "_getter", getter)

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_getter")(), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_getter")(), name, value)
