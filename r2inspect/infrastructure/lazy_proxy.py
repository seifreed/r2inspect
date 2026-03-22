"""Generic lazy proxy for deferred singleton initialization."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


class LazyProxy[T]:
    """Proxy that lazily creates and delegates to a singleton instance.

    Usage::

        _instance: MyService | None = None

        def _factory() -> MyService:
            global _instance
            if _instance is None:
                _instance = MyService()
            return _instance

        my_service: MyService = LazyProxy(_factory)  # type: ignore[assignment]
    """

    def __init__(self, factory: Callable[[], T]) -> None:
        object.__setattr__(self, "_factory", factory)

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_factory")(), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_factory")(), name, value)
