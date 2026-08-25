"""Backend discovery and lightweight core-backend implementations."""

from .registry import available_backends, resolve_backend

__all__ = ["available_backends", "resolve_backend"]
