from __future__ import annotations

import builtins
import importlib
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any


def import_fresh(module_name: str) -> Any:
    sys.modules.pop(module_name, None)
    return importlib.import_module(module_name)


@contextmanager
def blocked_import(module_name: str, exc: Exception | None = None) -> Iterator[None]:
    original_import = builtins.__import__
    failure = exc or ImportError(f"forced import failure: {module_name}")

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == module_name:
            raise failure
        return original_import(name, *args, **kwargs)

    builtins.__import__ = fake_import
    try:
        yield
    finally:
        builtins.__import__ = original_import
