"""Environment-variable isolation helpers for tests.

Replaces the forbidden ``monkeypatch.setenv``/``monkeypatch.delenv`` with a
hand-rolled context manager that snapshots and restores ``os.environ``.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager


@contextmanager
def env_vars(**overrides: str | None) -> Iterator[None]:
    """Temporarily apply ``os.environ`` overrides, restoring prior state.

    Each keyword sets that variable for the duration of the block; a value of
    ``None`` removes the variable instead. On exit every touched key is
    restored to exactly what it was before (including being unset).
    """
    previous: dict[str, str | None] = {key: os.environ.get(key) for key in overrides}
    try:
        for key, value in overrides.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        yield
    finally:
        for key, old in previous.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old
