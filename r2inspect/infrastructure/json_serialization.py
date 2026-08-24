"""Strict JSON serialization shared by CLI and batch writers."""

from __future__ import annotations

import json
from typing import Any, TextIO

from pydantic_core import to_jsonable_python


def jsonable(value: Any) -> Any:
    """Convert supported standard/Pydantic values and reject unknown types."""
    return to_jsonable_python(value, serialize_unknown=False)


def dumps(value: Any, *, indent: int = 2) -> str:
    return json.dumps(jsonable(value), indent=indent, allow_nan=False)


def dump(value: Any, handle: TextIO, *, indent: int = 2) -> None:
    json.dump(jsonable(value), handle, indent=indent, allow_nan=False)
