"""Strict JSON serialization shared by CLI and batch writers."""

from __future__ import annotations

import json
from dataclasses import fields, is_dataclass
from typing import Any, TextIO

from pydantic_core import to_jsonable_python


def _reject_empty_dataclasses(value: Any) -> None:
    if is_dataclass(value) and not isinstance(value, type):
        if not fields(value):
            raise TypeError(f"empty dataclass is not a report value: {type(value).__name__}")
        for field in fields(value):
            _reject_empty_dataclasses(getattr(value, field.name))
    elif isinstance(value, dict):
        for item in value.values():
            _reject_empty_dataclasses(item)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            _reject_empty_dataclasses(item)


def jsonable(value: Any) -> Any:
    """Convert supported standard/Pydantic values and reject unknown types."""
    _reject_empty_dataclasses(value)
    return to_jsonable_python(value, serialize_unknown=False)


def dumps(value: Any, *, indent: int = 2) -> str:
    return json.dumps(jsonable(value), indent=indent, allow_nan=False)


def dump(value: Any, handle: TextIO, *, indent: int = 2) -> None:
    json.dump(jsonable(value), handle, indent=indent, allow_nan=False)
