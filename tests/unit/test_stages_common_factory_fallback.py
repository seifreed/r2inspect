"""Unit coverage for default_analyzer_factory's filename->filepath fallback."""

from __future__ import annotations

from typing import Any

import pytest

from r2inspect.pipeline.stages_common import (
    _construct_with_filename_fallback,
    default_analyzer_factory,
)


class _NeedsFilepath:
    def __init__(self, filepath: str) -> None:
        self.filepath = filepath


class _AlwaysFails:
    def __init__(self, filepath: str) -> None:
        raise TypeError("cannot construct")


class _KwargsRejectsFilename:
    def __init__(self, **kwargs: Any) -> None:
        if "filename" in kwargs:
            raise TypeError("filename not accepted")
        self.filepath = kwargs.get("filepath")


def test_construct_fallback_reraises_when_no_filename() -> None:
    exc = TypeError("boom")
    with pytest.raises(TypeError, match="boom"):
        _construct_with_filename_fallback(_NeedsFilepath, {"other": 1}, exc)


def test_construct_fallback_retries_with_filepath() -> None:
    obj = _construct_with_filename_fallback(_NeedsFilepath, {"filename": "/tmp/x"}, TypeError("o"))
    assert obj.filepath == "/tmp/x"


def test_construct_fallback_raises_original_when_retry_also_fails() -> None:
    exc = TypeError("original")
    with pytest.raises(TypeError, match="original"):
        _construct_with_filename_fallback(_AlwaysFails, {"filename": "/tmp/x"}, exc)


def test_default_analyzer_factory_recovers_via_filepath_fallback() -> None:
    obj = default_analyzer_factory(_KwargsRejectsFilename, filename="/tmp/sample")
    assert obj.filepath == "/tmp/sample"
