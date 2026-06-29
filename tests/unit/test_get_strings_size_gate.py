"""The whole-file string scan (izzj) is downgraded to sections-only (izj) on
oversized binaries to bound memory. Uses a real R2PipeAdapter wrapping a
FakeR2Adapter -- no mocks, no monkeypatch.
"""

from __future__ import annotations

import logging

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.domain.constants import OVERLAY_STRING_SCAN_THRESHOLD_MB
from tests.helpers.r2_fakes import FakeR2Adapter

_LOGGER = "r2inspect.adapters.r2pipe_query_cached"
_IZZJ = [{"string": "overlay_string"}]
_IZJ = [{"string": "section_string"}]


def test_get_strings_uses_sections_above_threshold(caplog):
    big = int((OVERLAY_STRING_SCAN_THRESHOLD_MB + 50) * 1024 * 1024)
    fake = FakeR2Adapter(
        cmdj_responses={"ij": {"core": {"size": big}}, "izzj": [_IZZJ], "izj": [_IZJ]},
    )
    adapter = R2PipeAdapter(fake)

    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        result = adapter.get_strings()

    assert result == _IZJ  # sections-only, not the whole-file overlay scan
    assert "izzj" not in fake.calls["cmdj"]  # whole-file scan never issued
    assert any("string-scan threshold" in r.getMessage() for r in caplog.records)


def test_get_strings_logs_only_once(caplog):
    big = int((OVERLAY_STRING_SCAN_THRESHOLD_MB + 50) * 1024 * 1024)
    fake = FakeR2Adapter(
        cmdj_responses={"ij": {"core": {"size": big}}, "izj": [_IZJ, _IZJ]},
    )
    adapter = R2PipeAdapter(fake)

    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        adapter.get_strings()
        adapter.get_strings()

    warnings = [r for r in caplog.records if "string-scan threshold" in r.getMessage()]
    assert len(warnings) == 1


def test_get_strings_uses_whole_file_below_threshold():
    small = 5 * 1024 * 1024
    fake = FakeR2Adapter(
        cmdj_responses={"ij": {"core": {"size": small}}, "izzj": [_IZZJ]},
    )
    adapter = R2PipeAdapter(fake)

    assert adapter.get_strings() == _IZZJ


def test_get_strings_uses_whole_file_when_size_unknown():
    fake = FakeR2Adapter(
        cmdj_responses={"ij": {"core": {}}, "izzj": [_IZZJ]},
    )
    adapter = R2PipeAdapter(fake)

    assert adapter.get_strings() == _IZZJ


def test_string_scan_threshold_env_override():
    import os

    os.environ["R2INSPECT_STRING_SCAN_THRESHOLD_MB"] = "1"
    try:
        size = 5 * 1024 * 1024  # 5 MB > 1 MB override
        fake = FakeR2Adapter(
            cmdj_responses={"ij": {"core": {"size": size}}, "izj": [_IZJ]},
        )
        adapter = R2PipeAdapter(fake)
        assert adapter.get_strings() == _IZJ
    finally:
        del os.environ["R2INSPECT_STRING_SCAN_THRESHOLD_MB"]


def test_string_scan_threshold_env_invalid_uses_default():
    # An unparseable override falls back to the default threshold (no downgrade
    # for a small file).
    import os

    os.environ["R2INSPECT_STRING_SCAN_THRESHOLD_MB"] = "not-a-number"
    try:
        fake = FakeR2Adapter(
            cmdj_responses={"ij": {"core": {"size": 5 * 1024 * 1024}}, "izzj": [_IZZJ]},
        )
        adapter = R2PipeAdapter(fake)
        assert adapter.get_strings() == _IZZJ
    finally:
        del os.environ["R2INSPECT_STRING_SCAN_THRESHOLD_MB"]
