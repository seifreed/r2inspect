#!/usr/bin/env python3
"""Batch summary JSON timestamps must be UTC-aware, not naive local time.

The batch report's ``timestamp`` is forensic metadata serialized alongside the
schema's UTC-aware result timestamps; a naive local-time value is ambiguous and
non-reproducible across machines/timezones.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from r2inspect.cli.batch_output_json import build_batch_summary_payload


@pytest.mark.unit
def test_build_batch_summary_payload_timestamp_is_utc() -> None:
    payload = build_batch_summary_payload(
        {"a.bin": {"file_info": {"name": "a.bin"}}},
        [("bad.bin", "boom")],
        collect_batch_statistics=lambda _results: {"ok": True},
    )
    raw = payload["batch_summary"]["timestamp"]
    parsed = datetime.fromisoformat(raw)
    assert parsed.tzinfo is not None, "timestamp must carry timezone info"
    assert parsed.utcoffset() == timedelta(0), "timestamp must be UTC"
