from __future__ import annotations

from pathlib import Path

import pytest
import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter


def test_cached_query_invalid_response(tmp_path: Path):
    # Use an empty file to encourage empty/invalid responses
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")

    r2 = r2pipe.open(str(empty))
    try:
        adapter = R2PipeAdapter(r2)
        # Use a bogus JSON command to force empty list default
        result = adapter._cached_query("bogusj", "list", error_msg="nope")
        assert isinstance(result, list)
    finally:
        r2.quit()
