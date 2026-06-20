#!/usr/bin/env python3
"""JSON-only batch summary must treat a ``.json`` ``-o`` target as a file.

When the batch is invoked as ``-j -o report.json``, ``output_path`` is a file
path whose parent is the real output directory. The JSON+CSV branch already
normalizes this to ``output_path.parent``; the JSON-only branch did not, so it
passed the file path into ``create_json_batch_summary`` which then tried to
write *under* the file and crashed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.cli.batch_output_json import create_json_batch_summary
from r2inspect.cli.batch_summary_runtime import create_batch_summary_output


def _unused(*_args: object, **_kwargs: object) -> object:
    raise AssertionError("CSV path helpers must not be called for a JSON-only batch")


@pytest.mark.unit
def test_json_only_batch_with_json_target_writes_into_parent_dir(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    timestamp = "20260620_000000"

    def json_summary(all_results, failed_files, output_path, ts):  # type: ignore[no-untyped-def]
        return create_json_batch_summary(
            all_results,
            failed_files,
            output_path,
            ts,
            collect_batch_statistics=lambda _results: {"ok": True},
        )

    output_filename = create_batch_summary_output(
        all_results={"a.bin": {"file_info": {"name": "a.bin"}}},
        failed_files=[],
        output_path=target,
        output_json=True,
        output_csv=False,
        determine_csv_file_path=_unused,
        write_csv_results=_unused,
        create_json_batch_summary=json_summary,
        timestamp=timestamp,
    )

    summary_file = tmp_path / f"r2inspect_batch_{timestamp}.json"
    assert summary_file.is_file()
    assert output_filename is not None
    # The file path target must not have been created as a directory.
    assert not target.is_dir()
