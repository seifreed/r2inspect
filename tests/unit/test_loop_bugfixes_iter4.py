"""Regression test for loop iteration 4.

The batch CSV writer kept its own hard-coded column list that diverged from the
single-file CSV schema, silently dropping the ``*_available`` columns so the
same binary produced different CSV headers via ``-c`` vs ``--batch``. Batch CSV
now shares the single source of truth.
"""

from __future__ import annotations

from r2inspect.cli.batch_output import get_csv_fieldnames
from r2inspect.cli.output_csv_fields import FIELDNAMES as CANONICAL_FIELDNAMES


def test_batch_csv_fieldnames_match_single_file_schema() -> None:
    assert get_csv_fieldnames() == list(CANONICAL_FIELDNAMES)


def test_batch_csv_includes_availability_columns() -> None:
    fields = get_csv_fieldnames()
    for column in (
        "ssdeep_available",
        "tlsh_available",
        "telfhash_available",
        "rich_header_available",
    ):
        assert column in fields
