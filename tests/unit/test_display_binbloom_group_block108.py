from __future__ import annotations

from rich.table import Table

from r2inspect.cli.display import _add_binbloom_group


def test_add_binbloom_group_adds_rows():
    table = Table(show_header=True)
    table.add_column("Field")
    table.add_column("Value")

    group = {
        "count": 7,
        "signature": "abcd" * 20,
        "functions": [
            "func_one",
            "func_two",
            "func_three",
            "func_four",
            "func_five",
            "func_six",
            "func_seven",
        ],
    }

    _add_binbloom_group(table, 1, group)

    # Expect rows for size, signature, and functions
    assert len(table.rows) >= 3
