from __future__ import annotations

from r2inspect.cli.display import _display_machoc_functions


def test_display_machoc_functions_outputs(capsys):
    results = {
        "functions": {
            "total_functions": 3,
            "machoc_hashes": {
                "f1": "hash1",
                "f2": "hash1",
                "f3": "hash2",
            },
        }
    }

    _display_machoc_functions(results)

    captured = capsys.readouterr()
    assert "Function Analysis" in captured.out
    assert "Unique MACHOC Hashes" in captured.out
