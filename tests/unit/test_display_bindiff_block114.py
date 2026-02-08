from __future__ import annotations

from r2inspect.cli.display import _display_bindiff


def test_display_bindiff_outputs(capsys):
    results = {
        "bindiff": {
            "filename": "sample.bin",
            "comparison_ready": True,
            "structural_features": {"file_type": "PE", "section_count": 1},
            "function_features": {"function_count": 1},
            "string_features": {"total_strings": 0},
            "byte_features": {"entropy": 1.0},
            "behavioral_features": {"api_calls": []},
            "signatures": {"structural": "a", "function": "b"},
        }
    }

    _display_bindiff(results)

    captured = capsys.readouterr()
    assert "BinDiff" in captured.out
