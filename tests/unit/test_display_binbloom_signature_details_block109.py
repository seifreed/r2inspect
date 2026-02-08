from __future__ import annotations

from r2inspect.cli.display import _display_binbloom_signature_details


def test_display_binbloom_signature_details_outputs(capsys):
    binbloom_info = {
        "available": True,
        "unique_signatures": 2,
        "function_signatures": {
            "func_a": {"signature": "abc" * 30},
            "func_b": {"signature": "def" * 30},
            "func_c": {"signature": "abc" * 30},
        },
    }

    _display_binbloom_signature_details(binbloom_info)

    captured = capsys.readouterr()
    assert "Binbloom Signature Details" in captured.out
