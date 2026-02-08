from __future__ import annotations

from r2inspect.cli.display import (
    _display_binbloom_signature_details,
    _display_binlex,
    _display_indicators,
)


def test_display_binlex_binbloom_and_indicators(capsys):
    results = {
        "binlex": {
            "available": False,
            "error": "missing",
        },
        "binbloom": {
            "available": True,
            "signatures": ["a", "b"],
            "file_bloom_bits": 10,
            "function_bloom_bits": 10,
            "strings_bloom_bits": 10,
            "sections_bloom_bits": 10,
            "functions_with_bloom": 1,
            "functions_without_bloom": 0,
            "sections_with_bloom": 1,
            "sections_without_bloom": 0,
            "bloom_error_rate": 0.01,
            "bloom_hashes": 3,
            "bloom_filters": {
                "file": {"size_bits": 10, "hashes": 3},
                "functions": {"size_bits": 10, "hashes": 3},
                "strings": {"size_bits": 10, "hashes": 3},
                "sections": {"size_bits": 10, "hashes": 3},
            },
        },
        "indicators": [{"type": "suspicious", "confidence": 0.9, "description": "x"}],
    }

    _display_binlex(results)
    results["binbloom"]["unique_signatures"] = 2
    results["binbloom"]["function_signatures"] = {
        "f": {"signature": "abcd"},
        "g": {"signature": "abcd"},
    }
    _display_binbloom_signature_details(results["binbloom"])
    _display_indicators(results)

    out = capsys.readouterr().out
    assert "Binlex" in out
    assert "Binbloom" in out
    assert "Indicators" in out
