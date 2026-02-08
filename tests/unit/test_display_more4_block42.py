from __future__ import annotations

from r2inspect.cli.display import _display_ccbhash, _display_impfuzzy, _display_simhash


def test_display_impfuzzy_ccbhash_simhash(capsys):
    results = {
        "impfuzzy": {"available": False, "error": "missing"},
        "ccbhash": {"available": False, "error": "missing"},
        "simhash": {"available": True, "hash": "abcd", "error": None},
    }

    _display_impfuzzy(results)
    _display_ccbhash(results)
    _display_simhash(results)

    out = capsys.readouterr().out
    assert "Impfuzzy" in out
    assert "CCBHash" in out
    assert "SimHash" in out
