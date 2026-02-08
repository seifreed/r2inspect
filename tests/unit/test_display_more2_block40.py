from __future__ import annotations

from r2inspect.cli.display import (
    _display_binbloom,
    _display_bindiff,
    _display_rich_header,
    _display_simhash,
)


def test_display_rich_header_and_similarity(capsys):
    results = {
        "rich_header": {
            "available": True,
            "checksum": "1234",
            "xor_key": "abcd",
            "entries": [],
            "compilers": [],
            "richpe_hash": "deadbeef",
        },
        "binbloom": {
            "available": False,
            "error": "missing",
        },
        "simhash": {
            "available": False,
            "error": "missing",
        },
        "bindiff": {
            "available": False,
            "error": "missing",
        },
    }

    _display_rich_header(results)
    _display_binbloom(results)
    _display_simhash(results)
    _display_bindiff(results)

    out = capsys.readouterr().out
    assert "Rich Header" in out
    assert "Binbloom" in out
    assert "SimHash" in out
    assert "BinDiff" in out
