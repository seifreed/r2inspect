from __future__ import annotations

from r2inspect.cli.display import (
    _display_circuit_breaker_statistics,
    _display_file_info,
    _display_pe_info,
    _display_security,
    _display_ssdeep,
    _display_telfhash,
    _display_tlsh,
)


def test_display_additional_sections(capsys):
    _display_circuit_breaker_statistics({"total_failures": 2, "open_circuits": 1})

    results = {
        "file_info": {
            "name": "sample",
            "file_type": "PE32 executable",
            "size": 123,
            "md5": "x" * 32,
        },
        "pe_info": {"compile_time": "2020", "machine": "x86"},
        "security_features": {"aslr": True, "nx": False},
        "ssdeep": {"available": False, "error": "missing"},
        "tlsh": {"available": False, "error": "missing"},
        "telfhash": {"available": False, "error": "missing"},
    }

    _display_file_info(results)
    results["security"] = {"aslr": True, "nx": False}
    _display_pe_info(results)
    _display_security(results)
    _display_ssdeep(results)
    _display_tlsh(results)
    _display_telfhash(results)

    out = capsys.readouterr().out
    assert "File Information" in out
    assert "PE Analysis" in out
    assert "Security Features" in out
