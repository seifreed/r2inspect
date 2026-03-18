from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from r2inspect.modules.ccbhash_analyzer import CCBHashAnalyzer
from r2inspect.modules.pe_security import (
    _apply_authenticode_feature,
    _apply_security_flags_from_header,
    _apply_security_flags_from_text,
    _get_pe_security_text,
)
from r2inspect.modules.string_analyzer import StringAnalyzer


def _string_config() -> Any:
    strings_cfg = SimpleNamespace(
        min_length=2,
        max_length=200,
        extract_ascii=True,
        extract_unicode=True,
    )
    general_cfg = SimpleNamespace(max_strings=200)
    return SimpleNamespace(typed_config=SimpleNamespace(strings=strings_cfg, general=general_cfg))


def test_pe_security_helpers_apply_flags_and_authenticode_consistently() -> None:
    features: dict[str, Any] = {}
    logger = SimpleNamespace(debug=lambda *_a, **_k: None, error=lambda *_a, **_k: None)
    _apply_security_flags_from_header(
        features, {"nx": True, "aslr": True, "high_entropy_va": True, "guard_cf": False}, logger
    )
    _apply_security_flags_from_text(
        features, "RELRO: full\nCanary: yes\nDEP: enabled\nPIE: enabled\nFortify: yes"
    )
    _apply_authenticode_feature(features, {"has_signature": True, "signature_valid": True})

    assert set(features) >= {"aslr", "dep", "seh", "guard_cf"}
    assert isinstance(features["aslr"], bool)
    assert isinstance(features["dep"], bool)
    assert isinstance(
        _get_pe_security_text(SimpleNamespace(cmd=lambda _cmd: "DLL characteristics")), str
    )


def test_string_analyzer_and_ccbhash_fail_safely_on_sparse_inputs(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00" * 64 + b"hello\x00world\x00")

    analyzer = StringAnalyzer(adapter=SimpleNamespace(), config=_string_config())
    result = analyzer.analyze()
    assert isinstance(result, dict)
    assert result["available"] is True

    ccbhash = CCBHashAnalyzer(adapter=SimpleNamespace(), filepath=str(sample))
    ccbhash._extract_functions = lambda: [{"name": "bad", "addr": None}, {"name": "ok", "addr": 0x1000, "size": 8}]  # type: ignore[method-assign]
    ccbhash._calculate_function_ccbhash = lambda *_args, **_kwargs: "h"  # type: ignore[method-assign]
    ccbhash._calculate_binary_ccbhash = lambda *_args, **_kwargs: None  # type: ignore[method-assign]

    value, method, error = ccbhash._calculate_hash()
    assert value is None
    assert method is None
    assert error == "Failed to calculate binary CCBHash"
