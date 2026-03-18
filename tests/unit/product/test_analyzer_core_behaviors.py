from __future__ import annotations

import os
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from r2inspect.abstractions.base_analyzer import BaseAnalyzer
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer
from r2inspect.modules.simhash_analyzer import SimHashAnalyzer


class MinimalAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict[str, Any]:
        return self._init_result_structure()


class StubAdapter:
    def __init__(self, strings: list[dict[str, Any]] | None = None) -> None:
        self._strings = strings or []

    def get_strings(self) -> list[dict[str, Any]]:
        return self._strings


def _build_pe_no_rich() -> bytes:
    mz = bytearray(0x40)
    mz[0] = ord("M")
    mz[1] = ord("Z")
    struct.pack_into("<I", mz, 0x3C, 0x40)
    return bytes(mz) + b"PE\x00\x00" + b"\x00" * 200


def _write_tmp(data: bytes, suffix: str = ".exe") -> str:
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, mode="wb") as handle:
        handle.write(data)
    return handle.name


def test_base_analyzer_context_timing_and_identity_behaviors() -> None:
    analyzer = MinimalAnalyzer(filepath="/tmp/sample.bin")
    result: dict[str, Any] = {"available": False, "error": None}

    with analyzer._analysis_context(result, error_message="unused"):
        pass

    @analyzer._measure_execution_time
    def _compute() -> dict[str, Any]:
        return {"ok": True}

    timed = _compute()

    assert result["available"] is True
    assert result["error"] is None
    assert timed["ok"] is True
    assert "execution_time" in timed
    assert "sample.bin" in str(analyzer)
    assert analyzer.supports_format("PE") is True
    assert analyzer.get_category() == "unknown"


def test_rich_header_and_simhash_fail_safely_on_sparse_inputs() -> None:
    path = _write_tmp(_build_pe_no_rich())
    try:
        rich = RichHeaderAnalyzer(adapter=object(), filepath=path)
        assert rich._check_magic_bytes() is True
        assert rich._direct_file_rich_search() is None

        simhash = SimHashAnalyzer(adapter=StubAdapter(strings=[]), filepath="/tmp/f.bin")
        extracted = simhash._extract_opcodes_from_ops(
            [{"opcode": "mov eax, ebx"}, {"mnemonic": "ret"}]
        )
        assert "OP:mov" in extracted

        simhash.analyze = lambda: {"available": True, "hash_value": 12345}  # type: ignore[method-assign]
        assert "distance" in simhash.calculate_similarity(54321, hash_type="combined")
    finally:
        os.unlink(path)
