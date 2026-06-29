"""Shared per-function mnemonic cache: one pdfj pass reused across the
similarity analyzers, with transforms that stay equivalent to the per-ops paths.
Uses a real R2PipeAdapter wrapping a FakeR2Adapter -- no mocks, no monkeypatch.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.binlex_runtime import extract_tokens_from_pdfj
from r2inspect.modules.function_analyzer_extraction_support import try_pdfj_extraction
from r2inspect.modules.simhash_features import extract_function_opcodes
from r2inspect.domain.services.binlex import extract_tokens_from_ops, normalize_mnemonic
from r2inspect.domain.services.simhash import (
    extract_opcodes_from_ops,
    opcode_features_from_mnemonics,
)
from tests.helpers.r2_fakes import FakeR2Adapter

# radare2's pdfj carries no "mnemonic" field; the mnemonic is the first token
# of "opcode" -- mirror that here.
_OPS = [{"opcode": "mov eax, 1"}, {"opcode": "ADD rbx, rcx"}, {"opcode": "ret"}]
_PDFJ = {"ops": _OPS}


def test_get_function_mnemonics_extracts_and_caches():
    fake = FakeR2Adapter(cmdj_responses={"pdfj @ 4096": _PDFJ})
    adapter = R2PipeAdapter(fake)

    assert adapter.get_function_mnemonics(0x1000) == ("mov", "ADD", "ret")
    # Second call is served from the compact cache: pdfj is issued only once.
    adapter.get_function_mnemonics(0x1000)
    assert fake.calls["cmdj"].count("pdfj @ 4096") == 1


def test_get_function_mnemonics_empty_when_no_ops():
    fake = FakeR2Adapter(cmdj_responses={"pdfj @ 4096": {"ops": []}})
    adapter = R2PipeAdapter(fake)

    assert adapter.get_function_mnemonics(0x1000) == ()


def test_get_function_mnemonics_cache_cleared():
    fake = FakeR2Adapter(cmdj_responses={"pdfj @ 4096": _PDFJ})
    adapter = R2PipeAdapter(fake)

    adapter.get_function_mnemonics(0x1000)
    adapter.clear_disasm_cache()
    adapter.get_function_mnemonics(0x1000)
    assert fake.calls["cmdj"].count("pdfj @ 4096") == 2


def test_simhash_features_from_mnemonics_match_per_ops_path():
    # The shared raw-mnemonic transform must reproduce extract_opcodes_from_ops
    # for radare2's pdfj output (opcode-only ops, no mnemonic field -> no bigram).
    raw = ["mov", "ADD", "ret"]
    via_mnemonics = opcode_features_from_mnemonics(raw, max_instructions=500)
    via_ops = extract_opcodes_from_ops(_OPS, max_instructions=500)
    assert via_mnemonics == via_ops


def test_binlex_tokens_from_mnemonics_match_per_ops_path():
    raw = ["mov", "ADD", "ret"]
    via_mnemonics = [t for m in raw if (t := normalize_mnemonic(m))]
    via_ops = extract_tokens_from_ops(_OPS)
    assert via_mnemonics == via_ops


# --- the three call sites use the shared cache when the adapter provides it ---
_LOG = logging.getLogger("test_mnemonic_cache")


def _shared_adapter():
    return R2PipeAdapter(FakeR2Adapter(cmdj_responses={"pdfj @ 4096": _PDFJ}))


def test_function_analyzer_uses_shared_cache():
    host = SimpleNamespace(adapter=_shared_adapter())
    assert try_pdfj_extraction(host, "fn", 0x1000, _LOG) == ["mov", "ADD", "ret"]


def test_binlex_uses_shared_cache():
    host = SimpleNamespace(adapter=_shared_adapter())
    assert extract_tokens_from_pdfj(host, 0x1000, "fn", logger=_LOG) == ["mov", "add", "ret"]


def test_simhash_uses_shared_cache():
    host = SimpleNamespace(adapter=_shared_adapter(), max_instructions_per_function=500)
    feats = extract_function_opcodes(host, 0x1000, "fn", logger=_LOG)
    assert "OP:mov" in feats and "OP:add" in feats and "OP:ret" in feats


class _DisasmOnlyAdapter:
    """Has get_disasm but not get_function_mnemonics (the legacy per-ops path)."""

    def get_disasm(self, address=None, size=None):
        return _PDFJ if size is None else {}


def test_simhash_falls_back_to_per_ops_without_shared_cache():
    # An adapter lacking get_function_mnemonics uses the original pdfj-via-ops
    # path, producing the same features.
    host = SimpleNamespace(
        adapter=_DisasmOnlyAdapter(),
        max_instructions_per_function=500,
        _extract_ops_from_disasm=lambda d: d.get("ops", []) if isinstance(d, dict) else [],
        _extract_opcodes_from_ops=lambda ops: extract_opcodes_from_ops(ops, max_instructions=500),
    )
    feats = extract_function_opcodes(host, 0x1000, "fn", logger=_LOG)
    assert feats == opcode_features_from_mnemonics(["mov", "ADD", "ret"], max_instructions=500)
