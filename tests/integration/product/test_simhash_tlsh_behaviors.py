from __future__ import annotations

from r2inspect.modules.simhash_analyzer import SimHashAnalyzer
from r2inspect.modules.tlsh_analyzer import TLSHAnalyzer


class Adapter:
    def cmdj(self, _cmd: str):
        return {}

    def cmd(self, _cmd: str):
        return ""


def test_simhash_uses_opcode_fallback_when_mnemonic_is_missing() -> None:
    analyzer = SimHashAnalyzer(adapter=Adapter(), filepath="/tmp/f.bin")
    extracted = analyzer._extract_opcodes_from_ops(
        [{"opcode": "mov eax, ebx"}, {"mnemonic": "ret"}]
    )
    assert "OP:mov" in extracted


def test_tlsh_returns_missing_section_hashes_as_none_on_read_errors() -> None:
    class _ReadErrorTLSH(TLSHAnalyzer):
        def _get_sections(self):
            return [{"name": ".text", "vaddr": 4096, "size": 16}]

        def _read_bytes_hex(self, *_a, **_k):
            raise RuntimeError("read")

    analyzer = _ReadErrorTLSH(adapter=Adapter(), filename="/tmp/f.bin")
    assert analyzer._calculate_section_tlsh()[".text"] is None
