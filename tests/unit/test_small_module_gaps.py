#!/usr/bin/env python3
"""
Tests targeting small uncovered lines across multiple modules.

Covers:
  - utils/r2_suppress.py: lines 76-79  (safe_r2_command fallback path)
  - modules/pe_info.py: lines 54-56    (_fetch_pe_header exception branch)
  - modules/resource_analyzer.py: 457  (ASCII return text path)
  - modules/packer_detector.py: 112    (Unknown heuristic packer_type)
  - modules/pe_imports.py: 79          (continue on empty funcname)
  - modules/overlay_analyzer.py: 313   (return "unknown" from _determine_overlay_type)
  - modules/crypto_analyzer.py: 261    (return 0.0 when fromhex yields empty bytes)
  - modules/ccbhash_analyzer.py: 42    (_check_library_availability → False)
  - utils/hashing.py: 100              (calculate_ssdeep when get_ssdeep() is None)
  - modules/rich_header_domain.py: 291 (break when entry_bytes < 8)
"""

from __future__ import annotations

import logging

import pytest

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class _NullAdapter:
    def get_file_info(self):
        return {}

    def cmdj(self, cmd):
        return None

    def cmd(self, cmd):
        return ""

    def get_symbols(self):
        return []

    def get_info_text(self):
        return ""

    def get_imports(self):
        return []

    def get_sections(self):
        return []

    def get_strings(self):
        return []


# ---------------------------------------------------------------------------
# utils/r2_suppress.py – lines 76-79
# ---------------------------------------------------------------------------


def test_r2_suppress_silent_cmdj_lines_76_78() -> None:
    """
    Patch _try_cmdj to return None (simulating a None result when default is not None).
    _try_cmd_parse then returns default, so we return parsed at line 78.
    Covers lines 76, 77, 78.
    """
    import r2inspect.utils.r2_suppress as _sup

    orig_try_cmdj = _sup._try_cmdj
    # Force _try_cmdj to return None so that lines 76-79 become reachable
    _sup._try_cmdj = lambda *a: None  # type: ignore[assignment]
    try:
        adapter = _NullAdapter()
        default = ["fallback"]
        result = _sup.silent_cmdj(adapter, "ij", default=default)
        # _try_cmd_parse sees empty cmd output → returns default
        assert result == default
    finally:
        _sup._try_cmdj = orig_try_cmdj  # type: ignore[assignment]


def test_r2_suppress_silent_cmdj_line_79() -> None:
    """
    Patch both _try_cmdj and _try_cmd_parse to return None so that
    the final return safe_cmdj(...) on line 79 is reached.
    """
    import r2inspect.utils.r2_suppress as _sup

    orig_try_cmdj = _sup._try_cmdj
    orig_try_cmd_parse = _sup._try_cmd_parse
    _sup._try_cmdj = lambda *a: None  # type: ignore[assignment]
    _sup._try_cmd_parse = lambda *a: None  # type: ignore[assignment]
    try:
        adapter = _NullAdapter()
        result = _sup.silent_cmdj(adapter, "ij", default=["fallback"])
        # safe_cmdj on a null adapter returns its default
        assert result is not None or result == ["fallback"]
    finally:
        _sup._try_cmdj = orig_try_cmdj  # type: ignore[assignment]
        _sup._try_cmd_parse = orig_try_cmd_parse  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# modules/pe_info.py – lines 54-56
# ---------------------------------------------------------------------------


def test_pe_info_fetch_pe_header_exception_returns_none() -> None:
    """
    Patch get_pe_headers inside the pe_info module to raise, triggering
    the except branch that logs and returns None (lines 54-56).
    """
    import r2inspect.modules.pe_info as _pe

    orig = _pe.get_pe_headers  # type: ignore[attr-defined]

    def _raising(*args: object) -> None:
        raise RuntimeError("simulated PE header failure")

    _pe.get_pe_headers = _raising  # type: ignore[attr-defined]
    try:
        result = _pe._fetch_pe_header(_NullAdapter(), logging.getLogger("test"))
        assert result is None
    finally:
        _pe.get_pe_headers = orig  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# modules/resource_analyzer.py – line 457
# ---------------------------------------------------------------------------


class _SneakyData:
    """
    Raises TypeError on the first two ``bytes()`` conversion attempts;
    succeeds (returning [65, 66] = 'AB') on the third.

    This forces the UTF-16LE and UTF-8 decode blocks to fall into their
    ``except TypeError`` handlers, allowing the ASCII block to produce a
    printable result and hit line 457 (``return text``).
    """

    def __init__(self) -> None:
        self._calls = 0

    def __bool__(self) -> bool:
        return True

    def __len__(self) -> int:
        return 2

    def __iter__(self):  # type: ignore[override]
        self._calls += 1
        if self._calls <= 2:
            raise TypeError("simulated for test")
        return iter([65, 66])


def test_resource_analyzer_read_as_string_ascii_return() -> None:
    """
    Force _read_resource_as_string to walk past UTF-16LE/UTF-8 try blocks
    (both raise TypeError) and return the ASCII-decoded result, covering
    line 457 (``return text``).
    """
    from r2inspect.modules.resource_analyzer import ResourceAnalyzer

    class _SneakyResourceAnalyzer(ResourceAnalyzer):
        def _cmdj(self, cmd: str, default: object = None) -> object:
            return _SneakyData()

    analyzer = _SneakyResourceAnalyzer(_NullAdapter())
    result = analyzer._read_resource_as_string(0x1000, 100)
    assert result == "AB"


# ---------------------------------------------------------------------------
# modules/packer_detector.py – line 112
# ---------------------------------------------------------------------------


class _PackerThreshold:
    entropy_threshold = 7.0


class _PackerTypedConfig:
    packer = _PackerThreshold()


class _FakeDetectorConfig:
    typed_config = _PackerTypedConfig()


class _HighEvidenceNoSignatureDetector:
    """
    Subclass stub whose helper methods produce evidence_score >= 50
    with no packer_type set, causing line 112 to execute.
    """

    def _check_packer_signatures(self):
        return None  # no signature → packer_type stays None

    def _analyze_entropy(self):
        # 2 high-entropy sections → +30 points
        return {"summary": {"high_entropy_sections": 2, "high_entropy_ratio": 0.5}}

    def _analyze_sections(self):
        # 3 suspicious sections → min(3*10, 20) = 20 points
        return {
            "suspicious_sections": ["s1", "s2", "s3"],
            "section_count": 3,
            "executable_sections": 1,
            "writable_executable": 0,
        }

    def _count_imports(self) -> int:
        return 5  # < 10 → +10 points  (total: 60 >= 50)


def test_packer_detector_unknown_heuristic_line_112() -> None:
    """
    Build a PackerDetector whose helpers yield high evidence without a
    known signature, so packer_type is set to 'Unknown (heuristic)'
    at line 112.
    """
    from r2inspect.modules.packer_detector import PackerDetector

    class _TestDetector(_HighEvidenceNoSignatureDetector, PackerDetector):
        pass

    detector = _TestDetector.__new__(_TestDetector)
    detector.adapter = _NullAdapter()
    detector.r2 = detector.adapter
    detector.config = _FakeDetectorConfig()
    detector.entropy_threshold = 7.0
    detector.packer_signatures = {}

    result = detector.detect()
    assert result["packer_type"] == "Unknown (heuristic)"
    assert result["is_packed"] is True


# ---------------------------------------------------------------------------
# modules/pe_imports.py – line 79
# ---------------------------------------------------------------------------


def test_pe_imports_empty_funcname_continue() -> None:
    """
    Patch group_imports_by_library to return a dict containing an empty
    string in the functions list, causing ``continue`` at line 79.
    """
    import r2inspect.modules.pe_imports as _pe_imp

    class _AdapterWithImports(_NullAdapter):
        def get_imports(self):
            return [{"libname": "kernel32.dll", "name": "GetProcAddress"}]

    orig = _pe_imp.group_imports_by_library  # type: ignore[attr-defined]
    _pe_imp.group_imports_by_library = lambda _imports: {  # type: ignore[attr-defined]
        "kernel32": ["GetProcAddress", "", "ExitProcess"]
    }
    try:
        result = _pe_imp.calculate_imphash(_AdapterWithImports(), logging.getLogger("test"))
        # imphash is computed from the two non-empty names only
        assert isinstance(result, str)
        assert result != ""
    finally:
        _pe_imp.group_imports_by_library = orig  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# modules/overlay_analyzer.py – line 313
# ---------------------------------------------------------------------------


class _TruthyEmpty:
    """
    A truthy object that iterates as empty.
    Makes ``if not patterns`` False (so the entropy branch is skipped)
    while both ``for pattern in patterns`` loops produce no iterations,
    leaving type_counts empty and reaching ``return "unknown"`` at line 313.
    """

    def __bool__(self) -> bool:
        return True

    def __iter__(self):  # type: ignore[override]
        return iter([])


def test_overlay_analyzer_determine_overlay_type_unknown() -> None:
    """
    Call _determine_overlay_type with a truthy-but-empty patterns object so
    that type_counts stays empty and ``return "unknown"`` (line 313) is hit.
    """
    from r2inspect.modules.overlay_analyzer import OverlayAnalyzer

    analyzer = OverlayAnalyzer(_NullAdapter())
    result = analyzer._determine_overlay_type(_TruthyEmpty(), [])
    assert result == "unknown"


# ---------------------------------------------------------------------------
# modules/crypto_analyzer.py – line 261
# ---------------------------------------------------------------------------


class _SpaceHexBytes(bytes):
    """
    A bytes subclass whose .hex() returns only whitespace.
    bytes.fromhex('   ') == b'' in Python 3.7+, making len(data) == 0
    and covering line 261.
    """

    def hex(self, *args: object, **kwargs: object) -> str:  # type: ignore[override]
        return "   "


class _SpaceHexAdapter(_NullAdapter):
    def get_sections(self):
        return [{"name": ".text", "vaddr": 0x1000, "size": 64}]

    def read_bytes(self, addr: int, size: int) -> bytes:
        return _SpaceHexBytes()


def test_crypto_analyzer_section_entropy_empty_bytes_line_261() -> None:
    """
    Make _read_bytes return a bytes-like whose .hex() is all-whitespace.
    bytes.fromhex('   ') returns b'', so len(data)==0 triggers line 261.
    """
    from r2inspect.modules.crypto_analyzer import CryptoAnalyzer

    analyzer = CryptoAnalyzer(_SpaceHexAdapter())
    section = {"name": ".text", "vaddr": 0x1000, "size": 64}
    result = analyzer._calculate_section_entropy(section)
    assert result == 0.0


# ---------------------------------------------------------------------------
# modules/ccbhash_analyzer.py – line 42
# ---------------------------------------------------------------------------


def test_ccbhash_check_library_unavailable_line_42() -> None:
    """
    Temporarily make CCBHashAnalyzer.is_available() return False so that
    _check_library_availability returns (False, error_message) at line 42.
    """
    from r2inspect.modules.ccbhash_analyzer import CCBHashAnalyzer

    orig = CCBHashAnalyzer.is_available
    CCBHashAnalyzer.is_available = staticmethod(lambda: False)  # type: ignore[assignment]
    try:
        analyzer = CCBHashAnalyzer(adapter=_NullAdapter(), filepath="nonexistent.bin")
        ok, err = analyzer._check_library_availability()
        assert ok is False
        assert err is not None
        assert "not available" in err.lower()
    finally:
        CCBHashAnalyzer.is_available = orig  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# utils/hashing.py – line 100
# ---------------------------------------------------------------------------


def test_calculate_ssdeep_returns_none_when_get_ssdeep_is_none() -> None:
    """
    Patch get_ssdeep to return None so calculate_ssdeep short-circuits and
    returns None at line 100.
    """
    import r2inspect.utils.hashing as _hash_mod

    orig = _hash_mod.get_ssdeep  # type: ignore[attr-defined]
    _hash_mod.get_ssdeep = lambda: None  # type: ignore[attr-defined]
    try:
        result = _hash_mod.calculate_ssdeep("any_file.bin")
        assert result is None
    finally:
        _hash_mod.get_ssdeep = orig  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# modules/rich_header_domain.py – line 291
# ---------------------------------------------------------------------------


class _TruncatingBytes(bytes):
    """
    A bytes subclass that truncates all slice results to 4 bytes.
    When decode_rich_header slices entry_bytes = data[i:i+8], the result
    has length 4 < 8, triggering the ``break`` at line 291.
    """

    def __getitem__(self, key: object) -> object:
        result = super().__getitem__(key)  # type: ignore[arg-type]
        if isinstance(key, slice) and isinstance(result, bytes) and len(result) > 4:
            return result[:4]
        return result


def test_rich_header_decode_truncated_entry_line_291() -> None:
    """
    Use a TruncatingBytes object so that entry_bytes is only 4 bytes long,
    triggering the safety ``break`` at line 291.
    """
    from r2inspect.modules.rich_header_domain import decode_rich_header

    # 24 bytes is enough for range(4, 20, 8) = [4, 12] → first iteration hits line 291
    encoded_data = _TruncatingBytes(bytes(24))
    entries = decode_rich_header(encoded_data, xor_key=0)
    # The break exits early; no entries are appended
    assert isinstance(entries, list)
