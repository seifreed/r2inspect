"""Tests targeting specific uncovered lines in rich_header_analyzer.py.

Covered lines:
  141-143  – get_rich_header_hash() returns None/empty
  159-161  – pe.close() raises inside the finally block
  269-270  – _check_magic_bytes read_bytes raises
  309-310  – _extract_rich_header: all strategies fail after r2pipe offsets found
  398      – _direct_file_rich_search: xor_key is None
  402      – _direct_file_rich_search: dans_pos is None
  406      – _direct_file_rich_search: encoded_data is empty
  410-411  – _direct_file_rich_search: decode_rich_header returns no entries
  586      – calculate_richpe_hash_from_file: normal return via results.get()
"""

import os
import struct
import tempfile

import r2inspect.modules.rich_header_analyzer as _rha_mod
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer

# ── tiny helpers ─────────────────────────────────────────────────────────────


class _MinimalAdapter:
    def get_file_info(self):
        return {}

    def cmdj(self, cmd):
        return None

    def cmd(self, cmd):
        return ""

    def get_info_text(self):
        return ""


def _make_pe_bytes(dos_stub: bytes) -> bytes:
    """Build minimal valid PE binary with the supplied DOS stub region."""
    pe_offset = 0x40 + len(dos_stub)
    header = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", pe_offset)
    assert len(header) == 0x40
    return header + dos_stub + b"PE\x00\x00" + b"\x00" * 20


def _write_temp_pe(dos_stub: bytes) -> str:
    """Write minimal PE bytes to a temp file; caller must unlink."""
    data = _make_pe_bytes(dos_stub)
    fd, path = tempfile.mkstemp(suffix=".exe")
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


def _analyzer(filepath: str) -> RichHeaderAnalyzer:
    return RichHeaderAnalyzer(adapter=_MinimalAdapter(), filepath=filepath)


# ── Fake pefile objects (module-attribute patching, no mocks) ─────────────────


class _FakeRichHeader:
    checksum = 0x12345678
    values = []


class _FakePENoHash:
    """PE whose get_rich_header_hash() returns None."""

    def __init__(self, filepath):
        self.RICH_HEADER = _FakeRichHeader()

    def get_rich_header_hash(self):
        return None

    def close(self):
        pass


class _FakePECloseRaises:
    """PE whose get_rich_header_hash() returns None AND close() raises."""

    def __init__(self, filepath):
        self.RICH_HEADER = _FakeRichHeader()

    def get_rich_header_hash(self):
        return None

    def close(self):
        raise RuntimeError("simulated close failure")


class _FakePEModuleNoHash:
    PE = _FakePENoHash


class _FakePEModuleCloseRaises:
    PE = _FakePECloseRaises


# ── Lines 141-143: get_rich_header_hash() returns None ───────────────────────


def test_pefile_returns_none_when_hash_empty():
    """Lines 141-143: rich_hash falsy → logger.debug + return None."""
    orig = _rha_mod.pefile
    _rha_mod.pefile = _FakePEModuleNoHash()
    try:
        fd, path = tempfile.mkstemp(suffix=".exe")
        os.close(fd)
        try:
            result = _analyzer(path)._extract_rich_header_pefile()
            assert result is None
        finally:
            os.unlink(path)
    finally:
        _rha_mod.pefile = orig


# ── Lines 159-161: pe.close() raises in the finally block ────────────────────


def test_pefile_close_exception_is_swallowed():
    """Lines 159-161: pe.close() raises → exception logged, not propagated."""
    orig = _rha_mod.pefile
    _rha_mod.pefile = _FakePEModuleCloseRaises()
    try:
        fd, path = tempfile.mkstemp(suffix=".exe")
        os.close(fd)
        try:
            result = _analyzer(path)._extract_rich_header_pefile()
            assert result is None  # still returns None; exception was swallowed
        finally:
            os.unlink(path)
    finally:
        _rha_mod.pefile = orig


# ── Lines 269-270: _check_magic_bytes read_bytes raises ──────────────────────


def test_check_magic_bytes_read_raises_returns_false():
    """Lines 269-270: read_bytes raises → except catches, returns False."""
    orig_read = _rha_mod.default_file_system.read_bytes

    def _raise(path, size=None):
        raise OSError("simulated read error")

    _rha_mod.default_file_system.read_bytes = _raise
    try:
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            result = _analyzer(path)._check_magic_bytes()
            assert result is False
        finally:
            os.unlink(path)
    finally:
        _rha_mod.default_file_system.read_bytes = orig_read


# ── Lines 309-310: _extract_rich_header – all strategies fail ────────────────


class _AllStrategiesFailAnalyzer(RichHeaderAnalyzer):
    """Direct search fails; r2pipe returns non-empty offsets; combinations fail."""

    def _direct_file_rich_search(self):
        return None

    def _collect_rich_dans_offsets(self):
        return [{"offset": 100}], [{"offset": 50}]

    def _try_rich_dans_combinations(self, rich_results, dans_results):
        return None


def test_extract_rich_header_all_strategies_fail():
    """Lines 309-310: no strategy succeeds → logger.debug + return None."""
    fd, path = tempfile.mkstemp(suffix=".exe")
    os.close(fd)
    try:
        analyzer = _AllStrategiesFailAnalyzer(adapter=_MinimalAdapter(), filepath=path)
        result = analyzer._extract_rich_header()
        assert result is None
    finally:
        os.unlink(path)


# ── Lines 398-411: _direct_file_rich_search early-return paths ───────────────


def test_direct_rich_search_none_when_xor_key_none():
    """Line 398: Rich too close to end of dos_stub → xor_key is None."""
    # rich_pos=4, rich_pos+8=12, len(dos_stub)=11 → 12 > 11 → return None
    dos_stub = b"\x00" * 4 + b"Rich" + b"\x00\x00\x00"
    path = _write_temp_pe(dos_stub)
    try:
        assert _analyzer(path)._direct_file_rich_search() is None
    finally:
        os.unlink(path)


def test_direct_rich_search_none_when_dans_pos_none():
    """Line 402: Rich at offset 0 with no DanS → estimate fails → dans_pos None."""
    # rich_pos=0, _estimate_dans_start: range(0, 0) empty → None
    dos_stub = b"Rich" + struct.pack("<I", 1)  # 8 bytes; rich_pos=0
    path = _write_temp_pe(dos_stub)
    try:
        assert _analyzer(path)._direct_file_rich_search() is None
    finally:
        os.unlink(path)


def test_direct_rich_search_none_when_encoded_data_empty():
    """Line 406: DanS immediately before Rich → encoded_data is b'' → return None."""
    # dans_pos=0, rich_pos=4 → dos_stub[4:4] = b''
    dos_stub = b"DanS" + b"Rich" + struct.pack("<I", 1)  # 12 bytes
    path = _write_temp_pe(dos_stub)
    try:
        assert _analyzer(path)._direct_file_rich_search() is None
    finally:
        os.unlink(path)


def test_direct_rich_search_none_when_entries_empty():
    """Lines 410-411: decode_rich_header returns [] → logger.debug + return None."""
    # xor_key=1; encoded bytes: prodid^1=0, count^1=0 → all counts zero → entries=[]
    xor_key = 1
    encoded = struct.pack("<II", xor_key, xor_key) * 2  # 16 bytes
    dos_stub = b"DanS" + encoded + b"Rich" + struct.pack("<I", xor_key)
    path = _write_temp_pe(dos_stub)
    try:
        assert _analyzer(path)._direct_file_rich_search() is None
    finally:
        os.unlink(path)


# ── Line 586: calculate_richpe_hash_from_file normal return path ──────────────


def test_calculate_richpe_hash_from_file_returns_hash_value():
    """Line 586: run_analyzer_on_file returns dict with richpe_hash → return it."""
    orig = _rha_mod.run_analyzer_on_file
    _rha_mod.run_analyzer_on_file = lambda cls, path: {"richpe_hash": "deadbeef01"}
    try:
        result = RichHeaderAnalyzer.calculate_richpe_hash_from_file("dummy.exe")
        assert result == "deadbeef01"
    finally:
        _rha_mod.run_analyzer_on_file = orig


def test_calculate_richpe_hash_from_file_returns_none_when_key_missing():
    """Line 586: results dict has no richpe_hash key → cast returns None."""
    orig = _rha_mod.run_analyzer_on_file
    _rha_mod.run_analyzer_on_file = lambda cls, path: {}
    try:
        result = RichHeaderAnalyzer.calculate_richpe_hash_from_file("dummy.exe")
        assert result is None
    finally:
        _rha_mod.run_analyzer_on_file = orig
