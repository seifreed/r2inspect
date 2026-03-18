"""Edge case tests for authenticode_analyzer.py - covering missing branches.

All tests use FakeR2 + R2PipeAdapter instead of mocks.
"""

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer


class FakeR2:
    """Minimal r2pipe stand-in driven by cmd/cmdj lookup tables."""

    def __init__(self, cmd_map=None, cmdj_map=None):
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command):
        return self._cmd_map.get(command, "")

    def cmdj(self, command):
        return self._cmdj_map.get(command)


def _make_analyzer(*, cmdj_map=None, cmd_map=None):
    """Build an AuthenticodeAnalyzer backed by FakeR2 + R2PipeAdapter."""
    r2 = FakeR2(cmd_map=cmd_map or {}, cmdj_map=cmdj_map or {})
    adapter = R2PipeAdapter(r2)
    return AuthenticodeAnalyzer(adapter)


# ---------------------------------------------------------------------------
# _has_required_headers
# ---------------------------------------------------------------------------


def test_has_required_headers_no_pe_header():
    analyzer = _make_analyzer(cmdj_map={"ihj": None})

    result = analyzer._has_required_headers()

    assert result is False


def test_has_required_headers_no_optional_header():
    analyzer = _make_analyzer(
        cmdj_map={
            "ihj": {"class": "PE32"},
            "iHj": None,
        }
    )

    result = analyzer._has_required_headers()

    assert result is False


# ---------------------------------------------------------------------------
# _get_security_directory
# ---------------------------------------------------------------------------


def test_get_security_directory_not_list():
    analyzer = _make_analyzer(cmdj_map={"iDj": {"invalid": "format"}})

    result = analyzer._get_security_directory()

    assert result is None


def test_get_security_directory_no_security():
    analyzer = _make_analyzer(
        cmdj_map={
            "iDj": [
                {"name": "CODE", "vaddr": 0x1000, "paddr": 0x800, "size": 100},
                {"name": "DATA", "vaddr": 0x2000, "paddr": 0x900, "size": 200},
            ],
        }
    )

    result = analyzer._get_security_directory()

    assert result is None


# ---------------------------------------------------------------------------
# _read_win_certificate
# ---------------------------------------------------------------------------


def test_read_win_certificate_invalid_offset():
    analyzer = _make_analyzer()
    security_dir = {"paddr": 0, "size": 0}
    result = {"errors": []}

    cert = analyzer._read_win_certificate(security_dir, result)

    assert cert is None
    assert "Invalid security directory" in result["errors"]


def test_read_win_certificate_short_data():
    # pxj 8 @ 4096 -> only 2 bytes, too short
    analyzer = _make_analyzer(
        cmdj_map={
            "pxj 8 @ 4096": [0x01, 0x02],
        }
    )
    security_dir = {"paddr": 0x1000, "size": 100}
    result = {"errors": []}

    cert = analyzer._read_win_certificate(security_dir, result)

    assert cert is None


# ---------------------------------------------------------------------------
# _detect_digest_algorithm
# ---------------------------------------------------------------------------


def test_detect_digest_algorithm_sha1():
    analyzer = _make_analyzer()
    pkcs7_data = [0x01, 0x02, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x03, 0x04]

    result = analyzer._detect_digest_algorithm(pkcs7_data)

    assert result == "SHA1"


def test_detect_digest_algorithm_none():
    analyzer = _make_analyzer()
    pkcs7_data = [0x01, 0x02, 0x03, 0x04, 0x05]

    result = analyzer._detect_digest_algorithm(pkcs7_data)

    assert result is None


# ---------------------------------------------------------------------------
# _detect_encryption_algorithm
# ---------------------------------------------------------------------------


def test_detect_encryption_algorithm_rsa():
    analyzer = _make_analyzer()
    pkcs7_data = [
        0x01,
        0x02,
        0x2A,
        0x86,
        0x48,
        0x86,
        0xF7,
        0x0D,
        0x01,
        0x01,
        0x01,
        0x05,
    ]

    result = analyzer._detect_encryption_algorithm(pkcs7_data)

    assert result == "RSA"


def test_detect_encryption_algorithm_none():
    analyzer = _make_analyzer()
    pkcs7_data = [0x01, 0x02, 0x03, 0x04, 0x05]

    result = analyzer._detect_encryption_algorithm(pkcs7_data)

    assert result is None


# ---------------------------------------------------------------------------
# _extract_cn_entry
# ---------------------------------------------------------------------------


def test_extract_cn_entry_short_data():
    analyzer = _make_analyzer()
    pkcs7_data = [0x01, 0x02, 0x03]

    entry = analyzer._extract_cn_entry(pkcs7_data, 0x1000, 0)

    assert entry is None


def test_extract_cn_entry_invalid_length():
    analyzer = _make_analyzer()
    pkcs7_data = [0x01, 0x02, 0x03, 0x04, 0x80, 0xFF] + [0x00] * 100

    entry = analyzer._extract_cn_entry(pkcs7_data, 0x1000, 0)

    assert entry is None


def test_extract_cn_entry_zero_length():
    analyzer = _make_analyzer()
    pkcs7_data = [0x01, 0x02, 0x03, 0x04, 0x00, 0xFF] + [0x00] * 100

    entry = analyzer._extract_cn_entry(pkcs7_data, 0x1000, 0)

    assert entry is None


def test_extract_cn_entry_overflow():
    analyzer = _make_analyzer()
    pkcs7_data = [0x01, 0x02, 0x03, 0x04, 0xFF] + [0x00] * 10

    entry = analyzer._extract_cn_entry(pkcs7_data, 0x1000, 1)

    assert entry is None


def test_extract_cn_entry_decode_error():
    analyzer = _make_analyzer()
    pkcs7_data = [0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0xFE, 0xFD, 0xFC] + [0x00] * 100

    entry = analyzer._extract_cn_entry(pkcs7_data, 0x1000, 0)

    assert entry is None


def test_extract_cn_entry_success():
    analyzer = _make_analyzer()
    cn_bytes = b"TestCN"
    pkcs7_data = [0x01, 0x02, 0x03, 0x04, len(cn_bytes)] + list(cn_bytes) + [0x00] * 100

    entry = analyzer._extract_cn_entry(pkcs7_data, 0x1000, 0)

    assert entry is not None
    assert entry["common_name"] == "TestCN"
    assert entry["offset"] == 0x1000


# ---------------------------------------------------------------------------
# _parse_pkcs7
# ---------------------------------------------------------------------------


def test_parse_pkcs7_no_data():
    # read_bytes_list dispatches through p8 command; empty response -> None
    analyzer = _make_analyzer(
        cmd_map={
            "p8 100 @ 4096": "",
        }
    )

    result = analyzer._parse_pkcs7(0x1000, 100)

    assert result is None


def test_parse_pkcs7_success():
    pkcs7_data = [0x01, 0x02, 0x2B, 0x0E, 0x03, 0x02, 0x1A] + [0x00] * 100
    hex_str = bytes(pkcs7_data).hex()
    analyzer = _make_analyzer(
        cmd_map={
            "p8 100 @ 4096": hex_str,
        }
    )

    result = analyzer._parse_pkcs7(0x1000, 100)

    assert result is not None
    assert result["digest_algorithm"] == "SHA1"


# ---------------------------------------------------------------------------
# _compute_authenticode_hash
# ---------------------------------------------------------------------------


def test_compute_authenticode_hash_no_file_info():
    analyzer = _make_analyzer(cmdj_map={"ij": None})

    result = analyzer._compute_authenticode_hash()

    assert result is None


def test_compute_authenticode_hash_zero_size():
    analyzer = _make_analyzer(
        cmdj_map={
            "ij": {"core": {"size": 0}},
        }
    )

    result = analyzer._compute_authenticode_hash()

    assert result is None


def test_compute_authenticode_hash_no_pe():
    analyzer = _make_analyzer(
        cmdj_map={
            "ij": {"core": {"size": 1000}},
            "ihj": None,
        }
    )

    result = analyzer._compute_authenticode_hash()

    assert result is None


def test_compute_authenticode_hash_no_optional_header():
    analyzer = _make_analyzer(
        cmdj_map={
            "ij": {"core": {"size": 1000}},
            "ihj": {"offset": 0x3C},
            "iHj": None,
        }
    )

    result = analyzer._compute_authenticode_hash()

    assert result is None


# ---------------------------------------------------------------------------
# _verify_signature_integrity
# ---------------------------------------------------------------------------


def test_verify_signature_integrity_no_signature():
    analyzer = _make_analyzer()
    sig_info = {"has_signature": False}

    result = analyzer._verify_signature_integrity(sig_info)

    assert result is False


def test_verify_signature_integrity_no_certs():
    analyzer = _make_analyzer()
    sig_info = {"has_signature": True, "certificates": []}

    result = analyzer._verify_signature_integrity(sig_info)

    assert result is False


def test_verify_signature_integrity_with_errors():
    analyzer = _make_analyzer()
    sig_info = {
        "has_signature": True,
        "certificates": [{"type": "X.509"}],
        "errors": ["Some error"],
    }

    result = analyzer._verify_signature_integrity(sig_info)

    assert result is False


def test_verify_signature_integrity_no_security_dir():
    analyzer = _make_analyzer()
    sig_info = {
        "has_signature": True,
        "certificates": [{"type": "X.509"}],
        "errors": [],
        "security_directory": None,
    }

    result = analyzer._verify_signature_integrity(sig_info)

    assert result is False


def test_verify_signature_integrity_empty_sec_dir():
    analyzer = _make_analyzer()
    sig_info = {
        "has_signature": True,
        "certificates": [{"type": "X.509"}],
        "errors": [],
        "security_directory": {"size": 0},
    }

    result = analyzer._verify_signature_integrity(sig_info)

    assert result is False
