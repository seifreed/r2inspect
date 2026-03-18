"""Comprehensive tests for authenticode_analyzer.py - 100% coverage target.

Uses FakeR2 + R2PipeAdapter exclusively. NO mocks, NO monkeypatch, NO @patch.
"""

from __future__ import annotations

from typing import Any

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer


# ---------------------------------------------------------------------------
# FakeR2 - deterministic r2pipe stand-in
# ---------------------------------------------------------------------------


class FakeR2:
    """Fake r2pipe instance returning predetermined responses by command."""

    def __init__(
        self,
        cmdj_map: dict[str, Any] | None = None,
        cmd_map: dict[str, str] | None = None,
    ):
        self.cmdj_map: dict[str, Any] = cmdj_map or {}
        self.cmd_map: dict[str, str] = cmd_map or {}

    def cmdj(self, command: str) -> Any:
        if command in self.cmdj_map:
            value = self.cmdj_map[command]
            if isinstance(value, Exception):
                raise value
            return value
        for key, value in self.cmdj_map.items():
            if key in command:
                if isinstance(value, Exception):
                    raise value
                return value
        return None

    def cmd(self, command: str) -> str:
        if command in self.cmd_map:
            value = self.cmd_map[command]
            if isinstance(value, Exception):
                raise value
            return value
        for key, value in self.cmd_map.items():
            if key in command:
                if isinstance(value, Exception):
                    raise value
                return value
        return ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# WIN_CERTIFICATE header: length=0x190, revision=0x200, type=0x0002 (PKCS#7)
WIN_CERT_HEADER = [0x90, 0x01, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00]

# SHA256 OID bytes embedded in PKCS#7 data
SHA256_OID = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]

# SHA1 OID bytes
SHA1_OID = [0x2B, 0x0E, 0x03, 0x02, 0x1A]

# RSA OID bytes
RSA_OID = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]

# Timestamp OID bytes
TIMESTAMP_OID = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E]

# CN OID
CN_OID = [0x55, 0x04, 0x03]


def _bytes_to_hex(data: list[int]) -> str:
    """Convert a list of ints to a hex string (p8 output format)."""
    return "".join(f"{b:02x}" for b in data)


def _build_pkcs7_data_with_sha256_rsa_cn_ts() -> list[int]:
    """Build a PKCS#7 byte stream containing SHA256, RSA, CN, and timestamp OIDs."""
    data: list[int] = [0] * 20
    data.extend(SHA256_OID)
    data.extend([0] * 10)
    data.extend(RSA_OID)
    data.extend([0] * 10)
    # CN entry: OID + padding byte + length(6) + "TestCN"
    data.extend(CN_OID)
    data.append(0)  # padding
    data.append(6)  # length
    data.extend([ord(c) for c in "TestCN"])
    data.extend([0] * 20)
    # timestamp OID
    data.extend(TIMESTAMP_OID)
    data.extend([0] * 20)
    return data


def _make_analyzer(
    cmdj_map: dict[str, Any] | None = None,
    cmd_map: dict[str, str] | None = None,
) -> AuthenticodeAnalyzer:
    """Create an AuthenticodeAnalyzer backed by FakeR2 + R2PipeAdapter."""
    fake_r2 = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map)
    adapter = R2PipeAdapter(fake_r2)
    return AuthenticodeAnalyzer(adapter=adapter)


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------


def test_init():
    analyzer = _make_analyzer()
    assert analyzer.adapter is not None


# ---------------------------------------------------------------------------
# analyze() - full success path
# ---------------------------------------------------------------------------


def test_analyze_success():
    """Full analysis with valid PE headers, security dir, certificate, authenticode hash."""
    pkcs7_data = _build_pkcs7_data_with_sha256_rsa_cn_ts()
    # pxj commands are dispatched as p8 via adapter.read_bytes_list -> read_bytes -> cmd("p8 ...")
    cmd_map = {
        "p8 8": _bytes_to_hex(WIN_CERT_HEADER),
        "p8": _bytes_to_hex(pkcs7_data),
    }
    cmdj_map = {
        "ihj": {"machine": "i386"},
        "iHj": {"magic": "PE32"},
        "iDj": [
            {"name": "EXPORT", "vaddr": 100},
            {"name": "SECURITY", "vaddr": 0x1000, "paddr": 0x800, "size": 500},
        ],
        "ij": {"core": {"size": 10000}},
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map, cmd_map=cmd_map)
    result = analyzer.analyze()

    assert result["available"] is True
    assert result["has_signature"] is True
    assert result["signature_valid"] is True
    assert "authenticode_hash" in result
    assert len(result["certificates"]) >= 1


# ---------------------------------------------------------------------------
# analyze() - no required headers
# ---------------------------------------------------------------------------


def test_analyze_no_pe_header():
    """PE header missing -> available=False."""
    analyzer = _make_analyzer(cmdj_map={"ihj": None})
    result = analyzer.analyze()
    assert result["available"] is False


def test_analyze_no_optional_header():
    """Optional header missing -> available=False."""
    analyzer = _make_analyzer(cmdj_map={"ihj": {"machine": "i386"}, "iHj": None})
    result = analyzer.analyze()
    assert result["available"] is False


# ---------------------------------------------------------------------------
# analyze() - no signature
# ---------------------------------------------------------------------------


def test_analyze_no_security_directory():
    """No SECURITY data directory -> has_signature=False."""
    cmdj_map = {
        "ihj": {"machine": "i386"},
        "iHj": {"magic": "PE32"},
        "iDj": [{"name": "EXPORT", "vaddr": 100}],
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = analyzer.analyze()
    assert result["has_signature"] is False


def test_analyze_security_directory_zero_vaddr():
    """SECURITY directory with vaddr=0 -> has_signature=False."""
    cmdj_map = {
        "ihj": {"machine": "i386"},
        "iHj": {"magic": "PE32"},
        "iDj": [{"name": "SECURITY", "vaddr": 0, "paddr": 0, "size": 0}],
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = analyzer.analyze()
    assert result["has_signature"] is False


# ---------------------------------------------------------------------------
# analyze() - exception path
# ---------------------------------------------------------------------------


def test_analyze_exception():
    """Exception during analysis -> available=False, error set."""
    cmdj_map = {
        "ihj": Exception("Simulated r2 crash"),
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = analyzer.analyze()
    assert result["available"] is False
    assert "error" in result


# ---------------------------------------------------------------------------
# _has_required_headers
# ---------------------------------------------------------------------------


def test_has_required_headers_both_present():
    analyzer = _make_analyzer(
        cmdj_map={
            "ihj": {"machine": "i386"},
            "iHj": {"magic": "PE32"},
        }
    )
    assert analyzer._has_required_headers() is True


def test_has_required_headers_no_pe():
    analyzer = _make_analyzer(cmdj_map={"ihj": None})
    assert analyzer._has_required_headers() is False


def test_has_required_headers_no_optional():
    analyzer = _make_analyzer(cmdj_map={"ihj": {"machine": "i386"}, "iHj": None})
    assert analyzer._has_required_headers() is False


# ---------------------------------------------------------------------------
# _get_security_directory
# ---------------------------------------------------------------------------


def test_get_security_directory_found():
    cmdj_map = {
        "iDj": [
            {"name": "EXPORT", "vaddr": 100},
            {"name": "SECURITY", "vaddr": 200, "paddr": 150, "size": 300},
        ]
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = analyzer._get_security_directory()
    assert result is not None
    assert result["name"] == "SECURITY"


def test_get_security_directory_not_found():
    cmdj_map = {"iDj": [{"name": "EXPORT", "vaddr": 100}]}
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = analyzer._get_security_directory()
    assert result is None


def test_get_security_directory_none_response():
    analyzer = _make_analyzer(cmdj_map={"iDj": None})
    result = analyzer._get_security_directory()
    assert result is None


# ---------------------------------------------------------------------------
# _read_win_certificate
# ---------------------------------------------------------------------------


def test_read_win_certificate_valid_pkcs7():
    """Valid WIN_CERTIFICATE with PKCS#7 type."""
    pkcs7_data = _build_pkcs7_data_with_sha256_rsa_cn_ts()
    cmd_map = {
        "p8 8": _bytes_to_hex(WIN_CERT_HEADER),
        "p8": _bytes_to_hex(pkcs7_data),
    }
    analyzer = _make_analyzer(cmd_map=cmd_map)
    result_dict: dict[str, Any] = {"errors": []}
    security_dir = {"paddr": 1000, "size": 400}
    cert = analyzer._read_win_certificate(security_dir, result_dict)

    assert cert is not None
    assert "length" in cert
    assert cert["type"] == "PKCS#7"
    assert cert["format"] == "PKCS#7"


def test_read_win_certificate_invalid_offset():
    """Invalid security directory (zero offset) -> None."""
    analyzer = _make_analyzer()
    result_dict: dict[str, Any] = {"errors": []}
    cert = analyzer._read_win_certificate({"paddr": 0, "size": 0}, result_dict)
    assert cert is None
    assert len(result_dict["errors"]) > 0


def test_read_win_certificate_short_data():
    """Certificate data too short (< 8 bytes) -> None."""
    cmd_map = {"p8 8": _bytes_to_hex([0x01, 0x02])}
    analyzer = _make_analyzer(cmd_map=cmd_map)
    result_dict: dict[str, Any] = {"errors": []}
    cert = analyzer._read_win_certificate({"paddr": 1000, "size": 100}, result_dict)
    assert cert is None


def test_read_win_certificate_empty_data():
    """Empty certificate data -> None."""
    analyzer = _make_analyzer()
    result_dict: dict[str, Any] = {"errors": []}
    cert = analyzer._read_win_certificate({"paddr": 1000, "size": 100}, result_dict)
    assert cert is None


def test_read_win_certificate_non_pkcs7():
    """WIN_CERTIFICATE with X.509 type (not PKCS#7) -> cert_info without format."""
    # type=0x0001 (X.509)
    x509_header = [0x90, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00]
    cmd_map = {"p8 8": _bytes_to_hex(x509_header)}
    analyzer = _make_analyzer(cmd_map=cmd_map)
    result_dict: dict[str, Any] = {"errors": []}
    cert = analyzer._read_win_certificate({"paddr": 1000, "size": 400}, result_dict)
    assert cert is not None
    assert "X.509" in cert["type"]
    assert "format" not in cert


# ---------------------------------------------------------------------------
# _parse_win_cert_header
# ---------------------------------------------------------------------------


def test_parse_win_cert_header():
    analyzer = _make_analyzer()
    data = [0x90, 0x01, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00]
    length, revision, cert_type = analyzer._parse_win_cert_header(data)
    assert length == 0x190
    assert revision == 0x200
    assert cert_type == 0x2


def test_parse_win_cert_header_too_short():
    analyzer = _make_analyzer()
    try:
        analyzer._parse_win_cert_header([0x01, 0x02])
        pytest.fail("Should have raised ValueError")
    except ValueError as exc:
        assert "8 bytes" in str(exc)


# ---------------------------------------------------------------------------
# _get_cert_type_name
# ---------------------------------------------------------------------------


def test_get_cert_type_name_x509():
    analyzer = _make_analyzer()
    assert "X.509" in analyzer._get_cert_type_name(0x0001)


def test_get_cert_type_name_pkcs7():
    analyzer = _make_analyzer()
    assert "PKCS#7" in analyzer._get_cert_type_name(0x0002)


def test_get_cert_type_name_reserved():
    analyzer = _make_analyzer()
    assert "RESERVED" in analyzer._get_cert_type_name(0x0003)


def test_get_cert_type_name_ts_stack():
    analyzer = _make_analyzer()
    assert "TS_STACK_SIGNED" in analyzer._get_cert_type_name(0x0004)


def test_get_cert_type_name_unknown():
    analyzer = _make_analyzer()
    result = analyzer._get_cert_type_name(0x9999)
    assert "UNKNOWN" in result


# ---------------------------------------------------------------------------
# _parse_pkcs7
# ---------------------------------------------------------------------------


def test_parse_pkcs7_success():
    """Parse PKCS#7 with recognisable OIDs."""
    pkcs7_data = _build_pkcs7_data_with_sha256_rsa_cn_ts()
    cmd_map = {"p8": _bytes_to_hex(pkcs7_data)}
    analyzer = _make_analyzer(cmd_map=cmd_map)

    result = analyzer._parse_pkcs7(1000, 512)
    assert result is not None
    assert result["digest_algorithm"] == "SHA256"
    assert result["encryption_algorithm"] == "RSA"
    assert result["has_timestamp"] is True
    assert len(result["signer_info"]) >= 1


def test_parse_pkcs7_no_data():
    """p8 returns empty -> None."""
    analyzer = _make_analyzer()
    result = analyzer._parse_pkcs7(1000, 512)
    assert result is None


def test_parse_pkcs7_invalid_size():
    """size <= 0 -> None."""
    analyzer = _make_analyzer()
    result = analyzer._parse_pkcs7(1000, 0)
    assert result is None


def test_parse_pkcs7_invalid_offset():
    """offset < 0 -> None."""
    analyzer = _make_analyzer()
    result = analyzer._parse_pkcs7(-1, 512)
    assert result is None


# ---------------------------------------------------------------------------
# _detect_digest_algorithm
# ---------------------------------------------------------------------------


def test_detect_digest_algorithm_sha256():
    analyzer = _make_analyzer()
    data = [0] * 5 + SHA256_OID + [0] * 5
    assert analyzer._detect_digest_algorithm(data) == "SHA256"


def test_detect_digest_algorithm_sha1():
    analyzer = _make_analyzer()
    data = [0] * 5 + SHA1_OID + [0] * 5
    assert analyzer._detect_digest_algorithm(data) == "SHA1"


def test_detect_digest_algorithm_unknown():
    analyzer = _make_analyzer()
    data = [0] * 50
    assert analyzer._detect_digest_algorithm(data) is None


# ---------------------------------------------------------------------------
# _detect_encryption_algorithm
# ---------------------------------------------------------------------------


def test_detect_encryption_algorithm_rsa():
    analyzer = _make_analyzer()
    data = [0] * 5 + RSA_OID + [0] * 5
    assert analyzer._detect_encryption_algorithm(data) == "RSA"


def test_detect_encryption_algorithm_unknown():
    analyzer = _make_analyzer()
    data = [0] * 50
    assert analyzer._detect_encryption_algorithm(data) is None


# ---------------------------------------------------------------------------
# _extract_common_names
# ---------------------------------------------------------------------------


def test_extract_common_names_found():
    analyzer = _make_analyzer()
    data = [0] * 10
    data.extend(CN_OID)
    data.append(0)  # padding
    data.append(4)  # length = 4
    data.extend([ord(c) for c in "Test"])
    data.extend([0] * 20)

    result = analyzer._extract_common_names(data, 5000)
    assert len(result) >= 1
    assert result[0]["common_name"] == "Test"


def test_extract_common_names_none():
    analyzer = _make_analyzer()
    data = [0] * 50
    result = analyzer._extract_common_names(data, 5000)
    assert result == []


def test_extract_common_names_multiple():
    analyzer = _make_analyzer()
    data: list[int] = []
    for name in ["AAA", "BBB", "CCC"]:
        data.extend([0] * 5)
        data.extend(CN_OID)
        data.append(0)
        data.append(3)
        data.extend([ord(c) for c in name])
    data.extend([0] * 20)

    result = analyzer._extract_common_names(data, 1000)
    assert len(result) == 3


# ---------------------------------------------------------------------------
# _extract_cn_entry
# ---------------------------------------------------------------------------


def test_extract_cn_entry_valid():
    analyzer = _make_analyzer()
    data = [0] * 20
    pos = 5
    data[pos : pos + 3] = CN_OID
    data[pos + 3] = 0  # padding
    data[pos + 4] = 4  # length
    data[pos + 5 : pos + 9] = [ord(c) for c in "ABCD"]

    result = analyzer._extract_cn_entry(data, 1000, pos)
    assert result is not None
    assert result["common_name"] == "ABCD"


def test_extract_cn_entry_pos_too_close_to_end():
    analyzer = _make_analyzer()
    data = [0] * 10
    result = analyzer._extract_cn_entry(data, 1000, 5)
    assert result is None


def test_extract_cn_entry_zero_length():
    analyzer = _make_analyzer()
    data = [0] * 30
    pos = 5
    data[pos : pos + 3] = CN_OID
    data[pos + 3] = 0
    data[pos + 4] = 0  # length=0

    result = analyzer._extract_cn_entry(data, 1000, pos)
    assert result is None


def test_extract_cn_entry_length_too_large():
    analyzer = _make_analyzer()
    data = [0] * 30
    pos = 5
    data[pos : pos + 3] = CN_OID
    data[pos + 3] = 0
    data[pos + 4] = 120  # length >= 100

    result = analyzer._extract_cn_entry(data, 1000, pos)
    assert result is None


# ---------------------------------------------------------------------------
# _has_timestamp
# ---------------------------------------------------------------------------


def test_has_timestamp_present():
    analyzer = _make_analyzer()
    data = [0] * 5 + TIMESTAMP_OID + [0] * 5
    assert analyzer._has_timestamp(data) is True


def test_has_timestamp_absent():
    analyzer = _make_analyzer()
    data = [0] * 50
    assert analyzer._has_timestamp(data) is False


# ---------------------------------------------------------------------------
# _find_pattern
# ---------------------------------------------------------------------------


def test_find_pattern_found():
    analyzer = _make_analyzer()
    assert analyzer._find_pattern([0, 1, 2, 3, 4, 5], [2, 3, 4]) is True


def test_find_pattern_not_found():
    analyzer = _make_analyzer()
    assert analyzer._find_pattern([0, 1, 2, 3], [9, 10]) is False


def test_find_pattern_at_start():
    analyzer = _make_analyzer()
    assert analyzer._find_pattern([1, 2, 3, 4], [1, 2]) is True


def test_find_pattern_at_end():
    analyzer = _make_analyzer()
    assert analyzer._find_pattern([0, 0, 1, 2], [1, 2]) is True


def test_find_pattern_empty_data():
    analyzer = _make_analyzer()
    assert analyzer._find_pattern([], [1, 2]) is False


# ---------------------------------------------------------------------------
# _find_all_patterns
# ---------------------------------------------------------------------------


def test_find_all_patterns_multiple():
    analyzer = _make_analyzer()
    data = [1, 2, 3, 1, 2, 3, 1, 2, 3]
    result = analyzer._find_all_patterns(data, [1, 2, 3])
    assert len(result) == 3
    assert result == [0, 3, 6]


def test_find_all_patterns_none():
    analyzer = _make_analyzer()
    result = analyzer._find_all_patterns([0, 0, 0], [9, 9])
    assert result == []


# ---------------------------------------------------------------------------
# _compute_authenticode_hash
# ---------------------------------------------------------------------------


def test_compute_authenticode_hash_success():
    cmdj_map = {
        "ij": {"core": {"size": 10000}},
        "ihj": {"machine": "i386"},
        "iHj": {"magic": "PE32"},
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = analyzer._compute_authenticode_hash()
    assert result is not None
    assert result["algorithm"] == "SHA256"
    assert result["file_size"] == 10000


def test_compute_authenticode_hash_no_file_info():
    analyzer = _make_analyzer(cmdj_map={"ij": None})
    result = analyzer._compute_authenticode_hash()
    assert result is None


def test_compute_authenticode_hash_zero_size():
    cmdj_map = {"ij": {"core": {"size": 0}}}
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = analyzer._compute_authenticode_hash()
    assert result is None


def test_compute_authenticode_hash_no_pe_header():
    cmdj_map = {"ij": {"core": {"size": 10000}}, "ihj": None}
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = analyzer._compute_authenticode_hash()
    assert result is None


def test_compute_authenticode_hash_no_optional_header():
    cmdj_map = {
        "ij": {"core": {"size": 10000}},
        "ihj": {"machine": "i386"},
        "iHj": None,
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = analyzer._compute_authenticode_hash()
    assert result is None


# ---------------------------------------------------------------------------
# _verify_signature_integrity
# ---------------------------------------------------------------------------


def test_verify_signature_integrity_valid():
    analyzer = _make_analyzer()
    info = {
        "has_signature": True,
        "certificates": [{"test": "cert"}],
        "errors": [],
        "security_directory": {"size": 100},
    }
    assert analyzer._verify_signature_integrity(info) is True


def test_verify_signature_integrity_no_signature():
    analyzer = _make_analyzer()
    info = {
        "has_signature": False,
        "certificates": [],
        "errors": [],
        "security_directory": None,
    }
    assert analyzer._verify_signature_integrity(info) is False


def test_verify_signature_integrity_no_certs():
    analyzer = _make_analyzer()
    info = {
        "has_signature": True,
        "certificates": [],
        "errors": [],
        "security_directory": {"size": 100},
    }
    assert analyzer._verify_signature_integrity(info) is False


def test_verify_signature_integrity_with_errors():
    analyzer = _make_analyzer()
    info = {
        "has_signature": True,
        "certificates": [{"test": "cert"}],
        "errors": ["Error 1"],
        "security_directory": {"size": 100},
    }
    assert analyzer._verify_signature_integrity(info) is False


def test_verify_signature_integrity_no_security_dir():
    analyzer = _make_analyzer()
    info = {
        "has_signature": True,
        "certificates": [{"test": "cert"}],
        "errors": [],
        "security_directory": None,
    }
    assert analyzer._verify_signature_integrity(info) is False


def test_verify_signature_integrity_zero_size_dir():
    analyzer = _make_analyzer()
    info = {
        "has_signature": True,
        "certificates": [{"test": "cert"}],
        "errors": [],
        "security_directory": {"size": 0},
    }
    assert analyzer._verify_signature_integrity(info) is False
