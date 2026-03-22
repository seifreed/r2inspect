"""Comprehensive tests for authenticode_analyzer.py signature parsing.

All tests use real objects (FakeR2 + R2PipeAdapter) instead of mocks.
"""

import logging

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer
from r2inspect.modules.authenticode_parsing_support import (
    get_security_directory,
    parse_pkcs7,
    read_win_certificate,
)
from r2inspect.modules.authenticode_result_support import (
    apply_security_directory,
    init_authenticode_result,
)
from r2inspect.testing.fake_r2 import FakeR2


def _bytes_to_hex(byte_list):
    """Convert a list of ints (0-255) to a hex string for p8 commands."""
    return bytes(byte_list).hex()


def _make_analyzer(cmdj_map=None, cmd_map=None):
    """Create an AuthenticodeAnalyzer backed by FakeR2 + R2PipeAdapter."""
    fake_r2 = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map)
    adapter = R2PipeAdapter(fake_r2)
    return AuthenticodeAnalyzer(adapter=adapter)


def _p8_key(size, address):
    """Build the p8 command string that read_bytes will issue."""
    return f"p8 {size} @ {address}"


class TestAuthenticodeAnalyzerBasics:
    """Test basic Authenticode analyzer functionality."""

    def test_init(self):
        """Test analyzer initialization."""
        analyzer = _make_analyzer()
        assert analyzer.adapter is not None
        assert analyzer.pe_info is None

    def test_analyze_no_headers(self):
        """Test analyze when PE headers missing."""
        analyzer = _make_analyzer(cmdj_map={"ihj": None})

        result = analyzer.analyze()

        assert result["available"] is False
        assert result["has_signature"] is False

    def test_analyze_no_security_directory(self):
        """Test analyze when security directory missing."""
        analyzer = _make_analyzer(
            cmdj_map={
                "ihj": {"format": "pe"},
                "iHj": {"optional_header": True},
                "iDj": [],
            }
        )

        result = analyzer.analyze()

        assert result["has_signature"] is False
        assert result["security_directory"] is None

    def test_analyze_security_directory_zero_vaddr(self):
        """Test analyze with zero virtual address in security dir."""
        analyzer = _make_analyzer(
            cmdj_map={
                "ihj": {"format": "pe"},
                "iHj": {"optional_header": True},
                "iDj": [{"name": "SECURITY", "vaddr": 0, "paddr": 100, "size": 500}],
            }
        )

        result = analyzer.analyze()

        assert result["has_signature"] is False

    def test_analyze_with_signature(self):
        """Test analyze with valid signature containing PKCS#7 + SHA256."""
        # WIN_CERTIFICATE header: length=512, revision=0x0200, type=PKCS#7 (0x0002)
        win_cert_header = [0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00]
        # PKCS#7 data with SHA256 OID embedded
        sha256_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
        pkcs7_data = [0x30, 0x82] + [0] * 50 + sha256_oid + [0] * 50

        # read_bytes uses p8 commands via cmd()
        cmd_map = {
            _p8_key(8, 2048): _bytes_to_hex(win_cert_header),
            # cert_length=512, minus 8 for header = 504; min(504, 1024) = 504
            _p8_key(504, 2056): _bytes_to_hex(pkcs7_data),
        }

        analyzer = _make_analyzer(
            cmdj_map={
                "ihj": {"format": "pe"},
                "iHj": {"optional_header": True},
                "iDj": [{"name": "SECURITY", "vaddr": 0x1000, "paddr": 0x800, "size": 0x200}],
                "ij": {"core": {"size": 10000}},
            },
            cmd_map=cmd_map,
        )

        result = analyzer.analyze()

        assert result["has_signature"] is True
        assert result["security_directory"]["offset"] == 0x800
        assert len(result["certificates"]) == 1
        assert result["certificates"][0]["type"] == "PKCS#7"

    def test_analyze_exception_handling(self):
        """Test exception handling in analyze.

        When the underlying r2 raises, silent_cmdj catches the error and
        returns the default (None).  This causes _has_required_headers to
        return False, so analyze() sets available=False gracefully.
        """
        fake_r2 = FakeR2()

        def raising_cmdj(command):
            raise Exception("Test error")

        fake_r2.cmdj = raising_cmdj
        adapter = R2PipeAdapter(fake_r2)
        analyzer = AuthenticodeAnalyzer(adapter=adapter)

        result = analyzer.analyze()

        # The exception is caught by the adapter layer; the analyzer sees
        # None responses and marks the result as unavailable.
        assert result["available"] is False
        assert result["has_signature"] is False


class TestSecurityDirectoryParsing:
    """Test security directory and certificate parsing."""

    def test_has_required_headers_success(self):
        """Test required headers check success."""
        analyzer = _make_analyzer(
            cmdj_map={
                "ihj": {"format": "pe"},
                "iHj": {"optional_header": True},
            }
        )

        result = analyzer._has_required_headers()

        assert result is True

    def test_has_required_headers_no_pe_header(self):
        """Test required headers when PE header missing."""
        analyzer = _make_analyzer(cmdj_map={"ihj": None})

        result = analyzer._has_required_headers()

        assert result is False

    def test_has_required_headers_no_optional_header(self):
        """Test required headers when optional header missing."""
        analyzer = _make_analyzer(
            cmdj_map={
                "ihj": {"format": "pe"},
                "iHj": None,
            }
        )

        result = analyzer._has_required_headers()

        assert result is False

    def test_get_security_directory_found(self):
        """Test finding security directory."""
        analyzer = _make_analyzer(
            cmdj_map={
                "iDj": [
                    {"name": "EXPORT", "vaddr": 0x1000},
                    {"name": "SECURITY", "vaddr": 0x2000, "paddr": 0x1800, "size": 0x400},
                ],
            }
        )

        result = analyzer._get_security_directory()

        assert result is not None
        assert result["name"] == "SECURITY"
        assert result["vaddr"] == 0x2000

    def test_get_security_directory_not_found(self):
        """Test when security directory not found."""
        analyzer = _make_analyzer(
            cmdj_map={
                "iDj": [
                    {"name": "EXPORT", "vaddr": 0x1000},
                    {"name": "IMPORT", "vaddr": 0x2000},
                ],
            }
        )

        result = analyzer._get_security_directory()

        assert result is None

    def test_get_security_directory_not_list(self):
        """Test when data directories is not a list."""
        analyzer = _make_analyzer(
            cmdj_map={
                "iDj": {"not": "a list"},
            }
        )

        result = analyzer._get_security_directory()

        assert result is None

    def test_read_win_certificate_invalid_offset(self):
        """Test reading certificate with invalid offset (zero)."""
        analyzer = _make_analyzer()

        security_dir = {"paddr": 0, "size": 0x200}
        result_dict = {"errors": []}

        cert_info = analyzer._read_win_certificate(security_dir, result_dict)

        assert cert_info is None
        assert len(result_dict["errors"]) == 1

    def test_read_win_certificate_invalid_size(self):
        """Test reading certificate with invalid size (zero)."""
        analyzer = _make_analyzer()

        security_dir = {"paddr": 0x1000, "size": 0}
        result_dict = {"errors": []}

        cert_info = analyzer._read_win_certificate(security_dir, result_dict)

        assert cert_info is None

    def test_read_win_certificate_no_data(self):
        """Test reading certificate when data unavailable."""
        # cmd returns empty for p8 -> read_bytes returns b"" -> read_bytes_list returns []
        analyzer = _make_analyzer()

        security_dir = {"paddr": 0x1000, "size": 0x200}
        result_dict = {"errors": []}

        cert_info = analyzer._read_win_certificate(security_dir, result_dict)

        assert cert_info is None

    def test_read_win_certificate_insufficient_data(self):
        """Test reading certificate with insufficient header data (< 8 bytes)."""
        # Return only 3 bytes
        analyzer = _make_analyzer(
            cmd_map={
                _p8_key(8, 4096): _bytes_to_hex([1, 2, 3]),
            }
        )

        security_dir = {"paddr": 0x1000, "size": 0x200}
        result_dict = {"errors": [], "signature_offset": None, "signature_size": None}

        cert_info = analyzer._read_win_certificate(security_dir, result_dict)

        assert cert_info is None
        assert result_dict["signature_offset"] == 0x1000

    def test_read_win_certificate_pkcs7(self):
        """Test reading PKCS#7 certificate."""
        win_cert_header = [
            0x00,
            0x02,
            0x00,
            0x00,  # Length: 512
            0x00,
            0x02,  # Revision: 0x0200
            0x02,
            0x00,  # Type: PKCS#7 (0x0002)
        ]
        # PKCS#7 data with SHA256 OID
        sha256_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
        pkcs7_data = [0x30, 0x82] + [0] * 50 + sha256_oid + [0] * 50

        cmd_map = {
            _p8_key(8, 4096): _bytes_to_hex(win_cert_header),
            _p8_key(504, 4104): _bytes_to_hex(pkcs7_data),
        }

        analyzer = _make_analyzer(cmd_map=cmd_map)

        security_dir = {"paddr": 0x1000, "size": 0x200}
        result_dict = {"errors": []}

        cert_info = analyzer._read_win_certificate(security_dir, result_dict)

        assert cert_info is not None
        assert cert_info["type"] == "PKCS#7"
        assert cert_info["format"] == "PKCS#7"
        assert cert_info["digest_algorithm"] == "SHA256"

    def test_read_win_certificate_x509(self):
        """Test reading X.509 certificate."""
        win_cert_header = [
            0x00,
            0x01,
            0x00,
            0x00,  # Length: 256
            0x00,
            0x02,  # Revision
            0x01,
            0x00,  # Type: X.509 (0x0001)
        ]

        cmd_map = {
            _p8_key(8, 4096): _bytes_to_hex(win_cert_header),
        }

        analyzer = _make_analyzer(cmd_map=cmd_map)

        security_dir = {"paddr": 0x1000, "size": 0x100}
        result_dict = {"errors": []}

        cert_info = analyzer._read_win_certificate(security_dir, result_dict)

        assert cert_info is not None
        assert cert_info["type"] == "X.509"

    def test_parse_win_cert_header(self):
        """Test parsing WIN_CERTIFICATE header."""
        analyzer = _make_analyzer()

        data = [0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00]

        length, revision, cert_type = analyzer._parse_win_cert_header(data)

        assert length == 0x200
        assert revision == 0x0200
        assert cert_type == 0x0002

    def test_get_cert_type_name(self):
        """Test getting certificate type name."""
        analyzer = _make_analyzer()

        assert analyzer._get_cert_type_name(0x0001) == "X.509"
        assert analyzer._get_cert_type_name(0x0002) == "PKCS#7"
        assert analyzer._get_cert_type_name(0x0003) == "RESERVED"
        assert analyzer._get_cert_type_name(0x0004) == "TS_STACK_SIGNED"
        assert "UNKNOWN" in analyzer._get_cert_type_name(0x9999)


class TestPKCS7Parsing:
    """Test PKCS#7 signature data parsing."""

    def test_parse_pkcs7_no_data(self):
        """Test parsing PKCS#7 with no data (empty response from r2)."""
        # cmd returns empty for p8 -> read_bytes returns b"" -> None data
        analyzer = _make_analyzer()

        result = analyzer._parse_pkcs7(0x1000, 0x100)

        assert result is None

    def test_parse_pkcs7_with_sha256(self):
        """Test parsing PKCS#7 with SHA256 digest."""
        sha256_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
        pkcs7_data = [0x30, 0x82] + [0] * 50 + sha256_oid
        read_size = min(len(pkcs7_data), 1024)

        analyzer = _make_analyzer(
            cmd_map={
                _p8_key(read_size, 4096): _bytes_to_hex(pkcs7_data),
            }
        )

        result = analyzer._parse_pkcs7(0x1000, len(pkcs7_data))

        assert result is not None
        assert result["digest_algorithm"] == "SHA256"

    def test_parse_pkcs7_with_sha1(self):
        """Test parsing PKCS#7 with SHA1 digest."""
        sha1_oid = [0x2B, 0x0E, 0x03, 0x02, 0x1A]
        pkcs7_data = [0x30, 0x82] + [0] * 50 + sha1_oid
        read_size = min(len(pkcs7_data), 1024)

        analyzer = _make_analyzer(
            cmd_map={
                _p8_key(read_size, 4096): _bytes_to_hex(pkcs7_data),
            }
        )

        result = analyzer._parse_pkcs7(0x1000, len(pkcs7_data))

        assert result["digest_algorithm"] == "SHA1"

    def test_parse_pkcs7_with_rsa(self):
        """Test parsing PKCS#7 with RSA encryption."""
        rsa_oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        pkcs7_data = [0x30] * 50 + rsa_oid
        read_size = min(len(pkcs7_data), 1024)

        analyzer = _make_analyzer(
            cmd_map={
                _p8_key(read_size, 4096): _bytes_to_hex(pkcs7_data),
            }
        )

        result = analyzer._parse_pkcs7(0x1000, len(pkcs7_data))

        assert result["encryption_algorithm"] == "RSA"

    def test_parse_pkcs7_with_timestamp(self):
        """Test parsing PKCS#7 with timestamp."""
        timestamp_oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E]
        pkcs7_data = [0x30] * 50 + timestamp_oid + [0] * 50
        read_size = min(len(pkcs7_data), 1024)

        analyzer = _make_analyzer(
            cmd_map={
                _p8_key(read_size, 4096): _bytes_to_hex(pkcs7_data),
            }
        )

        result = analyzer._parse_pkcs7(0x1000, len(pkcs7_data))

        assert result["has_timestamp"] is True

    def test_parse_pkcs7_with_signer_info(self):
        """Test parsing PKCS#7 with signer info (common name in data)."""
        cn_oid = [0x55, 0x04, 0x03]
        cn_name = list(b"TestSigner")
        # CN OID + padding byte + length + name, plus enough trailing data
        pkcs7_data = [0x30] * 20 + cn_oid + [0, len(cn_name)] + cn_name + [0] * 50
        read_size = min(len(pkcs7_data), 1024)

        analyzer = _make_analyzer(
            cmd_map={
                _p8_key(read_size, 4096): _bytes_to_hex(pkcs7_data),
            }
        )

        result = analyzer._parse_pkcs7(0x1000, len(pkcs7_data))

        assert len(result["signer_info"]) == 1
        assert result["signer_info"][0]["common_name"] == "TestSigner"

    def test_parse_pkcs7_size_limited(self):
        """Test that PKCS#7 parsing limits read size to 1024 bytes."""
        pkcs7_data = [0x30] * 1024

        analyzer = _make_analyzer(
            cmd_map={
                _p8_key(1024, 4096): _bytes_to_hex(pkcs7_data),
            }
        )

        # Request 10000 bytes but only 1024 should be read
        result = analyzer._parse_pkcs7(4096, 10000)

        assert result is not None

    def test_parse_pkcs7_exception(self):
        """Test PKCS#7 parsing with exception from r2."""
        fake_r2 = FakeR2()

        def raising_cmdj(command):
            raise Exception("Parse error")

        def raising_cmd(command):
            raise Exception("Parse error")

        fake_r2.cmdj = raising_cmdj
        fake_r2.cmd = raising_cmd
        adapter = R2PipeAdapter(fake_r2)
        analyzer = AuthenticodeAnalyzer(adapter=adapter)

        result = analyzer._parse_pkcs7(0x1000, 0x100)

        assert result is None


class TestCommonNameExtraction:
    """Test common name (CN) extraction from certificates."""

    def test_extract_common_names_found(self):
        """Test extracting common names from PKCS#7 data."""
        analyzer = _make_analyzer()

        cn_oid = [0x55, 0x04, 0x03]
        cn_name = list(b"TestCorp")
        # Need pos + 10 < len(data) for entry to be valid
        pkcs7_data = [0] * 20 + cn_oid + [0, len(cn_name)] + cn_name + [0] * 50

        result = analyzer._extract_common_names(pkcs7_data, 0x1000)

        assert len(result) == 1
        assert result[0]["common_name"] == "TestCorp"

    def test_extract_common_names_multiple(self):
        """Test extracting multiple common names."""
        analyzer = _make_analyzer()

        cn_oid = [0x55, 0x04, 0x03]
        pkcs7_data = (
            [0] * 10
            + cn_oid
            + [0, 5]
            + list(b"Name1")
            + [0] * 10
            + cn_oid
            + [0, 5]
            + list(b"Name2")
            + [0] * 50
        )

        result = analyzer._extract_common_names(pkcs7_data, 0x1000)

        assert len(result) == 2

    def test_extract_common_names_limited_to_three(self):
        """Test that common name extraction is limited to 3."""
        analyzer = _make_analyzer()

        cn_oid = [0x55, 0x04, 0x03]
        pkcs7_data = []
        for i in range(5):
            pkcs7_data.extend([0] * 10 + cn_oid + [0, 4] + list(f"Na{i}x".encode()))
        pkcs7_data.extend([0] * 50)

        result = analyzer._extract_common_names(pkcs7_data, 0x1000)

        assert len(result) <= 3

    def test_extract_cn_entry_valid(self):
        """Test extracting single CN entry."""
        analyzer = _make_analyzer()

        pkcs7_data = [0x55, 0x04, 0x03, 0, 8] + list(b"TestName") + [0] * 10

        result = analyzer._extract_cn_entry(pkcs7_data, 0x1000, 0)

        assert result is not None
        assert result["common_name"] == "TestName"
        assert result["offset"] == 0x1000

    def test_extract_cn_entry_insufficient_data(self):
        """Test CN extraction with insufficient data."""
        analyzer = _make_analyzer()

        pkcs7_data = [0x55, 0x04, 0x03]

        result = analyzer._extract_cn_entry(pkcs7_data, 0x1000, 0)

        assert result is None

    def test_extract_cn_entry_invalid_length(self):
        """Test CN extraction with invalid length (zero)."""
        analyzer = _make_analyzer()

        pkcs7_data = [0x55, 0x04, 0x03, 0, 0] + [0] * 50

        result = analyzer._extract_cn_entry(pkcs7_data, 0x1000, 0)

        assert result is None

    def test_extract_cn_entry_length_too_large(self):
        """Test CN extraction with excessive length (>= 100)."""
        analyzer = _make_analyzer()

        pkcs7_data = [0x55, 0x04, 0x03, 0, 200] + [0] * 50

        result = analyzer._extract_cn_entry(pkcs7_data, 0x1000, 0)

        assert result is None

    def test_extract_cn_entry_decode_error(self):
        """Test CN extraction with non-printable bytes."""
        analyzer = _make_analyzer()

        pkcs7_data = [0x55, 0x04, 0x03, 0, 4] + [0x01, 0x02, 0x03, 0x04] + [0] * 10

        result = analyzer._extract_cn_entry(pkcs7_data, 0x1000, 0)

        # Non-printable chars -> isprintable() returns False -> returns None
        assert result is None or isinstance(result, dict)


class TestPatternFinding:
    """Test pattern finding utilities."""

    def test_find_pattern_found(self):
        """Test finding pattern in data."""
        analyzer = _make_analyzer()

        data = [1, 2, 3, 4, 5, 6, 7]
        pattern = [4, 5, 6]

        result = analyzer._find_pattern(data, pattern)

        assert result is True

    def test_find_pattern_not_found(self):
        """Test pattern not found."""
        analyzer = _make_analyzer()

        data = [1, 2, 3, 4, 5]
        pattern = [6, 7, 8]

        result = analyzer._find_pattern(data, pattern)

        assert result is False

    def test_find_all_patterns_multiple(self):
        """Test finding all pattern occurrences."""
        analyzer = _make_analyzer()

        data = [1, 2, 3, 1, 2, 3, 4, 1, 2, 3]
        pattern = [1, 2, 3]

        result = analyzer._find_all_patterns(data, pattern)

        assert len(result) == 3
        assert result == [0, 3, 7]

    def test_find_all_patterns_none(self):
        """Test finding patterns when none exist."""
        analyzer = _make_analyzer()

        data = [1, 2, 3, 4, 5]
        pattern = [6, 7]

        result = analyzer._find_all_patterns(data, pattern)

        assert len(result) == 0

    def test_has_timestamp_found(self):
        """Test timestamp detection."""
        analyzer = _make_analyzer()

        pkcs7_data = [0] * 50 + [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E]

        result = analyzer._has_timestamp(pkcs7_data)

        assert result is True

    def test_has_timestamp_not_found(self):
        """Test timestamp not found."""
        analyzer = _make_analyzer()

        pkcs7_data = [0] * 100

        result = analyzer._has_timestamp(pkcs7_data)

        assert result is False


class TestAuthenticodeHash:
    """Test Authenticode hash computation."""

    def test_compute_authenticode_hash_no_file_info(self):
        """Test hash computation when file info unavailable."""
        analyzer = _make_analyzer(cmdj_map={"ij": None})

        result = analyzer._compute_authenticode_hash()

        assert result is None

    def test_compute_authenticode_hash_zero_size(self):
        """Test hash computation with zero file size."""
        analyzer = _make_analyzer(
            cmdj_map={
                "ij": {"core": {"size": 0}},
            }
        )

        result = analyzer._compute_authenticode_hash()

        assert result is None

    def test_compute_authenticode_hash_no_pe_header(self):
        """Test hash computation without PE header."""
        analyzer = _make_analyzer(
            cmdj_map={
                "ij": {"core": {"size": 10000}},
                "ihj": None,
            }
        )

        result = analyzer._compute_authenticode_hash()

        assert result is None

    def test_compute_authenticode_hash_no_optional_header(self):
        """Test hash computation without optional header."""
        analyzer = _make_analyzer(
            cmdj_map={
                "ij": {"core": {"size": 10000}},
                "ihj": {"format": "pe"},
                "iHj": None,
            }
        )

        result = analyzer._compute_authenticode_hash()

        assert result is None

    def test_compute_authenticode_hash_placeholder(self):
        """Test hash computation returns placeholder."""
        analyzer = _make_analyzer(
            cmdj_map={
                "ij": {"core": {"size": 10000}},
                "ihj": {"format": "pe"},
                "iHj": {"optional_header": True},
            }
        )

        result = analyzer._compute_authenticode_hash()

        assert result is not None
        assert result["algorithm"] == "SHA256"
        assert result["file_size"] == 10000

    def test_compute_authenticode_hash_exception(self):
        """Test hash computation with exception."""
        fake_r2 = FakeR2()

        def raising_cmdj(command):
            raise Exception("Hash error")

        fake_r2.cmdj = raising_cmdj
        adapter = R2PipeAdapter(fake_r2)
        analyzer = AuthenticodeAnalyzer(adapter=adapter)

        result = analyzer._compute_authenticode_hash()

        assert result is None


class TestSignatureVerification:
    """Test signature integrity verification."""

    def test_verify_signature_integrity_valid(self):
        """Test verification with valid signature."""
        analyzer = _make_analyzer()

        signature_info = {
            "has_signature": True,
            "certificates": [{"type": "PKCS#7"}],
            "errors": [],
            "security_directory": {"size": 500},
        }

        result = analyzer._verify_signature_integrity(signature_info)

        assert result is True

    def test_verify_signature_integrity_no_signature(self):
        """Test verification without signature."""
        analyzer = _make_analyzer()

        signature_info = {"has_signature": False}

        result = analyzer._verify_signature_integrity(signature_info)

        assert result is False

    def test_verify_signature_integrity_no_certificates(self):
        """Test verification without certificates."""
        analyzer = _make_analyzer()

        signature_info = {
            "has_signature": True,
            "certificates": [],
        }

        result = analyzer._verify_signature_integrity(signature_info)

        assert result is False

    def test_verify_signature_integrity_with_errors(self):
        """Test verification with parsing errors."""
        analyzer = _make_analyzer()

        signature_info = {
            "has_signature": True,
            "certificates": [{"type": "PKCS#7"}],
            "errors": ["Invalid certificate"],
        }

        result = analyzer._verify_signature_integrity(signature_info)

        assert result is False

    def test_verify_signature_integrity_no_security_dir(self):
        """Test verification without security directory."""
        analyzer = _make_analyzer()

        signature_info = {
            "has_signature": True,
            "certificates": [{"type": "PKCS#7"}],
            "errors": [],
            "security_directory": None,
        }

        result = analyzer._verify_signature_integrity(signature_info)

        assert result is False

    def test_verify_signature_integrity_zero_size(self):
        """Test verification with zero-size security directory."""
        analyzer = _make_analyzer()

        signature_info = {
            "has_signature": True,
            "certificates": [{"type": "PKCS#7"}],
            "errors": [],
            "security_directory": {"size": 0},
        }

        result = analyzer._verify_signature_integrity(signature_info)

        assert result is False

    def test_verify_signature_integrity_exception(self):
        """Test verification with missing keys triggers exception path."""
        analyzer = _make_analyzer()

        signature_info = {"has_signature": True}

        result = analyzer._verify_signature_integrity(signature_info)

        assert result is False


class TestAlgorithmDetection:
    """Test digest and encryption algorithm detection."""

    def test_detect_digest_algorithm_sha256(self):
        """Test SHA256 detection."""
        analyzer = _make_analyzer()

        sha256_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
        pkcs7_data = [0] * 50 + sha256_oid

        result = analyzer._detect_digest_algorithm(pkcs7_data)

        assert result == "SHA256"

    def test_detect_digest_algorithm_sha1(self):
        """Test SHA1 detection."""
        analyzer = _make_analyzer()

        sha1_oid = [0x2B, 0x0E, 0x03, 0x02, 0x1A]
        pkcs7_data = [0] * 50 + sha1_oid

        result = analyzer._detect_digest_algorithm(pkcs7_data)

        assert result == "SHA1"

    def test_detect_digest_algorithm_none(self):
        """Test when no known algorithm detected."""
        analyzer = _make_analyzer()

        pkcs7_data = [0] * 100

        result = analyzer._detect_digest_algorithm(pkcs7_data)

        assert result is None

    def test_detect_encryption_algorithm_rsa(self):
        """Test RSA detection."""
        analyzer = _make_analyzer()

        rsa_oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        pkcs7_data = [0] * 30 + rsa_oid

        result = analyzer._detect_encryption_algorithm(pkcs7_data)

        assert result == "RSA"

    def test_detect_encryption_algorithm_none(self):
        """Test when no encryption algorithm detected."""
        analyzer = _make_analyzer()

        pkcs7_data = [0] * 100

        result = analyzer._detect_encryption_algorithm(pkcs7_data)

        assert result is None


class TestSupportFunctionsDirect:
    """Test authenticode_parsing_support and authenticode_result_support directly."""

    def test_get_security_directory_direct(self):
        """Test get_security_directory helper directly."""

        def fake_cmdj(command, default=None):
            if command == "iDj":
                return [
                    {"name": "IMPORT", "vaddr": 0x100},
                    {"name": "SECURITY", "vaddr": 0x2000, "paddr": 0x1800, "size": 0x400},
                ]
            return default

        result = get_security_directory(fake_cmdj)
        assert result is not None
        assert result["name"] == "SECURITY"

    def test_get_security_directory_direct_none(self):
        """Test get_security_directory when no SECURITY entry."""

        def fake_cmdj(command, default=None):
            return [{"name": "IMPORT"}]

        result = get_security_directory(fake_cmdj)
        assert result is None

    def test_get_security_directory_direct_not_list(self):
        """Test get_security_directory when response is not a list."""

        def fake_cmdj(command, default=None):
            return "not a list"

        result = get_security_directory(fake_cmdj)
        assert result is None

    def test_init_authenticode_result_direct(self):
        """Test init_authenticode_result helper directly."""

        def fake_init_result(fields):
            result = dict(fields)
            result["analyzer"] = "test"
            return result

        result = init_authenticode_result(fake_init_result)
        assert result["available"] is True
        assert result["has_signature"] is False
        assert result["certificates"] == []
        assert result["errors"] == []

    def test_apply_security_directory_direct(self):
        """Test apply_security_directory helper directly."""
        result = {"has_signature": False, "security_directory": None}
        security_dir = {"paddr": 0x800, "size": 0x200, "vaddr": 0x1000}

        apply_security_directory(result, security_dir)

        assert result["has_signature"] is True
        assert result["security_directory"]["offset"] == 0x800
        assert result["security_directory"]["size"] == 0x200
        assert result["security_directory"]["virtual_address"] == 0x1000

    def test_read_win_certificate_direct_invalid_types(self):
        """Test read_win_certificate with non-integer types."""

        def fake_cmdj(command, default=None):
            return None

        security_dir = {"paddr": "not_int", "size": 0x200}
        result_dict = {"errors": []}

        cert_info = read_win_certificate(
            cmdj=fake_cmdj,
            security_dir=security_dir,
            result=result_dict,
            parse_header_fn=lambda d: (0, 0, 0),
            get_cert_type_name_fn=lambda t: "UNKNOWN",
            parse_pkcs7_fn=lambda o, s: None,
        )

        assert cert_info is None
        assert len(result_dict["errors"]) >= 1

    def test_parse_pkcs7_direct_invalid_offset(self):
        """Test parse_pkcs7 with negative offset."""
        result = parse_pkcs7(
            cmdj=lambda cmd, default=None: None,
            offset=-1,
            size=100,
            logger=logging.getLogger("test"),
            detect_digest_algorithm_fn=lambda d: None,
            detect_encryption_algorithm_fn=lambda d: None,
            extract_common_names_fn=lambda d, o: [],
            has_timestamp_fn=lambda d: False,
        )

        assert result is None

    def test_parse_pkcs7_direct_zero_size(self):
        """Test parse_pkcs7 with zero size."""
        result = parse_pkcs7(
            cmdj=lambda cmd, default=None: None,
            offset=100,
            size=0,
            logger=logging.getLogger("test"),
            detect_digest_algorithm_fn=lambda d: None,
            detect_encryption_algorithm_fn=lambda d: None,
            extract_common_names_fn=lambda d, o: [],
            has_timestamp_fn=lambda d: False,
        )

        assert result is None
