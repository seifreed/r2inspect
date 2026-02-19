"""Tests for authenticode_analyzer.py - wave 3, real code, no mocks."""
from __future__ import annotations

from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer


# ---------------------------------------------------------------------------
# Stub adapters – lightweight objects that return configurable data so that
# the real analyzer code runs end-to-end without unittest.mock.
# ---------------------------------------------------------------------------

class _BaseAdapter:
    """Returns sensible defaults for every adapter method used by the analyzer."""

    def get_headers_json(self):
        return {"class": "PE32"}

    def get_pe_optional_header(self):
        return {"subsystem": 2}

    def get_data_directories(self):
        return []

    def read_bytes_list(self, address, size):
        return []

    def get_file_info(self):
        return {"core": {"size": 10000}}


class _SignedAdapter(_BaseAdapter):
    """Simulates a signed PE with a SECURITY data directory and PKCS7 cert."""

    def get_data_directories(self):
        return [
            {"name": "EXPORT", "vaddr": 0x1000, "paddr": 0x800, "size": 100},
            {"name": "SECURITY", "vaddr": 0x5000, "paddr": 0x4000, "size": 400},
        ]

    def read_bytes_list(self, address, size):
        if size == 8:
            # WIN_CERTIFICATE header: length=0x190, revision=0x0200, type=0x0002
            return [0x90, 0x01, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00]
        # PKCS7 payload containing SHA256 OID + RSA OID
        sha256_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
        rsa_oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        return sha256_oid + rsa_oid + [0x00] * 100


class _NoSecurityDirAdapter(_BaseAdapter):
    def get_data_directories(self):
        return [{"name": "EXPORT", "vaddr": 0x1000, "paddr": 0x800, "size": 100}]


class _ZeroVaddrAdapter(_BaseAdapter):
    def get_data_directories(self):
        return [{"name": "SECURITY", "vaddr": 0, "paddr": 0, "size": 0}]


class _NonListDirAdapter(_BaseAdapter):
    def get_data_directories(self):
        return {"not": "a list"}


class _RaisingDirAdapter(_BaseAdapter):
    """Raises inside get_data_directories to exercise analyze()'s except block."""

    def get_data_directories(self):
        raise RuntimeError("forced error in data directories")


class _ShortBytesAdapter(_BaseAdapter):
    def get_data_directories(self):
        return [{"name": "SECURITY", "vaddr": 0x5000, "paddr": 0x4000, "size": 400}]

    def read_bytes_list(self, address, size):
        return [0x01, 0x02]  # fewer than 8 bytes


class _X509CertAdapter(_BaseAdapter):
    """Reports a certificate with type 0x0001 (X.509) so the PKCS7 branch is skipped."""

    def get_data_directories(self):
        return [{"name": "SECURITY", "vaddr": 0x5000, "paddr": 0x4000, "size": 400}]

    def read_bytes_list(self, address, size):
        if size == 8:
            # length=0x190, revision=0x0200, type=0x0001
            return [0x90, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00]
        return []


class _Pkcs7NoBytesAdapter(_BaseAdapter):
    """Returns a valid WIN_CERTIFICATE header but no PKCS7 payload."""

    def get_data_directories(self):
        return [{"name": "SECURITY", "vaddr": 0x5000, "paddr": 0x4000, "size": 400}]

    def read_bytes_list(self, address, size):
        if size == 8:
            return [0x90, 0x01, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00]
        return []  # empty payload causes _parse_pkcs7 to return None


class _RaisingPkcs7Adapter(_BaseAdapter):
    """Raises on every read_bytes_list call to exercise _parse_pkcs7 except branch."""

    def read_bytes_list(self, address, size):
        raise ValueError("forced error in read_bytes_list")


class _RaisingFileInfoAdapter(_BaseAdapter):
    """Raises on get_file_info to exercise _compute_authenticode_hash except branch."""

    def get_file_info(self):
        raise RuntimeError("forced error in file info")


# ---------------------------------------------------------------------------
# analyze() paths
# ---------------------------------------------------------------------------

def test_analyze_no_security_directory_returns_no_signature():
    analyzer = AuthenticodeAnalyzer(adapter=_NoSecurityDirAdapter())
    result = analyzer.analyze()
    assert result["has_signature"] is False
    assert result["available"] is True


def test_analyze_security_dir_vaddr_zero_returns_no_signature():
    analyzer = AuthenticodeAnalyzer(adapter=_ZeroVaddrAdapter())
    result = analyzer.analyze()
    assert result["has_signature"] is False


def test_analyze_signed_pe_sets_has_signature_and_security_directory():
    analyzer = AuthenticodeAnalyzer(adapter=_SignedAdapter())
    result = analyzer.analyze()
    assert result["has_signature"] is True
    assert result["security_directory"] is not None
    assert result["security_directory"]["offset"] == 0x4000
    assert result["security_directory"]["size"] == 400
    assert result["security_directory"]["virtual_address"] == 0x5000


def test_analyze_signed_pe_appends_certificate_info():
    analyzer = AuthenticodeAnalyzer(adapter=_SignedAdapter())
    result = analyzer.analyze()
    assert len(result["certificates"]) >= 1


def test_analyze_signed_pe_includes_authenticode_hash():
    analyzer = AuthenticodeAnalyzer(adapter=_SignedAdapter())
    result = analyzer.analyze()
    assert "authenticode_hash" in result
    assert result["authenticode_hash"]["algorithm"] == "SHA256"
    assert result["authenticode_hash"]["file_size"] == 10000


def test_analyze_signed_pe_sets_signature_valid():
    analyzer = AuthenticodeAnalyzer(adapter=_SignedAdapter())
    result = analyzer.analyze()
    # certificates present, no errors, security_directory.size > 0 => valid
    assert result["signature_valid"] is True


def test_analyze_exception_path_sets_error_fields():
    analyzer = AuthenticodeAnalyzer(adapter=_RaisingDirAdapter())
    result = analyzer.analyze()
    assert result["available"] is False
    assert result["has_signature"] is False
    assert result["signature_valid"] is False
    assert "error" in result
    assert "forced error" in result["error"]


# ---------------------------------------------------------------------------
# _get_security_directory()
# ---------------------------------------------------------------------------

def test_get_security_directory_not_a_list_returns_none():
    analyzer = AuthenticodeAnalyzer(adapter=_NonListDirAdapter())
    assert analyzer._get_security_directory() is None


def test_get_security_directory_no_matching_entry_returns_none():
    analyzer = AuthenticodeAnalyzer(adapter=_NoSecurityDirAdapter())
    assert analyzer._get_security_directory() is None


def test_get_security_directory_returns_security_entry():
    analyzer = AuthenticodeAnalyzer(adapter=_SignedAdapter())
    sd = analyzer._get_security_directory()
    assert sd is not None
    assert sd["name"] == "SECURITY"
    assert sd["vaddr"] == 0x5000


def test_get_security_directory_empty_list_returns_none():
    analyzer = AuthenticodeAnalyzer(adapter=_BaseAdapter())
    assert analyzer._get_security_directory() is None


# ---------------------------------------------------------------------------
# _read_win_certificate()
# ---------------------------------------------------------------------------

def test_read_win_certificate_zero_offset_returns_none_and_appends_error():
    analyzer = AuthenticodeAnalyzer(adapter=_BaseAdapter())
    result = {"errors": []}
    cert = analyzer._read_win_certificate({"paddr": 0, "size": 100}, result)
    assert cert is None
    assert "Invalid security directory" in result["errors"]


def test_read_win_certificate_zero_size_returns_none_and_appends_error():
    analyzer = AuthenticodeAnalyzer(adapter=_BaseAdapter())
    result = {"errors": []}
    cert = analyzer._read_win_certificate({"paddr": 0x1000, "size": 0}, result)
    assert cert is None
    assert "Invalid security directory" in result["errors"]


def test_read_win_certificate_short_header_data_returns_none():
    analyzer = AuthenticodeAnalyzer(adapter=_ShortBytesAdapter())
    result = {"errors": []}
    cert = analyzer._read_win_certificate({"paddr": 0x4000, "size": 400}, result)
    assert cert is None


def test_read_win_certificate_sets_signature_offset_and_size():
    analyzer = AuthenticodeAnalyzer(adapter=_SignedAdapter())
    result = {"errors": []}
    analyzer._read_win_certificate({"paddr": 0x4000, "size": 400}, result)
    assert result["signature_offset"] == 0x4000
    assert result["signature_size"] == 400


def test_read_win_certificate_pkcs7_type_sets_format():
    analyzer = AuthenticodeAnalyzer(adapter=_SignedAdapter())
    result = {"errors": []}
    cert = analyzer._read_win_certificate({"paddr": 0x4000, "size": 400}, result)
    assert cert is not None
    assert cert["format"] == "PKCS#7"
    assert cert["type"] == "PKCS#7"
    assert cert["type_value"] == hex(0x0002)


def test_read_win_certificate_x509_type_no_pkcs7_format_key():
    analyzer = AuthenticodeAnalyzer(adapter=_X509CertAdapter())
    result = {"errors": []}
    cert = analyzer._read_win_certificate({"paddr": 0x4000, "size": 400}, result)
    assert cert is not None
    assert cert["type"] == "X.509"
    assert "format" not in cert


def test_read_win_certificate_pkcs7_with_no_payload_returns_cert_without_pkcs7_info():
    analyzer = AuthenticodeAnalyzer(adapter=_Pkcs7NoBytesAdapter())
    result = {"errors": []}
    cert = analyzer._read_win_certificate({"paddr": 0x4000, "size": 400}, result)
    # cert_info exists but pkcs7_info is None so no extra keys merged
    assert cert is not None
    assert cert["type"] == "PKCS#7"


# ---------------------------------------------------------------------------
# _parse_win_cert_header()
# ---------------------------------------------------------------------------

def test_parse_win_cert_header_pkcs7_values():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    data = [0x90, 0x01, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00]
    length, revision, cert_type = analyzer._parse_win_cert_header(data)
    assert length == 0x190
    assert revision == 0x0200
    assert cert_type == 0x0002


def test_parse_win_cert_header_x509_type():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    data = [0x90, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00]
    length, revision, cert_type = analyzer._parse_win_cert_header(data)
    assert cert_type == 0x0001


def test_parse_win_cert_header_little_endian_length():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    # length = 0x00000100 = 256
    data = [0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00]
    length, _, _ = analyzer._parse_win_cert_header(data)
    assert length == 0x100


# ---------------------------------------------------------------------------
# _get_cert_type_name()
# ---------------------------------------------------------------------------

def test_get_cert_type_name_x509():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._get_cert_type_name(0x0001) == "X.509"


def test_get_cert_type_name_pkcs7():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._get_cert_type_name(0x0002) == "PKCS#7"


def test_get_cert_type_name_reserved():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._get_cert_type_name(0x0003) == "RESERVED"


def test_get_cert_type_name_ts_stack_signed():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._get_cert_type_name(0x0004) == "TS_STACK_SIGNED"


def test_get_cert_type_name_unknown_includes_hex():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    name = analyzer._get_cert_type_name(0xDEAD)
    assert "UNKNOWN" in name
    assert "0xdead" in name


# ---------------------------------------------------------------------------
# _parse_pkcs7()
# ---------------------------------------------------------------------------

class _Pkcs7Sha1Adapter(_BaseAdapter):
    def read_bytes_list(self, address, size):
        sha1_oid = [0x2B, 0x0E, 0x03, 0x02, 0x1A]
        return sha1_oid + [0x00] * 50


class _Pkcs7TimestampAdapter(_BaseAdapter):
    def read_bytes_list(self, address, size):
        ts_oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E]
        return ts_oid + [0x00] * 50


class _Pkcs7EmptyPayloadAdapter(_BaseAdapter):
    def read_bytes_list(self, address, size):
        return [0x00] * 50


def test_parse_pkcs7_empty_data_returns_none():
    class EmptyAdapter(_BaseAdapter):
        def read_bytes_list(self, address, size):
            return []
    analyzer = AuthenticodeAnalyzer(adapter=EmptyAdapter())
    assert analyzer._parse_pkcs7(0x1000, 100) is None


def test_parse_pkcs7_sha256_and_rsa_detected():
    analyzer = AuthenticodeAnalyzer(adapter=_SignedAdapter())
    result = analyzer._parse_pkcs7(0x4008, 392)
    assert result is not None
    assert result["digest_algorithm"] == "SHA256"
    assert result["encryption_algorithm"] == "RSA"


def test_parse_pkcs7_sha1_detected():
    analyzer = AuthenticodeAnalyzer(adapter=_Pkcs7Sha1Adapter())
    result = analyzer._parse_pkcs7(0x1000, 100)
    assert result is not None
    assert result["digest_algorithm"] == "SHA1"


def test_parse_pkcs7_timestamp_detected():
    analyzer = AuthenticodeAnalyzer(adapter=_Pkcs7TimestampAdapter())
    result = analyzer._parse_pkcs7(0x1000, 100)
    assert result is not None
    assert result["has_timestamp"] is True


def test_parse_pkcs7_no_known_algorithms_returns_nones():
    analyzer = AuthenticodeAnalyzer(adapter=_Pkcs7EmptyPayloadAdapter())
    result = analyzer._parse_pkcs7(0x1000, 100)
    assert result is not None
    assert result["digest_algorithm"] is None
    assert result["encryption_algorithm"] is None
    assert result["has_timestamp"] is False


def test_parse_pkcs7_exception_returns_none():
    analyzer = AuthenticodeAnalyzer(adapter=_RaisingPkcs7Adapter())
    result = analyzer._parse_pkcs7(0x1000, 100)
    assert result is None


# ---------------------------------------------------------------------------
# _detect_digest_algorithm()
# ---------------------------------------------------------------------------

def test_detect_digest_algorithm_sha256():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    data = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] + [0x00] * 10
    assert analyzer._detect_digest_algorithm(data) == "SHA256"


def test_detect_digest_algorithm_sha1_when_no_sha256():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    data = [0x2B, 0x0E, 0x03, 0x02, 0x1A] + [0x00] * 20
    assert analyzer._detect_digest_algorithm(data) == "SHA1"


def test_detect_digest_algorithm_returns_none_for_unknown():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._detect_digest_algorithm([0x01, 0x02, 0x03]) is None


# ---------------------------------------------------------------------------
# _detect_encryption_algorithm()
# ---------------------------------------------------------------------------

def test_detect_encryption_algorithm_rsa():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    data = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01] + [0x00] * 5
    assert analyzer._detect_encryption_algorithm(data) == "RSA"


def test_detect_encryption_algorithm_returns_none_for_unknown():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._detect_encryption_algorithm([0x01, 0x02, 0x03]) is None


# ---------------------------------------------------------------------------
# _extract_common_names()
# ---------------------------------------------------------------------------

def test_extract_common_names_returns_empty_list_for_no_oid():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    result = analyzer._extract_common_names([0x00] * 20, 0)
    assert result == []


def test_extract_common_names_finds_single_cn():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    cn_name = b"TestCorp"
    # OID at position 20, then tag byte, then length, then cn bytes
    data = [0x00] * 20 + [0x55, 0x04, 0x03, 0x00, len(cn_name)] + list(cn_name) + [0x00] * 50
    result = analyzer._extract_common_names(data, 0x1000)
    assert len(result) == 1
    assert result[0]["common_name"] == "TestCorp"


def test_extract_common_names_limits_to_three_entries():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    cn_name = b"Corp"
    entry = [0x55, 0x04, 0x03, 0x00, len(cn_name)] + list(cn_name) + [0x00] * 10
    # Build data with 4 CN OID occurrences
    data = entry * 4 + [0x00] * 20
    result = analyzer._extract_common_names(data, 0)
    assert len(result) <= 3


# ---------------------------------------------------------------------------
# _extract_cn_entry()
# ---------------------------------------------------------------------------

def test_extract_cn_entry_position_too_close_to_end_returns_none():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    data = [0x00] * 15
    # pos=6 => pos+10=16 >= len=15
    assert analyzer._extract_cn_entry(data, 0, 6) is None


def test_extract_cn_entry_length_zero_returns_none():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    # data[pos+4]=0 means length=0
    data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x41] + [0x00] * 50
    assert analyzer._extract_cn_entry(data, 0, 0) is None


def test_extract_cn_entry_length_too_large_returns_none():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    # data[pos+4]=100 means length >= 100 (boundary)
    data = [0x00, 0x00, 0x00, 0x00, 100] + [0x41] * 50 + [0x00] * 60
    assert analyzer._extract_cn_entry(data, 0, 0) is None


def test_extract_cn_entry_length_exceeds_data_returns_none():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    # length=50 but data only has 20 bytes total => start+length > len
    data = [0x00, 0x00, 0x00, 0x00, 50, 0x41] + [0x00] * 14
    assert analyzer._extract_cn_entry(data, 0, 0) is None


def test_extract_cn_entry_valid_printable_cn_returns_dict():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    cn_name = b"Microsoft"
    pos = 0
    data = [0x00, 0x00, 0x00, 0x00, len(cn_name)] + list(cn_name) + [0x00] * 50
    result = analyzer._extract_cn_entry(data, 0x2000, pos)
    assert result is not None
    assert result["common_name"] == "Microsoft"
    assert result["offset"] == 0x2000 + pos


def test_extract_cn_entry_non_printable_cn_returns_none():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    # Use control characters that are not printable
    pos = 0
    cn_bytes = [0x01, 0x02, 0x03, 0x04, 0x05]
    data = [0x00, 0x00, 0x00, 0x00, len(cn_bytes)] + cn_bytes + [0x00] * 50
    result = analyzer._extract_cn_entry(data, 0, pos)
    assert result is None


# ---------------------------------------------------------------------------
# _has_timestamp()
# ---------------------------------------------------------------------------

def test_has_timestamp_returns_true_when_oid_present():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    ts_oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E]
    data = [0x00] * 5 + ts_oid + [0x00] * 5
    assert analyzer._has_timestamp(data) is True


def test_has_timestamp_returns_false_when_oid_absent():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._has_timestamp([0x00] * 30) is False


# ---------------------------------------------------------------------------
# _find_pattern()
# ---------------------------------------------------------------------------

def test_find_pattern_found_at_start():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._find_pattern([0x01, 0x02, 0x03], [0x01, 0x02]) is True


def test_find_pattern_found_at_end():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._find_pattern([0x00, 0x00, 0x01, 0x02], [0x01, 0x02]) is True


def test_find_pattern_not_found():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._find_pattern([0x01, 0x02, 0x03], [0x04, 0x05]) is False


def test_find_pattern_exact_full_match():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    data = [0xAA, 0xBB, 0xCC]
    assert analyzer._find_pattern(data, [0xAA, 0xBB, 0xCC]) is True


def test_find_pattern_empty_data_returns_false():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._find_pattern([], [0x01]) is False


# ---------------------------------------------------------------------------
# _find_all_patterns()
# ---------------------------------------------------------------------------

def test_find_all_patterns_multiple_occurrences():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    data = [0x01, 0x02, 0x03, 0x01, 0x02, 0x00, 0x01, 0x02]
    positions = analyzer._find_all_patterns(data, [0x01, 0x02])
    assert positions == [0, 3, 6]


def test_find_all_patterns_no_match_returns_empty():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._find_all_patterns([0x00] * 10, [0xFF]) == []


def test_find_all_patterns_single_match():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    positions = analyzer._find_all_patterns([0x00, 0xAA, 0xBB, 0x00], [0xAA, 0xBB])
    assert positions == [1]


def test_find_all_patterns_entire_data_is_pattern():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    positions = analyzer._find_all_patterns([0xCC, 0xDD], [0xCC, 0xDD])
    assert positions == [0]


# ---------------------------------------------------------------------------
# _compute_authenticode_hash()
# ---------------------------------------------------------------------------

def test_compute_authenticode_hash_success():
    analyzer = AuthenticodeAnalyzer(adapter=_BaseAdapter())
    result = analyzer._compute_authenticode_hash()
    assert result is not None
    assert result["algorithm"] == "SHA256"
    assert result["file_size"] == 10000
    assert "regions" in result


def test_compute_authenticode_hash_no_file_info_returns_none():
    class NullFileInfoAdapter(_BaseAdapter):
        def get_file_info(self):
            return None

    analyzer = AuthenticodeAnalyzer(adapter=NullFileInfoAdapter())
    assert analyzer._compute_authenticode_hash() is None


def test_compute_authenticode_hash_zero_file_size_returns_none():
    class ZeroSizeAdapter(_BaseAdapter):
        def get_file_info(self):
            return {"core": {"size": 0}}

    analyzer = AuthenticodeAnalyzer(adapter=ZeroSizeAdapter())
    assert analyzer._compute_authenticode_hash() is None


def test_compute_authenticode_hash_no_pe_header_returns_none():
    class NoPeHeaderAdapter(_BaseAdapter):
        def get_headers_json(self):
            return None

    analyzer = AuthenticodeAnalyzer(adapter=NoPeHeaderAdapter())
    assert analyzer._compute_authenticode_hash() is None


def test_compute_authenticode_hash_no_optional_header_returns_none():
    class NoOptHeaderAdapter(_BaseAdapter):
        def get_pe_optional_header(self):
            return None

    analyzer = AuthenticodeAnalyzer(adapter=NoOptHeaderAdapter())
    assert analyzer._compute_authenticode_hash() is None


def test_compute_authenticode_hash_exception_returns_none():
    analyzer = AuthenticodeAnalyzer(adapter=_RaisingFileInfoAdapter())
    assert analyzer._compute_authenticode_hash() is None


# ---------------------------------------------------------------------------
# _verify_signature_integrity()
# ---------------------------------------------------------------------------

def test_verify_signature_integrity_no_signature_returns_false():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._verify_signature_integrity({"has_signature": False}) is False


def test_verify_signature_integrity_empty_certificates_returns_false():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._verify_signature_integrity({
        "has_signature": True,
        "certificates": [],
    }) is False


def test_verify_signature_integrity_errors_present_returns_false():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._verify_signature_integrity({
        "has_signature": True,
        "certificates": ["cert"],
        "errors": ["parse error"],
    }) is False


def test_verify_signature_integrity_no_security_directory_returns_false():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._verify_signature_integrity({
        "has_signature": True,
        "certificates": ["cert"],
        "errors": [],
        "security_directory": None,
    }) is False


def test_verify_signature_integrity_security_dir_size_zero_returns_false():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._verify_signature_integrity({
        "has_signature": True,
        "certificates": ["cert"],
        "errors": [],
        "security_directory": {"size": 0},
    }) is False


def test_verify_signature_integrity_all_valid_returns_true():
    analyzer = AuthenticodeAnalyzer(adapter=None)
    assert analyzer._verify_signature_integrity({
        "has_signature": True,
        "certificates": ["cert"],
        "errors": [],
        "security_directory": {"size": 400},
    }) is True
