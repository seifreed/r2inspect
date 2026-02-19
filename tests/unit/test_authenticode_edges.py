"""Edge case tests for authenticode_analyzer.py - covering missing branches."""

from unittest.mock import Mock

from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer


def test_has_required_headers_no_pe_header():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    analyzer._cmdj = Mock(return_value=None)
    
    result = analyzer._has_required_headers()
    
    assert result is False


def test_has_required_headers_no_optional_header():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    
    def cmdj_side_effect(cmd, default):
        if cmd == "ihj":
            return {"class": "PE32"}
        elif cmd == "iHj":
            return None
        return default
    
    analyzer._cmdj = Mock(side_effect=cmdj_side_effect)
    
    result = analyzer._has_required_headers()
    
    assert result is False


def test_get_security_directory_not_list():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    analyzer._cmdj = Mock(return_value={"invalid": "format"})
    
    result = analyzer._get_security_directory()
    
    assert result is None


def test_get_security_directory_no_security():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    analyzer._cmdj = Mock(return_value=[
        {"name": "CODE", "vaddr": 0x1000, "paddr": 0x800, "size": 100},
        {"name": "DATA", "vaddr": 0x2000, "paddr": 0x900, "size": 200}
    ])
    
    result = analyzer._get_security_directory()
    
    assert result is None


def test_read_win_certificate_invalid_offset():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    security_dir = {"paddr": 0, "size": 0}
    result = {"errors": []}
    
    cert = analyzer._read_win_certificate(security_dir, result)
    
    assert cert is None
    assert "Invalid security directory" in result["errors"]


def test_read_win_certificate_short_data():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    security_dir = {"paddr": 0x1000, "size": 100}
    result = {}
    analyzer._cmdj = Mock(return_value=[0x01, 0x02])
    
    cert = analyzer._read_win_certificate(security_dir, result)
    
    assert cert is None


def test_detect_digest_algorithm_sha1():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    pkcs7_data = [0x01, 0x02, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x03, 0x04]
    
    result = analyzer._detect_digest_algorithm(pkcs7_data)
    
    assert result == "SHA1"


def test_detect_digest_algorithm_none():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    pkcs7_data = [0x01, 0x02, 0x03, 0x04, 0x05]
    
    result = analyzer._detect_digest_algorithm(pkcs7_data)
    
    assert result is None


def test_detect_encryption_algorithm_rsa():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    pkcs7_data = [0x01, 0x02, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05]
    
    result = analyzer._detect_encryption_algorithm(pkcs7_data)
    
    assert result == "RSA"


def test_detect_encryption_algorithm_none():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    pkcs7_data = [0x01, 0x02, 0x03, 0x04, 0x05]
    
    result = analyzer._detect_encryption_algorithm(pkcs7_data)
    
    assert result is None


def test_extract_cn_entry_short_data():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    pkcs7_data = [0x01, 0x02, 0x03]
    
    entry = analyzer._extract_cn_entry(pkcs7_data, 0x1000, 0)
    
    assert entry is None


def test_extract_cn_entry_invalid_length():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    pkcs7_data = [0x01, 0x02, 0x03, 0x04, 0x80, 0xFF] + [0x00] * 100
    
    entry = analyzer._extract_cn_entry(pkcs7_data, 0x1000, 0)
    
    assert entry is None


def test_extract_cn_entry_zero_length():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    pkcs7_data = [0x01, 0x02, 0x03, 0x04, 0x00, 0xFF] + [0x00] * 100
    
    entry = analyzer._extract_cn_entry(pkcs7_data, 0x1000, 0)
    
    assert entry is None


def test_extract_cn_entry_overflow():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    pkcs7_data = [0x01, 0x02, 0x03, 0x04, 0xFF] + [0x00] * 10
    
    entry = analyzer._extract_cn_entry(pkcs7_data, 0x1000, 1)
    
    assert entry is None


def test_extract_cn_entry_decode_error():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    pkcs7_data = [0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0xFE, 0xFD, 0xFC] + [0x00] * 100
    
    entry = analyzer._extract_cn_entry(pkcs7_data, 0x1000, 0)
    
    assert entry is None


def test_extract_cn_entry_success():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    cn_bytes = b"TestCN"
    pkcs7_data = [0x01, 0x02, 0x03, 0x04, len(cn_bytes)] + list(cn_bytes) + [0x00] * 100
    
    entry = analyzer._extract_cn_entry(pkcs7_data, 0x1000, 0)
    
    assert entry is not None
    assert entry["common_name"] == "TestCN"
    assert entry["offset"] == 0x1000


def test_parse_pkcs7_no_data():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    analyzer._cmdj = Mock(return_value=None)
    
    result = analyzer._parse_pkcs7(0x1000, 100)
    
    assert result is None


def test_parse_pkcs7_success():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    pkcs7_data = [0x01, 0x02, 0x2B, 0x0E, 0x03, 0x02, 0x1A] + [0x00] * 100
    analyzer._cmdj = Mock(return_value=pkcs7_data)
    
    result = analyzer._parse_pkcs7(0x1000, 100)
    
    assert result is not None
    assert result["digest_algorithm"] == "SHA1"


def test_compute_authenticode_hash_no_file_info():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    analyzer._cmdj = Mock(return_value=None)
    
    result = analyzer._compute_authenticode_hash()
    
    assert result is None


def test_compute_authenticode_hash_zero_size():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    
    def cmdj_side_effect(cmd, default):
        if cmd == "ij":
            return {"core": {"size": 0}}
        return default
    
    analyzer._cmdj = Mock(side_effect=cmdj_side_effect)
    
    result = analyzer._compute_authenticode_hash()
    
    assert result is None


def test_compute_authenticode_hash_no_pe():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    
    def cmdj_side_effect(cmd, default):
        if cmd == "ij":
            return {"core": {"size": 1000}}
        elif cmd == "ihj":
            return None
        return default
    
    analyzer._cmdj = Mock(side_effect=cmdj_side_effect)
    
    result = analyzer._compute_authenticode_hash()
    
    assert result is None


def test_compute_authenticode_hash_no_optional_header():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    
    def cmdj_side_effect(cmd, default):
        if cmd == "ij":
            return {"core": {"size": 1000}}
        elif cmd == "ihj":
            return {"offset": 0x3C}
        elif cmd == "iHj":
            return None
        return default
    
    analyzer._cmdj = Mock(side_effect=cmdj_side_effect)
    
    result = analyzer._compute_authenticode_hash()
    
    assert result is None


def test_verify_signature_integrity_no_signature():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    sig_info = {"has_signature": False}
    
    result = analyzer._verify_signature_integrity(sig_info)
    
    assert result is False


def test_verify_signature_integrity_no_certs():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    sig_info = {"has_signature": True, "certificates": []}
    
    result = analyzer._verify_signature_integrity(sig_info)
    
    assert result is False


def test_verify_signature_integrity_with_errors():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    sig_info = {
        "has_signature": True,
        "certificates": [{"type": "X.509"}],
        "errors": ["Some error"]
    }
    
    result = analyzer._verify_signature_integrity(sig_info)
    
    assert result is False


def test_verify_signature_integrity_no_security_dir():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    sig_info = {
        "has_signature": True,
        "certificates": [{"type": "X.509"}],
        "errors": [],
        "security_directory": None
    }
    
    result = analyzer._verify_signature_integrity(sig_info)
    
    assert result is False


def test_verify_signature_integrity_empty_sec_dir():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    sig_info = {
        "has_signature": True,
        "certificates": [{"type": "X.509"}],
        "errors": [],
        "security_directory": {"size": 0}
    }
    
    result = analyzer._verify_signature_integrity(sig_info)
    
    assert result is False
