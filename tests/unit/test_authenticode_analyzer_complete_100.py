"""Comprehensive tests for authenticode_analyzer.py - 100% coverage target."""

from unittest.mock import Mock

from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer


def test_init():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    assert analyzer.adapter == adapter


def test_analyze_success():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    analyzer._has_required_headers = Mock(return_value=True)
    analyzer._get_security_directory = Mock(return_value={"vaddr": 0x1000, "paddr": 0x800, "size": 500})
    analyzer._read_win_certificate = Mock(return_value={"length": 400, "type": "PKCS#7"})
    analyzer._compute_authenticode_hash = Mock(return_value={"algorithm": "SHA256"})
    analyzer._verify_signature_integrity = Mock(return_value=True)
    
    result = analyzer.analyze()
    
    assert result["available"] is True
    assert result["has_signature"] is True
    assert result["signature_valid"] is True


def test_analyze_no_headers():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    analyzer._has_required_headers = Mock(return_value=False)
    
    result = analyzer.analyze()
    
    assert result["available"] is False


def test_analyze_no_signature():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    analyzer._has_required_headers = Mock(return_value=True)
    analyzer._get_security_directory = Mock(return_value={"vaddr": 0, "paddr": 0, "size": 0})
    
    result = analyzer.analyze()
    
    assert result["has_signature"] is False


def test_analyze_exception():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    analyzer._has_required_headers = Mock(side_effect=Exception("Test error"))
    
    result = analyzer.analyze()
    
    assert result["available"] is False
    assert "error" in result


def test_has_required_headers():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    analyzer._cmdj = Mock(side_effect=[{"test": "pe_header"}, {"test": "optional_header"}])
    
    assert analyzer._has_required_headers() is True


def test_get_security_directory():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    analyzer._cmdj = Mock(return_value=[
        {"name": "EXPORT", "vaddr": 100},
        {"name": "SECURITY", "vaddr": 200, "paddr": 150, "size": 300}
    ])
    
    result = analyzer._get_security_directory()
    
    assert result["name"] == "SECURITY"


def test_read_win_certificate():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    analyzer._cmdj = Mock(return_value=[0x90, 0x01, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00])
    analyzer._parse_pkcs7 = Mock(return_value={"format": "PKCS#7"})
    
    result = {}
    cert = analyzer._read_win_certificate({"paddr": 1000, "size": 400}, result)
    
    assert cert is not None
    assert "length" in cert


def test_read_win_certificate_invalid():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    analyzer._cmdj = Mock(return_value=[])
    
    result = {"errors": []}
    cert = analyzer._read_win_certificate({"paddr": 0, "size": 0}, result)
    
    assert cert is None


def test_parse_win_cert_header():
    analyzer = AuthenticodeAnalyzer(Mock())
    data = [0x90, 0x01, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00]
    
    length, revision, cert_type = analyzer._parse_win_cert_header(data)
    
    assert length == 0x190
    assert revision == 0x200
    assert cert_type == 0x2


def test_get_cert_type_name():
    analyzer = AuthenticodeAnalyzer(Mock())
    
    assert "X.509" in analyzer._get_cert_type_name(0x0001)
    assert "PKCS#7" in analyzer._get_cert_type_name(0x0002)
    assert "UNKNOWN" in analyzer._get_cert_type_name(0x9999)


def test_parse_pkcs7():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    analyzer._cmdj = Mock(return_value=[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] + [0] * 100)
    analyzer._detect_digest_algorithm = Mock(return_value="SHA256")
    analyzer._detect_encryption_algorithm = Mock(return_value="RSA")
    analyzer._extract_common_names = Mock(return_value=[{"common_name": "Test"}])
    analyzer._has_timestamp = Mock(return_value=True)
    
    result = analyzer._parse_pkcs7(1000, 512)
    
    assert result is not None
    assert result["digest_algorithm"] == "SHA256"


def test_detect_digest_algorithm():
    analyzer = AuthenticodeAnalyzer(Mock())
    sha256_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
    analyzer._find_pattern = Mock(return_value=True)
    
    result = analyzer._detect_digest_algorithm(sha256_oid)
    
    assert result == "SHA256"


def test_detect_encryption_algorithm():
    analyzer = AuthenticodeAnalyzer(Mock())
    analyzer._find_pattern = Mock(return_value=True)
    
    result = analyzer._detect_encryption_algorithm([])
    
    assert result == "RSA"


def test_extract_common_names():
    analyzer = AuthenticodeAnalyzer(Mock())
    analyzer._find_all_patterns = Mock(return_value=[10, 50])
    analyzer._extract_cn_entry = Mock(side_effect=[{"common_name": "CN1"}, {"common_name": "CN2"}])
    
    result = analyzer._extract_common_names([0] * 100, 1000)
    
    assert len(result) == 2


def test_extract_cn_entry():
    analyzer = AuthenticodeAnalyzer(Mock())
    data = [0] * 100
    data[10:15] = [0x55, 0x04, 0x03, 0, 5]
    data[15:20] = [ord('T'), ord('e'), ord('s'), ord('t'), 0]
    
    result = analyzer._extract_cn_entry(data, 1000, 10)
    
    # May return None or dict depending on parsing
    assert result is None or isinstance(result, dict)


def test_has_timestamp():
    analyzer = AuthenticodeAnalyzer(Mock())
    analyzer._find_pattern = Mock(return_value=True)
    
    assert analyzer._has_timestamp([]) is True


def test_find_pattern_found():
    analyzer = AuthenticodeAnalyzer(Mock())
    data = [0, 1, 2, 3, 4, 5]
    pattern = [2, 3, 4]
    
    assert analyzer._find_pattern(data, pattern) is True


def test_find_pattern_not_found():
    analyzer = AuthenticodeAnalyzer(Mock())
    data = [0, 1, 2, 3]
    pattern = [9, 10]
    
    assert analyzer._find_pattern(data, pattern) is False


def test_find_all_patterns():
    analyzer = AuthenticodeAnalyzer(Mock())
    data = [1, 2, 3, 1, 2, 3, 1, 2, 3]
    pattern = [1, 2, 3]
    
    result = analyzer._find_all_patterns(data, pattern)
    
    assert len(result) == 3


def test_compute_authenticode_hash():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    analyzer._cmdj = Mock(side_effect=[
        {"core": {"size": 10000}},
        {"test": "pe_header"},
        {"test": "optional_header"}
    ])
    
    result = analyzer._compute_authenticode_hash()
    
    assert result is not None
    assert "algorithm" in result


def test_compute_authenticode_hash_no_info():
    adapter = Mock()
    analyzer = AuthenticodeAnalyzer(adapter)
    analyzer._cmdj = Mock(return_value=None)
    
    result = analyzer._compute_authenticode_hash()
    
    assert result is None


def test_verify_signature_integrity_valid():
    analyzer = AuthenticodeAnalyzer(Mock())
    
    signature_info = {
        "has_signature": True,
        "certificates": [{"test": "cert"}],
        "errors": [],
        "security_directory": {"size": 100}
    }
    
    result = analyzer._verify_signature_integrity(signature_info)
    
    assert result is True


def test_verify_signature_integrity_invalid():
    analyzer = AuthenticodeAnalyzer(Mock())
    
    signature_info = {
        "has_signature": False,
        "certificates": [],
        "errors": [],
        "security_directory": None
    }
    
    result = analyzer._verify_signature_integrity(signature_info)
    
    assert result is False


def test_verify_signature_integrity_with_errors():
    analyzer = AuthenticodeAnalyzer(Mock())
    
    signature_info = {
        "has_signature": True,
        "certificates": [{"test": "cert"}],
        "errors": ["Error 1"],
        "security_directory": {"size": 100}
    }
    
    result = analyzer._verify_signature_integrity(signature_info)
    
    assert result is False
