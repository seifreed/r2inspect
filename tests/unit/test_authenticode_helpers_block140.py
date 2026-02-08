from __future__ import annotations

from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer


def test_authenticode_helpers_parse_and_patterns():
    analyzer = AuthenticodeAnalyzer(adapter=None)

    length, revision, cert_type = analyzer._parse_win_cert_header([8, 0, 0, 0, 2, 0, 2, 0])
    assert length == 8
    assert revision == 2
    assert cert_type == 2

    assert analyzer._get_cert_type_name(0x0002) == "PKCS#7"
    assert "UNKNOWN" in analyzer._get_cert_type_name(0x9999)

    data = [1, 2, 3, 4, 5, 2, 3]
    assert analyzer._find_pattern(data, [2, 3]) is True
    assert analyzer._find_pattern(data, [9, 9]) is False
    assert analyzer._find_all_patterns(data, [2, 3]) == [1, 5]


def test_authenticode_helpers_algorithms_and_cn():
    analyzer = AuthenticodeAnalyzer(adapter=None)

    sha256_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
    rsa_oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]

    assert analyzer._detect_digest_algorithm(sha256_oid) == "SHA256"
    assert analyzer._detect_encryption_algorithm(rsa_oid) == "RSA"

    # CN extraction: place length at pos+4, string starts at pos+5
    data = [0, 0, 0, 0, 4, ord("T"), ord("e"), ord("s"), ord("t")] + [0] * 10
    entry = analyzer._extract_cn_entry(data, offset=100, pos=0)
    assert entry is not None
    assert entry["common_name"] == "Test"

    assert analyzer._has_timestamp(
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E]
    )
