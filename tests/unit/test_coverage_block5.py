from __future__ import annotations

from r2inspect.modules.authenticode_analyzer import AuthenticodeAnalyzer
from r2inspect.modules.resource_analyzer import ResourceAnalyzer


def test_resource_helpers_entropy_types_and_patterns() -> None:
    analyzer = ResourceAnalyzer(None)

    assert analyzer._get_resource_type_name(3) == "RT_ICON"
    assert analyzer._get_resource_type_name(999) == "UNKNOWN_999"

    assert analyzer._calculate_entropy([]) == 0.0
    assert analyzer._calculate_entropy([0, 0, 0, 0]) == 0.0
    assert analyzer._calculate_entropy([0, 1]) == 1.0

    data = [1, 2, 3, 4, 5]
    assert analyzer._find_pattern(data, [3, 4]) == 2
    assert analyzer._find_pattern(data, [9]) == -1


def test_resource_version_parsing_and_strings() -> None:
    analyzer = ResourceAnalyzer(None)

    # Build version data with VS signature at offset 0
    data = [0] * 60
    data[0:4] = [0xBD, 0x04, 0xEF, 0xFE]
    # file_version_ms = 1.2, file_version_ls = 3.4
    data[8:12] = [2, 0, 1, 0]  # low, high words
    data[12:16] = [4, 0, 3, 0]

    sig_pos = analyzer._find_vs_signature(data)
    assert sig_pos == 0
    assert analyzer._parse_fixed_file_info(data, sig_pos) == "1.2.3.4"

    key = "CompanyName"
    key_bytes = list(key.encode("utf-16le"))
    value_bytes = list("ACME".encode("utf-16le")) + [0, 0]
    payload = key_bytes + [0, 0, 0, 0] + value_bytes
    assert analyzer._read_version_string_value(payload, key) == "ACME"

    strings = analyzer._extract_version_strings(payload)
    assert strings.get("CompanyName") == "ACME"


def test_resource_statistics_and_suspicion_checks() -> None:
    analyzer = ResourceAnalyzer(None)

    resources = [
        {
            "type_name": "RT_ICON",
            "size": 2000,
            "entropy": 8.0,
            "name": "icon1",
            "offset": 10,
        },
        {
            "type_name": "RT_RCDATA",
            "size": 20000,
            "entropy": 7.6,
            "name": "data1",
            "offset": 20,
        },
        {
            "type_name": "RT_STRING",
            "size": 300,
            "entropy": 1.0,
            "name": "str1",
            "offset": 30,
        },
    ]

    result = {"resource_types": [], "total_size": 0, "statistics": {}}
    analyzer._analyze_resource_types(result, resources)
    assert result["total_size"] == 2000 + 20000 + 300

    analyzer._calculate_statistics(result, resources)
    assert result["statistics"]["total_resources"] == 3
    assert result["statistics"]["max_size"] == 20000

    assert analyzer._check_resource_entropy(resources[0]) == []
    assert analyzer._check_resource_entropy(resources[1])
    assert analyzer._check_resource_size({"type_name": "RT_ICON", "size": 200, "name": "x"}) == []
    assert analyzer._check_resource_size(
        {"type_name": "RT_ICON", "size": 2 * 1024 * 1024, "name": "x"}
    )
    assert analyzer._check_resource_rcdata(resources[1])

    icon_result = {"icons": []}
    analyzer._extract_icons(icon_result, resources)
    assert icon_result["icons"][0]["suspicious"]


def test_authenticode_helpers_and_signature_integrity() -> None:
    analyzer = AuthenticodeAnalyzer(None)

    cert_length, cert_revision, cert_type = analyzer._parse_win_cert_header(
        [0x10, 0, 0, 0, 0x02, 0, 0x02, 0]
    )
    assert cert_length == 16
    assert cert_revision == 2
    assert cert_type == 2
    assert analyzer._get_cert_type_name(2) == "PKCS#7"

    data = [1, 2, 3, 2, 3, 4, 2, 3]
    assert analyzer._find_pattern(data, [2, 3]) is True
    assert analyzer._find_pattern(data, [9]) is False
    assert analyzer._find_all_patterns(data, [2, 3]) == [1, 3, 6]

    pkcs7 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
    pkcs7 += [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
    pkcs7 += [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E]
    assert analyzer._detect_digest_algorithm(pkcs7) == "SHA256"
    assert analyzer._detect_encryption_algorithm(pkcs7) == "RSA"
    assert analyzer._has_timestamp(pkcs7) is True

    cn_data = [0x55, 0x04, 0x03, 0x00, 0x04] + list(b"Test") + [0x00, 0x00]
    assert analyzer._extract_common_names(cn_data, 100)[0]["common_name"] == "Test"

    assert analyzer._verify_signature_integrity({"has_signature": False}) is False
    assert (
        analyzer._verify_signature_integrity(
            {"has_signature": True, "certificates": [], "errors": []}
        )
        is False
    )
    assert (
        analyzer._verify_signature_integrity(
            {"has_signature": True, "certificates": [1], "errors": ["oops"]}
        )
        is False
    )
    assert (
        analyzer._verify_signature_integrity(
            {
                "has_signature": True,
                "certificates": [1],
                "errors": [],
                "security_directory": {"size": 0},
            }
        )
        is False
    )
    assert (
        analyzer._verify_signature_integrity(
            {
                "has_signature": True,
                "certificates": [1],
                "errors": [],
                "security_directory": {"size": 10},
            }
        )
        is True
    )
