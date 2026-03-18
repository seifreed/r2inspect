"""Comprehensive tests for crypto_analyzer.py -- no mocks, no monkeypatch, no @patch."""

from __future__ import annotations

import json
from typing import Any

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.crypto_analyzer import CryptoAnalyzer
from r2inspect.modules.crypto_constants import CRYPTO_CONSTANTS
from r2inspect.modules.crypto_domain import (
    consolidate_detections,
    detect_algorithms_from_strings,
    _is_candidate_string,
    _matches_any_pattern,
    CRYPTO_PATTERNS,
)
from r2inspect.modules.crypto_detection_support import (
    build_crypto_report,
    detect_crypto_apis,
    detect_crypto_constants,
    analyze_entropy,
    find_suspicious_patterns,
    detect_crypto_libraries,
)
from r2inspect.modules.domain_helpers import shannon_entropy
from r2inspect.modules.string_domain import parse_search_results


# ---------------------------------------------------------------------------
# FakeR2: minimal r2pipe-like backend driven by command maps
# ---------------------------------------------------------------------------


class FakeR2:
    """Minimal r2pipe-like object backed by static command maps."""

    def __init__(
        self, cmd_map: dict[str, str] | None = None, cmdj_map: dict[str, Any] | None = None
    ):
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command: str) -> str:
        return self._cmd_map.get(command, "")

    def cmdj(self, command: str) -> Any:
        return self._cmdj_map.get(command)


def _make_adapter(
    cmd_map: dict[str, str] | None = None, cmdj_map: dict[str, Any] | None = None
) -> R2PipeAdapter:
    return R2PipeAdapter(FakeR2(cmd_map=cmd_map, cmdj_map=cmdj_map))


# ---------------------------------------------------------------------------
# Typical imports / strings / sections data for a crypto-laden binary
# ---------------------------------------------------------------------------

CRYPTO_IMPORTS = [
    {
        "name": "CryptEncrypt",
        "plt": 0x1000,
        "libname": "advapi32.dll",
        "ordinal": 1,
        "type": "FUNC",
        "bind": "NONE",
    },
    {
        "name": "BCryptCreateHash",
        "plt": 0x1010,
        "libname": "bcrypt.dll",
        "ordinal": 2,
        "type": "FUNC",
        "bind": "NONE",
    },
    {
        "name": "AES_encrypt",
        "plt": 0x1020,
        "libname": "libcrypto.so",
        "ordinal": 3,
        "type": "FUNC",
        "bind": "NONE",
    },
]

CRYPTO_STRINGS = [
    {
        "string": "AES-256-CBC",
        "vaddr": 0x2000,
        "paddr": 0x2000,
        "length": 11,
        "size": 11,
        "section": ".rdata",
        "type": "ascii",
    },
    {
        "string": "RSA",
        "vaddr": 0x2010,
        "paddr": 0x2010,
        "length": 3,
        "size": 3,
        "section": ".rdata",
        "type": "ascii",
    },
    {
        "string": "MD5",
        "vaddr": 0x2020,
        "paddr": 0x2020,
        "length": 3,
        "size": 3,
        "section": ".rdata",
        "type": "ascii",
    },
    {
        "string": "VMware",
        "vaddr": 0x2030,
        "paddr": 0x2030,
        "length": 6,
        "size": 6,
        "section": ".rdata",
        "type": "ascii",
    },
]

CRYPTO_SECTIONS = [
    {"name": ".text", "size": 50000, "vaddr": 0x1000, "paddr": 0x400, "perm": "r-x", "flags": ""},
    {"name": ".data", "size": 10000, "vaddr": 0x10000, "paddr": 0xA000, "perm": "rw-", "flags": ""},
]


def _crypto_cmdj_map() -> dict[str, Any]:
    return {
        "iij": CRYPTO_IMPORTS,
        "iSj": CRYPTO_SECTIONS,
        "izzj": CRYPTO_STRINGS,
    }


def _crypto_cmd_map(*, has_crypto: bool = True) -> dict[str, str]:
    """Build a cmd map that returns search results for crypto patterns."""
    m: dict[str, str] = {}
    if has_crypto:
        m["/c xor"] = "0x1000\n0x1005\n0x100a\n"
        m["/c rol,ror"] = "0x2000\n"
        # mov table lookup pattern -- produce >10 hits to trigger Table Lookups
        mov_hits = "\n".join([f"0x{i:04x}" for i in range(3000, 3020)])
        m["/c mov.*\\[.*\\\\+.*\\]"] = mov_hits
        # AES S-box constant search
        m["/x 00000063"] = "0x5000\n"
        m["/x 67e6096a"] = "0x5000\n"
    return m


def _make_crypto_adapter(*, has_crypto: bool = True) -> R2PipeAdapter:
    cmdj = _crypto_cmdj_map() if has_crypto else {}
    cmd = _crypto_cmd_map(has_crypto=has_crypto)
    return _make_adapter(cmd_map=cmd, cmdj_map=cmdj)


# ---------------------------------------------------------------------------
# 1. Initialization
# ---------------------------------------------------------------------------


class TestCryptoAnalyzerInit:
    def test_initialization_stores_adapter(self):
        adapter = _make_crypto_adapter()
        analyzer = CryptoAnalyzer(adapter, config=None)
        assert analyzer.adapter is adapter
        assert analyzer.config is None

    def test_initialization_loads_crypto_constants(self):
        adapter = _make_crypto_adapter()
        analyzer = CryptoAnalyzer(adapter)
        assert analyzer.crypto_constants is CRYPTO_CONSTANTS

    def test_initialization_with_config(self):
        adapter = _make_crypto_adapter()
        cfg = {"max_entropy_sections": 5}
        analyzer = CryptoAnalyzer(adapter, config=cfg)
        assert analyzer.config == cfg


# ---------------------------------------------------------------------------
# 2. Full detect() pipeline
# ---------------------------------------------------------------------------


class TestCryptoDetect:
    def test_detect_returns_expected_keys(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        result = analyzer.detect()

        assert "algorithms" in result
        assert "constants" in result
        assert "entropy_analysis" in result
        assert "suspicious_patterns" in result

    def test_detect_no_crypto(self):
        adapter = _make_crypto_adapter(has_crypto=False)
        analyzer = CryptoAnalyzer(adapter)
        result = analyzer.detect()

        assert isinstance(result["algorithms"], list)
        assert isinstance(result["constants"], list)
        assert isinstance(result["entropy_analysis"], dict)

    def test_detect_algorithms_found(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        result = analyzer.detect()

        algo_names = {a["algorithm"] for a in result["algorithms"]}
        # We expect at least CryptoAPI (from CryptEncrypt) and AES (from AES_encrypt + string)
        assert "CryptoAPI" in algo_names or "AES" in algo_names

    def test_detect_error_handling(self):
        """When the underlying adapter raises, detect() catches and returns error."""

        class FailingR2:
            def cmd(self, command):
                raise RuntimeError("boom")

            def cmdj(self, command):
                raise RuntimeError("boom")

        adapter = R2PipeAdapter(FailingR2())
        analyzer = CryptoAnalyzer(adapter)
        result = analyzer.detect()

        # Should not raise; returns a dict with error info
        assert isinstance(result, dict)
        assert "error" in result or "algorithms" in result


# ---------------------------------------------------------------------------
# 3. Crypto API detection
# ---------------------------------------------------------------------------


class TestCryptoApiDetection:
    def test_detect_crypto_apis_returns_list(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        apis = analyzer._detect_crypto_apis()

        assert isinstance(apis, list)
        assert len(apis) >= 3

    def test_detect_crypto_apis_structure(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        apis = analyzer._detect_crypto_apis()

        for api in apis:
            assert "function" in api
            assert "algorithm" in api
            assert "library" in api
            assert "address" in api

    def test_detect_crypto_apis_library_key_fallback(self):
        """When import has 'library' instead of 'libname', it still works."""
        imports = [
            {
                "name": "CryptEncrypt",
                "plt": 0x1000,
                "library": "advapi32.dll",
                "ordinal": 1,
                "type": "FUNC",
                "bind": "NONE",
            }
        ]
        adapter = _make_adapter(cmdj_map={"iij": imports})
        analyzer = CryptoAnalyzer(adapter)
        apis = analyzer._detect_crypto_apis()

        assert len(apis) == 1
        assert apis[0]["library"] == "advapi32.dll"

    def test_bcrypt_api_detection(self):
        imports = [
            {
                "name": "BCryptOpenAlgorithmProvider",
                "plt": 0x1000,
                "libname": "bcrypt.dll",
                "ordinal": 1,
                "type": "FUNC",
                "bind": "NONE",
            },
            {
                "name": "BCryptEncrypt",
                "plt": 0x1010,
                "libname": "bcrypt.dll",
                "ordinal": 2,
                "type": "FUNC",
                "bind": "NONE",
            },
        ]
        adapter = _make_adapter(cmdj_map={"iij": imports})
        analyzer = CryptoAnalyzer(adapter)
        apis = analyzer._detect_crypto_apis()

        bcrypt_apis = [a for a in apis if a["algorithm"] == "BCrypt"]
        assert len(bcrypt_apis) >= 2

    def test_openssl_api_detection(self):
        imports = [
            {
                "name": "EVP_EncryptInit",
                "plt": 0x1000,
                "libname": "libcrypto.so",
                "ordinal": 1,
                "type": "FUNC",
                "bind": "NONE",
            },
            {
                "name": "AES_encrypt",
                "plt": 0x1010,
                "libname": "libcrypto.so",
                "ordinal": 2,
                "type": "FUNC",
                "bind": "NONE",
            },
        ]
        adapter = _make_adapter(cmdj_map={"iij": imports})
        analyzer = CryptoAnalyzer(adapter)
        apis = analyzer._detect_crypto_apis()

        assert len(apis) >= 2

    def test_detect_via_api_calls_populates_dict(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        detected_algos: dict[str, list] = {}

        analyzer._detect_via_api_calls(detected_algos)

        assert len(detected_algos) > 0
        for evidences in detected_algos.values():
            for e in evidences:
                assert e["evidence_type"] == "API Call"
                assert e["confidence"] == 0.9


# ---------------------------------------------------------------------------
# 4. Crypto constants detection
# ---------------------------------------------------------------------------


class TestCryptoConstants:
    def test_detect_crypto_constants_returns_list(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        constants = analyzer._detect_crypto_constants()

        assert isinstance(constants, list)

    def test_detect_via_constants(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        detected_algos: dict[str, list] = {}

        analyzer._detect_via_constants(detected_algos)

        assert isinstance(detected_algos, dict)


# ---------------------------------------------------------------------------
# 5. String-based algorithm detection
# ---------------------------------------------------------------------------


class TestCryptoStringDetection:
    def test_detect_via_strings(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        detected_algos: dict[str, list] = {}

        analyzer._detect_via_strings(detected_algos)

        assert isinstance(detected_algos, dict)
        # AES-256-CBC should match AES pattern
        assert "AES" in detected_algos

    def test_detect_via_strings_empty(self):
        adapter = _make_crypto_adapter(has_crypto=False)
        analyzer = CryptoAnalyzer(adapter)
        detected_algos: dict[str, list] = {}

        analyzer._detect_via_strings(detected_algos)

        assert len(detected_algos) == 0


# ---------------------------------------------------------------------------
# 6. Algorithm detection pipeline
# ---------------------------------------------------------------------------


class TestCryptoAlgorithms:
    def test_detect_algorithms_returns_list(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        algorithms = analyzer._detect_crypto_algorithms()

        assert isinstance(algorithms, list)

    def test_detect_algorithms_structure(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        algorithms = analyzer._detect_crypto_algorithms()

        for algo in algorithms:
            assert "algorithm" in algo
            assert "confidence" in algo
            assert "evidence_count" in algo


# ---------------------------------------------------------------------------
# 7. Entropy analysis
# ---------------------------------------------------------------------------


class TestEntropyAnalysis:
    def test_analyze_entropy_returns_dict(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        entropy_info = analyzer._analyze_entropy()

        assert isinstance(entropy_info, dict)

    def test_calculate_section_entropy_normal(self):
        # Build an adapter that returns some bytes via read_bytes (p8 command)
        # FakeR2 returns hex string for p8 command
        hex_data = "deadbeef" * 25  # 100 bytes of data
        adapter = _make_adapter(cmd_map={"p8 1000 @ 0x1000": hex_data})
        analyzer = CryptoAnalyzer(adapter)

        section = {"name": ".text", "vaddr": 0x1000, "size": 1000}
        entropy = analyzer._calculate_section_entropy(section)

        assert isinstance(entropy, float)
        assert 0.0 <= entropy <= 8.0

    def test_calculate_section_entropy_zero_size(self):
        adapter = _make_crypto_adapter()
        analyzer = CryptoAnalyzer(adapter)

        section = {"name": ".empty", "vaddr": 0x1000, "size": 0}
        entropy = analyzer._calculate_section_entropy(section)

        assert entropy == 0.0


# ---------------------------------------------------------------------------
# 8. Suspicious pattern detection
# ---------------------------------------------------------------------------


class TestSuspiciousPatterns:
    def test_find_suspicious_patterns_returns_list(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        patterns = analyzer._find_suspicious_patterns()

        assert isinstance(patterns, list)

    def test_xor_pattern_detected(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        patterns = analyzer._find_suspicious_patterns()

        xor_patterns = [p for p in patterns if p["type"] == "XOR Operations"]
        assert len(xor_patterns) >= 1

    def test_bit_rotation_detected(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        patterns = analyzer._find_suspicious_patterns()

        rot_patterns = [p for p in patterns if p["type"] == "Bit Rotation"]
        assert len(rot_patterns) >= 1

    def test_table_lookup_detected(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        patterns = analyzer._find_suspicious_patterns()

        table_patterns = [p for p in patterns if p["type"] == "Table Lookups"]
        assert len(table_patterns) >= 1

    def test_no_patterns_when_empty(self):
        adapter = _make_adapter()
        analyzer = CryptoAnalyzer(adapter)
        patterns = analyzer._find_suspicious_patterns()

        assert patterns == []


# ---------------------------------------------------------------------------
# 9. Crypto library detection
# ---------------------------------------------------------------------------


class TestCryptoLibraries:
    def test_detect_crypto_libraries(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        libs = analyzer.detect_crypto_libraries()

        assert isinstance(libs, list)

    def test_library_entry_structure(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        libs = analyzer.detect_crypto_libraries()

        for lib in libs:
            assert "library" in lib
            assert "api_function" in lib
            assert "address" in lib

    def test_detect_empty_when_no_imports(self):
        adapter = _make_adapter()
        analyzer = CryptoAnalyzer(adapter)
        libs = analyzer.detect_crypto_libraries()

        assert libs == []


# ---------------------------------------------------------------------------
# 10. Accessor methods (_get_imports, _get_sections, etc.)
# ---------------------------------------------------------------------------


class TestAccessorMethods:
    def test_get_imports(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        imports = analyzer._get_imports()

        assert isinstance(imports, list)
        assert len(imports) == 3

    def test_get_sections(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        sections = analyzer._get_sections()

        assert isinstance(sections, list)
        assert len(sections) == 2

    def test_get_strings(self):
        adapter = _make_crypto_adapter(has_crypto=True)
        analyzer = CryptoAnalyzer(adapter)
        strings = analyzer._get_strings()

        assert isinstance(strings, list)
        assert len(strings) == 4

    def test_search_text(self):
        cmd_map = {"/c xor": "0x1000\n0x1005\n"}
        adapter = _make_adapter(cmd_map=cmd_map)
        analyzer = CryptoAnalyzer(adapter)
        result = analyzer._search_text("xor")

        assert isinstance(result, str)
        assert "0x1000" in result

    def test_search_hex(self):
        cmd_map = {"/x 00000063": "0x5000\n"}
        adapter = _make_adapter(cmd_map=cmd_map)
        analyzer = CryptoAnalyzer(adapter)
        result = analyzer._search_hex("00000063")

        assert isinstance(result, str)

    def test_adapter_without_methods(self):
        """Adapter with no get_imports/etc falls back gracefully."""

        class MinimalR2:
            def cmd(self, command):
                return ""

            def cmdj(self, command):
                return None

        adapter = R2PipeAdapter(MinimalR2())
        analyzer = CryptoAnalyzer(adapter)

        # These should return empty defaults, not raise
        assert analyzer._get_imports() == []
        assert analyzer._get_sections() == []
        assert analyzer._get_strings() == []


# ---------------------------------------------------------------------------
# 11. Static / pure domain helpers
# ---------------------------------------------------------------------------


class TestCoerceDictList:
    def test_list_of_dicts(self):
        result = CryptoAnalyzer._coerce_dict_list([{"a": 1}, {"b": 2}])
        assert len(result) == 2

    def test_single_dict(self):
        result = CryptoAnalyzer._coerce_dict_list({"a": 1})
        assert len(result) == 1

    def test_list_of_non_dicts(self):
        result = CryptoAnalyzer._coerce_dict_list([1, 2, 3])
        assert len(result) == 0

    def test_non_list_non_dict(self):
        result = CryptoAnalyzer._coerce_dict_list("invalid")
        assert len(result) == 0

    def test_empty_list(self):
        result = CryptoAnalyzer._coerce_dict_list([])
        assert result == []

    def test_none(self):
        result = CryptoAnalyzer._coerce_dict_list(None)
        assert result == []


class TestParseSearchResults:
    def test_basic_parsing(self):
        result = "0x1000\n0x2000\n0x3000\n"
        addresses = parse_search_results(result)

        assert isinstance(addresses, list)
        assert len(addresses) == 3
        assert "0x1000" in addresses

    def test_empty_input(self):
        assert parse_search_results("") == []

    def test_non_hex_lines_skipped(self):
        result = "some noise\n0x1000\nanother line\n"
        addresses = parse_search_results(result)
        assert addresses == ["0x1000"]


class TestShannonEntropy:
    def test_uniform_data(self):
        data = bytes(range(256))
        entropy = shannon_entropy(data)
        assert abs(entropy - 8.0) < 0.01

    def test_constant_data(self):
        data = b"\x00" * 256
        entropy = shannon_entropy(data)
        assert entropy == 0.0

    def test_empty_data(self):
        assert shannon_entropy(b"") == 0.0


# ---------------------------------------------------------------------------
# 12. Domain model: detect_algorithms_from_strings
# ---------------------------------------------------------------------------


class TestDetectAlgorithmsFromStrings:
    def test_detects_aes_string(self):
        strings = [{"string": "AES-256-CBC", "vaddr": 0x1000}]
        detected: dict[str, list] = {}
        detect_algorithms_from_strings(strings, detected)

        assert "AES" in detected
        assert detected["AES"][0]["evidence_type"] == "String Reference"

    def test_detects_rsa_string(self):
        strings = [{"string": "RSA key exchange", "vaddr": 0x2000}]
        detected: dict[str, list] = {}
        detect_algorithms_from_strings(strings, detected)

        assert "RSA" in detected

    def test_ignores_noise_strings(self):
        strings = [{"string": "std::vector", "vaddr": 0x3000}]
        detected: dict[str, list] = {}
        detect_algorithms_from_strings(strings, detected)

        assert len(detected) == 0

    def test_short_strings_ignored(self):
        strings = [{"string": "ab", "vaddr": 0x4000}]
        detected: dict[str, list] = {}
        detect_algorithms_from_strings(strings, detected)

        assert len(detected) == 0


class TestIsCandidateString:
    def test_valid_candidate(self):
        assert _is_candidate_string("AES-256") is True

    def test_too_short(self):
        assert _is_candidate_string("ab") is False

    def test_noise_rejected(self):
        assert _is_candidate_string("std::vector") is False
        assert _is_candidate_string("vtable for Foo") is False


class TestMatchesAnyPattern:
    def test_match_found(self):
        assert _matches_any_pattern("aes-256-cbc", CRYPTO_PATTERNS["AES"]) is True

    def test_no_match(self):
        assert _matches_any_pattern("hello world", CRYPTO_PATTERNS["AES"]) is False


# ---------------------------------------------------------------------------
# 13. Domain model: consolidate_detections
# ---------------------------------------------------------------------------


class TestConsolidateDetections:
    def test_single_evidence(self):
        detected = {
            "AES": [
                {
                    "evidence_type": "API Call",
                    "evidence": "AES_encrypt",
                    "confidence": 0.9,
                    "address": "0x1000",
                }
            ]
        }
        result = consolidate_detections(detected)

        assert len(result) == 1
        assert result[0]["algorithm"] == "AES"
        assert result[0]["confidence"] == 0.9
        assert result[0]["evidence_count"] == 1

    def test_multi_evidence_boost(self):
        detected = {
            "AES": [
                {
                    "evidence_type": "API Call",
                    "evidence": "AES_encrypt",
                    "confidence": 0.9,
                    "address": "0x1000",
                },
                {
                    "evidence_type": "String Reference",
                    "evidence": "aes-256",
                    "confidence": 0.4,
                    "address": "0x2000",
                },
            ]
        }
        result = consolidate_detections(detected)

        # Multi-evidence boost should increase confidence beyond 0.9
        assert result[0]["confidence"] > 0.9
        assert result[0]["confidence"] <= 0.95
        assert result[0]["evidence_count"] == 2
        assert len(result[0]["evidence_types"]) == 2

    def test_empty_dict(self):
        assert consolidate_detections({}) == []

    def test_multiple_algorithms(self):
        detected = {
            "AES": [
                {
                    "evidence_type": "API Call",
                    "evidence": "AES_encrypt",
                    "confidence": 0.9,
                    "address": "0x1000",
                }
            ],
            "RSA": [
                {
                    "evidence_type": "String Reference",
                    "evidence": "rsa",
                    "confidence": 0.4,
                    "address": "0x2000",
                }
            ],
        }
        result = consolidate_detections(detected)

        algo_names = {r["algorithm"] for r in result}
        assert "AES" in algo_names
        assert "RSA" in algo_names
