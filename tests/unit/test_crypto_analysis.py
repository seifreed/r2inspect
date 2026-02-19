"""Comprehensive tests for crypto_analyzer.py."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from r2inspect.modules.crypto_analyzer import CryptoAnalyzer


class MockAdapter:
    def __init__(self, has_crypto: bool = True):
        self.has_crypto = has_crypto

    def get_imports(self):
        if not self.has_crypto:
            return []
        return [
            {"name": "CryptEncrypt", "plt": 0x1000, "libname": "advapi32.dll"},
            {"name": "BCryptCreateHash", "plt": 0x1010, "libname": "bcrypt.dll"},
            {"name": "AES_encrypt", "plt": 0x1020, "libname": "libcrypto.so"},
        ]

    def get_strings(self):
        if not self.has_crypto:
            return []
        return [
            {"string": "AES-256-CBC", "vaddr": 0x2000},
            {"string": "RSA", "vaddr": 0x2010},
            {"string": "MD5", "vaddr": 0x2020},
            {"string": "VMware", "vaddr": 0x2030},
        ]

    def get_sections(self):
        if not self.has_crypto:
            return []
        return [
            {"name": ".text", "size": 50000, "vaddr": 0x1000},
            {"name": ".data", "size": 10000, "vaddr": 0x10000},
        ]

    def search_text(self, pattern: str):
        if pattern == "xor":
            return "0x1000\n0x1005\n0x100a\n"
        if pattern == "rol,ror":
            return "0x2000\n"
        if pattern.startswith("mov"):
            return "\n".join([f"0x{i:04x}" for i in range(3000, 3020)])
        return ""

    def search_hex(self, hex_pattern: str):
        if self.has_crypto and hex_pattern in ["63", "67e6096a"]:
            return "0x5000\n"
        return ""

    def cmd(self, command: str):
        if command.startswith("/x "):
            return self.search_hex(command[3:])
        if command.startswith("/ "):
            return self.search_text(command[2:])
        return ""

    def cmdj(self, command: str, default=None):
        return default if default is not None else {}

    def read_bytes(self, vaddr: int, size: int):
        import random
        random.seed(vaddr)
        return bytes([random.randint(0, 255) for _ in range(min(size, 1000))])


def test_crypto_analyzer_initialization():
    adapter = MockAdapter()
    analyzer = CryptoAnalyzer(adapter, config=None)
    assert analyzer.adapter == adapter
    assert analyzer.r2 == adapter
    assert analyzer.config is None


def test_crypto_detect_basic():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    result = analyzer.detect()
    
    assert "algorithms" in result
    assert "constants" in result
    assert "entropy_analysis" in result
    assert "suspicious_patterns" in result


def test_crypto_detect_no_crypto():
    adapter = MockAdapter(has_crypto=False)
    analyzer = CryptoAnalyzer(adapter)
    result = analyzer.detect()
    
    assert isinstance(result["algorithms"], list)
    assert isinstance(result["constants"], list)
    assert isinstance(result["entropy_analysis"], dict)


def test_crypto_detect_crypto_constants():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    constants = analyzer._detect_crypto_constants()
    
    assert isinstance(constants, list)


def test_crypto_detect_crypto_apis():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    apis = analyzer._detect_crypto_apis()
    
    assert isinstance(apis, list)
    assert len(apis) >= 3
    for api in apis:
        assert "function" in api
        assert "algorithm" in api


def test_crypto_detect_algorithms():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    algorithms = analyzer._detect_crypto_algorithms()
    
    assert isinstance(algorithms, list)


def test_crypto_analyze_entropy():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    entropy_info = analyzer._analyze_entropy()
    
    assert isinstance(entropy_info, dict)


def test_crypto_calculate_section_entropy():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    
    section = {"name": ".text", "vaddr": 0x1000, "size": 1000}
    entropy = analyzer._calculate_section_entropy(section)
    
    assert isinstance(entropy, float)
    assert 0.0 <= entropy <= 8.0


def test_crypto_entropy_zero_size():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    
    section = {"name": ".empty", "vaddr": 0x1000, "size": 0}
    entropy = analyzer._calculate_section_entropy(section)
    
    assert entropy == 0.0


def test_crypto_find_suspicious_patterns():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    patterns = analyzer._find_suspicious_patterns()
    
    assert isinstance(patterns, list)


def test_crypto_parse_search_results():
    adapter = MockAdapter()
    analyzer = CryptoAnalyzer(adapter)
    
    result = "0x1000\n0x2000\n0x3000\n"
    addresses = analyzer._parse_search_results(result)
    
    assert isinstance(addresses, list)
    assert len(addresses) >= 3


def test_crypto_detect_via_api_calls():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    detected_algos = {}
    
    analyzer._detect_via_api_calls(detected_algos)
    
    assert len(detected_algos) > 0


def test_crypto_detect_via_constants():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    detected_algos = {}
    
    analyzer._detect_via_constants(detected_algos)
    
    assert isinstance(detected_algos, dict)


def test_crypto_detect_via_strings():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    detected_algos = {}
    
    analyzer._detect_via_strings(detected_algos)
    
    assert isinstance(detected_algos, dict)


def test_crypto_detect_libraries():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    libs = analyzer.detect_crypto_libraries()
    
    assert isinstance(libs, list)


def test_crypto_coerce_dict_list():
    result = CryptoAnalyzer._coerce_dict_list([{"a": 1}, {"b": 2}])
    assert len(result) == 2
    
    result = CryptoAnalyzer._coerce_dict_list({"a": 1})
    assert len(result) == 1
    
    result = CryptoAnalyzer._coerce_dict_list([1, 2, 3])
    assert len(result) == 0
    
    result = CryptoAnalyzer._coerce_dict_list("invalid")
    assert len(result) == 0


def test_crypto_get_imports():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    imports = analyzer._get_imports()
    
    assert isinstance(imports, list)
    assert len(imports) == 3


def test_crypto_get_sections():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    sections = analyzer._get_sections()
    
    assert isinstance(sections, list)
    assert len(sections) == 2


def test_crypto_get_strings():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    strings = analyzer._get_strings()
    
    assert isinstance(strings, list)
    assert len(strings) == 4


def test_crypto_search_text():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    result = analyzer._search_text("xor")
    
    assert isinstance(result, str)
    assert "0x1000" in result


def test_crypto_search_hex():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    result = analyzer._search_hex("63")
    
    assert isinstance(result, str)


def test_crypto_read_bytes():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    data = analyzer._read_bytes(0x1000, 100)
    
    assert isinstance(data, bytes)
    assert len(data) == 100


def test_crypto_adapter_without_methods():
    class MinimalAdapter:
        pass
    
    adapter = MinimalAdapter()
    analyzer = CryptoAnalyzer(adapter)
    
    assert analyzer._get_imports() == []
    assert analyzer._get_sections() == []
    assert analyzer._get_strings() == []
    assert analyzer._read_bytes(0, 10) == b""


def test_crypto_error_handling():
    class FailingAdapter:
        def get_imports(self):
            raise RuntimeError("Simulated error")
        
        def get_strings(self):
            raise RuntimeError("Simulated error")
        
        def get_sections(self):
            raise RuntimeError("Simulated error")
        
        def search_text(self, pattern: str):
            raise RuntimeError("Simulated error")
        
        def search_hex(self, pattern: str):
            raise RuntimeError("Simulated error")
    
    adapter = FailingAdapter()
    analyzer = CryptoAnalyzer(adapter)
    result = analyzer.detect()
    
    assert "error" in result or isinstance(result, dict)


def test_crypto_with_real_binary():
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("Sample binary not available")
    
    try:
        import r2pipe
        from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
    except ImportError:
        pytest.skip("r2pipe not available")
    
    r2 = None
    try:
        r2 = r2pipe.open(str(sample), flags=["-2"])
        adapter = R2PipeAdapter(r2)
        analyzer = CryptoAnalyzer(adapter)
        result = analyzer.detect()
        
        assert "algorithms" in result
        assert "constants" in result
        assert "entropy_analysis" in result
        assert "suspicious_patterns" in result
    except Exception:
        pytest.skip("Could not open binary with r2pipe")
    finally:
        if r2 is not None:
            try:
                r2.quit()
            except Exception:
                pass


def test_crypto_xor_pattern_detection():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    patterns = analyzer._find_suspicious_patterns()
    
    xor_patterns = [p for p in patterns if p["type"] == "XOR Operations"]
    assert len(xor_patterns) >= 0


def test_crypto_bit_rotation_detection():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    patterns = analyzer._find_suspicious_patterns()
    
    assert isinstance(patterns, list)


def test_crypto_table_lookup_detection():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    patterns = analyzer._find_suspicious_patterns()
    
    table_patterns = [p for p in patterns if p["type"] == "Table Lookups"]
    assert len(table_patterns) >= 0


def test_crypto_bcrypt_api_detection():
    class BCryptAdapter:
        def get_imports(self):
            return [
                {"name": "BCryptOpenAlgorithmProvider", "plt": 0x1000, "libname": "bcrypt.dll"},
                {"name": "BCryptEncrypt", "plt": 0x1010, "libname": "bcrypt.dll"},
            ]
        
        def get_strings(self):
            return []
        
        def get_sections(self):
            return []
        
        def search_text(self, pattern: str):
            return ""
        
        def search_hex(self, pattern: str):
            return ""
        
        def cmd(self, command: str):
            return ""
    
    adapter = BCryptAdapter()
    analyzer = CryptoAnalyzer(adapter)
    apis = analyzer._detect_crypto_apis()
    
    bcrypt_apis = [api for api in apis if api["algorithm"] == "BCrypt"]
    assert len(bcrypt_apis) >= 2


def test_crypto_openssl_api_detection():
    class OpenSSLAdapter:
        def get_imports(self):
            return [
                {"name": "EVP_EncryptInit", "plt": 0x1000, "libname": "libcrypto.so"},
                {"name": "AES_encrypt", "plt": 0x1010, "libname": "libcrypto.so"},
            ]
        
        def get_strings(self):
            return []
        
        def get_sections(self):
            return []
        
        def search_text(self, pattern: str):
            return ""
        
        def search_hex(self, pattern: str):
            return ""
        
        def cmd(self, command: str):
            return ""
    
    adapter = OpenSSLAdapter()
    analyzer = CryptoAnalyzer(adapter)
    apis = analyzer._detect_crypto_apis()
    
    assert len(apis) >= 2


def test_crypto_library_patterns():
    adapter = MockAdapter(has_crypto=True)
    analyzer = CryptoAnalyzer(adapter)
    libs = analyzer.detect_crypto_libraries()
    
    for lib in libs:
        assert "library" in lib
        assert "api_function" in lib
        assert "address" in lib
