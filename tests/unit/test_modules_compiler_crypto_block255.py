from r2inspect.modules.compiler_detector import CompilerDetector
from r2inspect.modules.crypto_analyzer import CryptoAnalyzer


class DummyAdapter:
    def __init__(self):
        self._file_info = {"bin": {"class": "PE"}, "core": {"file": ""}}
        self._strings = [
            {"string": "GCC 9.3.0"},
            {"string": "clang version 10.0.0"},
        ]
        self._imports = [
            {"libname": "MSVCR140.dll", "name": "CryptEncrypt", "plt": 1},
            {"libname": "KERNEL32.dll", "name": "CreateFile", "plt": 2},
        ]
        self._sections = [{"name": ".text"}]
        self._symbols = [{"name": "main"}]

    def get_file_info(self):
        return self._file_info

    def get_strings(self):
        return self._strings

    def get_imports(self):
        return self._imports

    def get_sections(self):
        return self._sections

    def get_symbols(self):
        return self._symbols

    def read_bytes(self, _addr, _size):
        return b"\x00" * 32

    def search_text(self, _pattern: str):
        return "xor"

    def search_hex(self, _pattern: str):
        return "0x1"


def test_compiler_detector_scoring():
    detector = CompilerDetector(DummyAdapter())
    result = detector.detect_compiler()
    assert result["detected"] in {True, False}
    assert "compiler" in result
    assert "confidence" in result


def test_crypto_analyzer_detection():
    analyzer = CryptoAnalyzer(DummyAdapter())
    result = analyzer.detect()
    assert "constants" in result
    assert "algorithms" in result
    assert "entropy_analysis" in result
    assert "suspicious_patterns" in result

    libs = analyzer.detect_crypto_libraries()
    assert libs
