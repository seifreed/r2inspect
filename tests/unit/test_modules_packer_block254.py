from r2inspect.modules import domain_helpers, packer_helpers
from r2inspect.modules.packer_detector import PackerDetector


class DummyConfig:
    def __init__(self):
        self.typed_config = type("Cfg", (), {})()
        self.typed_config.packer = type("Packer", (), {})()
        self.typed_config.packer.entropy_threshold = 1.0


class DummyAdapter:
    def __init__(self):
        self._strings = [{"string": "UPX"}]
        self._sections = [
            {"name": ".text", "flags": "r-x", "size": 200, "vaddr": 0},
            {"name": ".upx", "flags": "rwx", "size": 50, "vaddr": 100},
        ]
        self._imports = [{"name": "CreateFile"}]
        self._file_info = {"bin": {"size": 1000}}

    def get_strings(self):
        return self._strings

    def get_sections(self):
        return self._sections

    def get_imports(self):
        return self._imports

    def get_file_info(self):
        return self._file_info

    def read_bytes(self, addr, size):
        return bytes([1, 2, 3, 4])

    def search_hex(self, pattern: str):
        return "0x1" if pattern else ""


def test_packer_helpers_and_detector():
    # domain helpers
    assert domain_helpers.shannon_entropy(b"AAAA") >= 0.0
    assert domain_helpers.entropy_from_ints([65, 65]) >= 0.0
    assert domain_helpers.clamp_score(200) == 100
    assert domain_helpers.count_suspicious_imports([{"name": "X"}], {"X"}) == 1
    assert domain_helpers.normalize_section_name(".TEXT") == ".text"
    assert domain_helpers.suspicious_section_name_indicator(".upx", ["upx"]) is not None

    # packer helpers
    sig = packer_helpers.find_packer_signature(lambda _hex: "hit", {"UPX": [b"UPX!"]})
    assert sig["type"] == "UPX"

    sig2 = packer_helpers.find_packer_string([{"string": "upx"}], {"UPX": [b"UPX!"]})
    assert sig2["type"] == "UPX"

    sections = [{"name": ".text", "size": 4, "vaddr": 0, "flags": "rwx"}]
    entropy = packer_helpers.analyze_entropy(sections, lambda _a, _s: b"AAAA", 0.1)
    assert "summary" in entropy

    section_info = packer_helpers.analyze_sections(sections)
    assert section_info["section_count"] == 1

    assert packer_helpers.is_suspicious_section_name(".upx") is True

    overlay = packer_helpers.overlay_info({"bin": {"size": 100}}, sections)
    assert "overlay_size" in overlay

    # detector
    detector = PackerDetector(DummyAdapter(), DummyConfig())
    result = detector.detect()
    assert "entropy_analysis" in result
    assert "section_analysis" in result
    assert result["confidence"] >= 0.0

    overlay2 = detector.get_overlay_info()
    assert "has_overlay" in overlay2
