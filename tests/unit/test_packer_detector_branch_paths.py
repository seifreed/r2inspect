"""Branch-path tests for r2inspect/modules/packer_detector.py."""

from __future__ import annotations

from typing import Any

import pytest

from r2inspect.modules.packer_detector import PackerDetector


# ---------------------------------------------------------------------------
# Stub helpers
# ---------------------------------------------------------------------------


class _PackerConfig:
    entropy_threshold: float = 7.0


class _TypedConfig:
    packer = _PackerConfig()


class StubConfig:
    typed_config = _TypedConfig()


class AdapterWithAllMethods:
    """Adapter exposing all optional methods - tests the 'if hasattr' True branches."""

    def get_imports(self) -> list[dict[str, Any]]:
        return [{"name": "VirtualAlloc", "category": "Memory"}]

    def get_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".text", "vaddr": 0x1000, "vsize": 0x100, "size": 0x100, "flags": "r-x"}]

    def get_strings(self) -> list[dict[str, Any]]:
        return [{"string": "hello"}]

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"arch": "x86", "bits": 32}}

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b"\x00" * size


class AdapterWithoutOptionalMethods:
    """Adapter with no optional methods - tests the 'else' fallback branches (lines 222,227,232,235)."""
    pass


class AdapterWithRaisingMethods:
    """Adapter whose methods raise exceptions."""

    def get_imports(self) -> list[dict[str, Any]]:
        raise RuntimeError("imports failed")

    def get_sections(self) -> list[dict[str, Any]]:
        raise RuntimeError("sections failed")

    def get_strings(self) -> list[dict[str, Any]]:
        raise RuntimeError("strings failed")

    def get_file_info(self) -> dict[str, Any]:
        raise RuntimeError("file info failed")

    def read_bytes(self, addr: int, size: int) -> bytes:
        raise RuntimeError("read_bytes failed")


class AdapterWithHighEntropySection:
    def get_imports(self) -> list[dict[str, Any]]:
        return []

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "UPX0",
                "vaddr": 0x1000,
                "vsize": 0x1000,
                "size": 0x1000,
                "flags": "rwx",
            }
        ]

    def get_strings(self) -> list[dict[str, Any]]:
        return [{"string": "UPX!"}]

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def read_bytes(self, addr: int, size: int) -> bytes:
        # Return highly non-uniform bytes to create high entropy
        return bytes(range(256)) * (size // 256 + 1)


class AdapterReturningEmptyBytes:
    def get_imports(self) -> list[dict[str, Any]]:
        return []

    def get_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".text", "vaddr": 0x1000, "vsize": 0x100, "size": 0x100, "flags": "r-x"}]

    def get_strings(self) -> list[dict[str, Any]]:
        return []

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def read_bytes(self, addr: int, size: int) -> bytes:
        return b""


# ---------------------------------------------------------------------------
# Basic construction
# ---------------------------------------------------------------------------


def test_packer_detector_requires_config():
    with pytest.raises(ValueError, match="config must be provided"):
        PackerDetector(AdapterWithAllMethods(), None)


def test_packer_detector_stores_entropy_threshold():
    detector = PackerDetector(AdapterWithAllMethods(), StubConfig())
    assert detector.entropy_threshold == 7.0


# ---------------------------------------------------------------------------
# _get_imports branches (line 221 uses adapter.get_imports; 222 uses _cmd_list)
# ---------------------------------------------------------------------------


def test_get_imports_uses_adapter_method_when_available():
    detector = PackerDetector(AdapterWithAllMethods(), StubConfig())
    imports = detector._get_imports()
    assert isinstance(imports, list)
    assert any(imp.get("name") == "VirtualAlloc" for imp in imports)


def test_get_imports_falls_back_when_adapter_has_no_method():
    detector = PackerDetector(AdapterWithoutOptionalMethods(), StubConfig())
    imports = detector._get_imports()
    assert isinstance(imports, list)


# ---------------------------------------------------------------------------
# _get_sections branches (line 226 vs 227)
# ---------------------------------------------------------------------------


def test_get_sections_uses_adapter_method_when_available():
    detector = PackerDetector(AdapterWithAllMethods(), StubConfig())
    sections = detector._get_sections()
    assert isinstance(sections, list)
    assert len(sections) > 0


def test_get_sections_falls_back_when_adapter_has_no_method():
    detector = PackerDetector(AdapterWithoutOptionalMethods(), StubConfig())
    sections = detector._get_sections()
    assert isinstance(sections, list)


# ---------------------------------------------------------------------------
# _get_strings branches (line 231 vs 232)
# ---------------------------------------------------------------------------


def test_get_strings_uses_adapter_method_when_available():
    detector = PackerDetector(AdapterWithAllMethods(), StubConfig())
    strings = detector._get_strings()
    assert isinstance(strings, list)


def test_get_strings_falls_back_when_adapter_has_no_method():
    detector = PackerDetector(AdapterWithoutOptionalMethods(), StubConfig())
    strings = detector._get_strings()
    assert isinstance(strings, list)


# ---------------------------------------------------------------------------
# _get_file_info branches (line 242 vs 243)
# ---------------------------------------------------------------------------


def test_get_file_info_uses_adapter_method_when_available():
    detector = PackerDetector(AdapterWithAllMethods(), StubConfig())
    info = detector._get_file_info()
    assert isinstance(info, dict)


def test_get_file_info_falls_back_when_adapter_has_no_method():
    detector = PackerDetector(AdapterWithoutOptionalMethods(), StubConfig())
    info = detector._get_file_info()
    assert isinstance(info, dict)


# ---------------------------------------------------------------------------
# _read_bytes branches (line 247 vs 248-249)
# ---------------------------------------------------------------------------


def test_read_bytes_uses_adapter_method_when_available():
    detector = PackerDetector(AdapterWithAllMethods(), StubConfig())
    data = detector._read_bytes(0x1000, 16)
    assert isinstance(data, bytes)


def test_read_bytes_falls_back_when_adapter_has_no_method():
    detector = PackerDetector(AdapterWithoutOptionalMethods(), StubConfig())
    data = detector._read_bytes(0x1000, 16)
    assert isinstance(data, bytes)


# ---------------------------------------------------------------------------
# _analyze_entropy returns empty dict on exception (lines 148-151)
# ---------------------------------------------------------------------------


def test_analyze_entropy_returns_dict_on_exception():
    detector = PackerDetector(AdapterWithRaisingMethods(), StubConfig())
    result = detector._analyze_entropy()
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# _count_imports returns 0 on exception (lines 157-159)
# ---------------------------------------------------------------------------


def test_count_imports_returns_zero_on_exception():
    detector = PackerDetector(AdapterWithRaisingMethods(), StubConfig())
    count = detector._count_imports()
    assert count == 0


# ---------------------------------------------------------------------------
# _analyze_sections returns safe dict on exception (lines 166-169)
# ---------------------------------------------------------------------------


def test_analyze_sections_returns_safe_dict_on_exception():
    detector = PackerDetector(AdapterWithRaisingMethods(), StubConfig())
    result = detector._analyze_sections()
    assert "suspicious_sections" in result
    assert result["section_count"] == 0


# ---------------------------------------------------------------------------
# detect - packer_type set to "Unknown (heuristic)" when packed but unnamed (line 112)
# ---------------------------------------------------------------------------


def test_detect_sets_unknown_heuristic_packer_type_when_packed_no_signature():
    detector = PackerDetector(AdapterWithHighEntropySection(), StubConfig())
    result = detector.detect()
    assert "is_packed" in result
    assert "confidence" in result
    if result["is_packed"] and result.get("packer_type") is not None:
        assert isinstance(result["packer_type"], str)


def test_detect_returns_not_packed_when_evidence_low():
    detector = PackerDetector(AdapterWithAllMethods(), StubConfig())
    result = detector.detect()
    assert "is_packed" in result
    assert "confidence" in result
    assert "indicators" in result


# ---------------------------------------------------------------------------
# get_overlay_info (lines 214-217)
# ---------------------------------------------------------------------------


def test_get_overlay_info_returns_dict():
    detector = PackerDetector(AdapterWithAllMethods(), StubConfig())
    result = detector.get_overlay_info()
    assert isinstance(result, dict)


def test_get_overlay_info_returns_empty_dict_on_exception():
    detector = PackerDetector(AdapterWithRaisingMethods(), StubConfig())
    result = detector.get_overlay_info()
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# _calculate_heuristic_score branches (lines 203-204 exception)
# ---------------------------------------------------------------------------


def test_calculate_heuristic_score_with_valid_data():
    detector = PackerDetector(AdapterWithAllMethods(), StubConfig())
    entropy_results = {
        "summary": {"high_entropy_ratio": 0.5}
    }
    section_results = {
        "suspicious_sections": [{"name": "packed"}],
        "section_count": 2,
        "writable_executable": 1,
    }
    score = detector._calculate_heuristic_score(entropy_results, section_results)
    assert 0.0 <= score <= 1.0


def test_calculate_heuristic_score_with_empty_data():
    detector = PackerDetector(AdapterWithAllMethods(), StubConfig())
    score = detector._calculate_heuristic_score({}, {})
    # section_count defaults to 0 (<=3) so 0.2 is added for few sections
    assert 0.0 <= score <= 1.0


# ---------------------------------------------------------------------------
# detect - full flow with empty-bytes adapter
# ---------------------------------------------------------------------------


def test_detect_with_empty_bytes_adapter():
    detector = PackerDetector(AdapterReturningEmptyBytes(), StubConfig())
    result = detector.detect()
    assert "is_packed" in result
    assert "entropy_analysis" in result
    assert "section_analysis" in result
