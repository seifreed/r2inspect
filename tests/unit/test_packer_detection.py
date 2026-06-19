from __future__ import annotations

import json

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.modules.packer_detector import PackerDetector
from r2inspect.testing.fake_r2 import FakeR2


def _make_detector(imports=None, sections=None, strings=None, file_info=None, cmd_map=None):
    """Build a PackerDetector backed by FakeR2 with the given data."""
    cmdj_map = {
        "iij": imports if imports is not None else [],
        "iSj": sections if sections is not None else [],
        "izzj": strings if strings is not None else [],
        "ij": file_info if file_info is not None else {},
    }
    fake = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map or {})
    adapter = R2PipeAdapter(fake)
    config = Config()
    return PackerDetector(adapter, config)


def test_packer_upx_signature():
    detector = _make_detector(
        strings=[{"string": "UPX!", "vaddr": 0x1000}],
    )
    result = detector.detect()

    assert result["packer_type"] == "UPX"
    assert result["is_packed"] is True


def test_packer_themida_signature():
    detector = _make_detector(
        strings=[{"string": "Themida", "vaddr": 0x1000}],
    )
    result = detector.detect()

    assert result["packer_type"] == "Themida"
    assert result["is_packed"] is True


def test_packer_vmprotect_signature():
    detector = _make_detector(
        strings=[{"string": "VMProtect", "vaddr": 0x1000}],
    )
    result = detector.detect()

    assert result["packer_type"] == "VMProtect"


def test_packer_aspack_signature():
    detector = _make_detector(
        strings=[{"string": "ASPack", "vaddr": 0x1000}],
    )
    result = detector.detect()

    assert result["packer_type"] == "ASPack"


def test_packer_mpress_signature():
    detector = _make_detector(
        strings=[{"string": "MPRESS", "vaddr": 0x1000}],
    )
    result = detector.detect()

    assert result["packer_type"] == "MPRESS"


def test_packer_high_entropy_section():
    high_entropy_hex = (bytes(range(256)) * 4).hex()
    sections = [
        {
            "name": ".text",
            "vaddr": 0x1000,
            "size": 1000,
            "vsize": 1000,
            "perm": "r-x",
        }
    ]
    detector = _make_detector(
        sections=sections,
        cmd_map={f"p8 1000 @ {0x1000}": high_entropy_hex},
    )
    result = detector.detect()

    assert "entropy_analysis" in result


def test_packer_low_import_count():
    detector = _make_detector(
        imports=[{"name": "LoadLibraryA", "plt": 0x1000, "libname": "kernel32.dll"}],
    )
    result = detector.detect()

    assert isinstance(result["is_packed"], bool)


def test_packer_multiple_indicators():
    high_entropy_hex = (bytes(range(256)) * 4).hex()
    sections = [
        {
            "name": "UPX0",
            "vaddr": 0x1000,
            "size": 1000,
            "vsize": 1000,
            "perm": "rwx",
        }
    ]
    detector = _make_detector(
        sections=sections,
        strings=[{"string": "UPX!", "vaddr": 0x1000}],
        cmd_map={f"p8 1000 @ {0x1000}": high_entropy_hex},
    )
    result = detector.detect()

    assert result["is_packed"] is True
    assert result["confidence"] > 0.5
    assert len(result["indicators"]) > 1


def test_packer_no_indicators():
    low_entropy_hex = (b"\x00" * 1000).hex()
    sections = [
        {
            "name": ".text",
            "vaddr": 0x1000,
            "size": 1000,
            "vsize": 1000,
            "perm": "r-x",
        }
    ]
    imports = [
        {"name": f"Function{i}", "plt": 0x1000 + i, "libname": "kernel32.dll"} for i in range(20)
    ]
    detector = _make_detector(
        imports=imports,
        sections=sections,
        cmd_map={f"p8 1000 @ {0x1000}": low_entropy_hex},
    )
    result = detector.detect()

    assert result["is_packed"] is False


def test_packer_writable_executable_section():
    low_entropy_hex = (b"\x00" * 1000).hex()
    sections = [
        {
            "name": ".text",
            "vaddr": 0x1000,
            "size": 1000,
            "vsize": 1000,
            "perm": "rwx",
        }
    ]
    detector = _make_detector(
        sections=sections,
        cmd_map={f"p8 1000 @ {0x1000}": low_entropy_hex},
    )
    result = detector.detect()

    assert "section_analysis" in result


def test_packer_suspicious_section_name():
    low_entropy_hex = (b"\x00" * 1000).hex()
    sections = [
        {
            "name": "UPX0",
            "vaddr": 0x1000,
            "size": 1000,
            "vsize": 1000,
            "perm": "r-x",
        }
    ]
    detector = _make_detector(
        sections=sections,
        cmd_map={f"p8 1000 @ {0x1000}": low_entropy_hex},
    )
    result = detector.detect()

    assert "section_analysis" in result


def test_packer_confidence_calculation():
    detector = _make_detector(
        strings=[{"string": "UPX!", "vaddr": 0x1000}],
    )
    result = detector.detect()

    assert 0.0 <= result["confidence"] <= 1.0


def test_packer_entropy_analysis_coerces_string_sizes():
    from r2inspect.domain.services.packer_scoring import analyze_entropy

    entropy = analyze_entropy(
        [{"name": ".text", "size": "0x10", "vaddr": "0x1000"}],
        lambda _vaddr, _size: b"\x00" * 16,
        7.0,
    )

    assert entropy[".text"]["size"] == 16


def test_packer_overlay_info():
    detector = _make_detector()
    overlay = detector.get_overlay_info()

    assert isinstance(overlay, dict)


def test_overlay_info_uses_file_offsets_and_core_size():
    # Overlay is computed in file space: total size from core.size and each
    # section ending at paddr + size. Using vaddr (a virtual address) or
    # bin.size (absent for PE) made overlay_size always negative.
    from r2inspect.domain.services.packer_scoring import overlay_info

    file_info = {"core": {"size": 1000}, "bin": {}}
    sections = [
        {"name": ".text", "paddr": 0, "size": 400, "vaddr": 0x1000},
        {"name": ".data", "paddr": 400, "size": 200, "vaddr": 0x2000},
    ]
    info = overlay_info(file_info, sections)
    # last on-disk end = 400 + 200 = 600; overlay = 1000 - 600 = 400.
    assert info["has_overlay"] is True
    assert info["overlay_size"] == 400
    assert info["overlay_ratio"] == 0.4


def test_overlay_info_no_overlay_when_sections_fill_file():
    from r2inspect.domain.services.packer_scoring import overlay_info

    file_info = {"core": {"size": 600}}
    sections = [{"name": ".text", "paddr": 0, "size": 600}]
    info = overlay_info(file_info, sections)
    assert info["has_overlay"] is False
    assert info["overlay_size"] == 0


def test_packer_scoring_skips_malformed_strings_and_sections():
    from r2inspect.domain.services.packer_scoring import analyze_sections, find_packer_string

    signature = find_packer_string([{"string": ["UPX"]}, "bad"], {"UPX": [b"UPX"]})
    sections = analyze_sections(["bad", {"name": ".text", "flags": "x", "size": "big"}])

    assert signature is None
    assert sections["section_count"] == 1
    assert sections["executable_sections"] == 1
    assert sections["suspicious_sections"][0]["size"] == 0


def test_packer_scoring_replaces_missing_section_names():
    from r2inspect.domain.services.packer_scoring import analyze_entropy, analyze_sections

    sections = [{"name": None, "vaddr": 0, "size": 4, "flags": None}]
    entropy = analyze_entropy(sections, lambda _addr, _size: b"\x00" * 4, 7.0)
    summary = analyze_sections(sections)

    assert "unknown" in entropy
    assert "None" not in entropy
    assert summary["suspicious_sections"][0]["name"] == ""
    assert all(entry.get("name") != "None" for entry in summary["suspicious_sections"])


def test_search_signature_hex_skips_non_string_search_output():
    from r2inspect.domain.services.packer_scoring import _search_signature_hex

    def bad_search(_hex_sig: str):
        return None

    assert _search_signature_hex(bad_search, "deadbeef") is False


def test_find_packer_signature_skips_malformed_buckets():
    from r2inspect.domain.services.packer_scoring import find_packer_signature

    assert find_packer_signature(lambda _sig: "", None) is None  # type: ignore[arg-type]
    assert find_packer_signature(lambda _sig: "", {"UPX": "bad"}) is None  # type: ignore[arg-type]


def test_overlay_info_coerces_malformed_section_offsets():
    from r2inspect.domain.services.packer_scoring import overlay_info

    file_info = {"core": {"size": "100"}}
    sections = ["bad", {"name": ".text", "paddr": "bad", "size": 1}]

    info = overlay_info(file_info, sections)

    assert info["has_overlay"] is True
    assert info["overlay_size"] == 99


def test_overlay_info_accepts_hex_string_section_values():
    from r2inspect.domain.services.packer_scoring import overlay_info

    file_info = {"core": {"size": "0x100"}}
    sections = [{"name": ".text", "paddr": "0x40", "size": "0x20"}]

    info = overlay_info(file_info, sections)

    assert info["has_overlay"] is True
    assert info["overlay_size"] == 160
    assert info["overlay_ratio"] == 160 / 256


def test_packer_entropy_threshold():
    detector = _make_detector()

    assert hasattr(detector, "entropy_threshold")
    assert isinstance(detector.entropy_threshold, float)


def test_packer_entropy_logs_read_errors(caplog):
    from r2inspect.domain.services.packer_scoring import calculate_section_entropy

    def boom(_addr: int, _size: int) -> bytes:
        raise RuntimeError("read failed")

    with caplog.at_level("ERROR"):
        entropy = calculate_section_entropy(
            boom,
            {"name": ".text", "vaddr": 0x1000, "size": 16},
        )

    assert entropy == 0.0
    assert "Error calculating section entropy: read failed" in caplog.text


def test_packer_result_structure():
    detector = _make_detector()
    result = detector.detect()

    assert "is_packed" in result
    assert "packer_type" in result
    assert "confidence" in result
    assert "indicators" in result
    assert "entropy_analysis" in result
    assert "section_analysis" in result


def test_packer_armadillo_signature():
    detector = _make_detector(
        strings=[{"string": "Armadillo", "vaddr": 0x1000}],
    )
    result = detector.detect()

    assert result["packer_type"] == "Armadillo"


def test_packer_fsg_signature():
    detector = _make_detector(
        strings=[{"string": "FSG!", "vaddr": 0x1000}],
    )
    result = detector.detect()

    assert result["packer_type"] == "FSG"


def test_packer_pecompact_signature():
    detector = _make_detector(
        strings=[{"string": "PECompact", "vaddr": 0x1000}],
    )
    result = detector.detect()

    assert result["packer_type"] == "PECompact"


def test_packer_multiple_sections():
    low_entropy_hex = (b"\x00" * 1000).hex()
    sections = [
        {
            "name": ".text",
            "vaddr": 0x1000,
            "size": 1000,
            "vsize": 1000,
            "perm": "r-x",
        },
        {
            "name": ".data",
            "vaddr": 0x2000,
            "size": 500,
            "vsize": 500,
            "perm": "rw-",
        },
    ]
    detector = _make_detector(
        sections=sections,
        cmd_map={
            f"p8 1000 @ {0x1000}": low_entropy_hex,
            f"p8 500 @ {0x2000}": (b"\x00" * 500).hex(),
        },
    )
    result = detector.detect()

    assert "section_analysis" in result
