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


def test_packer_overlay_info():
    detector = _make_detector()
    overlay = detector.get_overlay_info()

    assert isinstance(overlay, dict)


def test_packer_entropy_threshold():
    detector = _make_detector()

    assert hasattr(detector, "entropy_threshold")
    assert isinstance(detector.entropy_threshold, float)


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
