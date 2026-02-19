from __future__ import annotations

from unittest.mock import Mock

from r2inspect.config import Config
from r2inspect.modules.packer_detector import PackerDetector


def test_packer_upx_signature():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_sections = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[
        {"string": "UPX!", "vaddr": 0x1000}
    ])
    adapter.cmdj = Mock(return_value={})
    adapter.cmd = Mock(return_value="")
    adapter.read_bytes = Mock(return_value=b"")
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    result = detector.detect()
    
    assert result["packer_type"] == "UPX"
    assert result["is_packed"] is True


def test_packer_themida_signature():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_sections = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[
        {"string": "Themida", "vaddr": 0x1000}
    ])
    adapter.cmdj = Mock(return_value={})
    adapter.cmd = Mock(return_value="")
    adapter.read_bytes = Mock(return_value=b"")
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    result = detector.detect()
    
    assert result["packer_type"] == "Themida"
    assert result["is_packed"] is True


def test_packer_vmprotect_signature():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_sections = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[
        {"string": "VMProtect", "vaddr": 0x1000}
    ])
    adapter.cmdj = Mock(return_value={})
    adapter.cmd = Mock(return_value="")
    adapter.read_bytes = Mock(return_value=b"")
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    result = detector.detect()
    
    assert result["packer_type"] == "VMProtect"


def test_packer_aspack_signature():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_sections = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[
        {"string": "ASPack", "vaddr": 0x1000}
    ])
    adapter.cmdj = Mock(return_value={})
    adapter.cmd = Mock(return_value="")
    adapter.read_bytes = Mock(return_value=b"")
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    result = detector.detect()
    
    assert result["packer_type"] == "ASPack"


def test_packer_mpress_signature():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_sections = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[
        {"string": "MPRESS", "vaddr": 0x1000}
    ])
    adapter.cmdj = Mock(return_value={})
    adapter.cmd = Mock(return_value="")
    adapter.read_bytes = Mock(return_value=b"")
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    result = detector.detect()
    
    assert result["packer_type"] == "MPRESS"


def test_packer_high_entropy_section():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_sections = Mock(return_value=[
        {
            "name": ".text",
            "vaddr": 0x1000,
            "size": 1000,
            "vsize": 1000,
            "perm": "r-x"
        }
    ])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value={})
    adapter.cmd = Mock(return_value="")
    
    high_entropy_data = bytes(range(256)) * 4
    adapter.read_bytes = Mock(return_value=high_entropy_data)
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    result = detector.detect()
    
    assert "entropy_analysis" in result


def test_packer_low_import_count():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[
        {"name": "LoadLibraryA", "plt": 0x1000, "libname": "kernel32.dll"}
    ])
    adapter.get_sections = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value={})
    adapter.cmd = Mock(return_value="")
    adapter.read_bytes = Mock(return_value=b"")
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    result = detector.detect()
    
    assert isinstance(result["is_packed"], bool)


def test_packer_multiple_indicators():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_sections = Mock(return_value=[
        {
            "name": "UPX0",
            "vaddr": 0x1000,
            "size": 1000,
            "vsize": 1000,
            "perm": "rwx"
        }
    ])
    adapter.get_strings = Mock(return_value=[
        {"string": "UPX!", "vaddr": 0x1000}
    ])
    adapter.cmdj = Mock(return_value={})
    adapter.cmd = Mock(return_value="")
    
    high_entropy_data = bytes(range(256)) * 4
    adapter.read_bytes = Mock(return_value=high_entropy_data)
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    result = detector.detect()
    
    assert result["is_packed"] is True
    assert result["confidence"] > 0.5
    assert len(result["indicators"]) > 1


def test_packer_no_indicators():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[
        {"name": f"Function{i}", "plt": 0x1000 + i, "libname": "kernel32.dll"}
        for i in range(20)
    ])
    adapter.get_sections = Mock(return_value=[
        {
            "name": ".text",
            "vaddr": 0x1000,
            "size": 1000,
            "vsize": 1000,
            "perm": "r-x"
        }
    ])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value={})
    adapter.cmd = Mock(return_value="")
    adapter.read_bytes = Mock(return_value=b"\x00" * 1000)
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    result = detector.detect()
    
    assert result["is_packed"] is False


def test_packer_writable_executable_section():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_sections = Mock(return_value=[
        {
            "name": ".text",
            "vaddr": 0x1000,
            "size": 1000,
            "vsize": 1000,
            "perm": "rwx"
        }
    ])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value={})
    adapter.cmd = Mock(return_value="")
    adapter.read_bytes = Mock(return_value=b"\x00" * 1000)
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    result = detector.detect()
    
    assert "section_analysis" in result


def test_packer_suspicious_section_name():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_sections = Mock(return_value=[
        {
            "name": "UPX0",
            "vaddr": 0x1000,
            "size": 1000,
            "vsize": 1000,
            "perm": "r-x"
        }
    ])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value={})
    adapter.cmd = Mock(return_value="")
    adapter.read_bytes = Mock(return_value=b"\x00" * 1000)
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    result = detector.detect()
    
    assert "section_analysis" in result


def test_packer_confidence_calculation():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_sections = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[
        {"string": "UPX!", "vaddr": 0x1000}
    ])
    adapter.cmdj = Mock(return_value={})
    adapter.cmd = Mock(return_value="")
    adapter.read_bytes = Mock(return_value=b"")
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    result = detector.detect()
    
    assert 0.0 <= result["confidence"] <= 1.0


def test_packer_overlay_info():
    adapter = Mock()
    adapter.get_sections = Mock(return_value=[])
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    overlay = detector.get_overlay_info()
    
    assert isinstance(overlay, dict)


def test_packer_entropy_threshold():
    adapter = Mock()
    config = Config()
    detector = PackerDetector(adapter, config)
    
    assert hasattr(detector, "entropy_threshold")
    assert isinstance(detector.entropy_threshold, float)


def test_packer_result_structure():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_sections = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value={})
    adapter.cmd = Mock(return_value="")
    adapter.read_bytes = Mock(return_value=b"")
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    result = detector.detect()
    
    assert "is_packed" in result
    assert "packer_type" in result
    assert "confidence" in result
    assert "indicators" in result
    assert "entropy_analysis" in result
    assert "section_analysis" in result


def test_packer_armadillo_signature():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_sections = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[
        {"string": "Armadillo", "vaddr": 0x1000}
    ])
    adapter.cmdj = Mock(return_value={})
    adapter.cmd = Mock(return_value="")
    adapter.read_bytes = Mock(return_value=b"")
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    result = detector.detect()
    
    assert result["packer_type"] == "Armadillo"


def test_packer_fsg_signature():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_sections = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[
        {"string": "FSG!", "vaddr": 0x1000}
    ])
    adapter.cmdj = Mock(return_value={})
    adapter.cmd = Mock(return_value="")
    adapter.read_bytes = Mock(return_value=b"")
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    result = detector.detect()
    
    assert result["packer_type"] == "FSG"


def test_packer_pecompact_signature():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_sections = Mock(return_value=[])
    adapter.get_strings = Mock(return_value=[
        {"string": "PECompact", "vaddr": 0x1000}
    ])
    adapter.cmdj = Mock(return_value={})
    adapter.cmd = Mock(return_value="")
    adapter.read_bytes = Mock(return_value=b"")
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    result = detector.detect()
    
    assert result["packer_type"] == "PECompact"


def test_packer_multiple_sections():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.get_sections = Mock(return_value=[
        {
            "name": ".text",
            "vaddr": 0x1000,
            "size": 1000,
            "vsize": 1000,
            "perm": "r-x"
        },
        {
            "name": ".data",
            "vaddr": 0x2000,
            "size": 500,
            "vsize": 500,
            "perm": "rw-"
        }
    ])
    adapter.get_strings = Mock(return_value=[])
    adapter.cmdj = Mock(return_value={})
    adapter.cmd = Mock(return_value="")
    adapter.read_bytes = Mock(return_value=b"\x00" * 1000)
    adapter.get_file_info = Mock(return_value={})
    
    config = Config()
    detector = PackerDetector(adapter, config)
    result = detector.detect()
    
    assert "section_analysis" in result
