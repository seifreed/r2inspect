"""Comprehensive tests for r2inspect/utils/file_type.py (14% coverage)"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import pytest

from r2inspect.utils.file_type import (
    _bin_info_has_elf,
    _bin_info_has_pe,
    is_elf_file,
    is_pe_file,
)


def test_is_pe_file_with_mz_header(tmp_path: Path):
    pe_file = tmp_path / "test.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)
    
    adapter = Mock()
    r2_instance = Mock()
    
    result = is_pe_file(str(pe_file), adapter, r2_instance)
    assert result is True


def test_is_pe_file_with_info_text_pe_keyword(tmp_path: Path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    adapter = Mock()
    adapter.get_info_text = Mock(return_value="format: PE 32-bit executable")
    r2_instance = Mock()
    
    result = is_pe_file(str(test_file), adapter, r2_instance)
    assert result is True


def test_is_pe_file_with_ij_format_field(tmp_path: Path):
    from unittest.mock import patch
    
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    adapter = Mock()
    adapter.get_info_text = Mock(return_value="")
    r2_instance = Mock()
    
    with patch("r2inspect.utils.file_type.cmdj_helper") as mock_cmdj:
        mock_cmdj.return_value = {"bin": {"format": "pe", "class": "PE32"}}
        result = is_pe_file(str(test_file), adapter, r2_instance)
        assert result is True


def test_is_pe_file_with_ij_class_field(tmp_path: Path):
    from unittest.mock import patch
    
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    adapter = Mock()
    adapter.get_info_text = Mock(return_value="")
    r2_instance = Mock()
    
    with patch("r2inspect.utils.file_type.cmdj_helper") as mock_cmdj:
        mock_cmdj.return_value = {"bin": {"format": "unknown", "class": "PE64"}}
        result = is_pe_file(str(test_file), adapter, r2_instance)
        assert result is True


def test_is_pe_file_no_pe_indicators(tmp_path: Path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
    
    adapter = Mock()
    adapter.get_info_text = Mock(return_value="")
    r2_instance = Mock()
    r2_instance.cmdj = Mock(return_value={"bin": {"format": "elf", "class": "ELF64"}})
    
    result = is_pe_file(str(test_file), adapter, r2_instance)
    assert result is False


def test_is_pe_file_with_none_filepath():
    adapter = Mock()
    adapter.get_info_text = Mock(return_value="format: PE 32-bit")
    r2_instance = Mock()
    
    result = is_pe_file(None, adapter, r2_instance)
    assert result is True


def test_is_pe_file_exception_handling(tmp_path: Path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"\x00" * 10)
    
    adapter = Mock()
    adapter.get_info_text = Mock(side_effect=Exception("Test error"))
    r2_instance = Mock()
    r2_instance.cmdj = Mock(side_effect=Exception("Test error"))
    
    result = is_pe_file(str(test_file), adapter, r2_instance)
    assert result is False


def test_is_elf_file_with_info_text_elf_keyword(tmp_path: Path):
    from unittest.mock import patch
    
    test_file = tmp_path / "test.elf"
    test_file.write_bytes(b"\x00" * 100)
    
    adapter = Mock()
    r2_instance = Mock()
    
    with patch("r2inspect.utils.file_type.cmd_helper") as mock_cmd:
        mock_cmd.return_value = "format: ELF 64-bit LSB executable"
        result = is_elf_file(str(test_file), adapter, r2_instance)
        assert result is True


def test_is_elf_file_with_ij_format_field(tmp_path: Path):
    from unittest.mock import patch
    
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    adapter = Mock()
    r2_instance = Mock()
    
    with patch("r2inspect.utils.file_type.cmd_helper") as mock_cmd:
        with patch("r2inspect.utils.file_type.cmdj_helper") as mock_cmdj:
            mock_cmd.return_value = ""
            mock_cmdj.return_value = {"bin": {"format": "elf", "type": "EXEC"}}
            result = is_elf_file(str(test_file), adapter, r2_instance)
            assert result is True


def test_is_elf_file_with_magic_bytes(tmp_path: Path):
    from unittest.mock import patch
    
    test_file = tmp_path / "test.elf"
    test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
    
    adapter = Mock()
    r2_instance = Mock()
    
    with patch("r2inspect.utils.file_type.cmd_helper") as mock_cmd:
        with patch("r2inspect.utils.file_type.cmdj_helper") as mock_cmdj:
            mock_cmd.return_value = ""
            mock_cmdj.return_value = {"bin": {"format": "unknown"}}
            result = is_elf_file(str(test_file), adapter, r2_instance)
            assert result is True


def test_is_elf_file_no_elf_indicators(tmp_path: Path):
    from unittest.mock import patch
    
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"MZ" + b"\x00" * 100)
    
    adapter = Mock()
    r2_instance = Mock()
    
    with patch("r2inspect.utils.file_type.cmd_helper") as mock_cmd:
        with patch("r2inspect.utils.file_type.cmdj_helper") as mock_cmdj:
            mock_cmd.return_value = "format: PE 32-bit"
            mock_cmdj.return_value = {"bin": {"format": "pe", "class": "PE32"}}
            result = is_elf_file(str(test_file), adapter, r2_instance)
            assert result is False


def test_is_elf_file_exception_handling(tmp_path: Path):
    from unittest.mock import patch
    
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"\x00" * 10)
    
    adapter = Mock()
    r2_instance = Mock()
    
    with patch("r2inspect.utils.file_type.cmd_helper") as mock_cmd:
        with patch("r2inspect.utils.file_type.cmdj_helper") as mock_cmdj:
            mock_cmd.side_effect = Exception("Test error")
            mock_cmdj.side_effect = Exception("Test error")
            result = is_elf_file(str(test_file), adapter, r2_instance)
            assert result is False


def test_is_elf_file_with_none_filepath():
    from unittest.mock import patch
    
    adapter = Mock()
    r2_instance = Mock()
    
    with patch("r2inspect.utils.file_type.cmd_helper") as mock_cmd:
        mock_cmd.return_value = "format: ELF 64-bit"
        result = is_elf_file(None, adapter, r2_instance)
        assert result is True


def test_bin_info_has_pe_format_field():
    bin_info = {"format": "pe", "class": "PE32"}
    result = _bin_info_has_pe(bin_info)
    assert result is True


def test_bin_info_has_pe_class_field():
    bin_info = {"format": "unknown", "class": "pe64"}
    result = _bin_info_has_pe(bin_info)
    assert result is True


def test_bin_info_has_pe_case_insensitive():
    bin_info = {"format": "PE32", "class": "UNKNOWN"}
    result = _bin_info_has_pe(bin_info)
    assert result is True


def test_bin_info_has_pe_no_pe():
    bin_info = {"format": "elf", "class": "ELF64"}
    result = _bin_info_has_pe(bin_info)
    assert result is False


def test_bin_info_has_pe_empty_dict():
    bin_info = {}
    result = _bin_info_has_pe(bin_info)
    assert result is False


def test_bin_info_has_elf_format_field():
    bin_info = {"format": "elf", "type": "EXEC", "class": "ELF64"}
    result = _bin_info_has_elf(bin_info)
    assert result is True


def test_bin_info_has_elf_type_field():
    bin_info = {"format": "unknown", "type": "elf64", "class": "UNKNOWN"}
    result = _bin_info_has_elf(bin_info)
    assert result is True


def test_bin_info_has_elf_class_field():
    bin_info = {"format": "unknown", "type": "EXEC", "class": "elf"}
    result = _bin_info_has_elf(bin_info)
    assert result is True


def test_bin_info_has_elf_case_insensitive():
    bin_info = {"format": "ELF64", "type": "UNKNOWN", "class": "UNKNOWN"}
    result = _bin_info_has_elf(bin_info)
    assert result is True


def test_bin_info_has_elf_no_elf():
    bin_info = {"format": "pe", "type": "EXEC", "class": "PE32"}
    result = _bin_info_has_elf(bin_info)
    assert result is False


def test_bin_info_has_elf_empty_dict():
    bin_info = {}
    result = _bin_info_has_elf(bin_info)
    assert result is False


def test_is_pe_file_read_permission_error(tmp_path: Path):
    import os
    
    pe_file = tmp_path / "test.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)
    os.chmod(pe_file, 0o000)
    
    adapter = Mock()
    adapter.get_info_text = Mock(return_value="")
    r2_instance = Mock()
    r2_instance.cmdj = Mock(return_value={})
    
    try:
        result = is_pe_file(str(pe_file), adapter, r2_instance)
        assert result is False
    finally:
        os.chmod(pe_file, 0o644)


def test_is_elf_file_read_permission_error(tmp_path: Path):
    import os
    from unittest.mock import patch
    
    elf_file = tmp_path / "test.elf"
    elf_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
    os.chmod(elf_file, 0o000)
    
    adapter = Mock()
    r2_instance = Mock()
    
    try:
        with patch("r2inspect.utils.file_type.cmd_helper") as mock_cmd:
            with patch("r2inspect.utils.file_type.cmdj_helper") as mock_cmdj:
                mock_cmd.return_value = ""
                mock_cmdj.return_value = {}
                result = is_elf_file(str(elf_file), adapter, r2_instance)
                assert result is False
    finally:
        os.chmod(elf_file, 0o644)


def test_is_pe_file_custom_logger(tmp_path: Path):
    pe_file = tmp_path / "test.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)
    
    adapter = Mock()
    r2_instance = Mock()
    custom_logger = Mock()
    
    result = is_pe_file(str(pe_file), adapter, r2_instance, logger=custom_logger)
    assert result is True
    custom_logger.debug.assert_called()


def test_is_elf_file_custom_logger(tmp_path: Path):
    from unittest.mock import patch
    
    elf_file = tmp_path / "test.elf"
    elf_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
    
    adapter = Mock()
    r2_instance = Mock()
    custom_logger = Mock()
    
    with patch("r2inspect.utils.file_type.cmd_helper") as mock_cmd:
        with patch("r2inspect.utils.file_type.cmdj_helper") as mock_cmdj:
            mock_cmd.return_value = ""
            mock_cmdj.return_value = {}
            result = is_elf_file(str(elf_file), adapter, r2_instance, logger=custom_logger)
            assert result is True
