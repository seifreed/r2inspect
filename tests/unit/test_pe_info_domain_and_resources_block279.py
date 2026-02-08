from __future__ import annotations

import pytest

from r2inspect.modules import pe_info_domain, pe_resources


class DummyAdapter:
    def __init__(self, cmdj_result=None, cmd_result="") -> None:
        self.cmdj_result = cmdj_result
        self.cmd_result = cmd_result

    def get_resources_info(self):
        return self.cmdj_result

    def get_pe_version_info_text(self):
        return self.cmd_result


class DummyLogger:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)


@pytest.mark.unit
def test_pe_info_domain_helpers() -> None:
    assert pe_info_domain.determine_pe_file_type({"class": "PE32"}, None, "DLL file") == "DLL"
    assert pe_info_domain.determine_pe_file_type({"class": "PE32"}, None, "executable") == "EXE"
    assert pe_info_domain.determine_pe_file_type({"class": "PE32"}, None, "driver") == "SYS"
    assert pe_info_domain.determine_pe_file_type({"class": "CUSTOM"}, None, None) == "CUSTOM"

    assert pe_info_domain.determine_pe_format({"format": "PE32+"}, None) == "PE32+"
    assert pe_info_domain.determine_pe_format({"bits": 32}, None) == "PE32"
    assert pe_info_domain.determine_pe_format({"bits": 64}, None) == "PE32+"
    assert pe_info_domain.determine_pe_format({}, {"optional_header": {"Magic": 0x10B}}) == "PE32"

    assert pe_info_domain.normalize_pe_format("pe32+") == "PE"
    assert pe_info_domain.normalize_pe_format("Unknown") == "PE"
    assert pe_info_domain.normalize_pe_format("Other") == "Other"

    assert pe_info_domain.compute_entry_point({"baddr": 1, "boffset": 2}, None) == 3
    assert pe_info_domain.compute_entry_point({}, [{"vaddr": 99}]) == 99

    info = pe_info_domain.apply_optional_header_info(
        {"image_base": 0}, {"optional_header": {"ImageBase": 4096, "AddressOfEntryPoint": 16}}
    )
    assert info["image_base"] == 4096
    assert info["entry_point"] == 4096 + 16

    assert pe_info_domain.characteristics_from_header(None) is None
    assert pe_info_domain.characteristics_from_header(
        {"file_header": {"Characteristics": 0x2002}}
    ) == {"is_dll": True, "is_executable": True}

    resources = pe_info_domain.normalize_resource_entries([{"name": "A", "type": "T"}])
    assert resources[0]["name"] == "A"

    version = pe_info_domain.parse_version_info_text("Company=Test\nVersion=1")
    assert version["Company"] == "Test"

    chars = pe_info_domain.characteristics_from_bin({"type": "DLL"}, "file.dll")
    assert chars["is_dll"] is True

    assert pe_info_domain.build_subsystem_info("Windows GUI")["gui_app"] is True
    assert pe_info_domain.build_subsystem_info("Console")["gui_app"] is False
    assert pe_info_domain.build_subsystem_info("Other")["gui_app"] is None


@pytest.mark.unit
def test_pe_resources_helpers() -> None:
    logger = DummyLogger()

    adapter = DummyAdapter(cmdj_result=[{"name": "A", "type": "T", "size": 1, "lang": "en"}])
    resources = pe_resources.get_resource_info(adapter, logger)
    assert resources[0]["name"] == "A"

    adapter = DummyAdapter(cmdj_result=None, cmd_result="Company=Test")
    version = pe_resources.get_version_info(adapter, logger)
    assert version["Company"] == "Test"
