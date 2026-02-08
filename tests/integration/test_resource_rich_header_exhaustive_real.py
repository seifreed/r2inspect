from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.core.r2_session import R2Session
from r2inspect.modules.resource_analyzer import ResourceAnalyzer
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer

pytestmark = pytest.mark.requires_r2


@pytest.fixture()
def real_pe_adapter(samples_dir: Path):
    pe_path = samples_dir / "hello_pe.exe"
    session = R2Session(str(pe_path))
    file_size_mb = pe_path.stat().st_size / (1024 * 1024)
    r2 = session.open(file_size_mb)
    adapter = R2PipeAdapter(r2)
    try:
        yield adapter, pe_path
    finally:
        session.close()


@pytest.fixture()
def real_non_pe_path(samples_dir: Path) -> Path:
    return samples_dir / "hello_elf"


def test_resource_analyzer_real_paths(real_pe_adapter) -> None:
    adapter, pe_path = real_pe_adapter
    analyzer = ResourceAnalyzer(adapter)

    result = analyzer.analyze()
    assert isinstance(result, dict)

    resource_dir = analyzer._get_resource_directory()
    assert resource_dir is None or isinstance(resource_dir, dict)

    resources = analyzer._parse_resources()
    assert isinstance(resources, list)

    manual_resources = analyzer._parse_resources_manual()
    assert isinstance(manual_resources, list)

    sections = analyzer._get_rsrc_section()
    assert sections is None or isinstance(sections, dict)

    assert analyzer._is_valid_dir_header([]) is False
    assert analyzer._is_valid_dir_header([0] * 16) is True
    assert analyzer._get_dir_total_entries([0] * 16) == 0

    entry_named = analyzer._parse_dir_entry(0x1000, [0, 0, 0, 0x80, 0, 0, 0, 0], 1)
    assert entry_named is not None
    assert entry_named["is_directory"] is False

    entry_id = analyzer._parse_dir_entry(0x2000, [1, 0, 0, 0, 0, 0, 0, 0], 2)
    assert entry_id is not None
    assert entry_id["type_id"] == 1

    assert analyzer._parse_dir_entry(0x0, [1, 2], 0) is None

    assert analyzer._get_resource_type_name(9999).startswith("UNKNOWN_")

    resource_stub = {"offset": 0, "size": 0, "entropy": 0.0, "hashes": {}}
    analyzer._analyze_resource_data(resource_stub)

    assert analyzer._calculate_entropy([0, 1, 2, 3]) >= 0.0

    result_types: dict[str, object] = {}
    analyzer._analyze_resource_types(
        result_types,
        [
            {"type_name": "RT_ICON", "size": 10},
            {"type_name": "RT_ICON", "size": 20},
            {"type_name": "RT_RCDATA", "size": 5},
        ],
    )
    assert result_types["total_size"] == 35

    version_data = analyzer._parse_version_info(0, 0)
    assert version_data is None

    empty_value = analyzer._read_version_string_value([0] * 10, "FileVersion")
    assert empty_value == ""

    assert analyzer._read_resource_as_string(0, 0) is None

    stats_result: dict[str, object] = {}
    analyzer._calculate_statistics(
        stats_result,
        [
            {"size": 10, "entropy": 2.0, "type_name": "A"},
            {"size": 20, "entropy": 3.0, "type_name": "B"},
        ],
    )
    assert stats_result["statistics"]["total_resources"] == 2

    suspicious_result: dict[str, object] = {}
    analyzer._check_suspicious_resources(
        suspicious_result,
        [
            {"name": "x", "type_name": "RT_RCDATA", "size": 10241, "entropy": 8.0, "offset": 1},
            {"name": "y", "type_name": "RT_ICON", "size": 2, "entropy": 8.0, "offset": 0},
            {"name": "z", "type_name": "UNKNOWN", "size": 2048, "entropy": 1.0, "offset": 1},
        ],
    )
    assert isinstance(suspicious_result["suspicious_resources"], list)

    assert analyzer._check_resource_entropy({"type_name": "RT_ICON", "entropy": 9.0}) == []
    assert analyzer._check_resource_size({"name": "big", "type_name": "RT_RCDATA", "size": 0}) == []
    assert analyzer._check_resource_rcdata({"type_name": "RT_RCDATA", "size": 1}) == []
    assert (
        analyzer._check_resource_embedded_pe(
            {"type_name": "RT_ICON", "size": 0, "offset": 0, "name": ""}
        )
        == []
    )

    assert analyzer._find_pattern([1, 2, 3, 4], [2, 3]) == 1
    assert analyzer._find_pattern([1, 2, 3, 4], [9]) == -1

    # Smoke read using a real offset when available.
    if resources:
        first = next((res for res in resources if res.get("size", 0) > 0), None)
        if first:
            _ = analyzer._read_resource_as_string(first["offset"], first["size"])

    assert pe_path.exists()


def test_rich_header_analyzer_real_paths(
    real_pe_adapter, real_non_pe_path: Path, tmp_path: Path
) -> None:
    adapter, pe_path = real_pe_adapter

    analyzer = RichHeaderAnalyzer(adapter=adapter, filepath=str(pe_path))
    pe_result = analyzer.analyze()
    assert isinstance(pe_result, dict)
    assert pe_result["is_pe"] is True

    non_pe_file = tmp_path / "not_pe.bin"
    non_pe_file.write_bytes(b"\x00\x01\x02\x03")
    non_pe_analyzer = RichHeaderAnalyzer(adapter=None, filepath=str(non_pe_file))
    non_pe_result = non_pe_analyzer.analyze()
    assert non_pe_result["is_pe"] is False
    assert non_pe_result["available"] is False

    assert analyzer._check_magic_bytes() is True

    assert analyzer._bin_info_has_pe({"format": "pe", "class": ""}) is True
    assert analyzer._bin_info_has_pe({"format": "", "class": "pe32"}) is True
    assert analyzer._bin_info_has_pe({"format": "elf", "class": "elf64"}) is False

    class _Entry:
        product_id = 1
        build_version = 2
        count = 3

    assert analyzer._pefile_parse_entry(_Entry())["prodid"] == (1 | (2 << 16))
    assert analyzer._pefile_parse_entry(object()) is None
