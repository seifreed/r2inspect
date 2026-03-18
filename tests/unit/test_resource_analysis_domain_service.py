"""Pure domain tests for resource analysis services."""

from r2inspect.domain.services.resource_analysis import (
    build_icon_entries,
    build_manifest_info,
    build_resource_statistics,
    build_suspicious_resources,
    check_resource_embedded_pe,
    check_resource_entropy,
    check_resource_rcdata,
    check_resource_size,
    decode_resource_text,
    is_embedded_pe_header,
    summarize_resource_types,
)


def test_summarize_resource_types_counts_and_sizes() -> None:
    resources = [
        {"type_name": "RT_ICON", "size": 100},
        {"type_name": "RT_ICON", "size": 50},
        {"type_name": "RT_VERSION", "size": 25},
    ]

    summary, total_size = summarize_resource_types(resources)

    assert total_size == 175
    assert {"type": "RT_ICON", "count": 2, "total_size": 150} in summary
    assert {"type": "RT_VERSION", "count": 1, "total_size": 25} in summary


def test_summarize_resource_types_tolerates_non_numeric_size() -> None:
    summary, total_size = summarize_resource_types([{"type_name": "RT_ICON", "size": "100"}])

    assert total_size == 0
    assert summary == [{"type": "RT_ICON", "count": 1, "total_size": 0}]


def test_build_icon_entries_marks_high_entropy_icons() -> None:
    icons = build_icon_entries(
        [
            {"type_name": "RT_ICON", "size": 10, "offset": 1, "entropy": 3.0},
            {"type_name": "RT_GROUP_ICON", "size": 20, "offset": 2, "entropy": 7.8},
            {"type_name": "RT_STRING", "size": 30, "offset": 3, "entropy": 1.0},
        ]
    )

    assert len(icons) == 2
    assert icons[1]["suspicious"] == "High entropy (possibly encrypted)"


def test_decode_resource_text_handles_utf16_utf8_and_empty() -> None:
    assert decode_resource_text("Hello".encode("utf-16le")) == "Hello"
    assert decode_resource_text(b"plain text") == "plain text"
    assert decode_resource_text(b"") is None


def test_build_manifest_info_extracts_flags_and_truncates_content() -> None:
    content = "<requestedExecutionLevel level='requireAdministrator'/> dpiAware highestAvailable"
    result = build_manifest_info(content, 512)

    assert result["size"] == 512
    assert result["requires_admin"] is True
    assert result["requires_elevation"] is True
    assert result["dpi_aware"] is True


def test_build_resource_statistics_summarizes_inventory() -> None:
    resources = [
        {"type_name": "RT_ICON", "size": 100, "entropy": 2.0},
        {"type_name": "RT_VERSION", "size": 200, "entropy": 6.0},
        {"type_name": "RT_VERSION", "size": 0, "entropy": 0.0},
    ]

    result = build_resource_statistics(resources)

    assert result["total_resources"] == 3
    assert result["total_size"] == 300
    assert result["average_size"] == 150
    assert result["max_entropy"] == 6.0
    assert result["unique_types"] == 2


def test_build_resource_statistics_tolerates_partial_entries() -> None:
    result = build_resource_statistics([{"entropy": 1.0}, {"type_name": "RT_ICON"}])

    assert result["total_resources"] == 2
    assert result["total_size"] == 0
    assert result["average_entropy"] == 1.0
    assert result["unique_types"] == 2


def test_individual_suspicious_checks_cover_main_cases() -> None:
    high_entropy = {"name": "res", "type_name": "RT_RCDATA", "size": 1000, "entropy": 7.9}
    large = {"name": "big", "type_name": "RT_STRING", "size": 2 * 1024 * 1024, "entropy": 1.0}
    rcdata = {"name": "blob", "type_name": "RT_RCDATA", "size": 20000, "entropy": 5.0}

    assert check_resource_entropy(high_entropy)
    assert check_resource_size(large)
    assert check_resource_rcdata(rcdata)
    assert (
        check_resource_entropy({"name": "ico", "type_name": "RT_ICON", "size": 10, "entropy": 8.0})
        == []
    )


def test_embedded_pe_detection_uses_header_bytes() -> None:
    resource = {"name": "payload", "type_name": "RT_RCDATA", "size": 5000, "offset": 100}

    assert is_embedded_pe_header([0x4D, 0x5A]) is True
    assert is_embedded_pe_header([0x00, 0x00]) is False
    assert (
        check_resource_embedded_pe(resource, [0x4D, 0x5A])[0]["reason"]
        == "Possible embedded PE file"
    )
    assert check_resource_embedded_pe(resource, [0x00, 0x00]) == []


def test_build_suspicious_resources_reads_headers_only_when_needed() -> None:
    calls: list[str] = []
    resources = [
        {"name": "a", "type_name": "RT_ICON", "size": 100, "entropy": 8.0, "offset": 10},
        {"name": "b", "type_name": "RT_RCDATA", "size": 3000, "entropy": 3.0, "offset": 20},
    ]

    def reader(resource):
        calls.append(resource["name"])
        return [0x4D, 0x5A]

    result = build_suspicious_resources(resources, reader)

    assert calls == ["b"]
    assert any(item["reason"] == "Possible embedded PE file" for item in result)


def test_build_icon_entries_tolerates_partial_icon_entries() -> None:
    icons = build_icon_entries([{"type_name": "RT_ICON"}])

    assert icons == [{"type": "RT_ICON", "size": 0, "offset": 0, "entropy": 0.0}]


def test_build_suspicious_resources_tolerates_partial_entries() -> None:
    result = build_suspicious_resources([{"entropy": 8.0}], lambda _: [])

    assert result == [
        {
            "resource": "UNKNOWN",
            "reason": "High entropy (possibly encrypted/packed)",
            "entropy": 8.0,
            "size": 0,
        }
    ]
