"""Targeted coverage for remaining branches in packer_helpers."""

from __future__ import annotations

from r2inspect.modules import packer_helpers


def test_find_packer_signature_returns_none_when_no_hits() -> None:
    result = packer_helpers.find_packer_signature(
        lambda _hex: "",
        {"UPX": [b"UPX!"]},
    )
    assert result is None


def test_find_packer_string_returns_none_for_empty_and_no_match() -> None:
    assert packer_helpers.find_packer_string(None, {"UPX": [b"UPX!"]}) is None

    result = packer_helpers.find_packer_string(
        [{"string": "harmless text"}],
        {"UPX": [b"UPX!"]},
    )
    assert result is None


def test_analyze_entropy_with_no_sections_returns_empty() -> None:
    assert packer_helpers.analyze_entropy(None, lambda _a, _s: b"", 7.0) == {}


def test_calculate_section_entropy_edge_branches() -> None:
    assert (
        packer_helpers.calculate_section_entropy(
            lambda _a, _s: b"",
            {"vaddr": 0x1000, "size": 0},
        )
        == 0.0
    )

    assert (
        packer_helpers.calculate_section_entropy(
            lambda _a, _s: b"",
            {"vaddr": 0x1000, "size": 32},
        )
        == 0.0
    )

    def _raise_reader(_addr: int, _size: int) -> bytes:
        raise RuntimeError("read error")

    assert (
        packer_helpers.calculate_section_entropy(
            _raise_reader,
            {"vaddr": 0x1000, "size": 32},
        )
        == 0.0
    )


def test_analyze_sections_with_none_returns_defaults() -> None:
    result = packer_helpers.analyze_sections(None)
    assert result["section_count"] == 0
    assert result["suspicious_sections"] == []


def test_update_section_info_marks_very_large_section() -> None:
    info = {
        "suspicious_sections": [],
        "section_count": 1,
        "executable_sections": 0,
        "writable_executable": 0,
    }
    packer_helpers.update_section_info(
        info,
        {"name": ".text", "flags": "r--", "size": 10000001},
    )
    assert any(entry.get("reason") == "Very large section" for entry in info["suspicious_sections"])


def test_overlay_info_missing_bin_or_sections_returns_empty() -> None:
    assert packer_helpers.overlay_info(None, [{"vaddr": 0, "size": 1}]) == {}
    assert packer_helpers.overlay_info({"core": {"size": 100}}, [{"vaddr": 0, "size": 1}]) == {}
    assert packer_helpers.overlay_info({"bin": {"size": 100}}, None) == {}
