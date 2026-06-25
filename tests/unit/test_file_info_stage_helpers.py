"""Unit coverage for FileInfoStage's pure detection/arch helpers."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from r2inspect.pipeline.stages_format import FileInfoStage, FormatDetectionStage


def _detection(**overrides: Any) -> dict[str, Any]:
    base = {
        "confidence": 0.9,
        "file_format": "PE32",
        "format_category": "executable",
        "potential_threat": False,
        "architecture": "Unknown",
        "bits": "Unknown",
    }
    base.update(overrides)
    return base


def test_enhanced_detection_info_below_threshold_is_empty() -> None:
    assert FileInfoStage._enhanced_detection_info(_detection(confidence=0.5)) == {}


def test_enhanced_detection_info_includes_known_arch_and_bits() -> None:
    info = FileInfoStage._enhanced_detection_info(
        _detection(potential_threat=True, architecture="x86", bits="64")
    )
    assert info["precise_format"] == "PE32"
    assert info["threat_level"] == "High"
    assert info["detected_architecture"] == "x86"
    assert info["detected_bits"] == "64"


def test_enhanced_detection_info_omits_unknown_arch_and_bits() -> None:
    info = FileInfoStage._enhanced_detection_info(_detection())
    assert info["threat_level"] == "Low"
    assert "detected_architecture" not in info
    assert "detected_bits" not in info


def test_enhanced_detection_info_rejects_malformed_input() -> None:
    assert FileInfoStage._enhanced_detection_info({}) == {}
    assert FileInfoStage._enhanced_detection_info({"confidence": "bad"}) == {}


def test_format_detection_stage_ignores_basic_magic_detector_errors() -> None:
    class _NullAdapter:
        def get_file_info(self) -> dict[str, Any]:
            return {}

    class _ExplodingDesc:
        def from_file(self, _path: str) -> str:
            raise PermissionError("magic failed")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"\x00" * 32)
        path = Path(f.name)
    try:
        stage = FormatDetectionStage(
            adapter=_NullAdapter(),
            filename=str(path),
            magic_detector_provider=type(
                "_Provider",
                (),
                {"get_detectors": staticmethod(lambda: (None, _ExplodingDesc()))},
            )(),
        )
        try:
            stage._detect_via_basic_magic()
            raise AssertionError("expected PermissionError")
        except PermissionError:
            pass
    finally:
        path.unlink(missing_ok=True)


def test_bin_arch_info_empty_without_bin() -> None:
    assert FileInfoStage._bin_arch_info(None) == {}
    assert FileInfoStage._bin_arch_info({}) == {}


def test_bin_arch_info_non_dict_bin_is_ignored() -> None:
    assert FileInfoStage._bin_arch_info({"bin": "not-a-dict"}) == {}


def test_bin_arch_info_promotes_x86_64() -> None:
    info = FileInfoStage._bin_arch_info({"bin": {"arch": "x86", "bits": 64, "endian": "little"}})
    assert info == {"architecture": "x86-64", "bits": 64, "endian": "little"}


def test_bin_arch_info_keeps_other_arch() -> None:
    info = FileInfoStage._bin_arch_info({"bin": {"arch": "arm", "bits": 32}})
    assert info == {"architecture": "arm", "bits": 32, "endian": "Unknown"}
