from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def _line_count(relative_path: str) -> int:
    return len((ROOT / relative_path).read_text(encoding="utf-8").splitlines())


def test_binbloom_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/binbloom_analyzer.py") <= 260


def test_rich_header_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/rich_header_analyzer.py") <= 220


def test_overlay_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/overlay_analyzer.py") <= 360


def test_section_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/section_analyzer.py") <= 290


def test_exploit_mitigation_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/exploit_mitigation_analyzer.py") <= 340


def test_yara_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/yara_analyzer.py") <= 300


def test_tlsh_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/tlsh_analyzer.py") <= 300


def test_anti_analysis_detector_stays_thin() -> None:
    assert _line_count("r2inspect/modules/anti_analysis.py") <= 260


def test_crypto_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/crypto_analyzer.py") <= 300


def test_ccbhash_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/ccbhash_analyzer.py") <= 320


def test_bindiff_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/bindiff_analyzer.py") <= 320


def test_telfhash_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/telfhash_analyzer.py") <= 295


def test_simhash_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/simhash_analyzer.py") <= 330


def test_binlex_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/binlex_analyzer.py") <= 350


def test_resource_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/resource_analyzer.py") <= 340


def test_function_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/function_analyzer.py") <= 260


def test_impfuzzy_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/impfuzzy_analyzer.py") <= 240


def test_authenticode_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/authenticode_analyzer.py") <= 260


def test_import_analyzer_stays_thin() -> None:
    assert _line_count("r2inspect/modules/import_analyzer.py") <= 260
