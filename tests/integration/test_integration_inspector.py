import json
from pathlib import Path

import pytest

from r2inspect.config import Config
from r2inspect.core.inspector import R2Inspector

pytestmark = pytest.mark.requires_r2

FIXTURES = {
    "hello_macho": "samples/fixtures/hello_macho",
    "hello_pe": "samples/fixtures/hello_pe.exe",
    "hello_elf": "samples/fixtures/hello_elf",
}


def _load_expected(name: str) -> dict:
    expected_path = Path("samples/fixtures/expected") / f"{name}.json"
    return json.loads(expected_path.read_text())


def _minimal_options() -> dict:
    return {
        "analyze_functions": False,
        "detect_packer": False,
        "detect_crypto": False,
    }


def _analyze(path: str) -> dict:
    config = Config(str(Path("/tmp") / "r2inspect_test_config.json"))
    with R2Inspector(path, config=config, verbose=False) as inspector:
        return inspector.analyze(**_minimal_options())


def _assert_expected(results: dict, expected: dict) -> None:
    assert results["format_detection"]["file_format"] == expected["file_format"]
    file_info = results["file_info"]
    assert file_info["name"] == expected["name"]
    assert file_info["size"] == expected["size"]
    assert file_info["md5"] == expected["hashes"]["md5"]
    assert file_info["sha256"] == expected["hashes"]["sha256"]


def test_integration_macho():
    results = _analyze(FIXTURES["hello_macho"])
    expected = _load_expected("hello_macho")
    _assert_expected(results, expected)


def test_integration_pe():
    results = _analyze(FIXTURES["hello_pe"])
    expected = _load_expected("hello_pe")
    _assert_expected(results, expected)


def test_integration_elf():
    results = _analyze(FIXTURES["hello_elf"])
    expected = _load_expected("hello_elf")
    _assert_expected(results, expected)
