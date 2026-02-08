import json
from pathlib import Path

import pytest

from r2inspect.config import Config
from r2inspect.factory import create_inspector
from r2inspect.registry.default_registry import create_default_registry

pytestmark = pytest.mark.requires_r2

EDGE_FIXTURES = {
    "edge_tiny": "samples/fixtures/edge_tiny.bin",
    "edge_high_entropy": "samples/fixtures/edge_high_entropy.bin",
    "edge_bad_pe": "samples/fixtures/edge_bad_pe.bin",
    "edge_packed": "samples/fixtures/edge_packed.bin",
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


def _analyze(path: str, config: Config | None = None) -> dict:
    cfg = config or Config(str(Path("/tmp") / "r2inspect_edge_config.json"))
    with create_inspector(path, config=cfg, verbose=False) as inspector:
        return inspector.analyze(**_minimal_options())


def _assert_expected(results: dict, expected: dict) -> None:
    assert results["format_detection"]["file_format"] == expected["file_format"]
    file_info = results["file_info"]
    assert file_info["name"] == expected["name"]
    assert file_info["size"] == expected["size"]
    assert file_info["md5"] == expected["hashes"]["md5"]
    assert file_info["sha256"] == expected["hashes"]["sha256"]


def test_edge_fixtures_formats():
    for name, path in EDGE_FIXTURES.items():
        results = _analyze(path)
        expected = _load_expected(name)
        _assert_expected(results, expected)


def test_options_disable_outputs():
    results = _analyze("samples/fixtures/hello_macho")
    assert "functions" not in results
    assert "packer" not in results
    assert "crypto" not in results


def test_config_driven_string_filtering(tmp_path):
    config = Config(str(tmp_path / "config.json")).from_dict(
        {"strings": {"min_length": 1000, "max_length": 2000}}
    )
    results = _analyze("samples/fixtures/hello_macho", config=config)
    assert results.get("strings", []) == []


def test_lazy_loader_stats_increase():
    registry = create_default_registry()
    loader = registry._lazy_loader
    assert loader is not None
    before = loader.get_stats()
    _ = registry.get_analyzer_class("pe_analyzer")
    after = loader.get_stats()
    assert after["load_count"] >= before["load_count"] + 1
