from __future__ import annotations

from pathlib import Path

from r2inspect.config_store import ConfigStore


def test_config_store_save_and_load(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    payload = {"general": {"verbose": True}}
    ConfigStore.save(str(path), payload)
    loaded = ConfigStore.load(str(path))
    assert loaded == payload


def test_config_store_load_missing(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    assert ConfigStore.load(str(missing)) is None
