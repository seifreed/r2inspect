from __future__ import annotations

import json
from pathlib import Path

from r2inspect.config_store import ConfigStore


def test_config_store_save_and_load(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    payload = {"pipeline": {"max_workers": 1}}
    ConfigStore.save(str(config_path), payload)
    loaded = ConfigStore.load(str(config_path))
    assert loaded == payload


def test_config_store_load_invalid(tmp_path: Path) -> None:
    invalid_path = tmp_path / "bad.json"
    invalid_path.write_text("not-json")
    assert ConfigStore.load(str(invalid_path)) is None

    list_path = tmp_path / "list.json"
    list_path.write_text(json.dumps([1, 2, 3]))
    assert ConfigStore.load(str(list_path)) is None
