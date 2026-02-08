from __future__ import annotations

import json
from pathlib import Path

from r2inspect.config import Config


def test_config_load_save_and_overrides(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config = Config(config_path=str(config_path))
    assert config.typed_config.general.verbose is False

    config.set("general", "verbose", True)
    assert config.typed_config.general.verbose is True

    config.apply_overrides({"output": {"json_indent": 4}})
    assert config.typed_config.output.json_indent == 4

    config.save_config()
    raw = json.loads(config_path.read_text())
    assert raw["general"]["verbose"] is True

    new_config = Config(config_path=str(config_path))
    assert new_config.typed_config.general.verbose is True


def test_config_from_dict(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config = Config(config_path=str(config_path))
    new_config = config.from_dict({"general": {"verbose": True}})
    assert new_config.typed_config.general.verbose is True
