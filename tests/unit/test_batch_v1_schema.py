from __future__ import annotations

import json
from pathlib import Path

from r2inspect.schemas.batch_v1 import BatchV1


def test_committed_batch_schema_matches_model() -> None:
    schema_path = (
        Path(__file__).resolve().parents[2]
        / "r2inspect"
        / "schemas"
        / "r2inspect.batch.v1.schema.json"
    )
    assert json.loads(schema_path.read_text(encoding="utf-8")) == BatchV1.model_json_schema()
