"""Generate the committed report and batch JSON Schemas."""

from __future__ import annotations

import json
from pathlib import Path

from r2inspect.schemas.batch_v1 import BatchV1
from r2inspect.schemas.report_v1 import ReportV1


def main() -> None:
    schema_dir = Path(__file__).resolve().parents[1] / "r2inspect" / "schemas"
    schema_dir.mkdir(exist_ok=True)
    schemas = {
        "r2inspect.report.v1.schema.json": ReportV1,
        "r2inspect.batch.v1.schema.json": BatchV1,
    }
    for filename, model in schemas.items():
        payload = json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n"
        (schema_dir / filename).write_text(payload, encoding="utf-8")


if __name__ == "__main__":
    main()
