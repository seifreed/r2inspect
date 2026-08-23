"""Generate the committed r2inspect.report/v1 JSON Schema."""

from __future__ import annotations

import json
from pathlib import Path

from r2inspect.schemas.report_v1 import ReportV1


def main() -> None:
    target = (
        Path(__file__).resolve().parents[1]
        / "r2inspect"
        / "schemas"
        / "r2inspect.report.v1.schema.json"
    )
    target.parent.mkdir(exist_ok=True)
    payload = json.dumps(ReportV1.model_json_schema(), indent=2, sort_keys=True) + "\n"
    target.write_text(payload, encoding="utf-8")


if __name__ == "__main__":
    main()
