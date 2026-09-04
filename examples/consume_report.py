#!/usr/bin/env python3
"""Validate and consume an r2inspect.report/v1 document."""

from __future__ import annotations

import argparse
import json
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


def consume_report(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    schema = json.loads(
        files("r2inspect.schemas")
        .joinpath("r2inspect.report.v1.schema.json")
        .read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(payload)

    return {
        "schema_version": payload["schema_version"],
        "analyzers": [
            {"analyzer_id": item["analyzer_id"], "status": item["status"]}
            for item in payload.get("analyzers", [])
        ],
        "findings": [
            {
                "rule_id": item["rule_id"],
                "source_analyzer": item["source_analyzer"],
                "evidence": item.get("evidence", []),
            }
            for item in payload.get("findings", [])
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    print(json.dumps(consume_report(args.report), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
