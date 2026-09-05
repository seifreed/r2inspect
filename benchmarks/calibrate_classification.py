#!/usr/bin/env python3
"""Calibrate the function-count classifier against labeled reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def calibrate(manifest_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows: list[tuple[int, bool]] = []
    for case in manifest.get("cases", []):
        if case.get("class") not in {"benign", "malware"}:
            continue
        report = json.loads((manifest_path.parent / case["report"]).read_text(encoding="utf-8"))
        functions = report.get("extras", {}).get("functions", {})
        count = functions.get("total_functions", 0) if isinstance(functions, dict) else 0
        rows.append(
            (int(count) if isinstance(count, int | float) else 0, case["class"] == "malware")
        )
    if not rows or not any(label for _count, label in rows):
        raise ValueError("calibration requires benign and malware reports")
    candidates = sorted({0, *(count for count, _label in rows)})
    results = []
    for threshold in candidates:
        tp = sum(label and count > threshold for count, label in rows)
        fp = sum(not label and count > threshold for count, label in rows)
        fn = sum(label and count <= threshold for count, label in rows)
        tn = sum(not label and count <= threshold for count, label in rows)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        results.append((f1, precision, recall, threshold, tp, fp, fn, tn))
    f1, precision, recall, threshold, tp, fp, fn, tn = max(results)
    return {
        "schema_version": "r2inspect.classification-calibration/v1",
        "corpus_id": manifest.get("corpus_id"),
        "strategy": "function_threshold",
        "cases": len(rows),
        "min_functions": threshold,
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(calibrate(args.manifest), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
