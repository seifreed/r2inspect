#!/usr/bin/env python3
"""Calibrate the report clustering threshold against labeled sample pairs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from r2inspect.application.report_similarity import feature_similarity, report_features
from r2inspect.schemas.report_v1 import ReportV1


def calibrate(manifest_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = manifest.get("cases")
    if not isinstance(cases, list) or len(cases) < 2:
        raise ValueError("calibration manifest requires at least two cases")
    labeled: list[tuple[str, dict[str, Any]]] = []
    radare2_versions = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("cluster"), str):
            raise ValueError("every calibration case requires a cluster label")
        report = ReportV1.model_validate_json(
            (manifest_path.parent / case["report"]).read_text(encoding="utf-8")
        )
        labeled.append((case["cluster"], report_features(report)))
        radare2_versions.add(report.tool.radare2_version or "unknown")
    pairs = [
        (feature_similarity(left[1], right[1]), left[0] == right[0])
        for index, left in enumerate(labeled)
        for right in labeled[index + 1 :]
    ]
    positive_pairs = sum(expected for _score, expected in pairs)
    if not positive_pairs:
        raise ValueError("calibration requires at least one same-cluster pair")
    candidates = sorted({0.0, 1.0, *(score for score, _expected in pairs)})
    results = []
    for threshold in candidates:
        tp = sum(score >= threshold and expected for score, expected in pairs)
        fp = sum(score >= threshold and not expected for score, expected in pairs)
        fn = positive_pairs - tp
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / positive_pairs
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        results.append((f1, precision, recall, threshold, tp, fp, fn))
    f1, precision, recall, threshold, tp, fp, fn = max(results)
    return {
        "schema_version": "r2inspect.clustering-calibration/v1",
        "corpus_id": manifest.get("corpus_id"),
        "profile": manifest.get("profile"),
        "radare2_versions": sorted(radare2_versions),
        "cases": len(labeled),
        "pairs": len(pairs),
        "positive_pairs": positive_pairs,
        "threshold": threshold,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(calibrate(args.manifest), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
