"""Deterministic finding-set clustering for analyst triage."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ..schemas.report_v1 import ReportV1


def _similarity(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def cluster_reports(paths: list[Path], threshold: float = 0.5) -> list[list[dict[str, Any]]]:
    reports = [ReportV1.model_validate_json(path.read_text(encoding="utf-8")) for path in paths]
    features = [
        {
            "path": str(path),
            "sample": report.sample.hashes.get("sha256") or report.analysis.id,
            "rule_ids": sorted({finding.rule_id for finding in report.findings}),
        }
        for path, report in zip(paths, reports, strict=True)
    ]
    parents = list(range(len(features)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    for left in range(len(features)):
        for right in range(left + 1, len(features)):
            if (
                _similarity(set(features[left]["rule_ids"]), set(features[right]["rule_ids"]))
                >= threshold
            ):
                root_left, root_right = find(left), find(right)
                if root_left != root_right:
                    parents[root_right] = root_left
    groups: dict[int, list[dict[str, Any]]] = {}
    for index, feature in enumerate(features):
        groups.setdefault(find(index), []).append(feature)
    return [groups[key] for key in sorted(groups)]


def cluster_main() -> None:
    parser = argparse.ArgumentParser(description="Cluster report/v1 files by finding similarity")
    parser.add_argument("reports", nargs="+", type=Path)
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args()
    if not 0.0 <= args.threshold <= 1.0:
        raise SystemExit("threshold must be between 0 and 1")
    print(json.dumps(cluster_reports(args.reports, args.threshold), indent=2, sort_keys=True))


__all__ = ["cluster_main", "cluster_reports"]
