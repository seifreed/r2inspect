"""Deterministic finding-set clustering for analyst triage."""

from __future__ import annotations

import argparse
import importlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from ..schemas.report_v1 import ReportV1

HASH_FIELDS = {"tlsh", "ssdeep", "imphash", "impfuzzy", "telfhash", "ccbhash", "simhash"}


def _similarity(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def _hash_similarity(kind: str, left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    if kind == "simhash":
        try:
            bits = max(len(left), len(right)) * 4
            return 1.0 - (int(left, 16) ^ int(right, 16)).bit_count() / bits
        except ValueError:
            return 0.0
    try:
        module = importlib.import_module("ssdeep" if kind == "ssdeep" else "tlsh")
        if kind == "ssdeep":
            return float(module.compare(left, right)) / 100.0
        if kind == "tlsh":
            return max(0.0, 1.0 - float(module.diff(left, right)) / 300.0)
    except (ImportError, ValueError, AttributeError):
        pass
    return 0.0


def _features(report: ReportV1) -> dict[str, Any]:
    hashes = {
        str(item["type"]): str(item["value"])
        for item in report.similarity
        if isinstance(item, dict) and item.get("type") in HASH_FIELDS and item.get("value")
    }
    hashes.update(
        {key: str(value) for key, value in report.sample.hashes.items() if key in HASH_FIELDS}
    )
    return {"rule_ids": {finding.rule_id for finding in report.findings}, "hashes": hashes}


def _feature_similarity(left: dict[str, Any], right: dict[str, Any]) -> float:
    rule_score = _similarity(left["rule_ids"], right["rule_ids"])
    scores = [
        _hash_similarity(kind, left["hashes"].get(kind, ""), right["hashes"].get(kind, ""))
        for kind in HASH_FIELDS
        if left["hashes"].get(kind) and right["hashes"].get(kind)
    ]
    return rule_score if not scores else 0.4 * rule_score + 0.6 * max(scores)


def cluster_reports(paths: list[Path], threshold: float = 0.5) -> list[list[dict[str, Any]]]:
    reports = [ReportV1.model_validate_json(path.read_text(encoding="utf-8")) for path in paths]
    report_features = [_features(report) for report in reports]
    features = [
        {
            "path": str(path),
            "sample": report.sample.hashes.get("sha256") or report.analysis.id,
            "rule_ids": sorted({finding.rule_id for finding in report.findings}),
            "hashes": report_features[index]["hashes"],
        }
        for index, (path, report) in enumerate(zip(paths, reports, strict=True))
    ]
    parents = list(range(len(features)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    for left in range(len(features)):
        for right in range(left + 1, len(features)):
            if _feature_similarity(report_features[left], report_features[right]) >= threshold:
                root_left, root_right = find(left), find(right)
                if root_left != root_right:
                    parents[root_right] = root_left
    groups: dict[int, list[dict[str, Any]]] = {}
    for index, feature in enumerate(features):
        groups.setdefault(find(index), []).append(feature)
    return [groups[key] for key in sorted(groups)]


def index_reports(paths: list[Path], database: Path) -> int:
    """Add or update report features in a persistent SQLite index."""
    reports = [ReportV1.model_validate_json(path.read_text(encoding="utf-8")) for path in paths]
    database.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database) as connection:
        connection.execute("""CREATE TABLE IF NOT EXISTS samples (
                sha256 TEXT PRIMARY KEY,
                report_path TEXT NOT NULL,
                rule_ids TEXT NOT NULL,
                hashes TEXT NOT NULL
            )""")
        for path, report in zip(paths, reports, strict=True):
            sha256 = report.sample.hashes.get("sha256")
            if not sha256:
                raise ValueError(f"report has no sample SHA-256: {path}")
            features = _features(report)
            connection.execute(
                """INSERT INTO samples (sha256, report_path, rule_ids, hashes)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                    report_path=excluded.report_path,
                    rule_ids=excluded.rule_ids,
                    hashes=excluded.hashes""",
                (
                    sha256,
                    str(path),
                    json.dumps(sorted(features["rule_ids"])),
                    json.dumps(features["hashes"], sort_keys=True),
                ),
            )
    return len(reports)


def query_index(database: Path, sha256: str, threshold: float = 0.5) -> list[dict[str, Any]]:
    """Return indexed samples similar to one SHA-256, best match first."""
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT sha256, report_path, rule_ids, hashes FROM samples"
        ).fetchall()
    features = {
        digest: {"rule_ids": set(json.loads(rule_ids)), "hashes": json.loads(hashes)}
        for digest, _path, rule_ids, hashes in rows
    }
    if sha256 not in features:
        raise ValueError(f"sample is not indexed: {sha256}")
    matches = [
        {
            "sha256": digest,
            "report_path": path,
            "similarity": round(_feature_similarity(features[sha256], features[digest]), 6),
        }
        for digest, path, _rule_ids, _hashes in rows
        if digest != sha256 and _feature_similarity(features[sha256], features[digest]) >= threshold
    ]
    return sorted(matches, key=lambda item: (-item["similarity"], item["sha256"]))


def cluster_main() -> None:
    parser = argparse.ArgumentParser(description="Cluster report/v1 files by finding similarity")
    parser.add_argument("reports", nargs="*", type=Path)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--index", type=Path, help="persist report features in a SQLite index")
    parser.add_argument("--query", metavar="SHA256", help="query an existing similarity index")
    args = parser.parse_args()
    if not 0.0 <= args.threshold <= 1.0:
        raise SystemExit("threshold must be between 0 and 1")
    if args.index and args.reports:
        index_reports(args.reports, args.index)
    if args.query:
        if args.index is None:
            raise SystemExit("--query requires --index")
        try:
            result = query_index(args.index, args.query, args.threshold)
        except (OSError, sqlite3.Error, ValueError) as exc:
            raise SystemExit(str(exc)) from exc
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    if not args.reports:
        raise SystemExit("at least one report is required")
    print(json.dumps(cluster_reports(args.reports, args.threshold), indent=2, sort_keys=True))


__all__ = ["cluster_main", "cluster_reports", "index_reports", "query_index"]
