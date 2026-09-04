"""Persistent cache for resumable batch analysis."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _config_digest(options: dict[str, Any], config: Any) -> str:
    config_data = config.to_dict() if hasattr(config, "to_dict") else config
    payload = {
        "options": {key: value for key, value in options.items() if not key.startswith("_batch_")},
        "config": config_data,
    }
    encoded = json.dumps(payload, default=str, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


class BatchCache:
    """SQLite result cache keyed by sample and effective configuration."""

    def __init__(self, database: Path, options: dict[str, Any], config: Any) -> None:
        self.database = database
        self.config_digest = _config_digest(options, config)
        self._sample_digests: dict[Path, str] = {}
        database.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(database) as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS batch_results (
                    sha256 TEXT NOT NULL,
                    config_digest TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    PRIMARY KEY (sha256, config_digest)
                )""")

    def _sample_digest(self, path: Path) -> str:
        if path not in self._sample_digests:
            self._sample_digests[path] = _digest_file(path)
        return self._sample_digests[path]

    def get(self, path: Path) -> dict[str, Any] | None:
        with sqlite3.connect(self.database) as connection:
            row = connection.execute(
                "SELECT result_json FROM batch_results WHERE sha256 = ? AND config_digest = ?",
                (self._sample_digest(path), self.config_digest),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, path: Path, result: dict[str, Any]) -> None:
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                """INSERT OR REPLACE INTO batch_results (sha256, config_digest, result_json)
                VALUES (?, ?, ?)""",
                (
                    self._sample_digest(path),
                    self.config_digest,
                    json.dumps(result, default=str, sort_keys=True),
                ),
            )


__all__ = ["BatchCache"]
