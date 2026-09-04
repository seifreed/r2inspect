"""SQLite-backed analysis job queue."""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any


class JobQueue:
    """Persist and atomically claim analysis jobs."""

    def __init__(self, database: Path) -> None:
        self.database = database
        database.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(database) as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    sample_path TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    result_json TEXT,
                    error TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )""")

    @staticmethod
    def _decode(row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "id": row[0],
            "status": row[1],
            "sample_path": row[2],
            "profile": row[3],
            "result": json.loads(row[4]) if row[4] else None,
            "error": row[5],
            "created_at": row[6],
            "updated_at": row[7],
        }

    def enqueue(self, sample_path: Path, profile: str) -> dict[str, Any]:
        job_id = str(uuid.uuid4())
        now = time.time()
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO jobs VALUES (?, 'queued', ?, ?, NULL, NULL, ?, ?)",
                (job_id, str(sample_path), profile, now, now),
            )
        job = self.get(job_id)
        if job is None:
            raise RuntimeError("failed to read newly queued job")
        return job

    def get(self, job_id: str) -> dict[str, Any] | None:
        with sqlite3.connect(self.database) as connection:
            row = connection.execute(
                """SELECT id, status, sample_path, profile, result_json, error,
                created_at, updated_at FROM jobs WHERE id = ?""",
                (job_id,),
            ).fetchone()
        return self._decode(row) if row else None

    def claim(self) -> dict[str, Any] | None:
        with sqlite3.connect(self.database) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("""SELECT id, status, sample_path, profile, result_json, error,
                created_at, updated_at FROM jobs WHERE status = 'queued'
                ORDER BY created_at, id LIMIT 1""").fetchone()
            if row is None:
                return None
            now = time.time()
            connection.execute(
                "UPDATE jobs SET status = 'running', updated_at = ? WHERE id = ?",
                (now, row[0]),
            )
        return {**self._decode(row), "status": "running", "updated_at": now}

    def complete(self, job_id: str, result: dict[str, Any]) -> None:
        self._finish(job_id, "completed", result=result)

    def fail(self, job_id: str, error: str) -> None:
        self._finish(job_id, "failed", error=error)

    def _finish(
        self,
        job_id: str,
        status: str,
        *,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                """UPDATE jobs SET status = ?, result_json = ?, error = ?, updated_at = ?
                WHERE id = ?""",
                (
                    status,
                    json.dumps(result, sort_keys=True) if result else None,
                    error,
                    time.time(),
                    job_id,
                ),
            )


__all__ = ["JobQueue"]
