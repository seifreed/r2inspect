from pathlib import Path
from typing import Any

from r2inspect.cli.batch_workers import process_files_parallel


class _Limiter:
    pass


def test_batch_cache_resumes_only_matching_sample_and_config(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    database = tmp_path / "cache.sqlite3"
    calls: list[Path] = []

    def worker(file_path: Path, *_args: Any) -> tuple[Path, dict[str, Any], None]:
        calls.append(file_path)
        return file_path, {"value": len(calls)}, None

    def run(profile: str, resume: bool) -> dict[str, dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        process_files_parallel(
            [sample],
            results,
            [],
            tmp_path,
            tmp_path,
            None,
            {
                "profile": profile,
                "_batch_cache": str(database),
                "_batch_resume": resume,
            },
            False,
            1,
            _Limiter(),
            process_fn=worker,
        )
        return results

    assert run("standard", False)[str(sample)] == {"value": 1}
    assert run("standard", True)[str(sample)] == {"value": 1}
    assert run("deep", True)[str(sample)] == {"value": 2}
    sample.write_bytes(b"changed")
    assert run("standard", True)[str(sample)] == {"value": 3}
    assert calls == [sample, sample, sample]
