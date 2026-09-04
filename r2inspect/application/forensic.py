"""Forensic evidence bundle creation."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..__version__ import __version__
from .forensic_support import (
    collect_messages,
    copy_artifact,
    effective_configuration,
    evidence_snippets,
    json_text,
    sha256_file,
    write_artifact,
)


def _preserve_native_output(
    directory: Path, results: dict[str, Any], artifacts: list[dict[str, Any]]
) -> None:
    for name in ("capa", "floss"):
        payload = results.get(name)
        native = payload.get("native_output") if isinstance(payload, dict) else None
        if not isinstance(native, dict):
            continue
        stdout = native.get("stdout")
        stdout_path = native.get("stdout_path")
        if isinstance(stdout_path, str) and Path(stdout_path).is_file():
            artifacts.append(copy_artifact(directory, f"{name}.raw.json", Path(stdout_path)))
            Path(stdout_path).unlink(missing_ok=True)
        elif isinstance(stdout, str):
            artifacts.append(write_artifact(directory, f"{name}.raw.json", stdout))
        stderr = native.get("stderr")
        stderr_path = native.get("stderr_path")
        if isinstance(stderr_path, str) and Path(stderr_path).is_file():
            artifacts.append(copy_artifact(directory, f"{name}.stderr.txt", Path(stderr_path)))
            Path(stderr_path).unlink(missing_ok=True)
        elif isinstance(stderr, str) and stderr:
            artifacts.append(write_artifact(directory, f"{name}.stderr.txt", stderr))
    if "yara_matches" in results:
        artifacts.append(
            write_artifact(directory, "yara.raw.json", json_text(results["yara_matches"]))
        )


def create_forensic_bundle(
    *,
    sample: str | Path,
    adapter: Any,
    config: Any,
    options: dict[str, Any],
    results: dict[str, Any],
    started_at: str,
) -> dict[str, Any]:
    """Persist analysis provenance and return its report-side reference."""
    sample_path = Path(sample).resolve()
    sample_sha256 = sha256_file(sample_path)
    root = Path(os.environ.get("R2INSPECT_EVIDENCE_DIR", "r2inspect-evidence")).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    prefix = f"{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{sample_sha256[:12]}-"
    directory = Path(tempfile.mkdtemp(prefix=prefix, dir=root))
    directory.chmod(0o700)

    safe_results = json.loads(json_text(results))
    snippets = evidence_snippets(sample_path, adapter, safe_results)
    raw_command_log: Any = getattr(adapter, "command_log", lambda: [])()
    command_log: list[dict[str, Any]] = raw_command_log if isinstance(raw_command_log, list) else []
    artifacts = [
        write_artifact(directory, "analysis-results.json", json_text(safe_results)),
        write_artifact(directory, "evidence-snippets.json", json_text(snippets)),
        write_artifact(directory, "radare2-commands.json", json_text(command_log)),
    ]
    if options.get("preserve_artifacts"):
        _preserve_native_output(directory, safe_results, artifacts)

    manifest = {
        "schema_version": "r2inspect.forensic/v1",
        "tool": {"name": "r2inspect", "version": __version__},
        "started_at": started_at,
        "completed_at": datetime.now(UTC).isoformat(),
        "sample": {
            "path": str(sample_path),
            "size": sample_path.stat().st_size,
            "sha256": sample_sha256,
        },
        "effective_configuration": effective_configuration(config, options),
        "radare2_commands": command_log,
        "messages": collect_messages(safe_results),
        "byte_snippets": snippets,
        "artifacts": artifacts,
    }
    manifest_path = directory / "chain-of-custody.json"
    manifest_record = write_artifact(directory, manifest_path.name, json_text(manifest))
    return {
        "evidence_directory": str(directory),
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_record["sha256"],
        "artifacts": artifacts,
    }


__all__ = ["create_forensic_bundle"]
