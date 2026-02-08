from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.core.r2_session import R2Session
from r2inspect.pipeline.stages_format import (
    FileInfoStage,
    FormatAnalysisStage,
    FormatDetectionStage,
)
from r2inspect.registry.default_registry import create_default_registry


def _open_adapter(sample: Path) -> tuple[R2Session, R2PipeAdapter]:
    session = R2Session(str(sample))
    size_mb = sample.stat().st_size / (1024 * 1024)
    r2 = session.open(size_mb)
    return session, R2PipeAdapter(r2)


@pytest.mark.requires_r2
def test_file_info_and_format_detection_pe(samples_dir: Path):
    sample = samples_dir / "hello_pe.exe"
    assert sample.exists()

    session, adapter = _open_adapter(sample)
    try:
        context = {"results": {}, "metadata": {}}
        file_info = FileInfoStage(adapter, str(sample)).execute(context)
        assert "file_info" in file_info

        detection = FormatDetectionStage(adapter, str(sample)).execute(context)
        assert detection["format_detection"]["file_format"] == "PE"
        assert context["metadata"]["file_format"] == "PE"
    finally:
        session.close()


@pytest.mark.requires_r2
def test_format_analysis_stage_pe(samples_dir: Path):
    sample = samples_dir / "hello_pe.exe"
    assert sample.exists()

    session, adapter = _open_adapter(sample)
    try:
        context = {"results": {}, "metadata": {}}
        FileInfoStage(adapter, str(sample)).execute(context)
        FormatDetectionStage(adapter, str(sample)).execute(context)

        registry = create_default_registry()
        config = Config()
        stage = FormatAnalysisStage(registry, adapter, config, str(sample))
        result = stage.execute(context)

        assert "pe_info" in result
        assert result["pe_info"]["format"] == "PE"
    finally:
        session.close()
