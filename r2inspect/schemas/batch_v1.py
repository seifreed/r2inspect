"""Stable r2inspect.batch/v1 wire models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from .report_v1 import AnalyzerStatus, WireModel

BATCH_SCHEMA_VERSION: Literal["r2inspect.batch/v1"] = "r2inspect.batch/v1"


class BatchReportReferenceV1(WireModel):
    sample: str
    sha256: str | None = None
    status: AnalyzerStatus
    report_path: str
    analysis_id: str | None = None


class BatchErrorV1(WireModel):
    sample: str
    message: str


class BatchV1(WireModel):
    schema_version: Literal["r2inspect.batch/v1"] = BATCH_SCHEMA_VERSION
    analysis_id: str
    profile: str
    generated_at: datetime
    total: int = Field(ge=0)
    completed: int = Field(ge=0)
    failed: int = Field(ge=0)
    reports: list[BatchReportReferenceV1] = Field(default_factory=list)
    errors: list[BatchErrorV1] = Field(default_factory=list)

    model_config = {
        **WireModel.model_config,
        "json_schema_extra": {
            "$id": "https://r2inspect.dev/schemas/r2inspect.batch.v1.schema.json"
        },
    }


__all__ = [
    "BATCH_SCHEMA_VERSION",
    "BatchErrorV1",
    "BatchReportReferenceV1",
    "BatchV1",
]
