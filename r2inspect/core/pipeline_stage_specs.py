#!/usr/bin/env python3
"""Stage argument and specification helpers for pipeline composition."""

from __future__ import annotations

from typing import Any

from ..pipeline.stages import (
    AnalyzerStage,
    DetectionStage,
    FileInfoStage,
    FormatAnalysisStage,
    FormatDetectionStage,
    HashingStage,
    IndicatorStage,
    MetadataStage,
    SecurityStage,
)


def file_info_args(builder: Any) -> tuple[Any, ...]:
    return (
        builder.adapter,
        builder.filename,
        builder.hash_calculator,
        builder.file_type_detector,
        builder.magic_detector_provider,
    )


def format_detection_args(builder: Any) -> tuple[Any, ...]:
    return (
        builder.adapter,
        builder.filename,
        builder.file_type_detector,
        builder.magic_detector_provider,
    )


def analysis_stage_args(builder: Any) -> tuple[Any, Any, Any, str, Any]:
    return (
        builder.registry,
        builder.adapter,
        builder.config,
        builder.filename,
        builder.analyzer_factory,
    )


def options_stage_args(
    builder: Any, options: dict[str, Any]
) -> tuple[Any, Any, Any, str, dict[str, Any], Any]:
    return (
        builder.registry,
        builder.adapter,
        builder.config,
        builder.filename,
        options,
        builder.analyzer_factory,
    )


def stage_specs(
    builder: Any, options: dict[str, Any]
) -> list[tuple[type[Any], tuple[Any, ...], dict[str, Any]]]:
    analysis_args = analysis_stage_args(builder)
    return [
        (FileInfoStage, file_info_args(builder), {}),
        (FormatDetectionStage, format_detection_args(builder), {}),
        (FormatAnalysisStage, analysis_args, {}),
        (MetadataStage, options_stage_args(builder, options), {}),
        (SecurityStage, analysis_args, {}),
        (HashingStage, analysis_args, {}),
        (DetectionStage, options_stage_args(builder, options), {}),
        (IndicatorStage, (builder.result_aggregator_factory,), {}),
    ]


def normalize_stage_args(
    builder: Any, stage_class: type[Any], args: tuple[Any, ...]
) -> tuple[Any, ...]:
    if stage_class is FileInfoStage and len(args) == 2:
        return (
            *args,
            builder.hash_calculator,
            builder.file_type_detector,
        )
    if stage_class is FormatDetectionStage and len(args) == 2:
        return (*args, builder.file_type_detector)
    if (
        stage_class
        in {
            FormatAnalysisStage,
            MetadataStage,
            SecurityStage,
            HashingStage,
            DetectionStage,
            AnalyzerStage,
        }
        and args
        and args[-1] is not builder.analyzer_factory
    ):
        return (*args, builder.analyzer_factory)
    if stage_class is IndicatorStage and not args:
        return (builder.result_aggregator_factory,)
    return args
