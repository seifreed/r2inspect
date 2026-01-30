"""
Pipeline module for orchestrating analysis stages in r2inspect.

This module implements the Pipeline Pattern for flexible, configurable
analysis workflows. It allows dynamic composition of analysis stages
based on file format, user options, and analyzer availability.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

from .analysis_pipeline import AnalysisPipeline, AnalysisStage

__all__ = [
    "AnalysisPipeline",
    "AnalysisStage",
]

# Note: Stage classes are intentionally not imported here to avoid importing
# optional dependencies (e.g., python-magic) during partial imports. Import
# r2inspect.pipeline.stages directly if you need the concrete Stage classes.
