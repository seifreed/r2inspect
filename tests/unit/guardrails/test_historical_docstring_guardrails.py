from __future__ import annotations

import ast
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
HISTORICAL_ROOT = PROJECT_ROOT / "tests" / "unit" / "historical"
ENFORCED_MARKERS = (
    "analysis_pipeline_",
    "batch_processing_additional_",
    "batch_processing_branches_",
    "batch_processing_helpers_",
    "batch_processing_real_",
    "cli_batch_processing",
    "pipeline_stages_common",
    "pipeline_stages_core",
    "pipeline_stages_detection",
    "pipeline_stages_format",
    "pipeline_stages_hashing",
    "pipeline_stages_metadata",
    "pipeline_stages_security",
)


def test_migrated_historical_files_have_module_docstrings() -> None:
    failures: list[str] = []
    for path in HISTORICAL_ROOT.rglob("test_*.py"):
        if not any(marker in path.name for marker in ENFORCED_MARKERS):
            continue
        module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        docstring = ast.get_docstring(module)
        if not docstring or len(docstring.strip()) < 10:
            failures.append(
                f"{path.relative_to(PROJECT_ROOT)} needs a module docstring explaining intent"
            )
    assert failures == []


def test_migrated_historical_docstrings_state_why_the_file_exists() -> None:
    failures: list[str] = []
    required_terms = ("historical", "regression", "coverage", "transition", "edge", "branch")
    for path in HISTORICAL_ROOT.rglob("test_*.py"):
        if not any(marker in path.name for marker in ENFORCED_MARKERS):
            continue
        module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        docstring = (ast.get_docstring(module) or "").lower()
        if not any(term in docstring for term in required_terms):
            failures.append(
                f"{path.relative_to(PROJECT_ROOT)} needs a docstring that explains why it remains historical"
            )
    assert failures == []
