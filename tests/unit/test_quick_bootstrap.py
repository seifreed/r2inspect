from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def _load_quick_bootstrap():
    module_path = Path(__file__).resolve().parents[2] / "scripts" / "quick_bootstrap.py"
    spec = importlib.util.spec_from_file_location("quick_bootstrap", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load quick_bootstrap module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_preflight_fails_when_planning_or_roadmap_missing(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    payload = {
        "roadmap_exists": False,
        "planning_exists": True,
        "task_dir": str(tmp_path / ".planning" / "quick" / "9-sample"),
        "next_num": 9,
        "slug": "sample",
    }
    with pytest.raises(quick_bootstrap.PreflightError):
        quick_bootstrap.run_preflight(payload)


def test_valid_objective_generates_slug_and_2_to_3_checks_in_memory():
    quick_bootstrap = _load_quick_bootstrap()
    checks = quick_bootstrap.build_measurable_checks("Stabilize quick bootstrap behavior")
    assert 2 <= len(checks) <= 3
    slug = quick_bootstrap.slugify("Stabilize quick bootstrap behavior")
    assert slug.startswith("stabilize-quick-bootstrap")


def test_bootstrap_retries_once_after_minimal_autofix(tmp_path):
    quick_bootstrap = _load_quick_bootstrap()
    calls = {"count": 0}

    def failing_runner(_objective: str, _gsd_tools_path: str):
        calls["count"] += 1
        raise quick_bootstrap.BootstrapError("bootstrap failed")

    retried = {"count": 0}

    def minimal_fix(_repo_root: Path):
        retried["count"] += 1
        return ["mkdir -p .planning/quick"]

    with pytest.raises(quick_bootstrap.BootstrapError):
        quick_bootstrap.execute_bootstrap(
            objective="Stabilize quick bootstrap behavior",
            gsd_tools_path="node fake",
            runner=failing_runner,
            autofix=minimal_fix,
            repo_root=tmp_path,
        )

    assert calls["count"] == 2
    assert retried["count"] == 1
