"""Regression test for loop iteration 6.

Batch statistics read ``result["packer_info"]`` / ``result["crypto_info"]``,
keys the analysis pipeline never produces — it emits ``packer`` (with
``is_packed`` / ``packer_type``) and ``crypto`` (a dict whose ``algorithms``
list holds ``{"algorithm": ...}`` entries). As a result every batch summary
reported ``packers_detected: []`` and ``crypto_patterns: []`` regardless of how
many samples were packed or used crypto.
"""

from __future__ import annotations

from r2inspect.application.batch_stats import collect_batch_statistics


def test_batch_statistics_use_real_pipeline_keys() -> None:
    all_results = {
        "/c/packed.exe": {
            "packer": {"is_packed": True, "packer_type": "UPX"},
            "crypto": {"algorithms": [{"algorithm": "AES"}, {"algorithm": "RC4"}]},
        },
        "/c/clean.exe": {
            "packer": {"is_packed": False, "packer_type": None},
            "crypto": {"algorithms": []},
        },
    }

    stats = collect_batch_statistics(all_results)

    assert stats["packers_detected"] == [{"file": "/c/packed.exe", "packer": "UPX"}]
    assert stats["crypto_patterns"] == [
        {"file": "/c/packed.exe", "pattern": "AES"},
        {"file": "/c/packed.exe", "pattern": "RC4"},
    ]


def test_batch_statistics_packer_type_falls_back_to_unknown() -> None:
    stats = collect_batch_statistics({"/x": {"packer": {"is_packed": True}}})
    assert stats["packers_detected"] == [{"file": "/x", "packer": "Unknown"}]
