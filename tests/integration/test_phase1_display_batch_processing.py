from __future__ import annotations

import io
import shutil
from pathlib import Path

import pytest

from r2inspect.cli import display as display_mod
from r2inspect.cli.batch_processing import run_batch_analysis
from r2inspect.config import Config

pytestmark = pytest.mark.requires_r2

FIXTURE_DIR = Path("samples/fixtures")


def test_display_hash_strings_sections_truncation() -> None:
    long_hash = "a" * 80
    results = {
        "bindiff": {
            "comparison_ready": True,
            "filename": "sample",
            "structural_features": {
                "file_type": "PE",
                "file_size": 123,
                "section_count": 10,
                "section_names": [f"sec{i}" for i in range(10)],
                "import_count": 1,
                "export_count": 0,
            },
            "function_features": {},
            "string_features": {
                "total_strings": 120,
                "categorized_strings": {
                    "urls": [],
                    "ips": [],
                    "emails": [],
                    "paths": [],
                },
            },
            "signatures": {
                "structural": "s" * 64,
                "function": "f" * 64,
                "string": "t" * 64,
            },
        },
        "binlex": {
            "available": True,
            "total_functions": 1,
            "analyzed_functions": 1,
            "ngram_sizes": [2],
            "unique_signatures": {2: 1},
            "similar_functions": {2: []},
            "binary_signature": {2: long_hash},
            "top_ngrams": {2: [("X" * 80, 5)]},
        },
        "ccbhash": {
            "available": True,
            "binary_ccbhash": long_hash,
            "total_functions": 1,
            "analyzed_functions": 1,
            "unique_hashes": 1,
            "similar_functions": [],
        },
    }

    buffer = io.StringIO()
    original_file = display_mod.console.file
    try:
        display_mod.console.file = buffer
        display_mod.display_results(results)
    finally:
        display_mod.console.file = original_file
    output = buffer.getvalue()

    assert "Section Names" in output
    assert "... and 5 more" in output
    assert "..." in output


def test_batch_processing_parallel_progress_and_outputs(tmp_path: Path) -> None:
    batch_dir = tmp_path / "batch_fixtures"
    batch_dir.mkdir()

    shutil.copy(FIXTURE_DIR / "hello_pe.exe", batch_dir / "hello_pe.exe")
    shutil.copy(FIXTURE_DIR / "hello_elf", batch_dir / "hello_elf.elf")
    shutil.copy(FIXTURE_DIR / "edge_bad_pe.bin", batch_dir / "edge_bad_pe.bin")

    output_dir = tmp_path / "batch_out"
    config = Config(str(tmp_path / "r2inspect_phase1_batch.json"))

    run_batch_analysis(
        batch_dir=str(batch_dir),
        options={"analyze_functions": False},
        output_json=True,
        output_csv=True,
        output_dir=str(output_dir),
        recursive=True,
        extensions="exe,elf,bin",
        verbose=False,
        config_obj=config,
        auto_detect=False,
        threads=2,
        quiet=True,
    )

    csv_files = list(output_dir.glob("*.csv"))
    json_files = list(output_dir.glob("*.json"))
    assert csv_files
    assert json_files

    expected_json = {
        "hello_pe_analysis.json",
        "hello_elf_analysis.json",
        "edge_bad_pe_analysis.json",
    }
    assert expected_json.issubset({path.name for path in json_files})
