from __future__ import annotations

import os
from pathlib import Path

from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer


def test_ssdeep_parse_output():
    output = "file1, file2 matches (42)\n"
    assert SSDeepAnalyzer._parse_ssdeep_output(output) == 42
    assert SSDeepAnalyzer._parse_ssdeep_output("no match here") is None


def test_ssdeep_write_temp_file_permissions(tmp_path: Path):
    target = tmp_path / "hash.txt"
    SSDeepAnalyzer._write_temp_hash_file(target, "hash, file\n")
    content = target.read_text()
    assert "hash" in content
    mode = os.stat(target).st_mode & 0o777
    assert mode == 0o600
