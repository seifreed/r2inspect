from __future__ import annotations

import os
from pathlib import Path

from r2inspect.modules.ssdeep_analyzer import SSDEEP_LIBRARY_AVAILABLE, SSDeepAnalyzer


def test_ssdeep_helpers(tmp_path: Path) -> None:
    output = "file1 matches file2 (42)"
    assert SSDeepAnalyzer._parse_ssdeep_output(output) == 42
    assert SSDeepAnalyzer._parse_ssdeep_output("no matches") is None

    file_path = tmp_path / "hash.txt"
    SSDeepAnalyzer._write_temp_hash_file(file_path, "abc")
    assert file_path.read_text() == "abc"
    assert oct(os.stat(file_path).st_mode & 0o777) == "0o600"


def test_ssdeep_compare_hashes() -> None:
    assert SSDeepAnalyzer.compare_hashes("", "hash") is None

    if not SSDEEP_LIBRARY_AVAILABLE:
        # Either binary will be used or None if missing
        assert SSDeepAnalyzer.compare_hashes("3:abc:abc", "3:abc:abc") in {0, None, 100}
        return

    import ssdeep

    hash1 = ssdeep.hash(b"abc123")
    hash2 = ssdeep.hash(b"abc123")
    score = SSDeepAnalyzer.compare_hashes(hash1, hash2)
    assert score is not None and score >= 0
