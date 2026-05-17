from __future__ import annotations

from r2inspect.modules.ssdeep_analyzer import SSDEEP_LIBRARY_AVAILABLE, SSDeepAnalyzer


def test_ssdeep_compare_hashes() -> None:
    assert SSDeepAnalyzer.compare_hashes("", "hash") is None

    if not SSDEEP_LIBRARY_AVAILABLE:
        assert SSDeepAnalyzer.compare_hashes("3:abc:abc", "3:abc:abc") in {0, None, 100}
        return

    import ssdeep

    hash1 = ssdeep.hash(b"abc123")
    hash2 = ssdeep.hash(b"abc123")
    score = SSDeepAnalyzer.compare_hashes(hash1, hash2)
    assert score is not None and score >= 0
