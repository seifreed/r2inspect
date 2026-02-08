from __future__ import annotations

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.simhash_analyzer import SIMHASH_AVAILABLE, SimHashAnalyzer

PE_FIXTURE = "samples/fixtures/hello_pe.exe"


def test_simhash_analyze_and_similarity() -> None:
    if not SIMHASH_AVAILABLE:
        return

    r2 = r2pipe.open(PE_FIXTURE)
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = SimHashAnalyzer(adapter, PE_FIXTURE)
        result = analyzer.analyze()
    finally:
        r2.quit()

    assert "available" in result
    if result.get("available") and result.get("combined_simhash"):
        current_hash = result["combined_simhash"]["hash"]
        similarity = analyzer.calculate_similarity(current_hash)
        assert similarity.get("similarity_level") == "identical"
    else:
        assert result.get("available") is True
