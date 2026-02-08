from __future__ import annotations

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.resource_analyzer import ResourceAnalyzer

PE_FIXTURE = "samples/fixtures/hello_pe.exe"


def test_resource_analyzer_real_fixture_details() -> None:
    r2 = r2pipe.open(PE_FIXTURE)
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = ResourceAnalyzer(adapter)
        result = analyzer.analyze()
    finally:
        r2.quit()

    assert "has_resources" in result
    assert "resource_types" in result
    assert "statistics" in result
    if result.get("has_resources"):
        assert "resources" in result
        assert isinstance(result["total_resources"], int)
