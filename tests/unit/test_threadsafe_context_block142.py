from __future__ import annotations

from r2inspect.pipeline.analysis_pipeline import ThreadSafeContext


def test_threadsafe_context_basic_operations():
    ctx = ThreadSafeContext({"a": 1})
    assert ctx.get("a") == 1
    assert ctx.get("missing", 5) == 5

    ctx.set("b", 2)
    ctx.update({"c": 3})

    data = ctx.get_all()
    assert data["a"] == 1
    assert data["b"] == 2
    assert data["c"] == 3
