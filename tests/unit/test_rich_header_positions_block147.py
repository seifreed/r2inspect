from __future__ import annotations

from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer


def test_find_rich_dans_positions():
    data = b"xxDanSyyRichzzDanS"
    rich_positions, dans_positions = RichHeaderAnalyzer._find_rich_dans_positions(data)
    assert rich_positions == [8]
    assert dans_positions == [2]
