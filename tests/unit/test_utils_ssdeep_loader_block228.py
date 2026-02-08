from __future__ import annotations

from r2inspect.utils.ssdeep_loader import get_ssdeep


def test_get_ssdeep_is_stable() -> None:
    first = get_ssdeep()
    second = get_ssdeep()
    assert first is second
