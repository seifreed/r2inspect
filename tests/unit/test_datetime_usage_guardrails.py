from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SEARCH_ROOTS = (ROOT / "r2inspect", ROOT / "tests")
FORBIDDEN_SNIPPET = "datetime.utcnow("


def test_datetime_utcnow_is_absent() -> None:
    offenders: list[str] = []
    this_file = Path(__file__).resolve()

    for search_root in SEARCH_ROOTS:
        for path in sorted(search_root.rglob("*.py")):
            if path == this_file:
                continue
            relative = path.relative_to(ROOT).as_posix()
            content = path.read_text(encoding="utf-8")
            if FORBIDDEN_SNIPPET in content:
                offenders.append(relative)

    assert offenders == []
