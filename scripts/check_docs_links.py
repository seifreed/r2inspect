#!/usr/bin/env python3
"""Fail when a public Markdown document links to a missing local path."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

LINK_PATTERN = re.compile(r"(?<!!)\[[^]]+\]\(([^)]+)\)")
EXTERNAL_PREFIXES = ("http://", "https://", "mailto:")


def check_docs(root: Path) -> list[str]:
    documents = sorted(root.glob("*.md")) + sorted((root / "docs").glob("*.md"))
    failures: list[str] = []
    for document in documents:
        text = document.read_text(encoding="utf-8")
        for raw_target in LINK_PATTERN.findall(text):
            target = raw_target.strip().strip("<>").split("#", 1)[0]
            if not target or target.startswith(EXTERNAL_PREFIXES):
                continue
            resolved = (document.parent / unquote(target)).resolve()
            if not resolved.exists():
                failures.append(f"{document.relative_to(root)}: missing {raw_target}")
    return failures


def main() -> int:
    failures = check_docs(Path(__file__).resolve().parents[1])
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("Documentation links are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
