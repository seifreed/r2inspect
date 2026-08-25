"""CLI entry point for backend consensus analysis."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..factory import create_inspector


def consensus_main() -> None:
    parser = argparse.ArgumentParser(description="Compare independent r2inspect backends")
    parser.add_argument("sample", type=Path)
    parser.add_argument("--backend", default="pe-core")
    args = parser.parse_args()
    with create_inspector(
        str(args.sample), backend="consensus", consensus_backend=args.backend
    ) as inspector:
        print(json.dumps(inspector.analyze(), indent=2, sort_keys=True, default=str))


__all__ = ["consensus_main"]
