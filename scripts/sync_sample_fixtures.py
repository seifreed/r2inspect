#!/usr/bin/env python3
"""Repair or populate samples/fixtures from the canonical fixture source."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from r2inspect.testing.fixtures import resolve_fixture_source_root, sync_legacy_fixtures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        default="",
        help="Path to fixture-binaries repository or legacy fixture root.",
    )
    parser.add_argument(
        "--target",
        default="samples/fixtures",
        help="Target legacy fixtures directory to repair.",
    )
    parser.add_argument(
        "--copy",
        action="store_true",
        help="Copy files instead of symlinking them.",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    source_root = resolve_fixture_source_root(repo_root, args.source)
    if source_root is None:
        print(
            "No fixture source found. Set --source or R2INSPECT_TEST_BINARIES_DIR, "
            "or clone ../r2inspect-test-binaries.",
            file=sys.stderr,
        )
        return 1

    target_dir = (repo_root / args.target).resolve()
    created = sync_legacy_fixtures(target_dir, source_root, copy_files=args.copy)
    print(f"Synchronized {len(created)} fixture paths into {target_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
