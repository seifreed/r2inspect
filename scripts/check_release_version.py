"""Fail a release when its public version declarations disagree."""

from __future__ import annotations

import argparse
import ast
import os
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _module_version(path: Path) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Constant):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        ):
            return str(node.value.value)
    raise ValueError(f"{path} does not declare __version__")


def _report_uses_module_version(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "ToolInfoV1"
        and any(
            keyword.arg == "version"
            and isinstance(keyword.value, ast.Name)
            and keyword.value.id == "__version__"
            for keyword in node.keywords
        )
        for node in ast.walk(tree)
    )


def declared_versions(root: Path = ROOT) -> dict[str, str]:
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    container = re.search(r"^ARG R2INSPECT_VERSION=(\S+)$", dockerfile, re.MULTILINE)
    if container is None:
        raise ValueError("Dockerfile does not declare R2INSPECT_VERSION")
    if 'LABEL org.opencontainers.image.version="${R2INSPECT_VERSION}"' not in dockerfile:
        raise ValueError("Dockerfile does not expose the r2inspect version label")
    module = _module_version(root / "r2inspect" / "__version__.py")
    report = (
        module
        if _report_uses_module_version(root / "r2inspect" / "application" / "report_builder.py")
        else "unwired"
    )
    return {
        "pyproject": str(project["version"]),
        "module": module,
        "container": container.group(1),
        "report": report,
    }


def version_errors(versions: dict[str, str], tag: str | None = None) -> list[str]:
    expected = versions["pyproject"]
    errors = [
        f"{name} declares {version}, expected {expected}"
        for name, version in versions.items()
        if version != expected
    ]
    if tag and tag != f"v{expected}":
        errors.append(f"tag {tag} does not match v{expected}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag")
    args = parser.parse_args()
    tag = args.tag or (
        os.getenv("GITHUB_REF_NAME") if os.getenv("GITHUB_REF_TYPE") == "tag" else None
    )
    versions = declared_versions()
    errors = version_errors(versions, tag)
    if errors:
        parser.error("; ".join(errors))
    print(f"release version {versions['pyproject']} is consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
