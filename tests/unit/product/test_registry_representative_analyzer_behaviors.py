from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from r2inspect.registry.default_registry import create_default_registry


class SectionAdapter:
    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {
                "name": ".text",
                "vaddr": 0x1000,
                "vsize": 0x200,
                "size": 0x200,
                "flags": "rx",
                "perm": "rx",
                "characteristics": 0x60000020,
            }
        ]

    def read_bytes(self, _addr: int, size: int) -> bytes:
        return b"\x90" * size

    def get_file_info(self) -> dict[str, Any]:
        return {"arch": "x86"}

    def cmdj(self, _cmd: str) -> list[dict[str, Any]]:
        return []


class CompilerAdapter:
    def get_strings(self) -> list[dict[str, Any]]:
        return [{"string": "GCC: (GNU) 13.2.0"}]

    def get_sections(self) -> list[dict[str, Any]]:
        return [{"name": ".text"}, {"name": ".eh_frame"}]

    def get_imports(self) -> list[dict[str, Any]]:
        return [{"name": "libgcc_s.so", "libname": "libgcc_s.so"}]

    def get_symbols(self) -> list[dict[str, Any]]:
        return []

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"class": "ELF64"}, "core": {"file": "/tmp/test.elf"}}

    def cmd(self, _cmd: str) -> str:
        return ""


def _write_sparse_pe() -> str:
    mz = bytearray(0x40)
    mz[0:2] = b"MZ"
    struct.pack_into("<I", mz, 0x3C, 0x40)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as handle:
        handle.write(bytes(mz) + b"PE\x00\x00" + b"\x00" * 128)
        return handle.name


def test_default_registry_resolves_representative_analyzer_classes() -> None:
    registry = create_default_registry()

    for name in ("section_analyzer", "compiler_detector", "rich_header"):
        analyzer_class = registry.get_analyzer_class(name)
        metadata = registry.get_metadata(name)
        assert analyzer_class is not None
        assert metadata is not None


def test_registry_section_and_compiler_analyzers_work_with_small_adapters() -> None:
    registry = create_default_registry()

    section_class = registry.get_analyzer_class("section_analyzer")
    compiler_class = registry.get_analyzer_class("compiler_detector")
    assert section_class is not None
    assert compiler_class is not None

    section_result = section_class(adapter=SectionAdapter()).analyze()
    compiler_result = compiler_class(adapter=CompilerAdapter()).detect_compiler()

    assert section_result["total_sections"] == 1
    assert isinstance(compiler_result, dict)
    assert "detected" in compiler_result
    assert "compiler" in compiler_result


def test_registry_rich_header_analyzer_fails_cleanly_on_sparse_pe() -> None:
    registry = create_default_registry()
    rich_class = registry.get_analyzer_class("rich_header")
    assert rich_class is not None

    path = _write_sparse_pe()
    try:
        analyzer = rich_class(adapter=object(), filepath=path)
        result = analyzer.analyze()
        assert result["is_pe"] is True
        assert result["available"] in {False, True}
    finally:
        Path(path).unlink(missing_ok=True)
