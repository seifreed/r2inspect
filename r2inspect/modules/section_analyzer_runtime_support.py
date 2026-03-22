"""Runtime helpers for section analysis seams."""

from __future__ import annotations

from typing import Any, cast

from ..domain.services.binary_helpers import shannon_entropy


def analyze_sections(analyzer: Any, logger: Any) -> list[dict[str, Any]]:
    sections_info = []

    try:
        sections = analyzer._cmd_list("iSj")

        if sections and isinstance(sections, list):
            for section in sections:
                if isinstance(section, dict):
                    sections_info.append(analyzer._analyze_single_section(section))
                else:
                    logger.warning("Unexpected section type: %s", type(section))

    except (RuntimeError, TypeError, ValueError, AttributeError, OSError) as exc:
        logger.error("Error analyzing sections from iSj: %s", exc)

    return sections_info


def calculate_entropy(analyzer: Any, section: dict[str, Any], logger: Any) -> float:
    try:
        vaddr = section.get("vaddr", 0)
        size = section.get("size", 0)

        if size == 0 or size > 50000000:
            return 0.0

        read_size = min(size, 1048576)
        data = analyzer.adapter.read_bytes(vaddr, read_size)

        if len(data) == 0:
            return 0.0
        return shannon_entropy(data)

    except (RuntimeError, TypeError, ValueError, AttributeError, OSError) as exc:
        logger.error("Error calculating entropy for section %s: %s", section.get("name", "?"), exc)
        return 0.0


def count_nops_in_section(analyzer: Any, vaddr: int, size: int) -> tuple[int, int]:
    arch = analyzer._get_arch()
    if not arch or size <= 0:
        return 0, 0
    if arch not in {"x86", "x86_64", "i386", "amd64"}:
        return 0, 0

    read_size = min(size, 1024 * 1024)
    data = analyzer.adapter.read_bytes(vaddr, read_size)
    if not data:
        return 0, 0
    return data.count(b"\x90"), len(data)


def get_arch(analyzer: Any, logger: Any) -> str | None:
    if analyzer._arch is not None:
        return cast(str | None, analyzer._arch)
    try:
        info = analyzer.adapter.get_file_info() if analyzer.adapter is not None else {}
        arch = None
        if isinstance(info, dict):
            bin_info = info.get("bin")
            if isinstance(bin_info, dict):
                arch = bin_info.get("arch")
            if arch is None:
                arch = info.get("arch")
        analyzer._arch = str(arch).lower() if arch else None
    except (RuntimeError, TypeError, ValueError, AttributeError, OSError) as exc:
        logger.debug("Error reading architecture from file info: %s", exc)
        analyzer._arch = None
    return cast(str | None, analyzer._arch)


def get_section_summary(analyzer: Any, logger: Any, update_summary_fn: Any) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "total_sections": 0,
        "executable_sections": 0,
        "writable_sections": 0,
        "suspicious_sections": 0,
        "high_entropy_sections": 0,
        "avg_entropy": 0.0,
        "section_flags_summary": {},
    }

    try:
        sections_info = analyzer.analyze_sections()

        if sections_info:
            summary["total_sections"] = len(sections_info)

            total_entropy = 0.0
            flag_counts: dict[str, int] = {}

            for section in sections_info:
                total_entropy += update_summary_fn(summary, section, flag_counts)

            summary["avg_entropy"] = total_entropy / len(sections_info)
            summary["section_flags_summary"] = flag_counts

    except (RuntimeError, TypeError, ValueError, AttributeError) as exc:
        logger.error("Error getting section summary: %s", exc)

    return summary
