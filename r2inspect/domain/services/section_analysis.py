"""Pure section analysis helpers."""

from __future__ import annotations

from typing import Any


PE_CHARACTERISTIC_FLAGS: dict[int, str] = {
    0x00000020: "IMAGE_SCN_CNT_CODE",
    0x00000040: "IMAGE_SCN_CNT_INITIALIZED_DATA",
    0x00000080: "IMAGE_SCN_CNT_UNINITIALIZED_DATA",
    0x00000200: "IMAGE_SCN_LNK_INFO",
    0x00000800: "IMAGE_SCN_LNK_REMOVE",
    0x00001000: "IMAGE_SCN_LNK_COMDAT",
    0x00008000: "IMAGE_SCN_GPREL",
    0x00020000: "IMAGE_SCN_MEM_PURGEABLE",
    0x00040000: "IMAGE_SCN_MEM_16BIT",
    0x00080000: "IMAGE_SCN_MEM_LOCKED",
    0x00100000: "IMAGE_SCN_MEM_PRELOAD",
    0x01000000: "IMAGE_SCN_MEM_EXECUTE",
    0x02000000: "IMAGE_SCN_MEM_READ",
    0x04000000: "IMAGE_SCN_MEM_WRITE",
    0x08000000: "IMAGE_SCN_MEM_SHARED",
    0x10000000: "IMAGE_SCN_MEM_NOT_CACHED",
    0x20000000: "IMAGE_SCN_MEM_NOT_PAGED",
    0x40000000: "IMAGE_SCN_MEM_DISCARDABLE",
}

SECTION_MAPPINGS: dict[str, tuple[str, str]] = {
    ".text": ("Executable code", "6.0-7.5"),
    ".data": ("Initialized data", "3.0-6.0"),
    ".rdata": ("Read-only data", "4.0-6.5"),
    ".bss": ("Uninitialized data", "0.0-1.0"),
    ".rsrc": ("Resources", "2.0-7.0"),
    ".idata": ("Import data", "3.0-5.0"),
    ".edata": ("Export data", "3.0-5.0"),
    ".reloc": ("Relocations", "2.0-4.0"),
}

SUSPICIOUS_SECTION_NAMES: tuple[str, ...] = (
    "upx",
    "aspack",
    "themida",
    "vmprotect",
    "armadillo",
    "fsg",
    "petite",
    "mew",
    "packed",
    "crypted",
)


def build_section_name_indicators(
    name: str, standard_sections: set[str], suspicious_name_detector
) -> list[str]:
    indicators: list[str] = []
    if isinstance(name, str) and name not in standard_sections and not name.startswith("."):
        indicators.append("Non-standard section name")
    if isinstance(name, str):
        indicator = suspicious_name_detector(name, list(SUSPICIOUS_SECTION_NAMES))
        if indicator:
            indicators.append(indicator)
    return indicators


def build_permission_indicators(analysis: dict[str, Any]) -> list[str]:
    indicators: list[str] = []
    if analysis["is_writable"] and analysis["is_executable"]:
        indicators.append("Writable and executable section")
    if analysis["is_executable"] and analysis.get("entropy", 0) < 1.0:
        indicators.append("Executable section with very low entropy")
    return indicators


def build_entropy_indicators(entropy: float) -> list[str]:
    indicators: list[str] = []
    if entropy > 7.5:
        indicators.append(f"High entropy ({entropy:.2f})")
    elif entropy > 7.0:
        indicators.append(f"Moderate high entropy ({entropy:.2f})")
    return indicators


def build_size_indicators(vsize: int, raw_size: int) -> list[str]:
    indicators: list[str] = []
    if vsize > 0 and raw_size > 0:
        ratio = vsize / raw_size
        size_diff_ratio = abs(vsize - raw_size) / max(vsize, raw_size)
        if ratio > 10:
            indicators.append(f"Suspicious size ratio: Virtual {ratio:.1f}x larger than raw")
        elif ratio > 5:
            indicators.append(f"Large size ratio: Virtual {ratio:.1f}x larger than raw")
        elif size_diff_ratio > 0.8:
            indicators.append(f"Large virtual/raw size difference ({size_diff_ratio:.1f})")
    if raw_size < 100 and raw_size > 0:
        indicators.append("Very small section")
    if raw_size > 52428800:
        indicators.append("Very large section")
    return indicators


def decode_pe_characteristics(characteristics: int) -> list[str]:
    return [
        flag_name
        for flag_value, flag_name in PE_CHARACTERISTIC_FLAGS.items()
        if characteristics & flag_value
    ]


def build_section_characteristics(
    name: str,
    analysis: dict[str, Any],
    code_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    characteristics: dict[str, Any] = {}
    purpose, expected_entropy = SECTION_MAPPINGS.get(name, ("Unknown/Custom", "Variable"))
    characteristics["purpose"] = purpose
    characteristics["expected_entropy"] = expected_entropy
    _mark_entropy_anomaly(characteristics, analysis)
    if analysis.get("is_executable") and code_analysis:
        characteristics["code_analysis"] = code_analysis
    return characteristics


def _mark_entropy_anomaly(characteristics: dict[str, Any], analysis: dict[str, Any]) -> None:
    if characteristics["expected_entropy"] == "Variable":
        return
    try:
        entropy = analysis.get("entropy", 0)
        min_entropy, max_entropy = map(float, characteristics["expected_entropy"].split("-"))
        if entropy < min_entropy or entropy > max_entropy:
            characteristics["entropy_anomaly"] = True
    except (ValueError, TypeError):
        return


def update_section_summary(
    summary: dict[str, Any],
    section: dict[str, Any],
    flag_counts: dict[str, int],
) -> float:
    if section.get("is_executable"):
        summary["executable_sections"] += 1
    if section.get("is_writable"):
        summary["writable_sections"] += 1
    if section.get("suspicious_indicators"):
        summary["suspicious_sections"] += 1
    entropy = float(section.get("entropy", 0.0) or 0.0)
    if entropy > 7.0:
        summary["high_entropy_sections"] += 1
    flags = section.get("flags", "")
    flag_counts[flags] = flag_counts.get(flags, 0) + 1
    return entropy
