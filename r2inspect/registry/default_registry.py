#!/usr/bin/env python3
"""Default analyzer registry configuration."""

from collections.abc import Callable
from typing import Any

from ..utils.logger import get_logger
from .analyzer_registry import AnalyzerCategory, AnalyzerMetadata, AnalyzerRegistry

logger = get_logger(__name__)

PE_FORMATS = {"PE", "PE32", "PE32+"}
ELF_FORMATS = {"ELF", "ELF32", "ELF64"}
MACHO_FORMATS = {"MACH0", "MACH064", "MACH032"}

_ANALYZERS: list[dict[str, Any]] = [
    {
        "name": "pe_analyzer",
        "module_path": "r2inspect.modules.pe_analyzer",
        "class_name": "PEAnalyzer",
        "category": AnalyzerCategory.FORMAT,
        "file_formats": PE_FORMATS,
        "required": True,
        "description": "PE (Portable Executable) format analyzer for Windows binaries",
    },
    {
        "name": "elf_analyzer",
        "module_path": "r2inspect.modules.elf_analyzer",
        "class_name": "ELFAnalyzer",
        "category": AnalyzerCategory.FORMAT,
        "file_formats": ELF_FORMATS,
        "required": True,
        "description": "ELF (Executable and Linkable Format) analyzer for Linux/Unix binaries",
    },
    {
        "name": "macho_analyzer",
        "module_path": "r2inspect.modules.macho_analyzer",
        "class_name": "MachOAnalyzer",
        "category": AnalyzerCategory.FORMAT,
        "file_formats": MACHO_FORMATS,
        "required": True,
        "description": "Mach-O format analyzer for macOS/iOS binaries",
    },
    {
        "name": "ssdeep",
        "module_path": "r2inspect.modules.ssdeep_analyzer",
        "class_name": "SSDeepAnalyzer",
        "category": AnalyzerCategory.HASHING,
        "file_formats": None,
        "required": False,
        "description": "SSDeep fuzzy hashing for file similarity detection",
    },
    {
        "name": "tlsh",
        "module_path": "r2inspect.modules.tlsh_analyzer",
        "class_name": "TLSHAnalyzer",
        "category": AnalyzerCategory.HASHING,
        "file_formats": None,
        "required": False,
        "description": "TLSH (Trend Micro Locality Sensitive Hash) for fuzzy matching",
    },
    {
        "name": "telfhash",
        "module_path": "r2inspect.modules.telfhash_analyzer",
        "class_name": "TelfhashAnalyzer",
        "category": AnalyzerCategory.HASHING,
        "file_formats": ELF_FORMATS,
        "required": False,
        "description": "Telfhash symbol-based hashing for ELF binaries",
    },
    {
        "name": "impfuzzy",
        "module_path": "r2inspect.modules.impfuzzy_analyzer",
        "class_name": "ImpfuzzyAnalyzer",
        "category": AnalyzerCategory.HASHING,
        "file_formats": PE_FORMATS,
        "required": False,
        "description": "Impfuzzy import table fuzzy hashing for PE files",
    },
    {
        "name": "ccbhash",
        "module_path": "r2inspect.modules.ccbhash_analyzer",
        "class_name": "CCBHashAnalyzer",
        "category": AnalyzerCategory.HASHING,
        "file_formats": None,
        "required": False,
        "description": "CCB (Code Context Block) hashing for code similarity",
    },
    {
        "name": "simhash",
        "module_path": "r2inspect.modules.simhash_analyzer",
        "class_name": "SimHashAnalyzer",
        "category": AnalyzerCategory.HASHING,
        "file_formats": None,
        "required": False,
        "description": "SimHash locality-sensitive hashing for near-duplicate detection",
    },
    {
        "name": "packer_detector",
        "module_path": "r2inspect.modules.packer_detector",
        "class_name": "PackerDetector",
        "category": AnalyzerCategory.DETECTION,
        "file_formats": None,
        "required": False,
        "description": "Packer and obfuscation detection using signatures and heuristics",
    },
    {
        "name": "crypto_analyzer",
        "module_path": "r2inspect.modules.crypto_analyzer",
        "class_name": "CryptoAnalyzer",
        "category": AnalyzerCategory.DETECTION,
        "file_formats": None,
        "required": False,
        "description": "Cryptographic constant and algorithm detection",
    },
    {
        "name": "anti_analysis",
        "module_path": "r2inspect.modules.anti_analysis",
        "class_name": "AntiAnalysisDetector",
        "category": AnalyzerCategory.DETECTION,
        "file_formats": None,
        "required": False,
        "description": "Anti-debugging and anti-analysis technique detection",
    },
    {
        "name": "yara_analyzer",
        "module_path": "r2inspect.modules.yara_analyzer",
        "class_name": "YaraAnalyzer",
        "category": AnalyzerCategory.DETECTION,
        "file_formats": None,
        "required": False,
        "description": "YARA rule-based pattern matching and malware detection",
    },
    {
        "name": "section_analyzer",
        "module_path": "r2inspect.modules.section_analyzer",
        "class_name": "SectionAnalyzer",
        "category": AnalyzerCategory.METADATA,
        "file_formats": None,
        "required": False,
        "description": "Binary section analysis including size, entropy, and permissions",
    },
    {
        "name": "import_analyzer",
        "module_path": "r2inspect.modules.import_analyzer",
        "class_name": "ImportAnalyzer",
        "category": AnalyzerCategory.METADATA,
        "file_formats": None,
        "required": False,
        "description": "Import table analysis and external dependency detection",
    },
    {
        "name": "export_analyzer",
        "module_path": "r2inspect.modules.export_analyzer",
        "class_name": "ExportAnalyzer",
        "category": AnalyzerCategory.METADATA,
        "file_formats": None,
        "required": False,
        "description": "Export table analysis for shared libraries and DLLs",
    },
    {
        "name": "compiler_detector",
        "module_path": "r2inspect.modules.compiler_detector",
        "class_name": "CompilerDetector",
        "category": AnalyzerCategory.METADATA,
        "file_formats": None,
        "required": False,
        "description": "Compiler and linker detection through signature analysis",
    },
    {
        "name": "function_analyzer",
        "module_path": "r2inspect.modules.function_analyzer",
        "class_name": "FunctionAnalyzer",
        "category": AnalyzerCategory.METADATA,
        "file_formats": None,
        "required": False,
        "description": "Function discovery and basic block analysis",
    },
    {
        "name": "rich_header",
        "module_path": "r2inspect.modules.rich_header_analyzer",
        "class_name": "RichHeaderAnalyzer",
        "category": AnalyzerCategory.METADATA,
        "file_formats": PE_FORMATS,
        "required": False,
        "description": "PE Rich Header parsing for build environment fingerprinting",
    },
    {
        "name": "resource_analyzer",
        "module_path": "r2inspect.modules.resource_analyzer",
        "class_name": "ResourceAnalyzer",
        "category": AnalyzerCategory.METADATA,
        "file_formats": PE_FORMATS,
        "required": False,
        "description": "PE resource section analysis (icons, version info, manifests)",
    },
    {
        "name": "overlay_analyzer",
        "module_path": "r2inspect.modules.overlay_analyzer",
        "class_name": "OverlayAnalyzer",
        "category": AnalyzerCategory.METADATA,
        "file_formats": PE_FORMATS,
        "required": False,
        "description": "PE overlay data detection and analysis",
    },
    {
        "name": "exploit_mitigation",
        "module_path": "r2inspect.modules.exploit_mitigation_analyzer",
        "class_name": "ExploitMitigationAnalyzer",
        "category": AnalyzerCategory.SECURITY,
        "file_formats": PE_FORMATS | ELF_FORMATS,
        "required": False,
        "description": "Exploit mitigation analysis (DEP, ASLR, Stack Canaries, CFG)",
    },
    {
        "name": "authenticode",
        "module_path": "r2inspect.modules.authenticode_analyzer",
        "class_name": "AuthenticodeAnalyzer",
        "category": AnalyzerCategory.SECURITY,
        "file_formats": PE_FORMATS,
        "required": False,
        "description": "Authenticode digital signature verification for PE files",
    },
    {
        "name": "binlex",
        "module_path": "r2inspect.modules.binlex_analyzer",
        "class_name": "BinlexAnalyzer",
        "category": AnalyzerCategory.SIMILARITY,
        "file_formats": None,
        "required": False,
        "description": "BinLex genetic malware analysis and code extraction",
    },
    {
        "name": "binbloom",
        "module_path": "r2inspect.modules.binbloom_analyzer",
        "class_name": "BinbloomAnalyzer",
        "category": AnalyzerCategory.SIMILARITY,
        "file_formats": None,
        "required": False,
        "description": "BinBloom raw binary similarity analysis using bloom filters",
    },
    {
        "name": "bindiff",
        "module_path": "r2inspect.modules.bindiff_analyzer",
        "class_name": "BinDiffAnalyzer",
        "category": AnalyzerCategory.SIMILARITY,
        "file_formats": None,
        "required": False,
        "description": "Binary diffing and comparison analysis",
    },
    {
        "name": "string_analyzer",
        "module_path": "r2inspect.modules.string_analyzer",
        "class_name": "StringAnalyzer",
        "category": AnalyzerCategory.BEHAVIORAL,
        "file_formats": None,
        "required": False,
        "description": "String extraction and analysis for URLs, IPs, and indicators",
    },
]


def create_default_registry() -> AnalyzerRegistry:
    """Create and configure the default analyzer registry."""
    registry = AnalyzerRegistry()
    for analyzer in _ANALYZERS:
        registry.register(**analyzer)

    try:
        registry.load_entry_points()
    except Exception as exc:
        logger.debug(f"Failed to load entry points: {exc}")

    return registry


def _filter_registry(predicate: Callable[[AnalyzerMetadata], bool]) -> AnalyzerRegistry:
    default_registry = create_default_registry()
    filtered = AnalyzerRegistry()

    for name in default_registry:
        metadata = default_registry.get_metadata(name)
        if metadata and predicate(metadata):
            filtered.register(
                name=metadata.name,
                analyzer_class=metadata.analyzer_class,
                category=metadata.category,
                file_formats=metadata.file_formats,
                required=metadata.required,
                dependencies=metadata.dependencies,
                description=metadata.description,
            )

    return filtered


def get_format_specific_analyzers(file_format: str) -> AnalyzerRegistry:
    """Create a registry containing only analyzers for a specific file format."""
    return _filter_registry(lambda metadata: metadata.supports_format(file_format))


def get_minimal_registry() -> AnalyzerRegistry:
    """Create a registry with only required analyzers."""
    return _filter_registry(lambda metadata: metadata.required)


def get_category_registry(category: AnalyzerCategory) -> AnalyzerRegistry:
    """Create a registry containing analyzers from a specific category."""
    return _filter_registry(lambda metadata: metadata.category == category)
