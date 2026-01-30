#!/usr/bin/env python3
"""
Default Analyzer Registry Configuration

This module provides the default registry configuration for r2inspect, registering
all built-in analyzers with their appropriate metadata, categorization, and
dependency relationships.

The default registry serves as the standard analyzer configuration for r2inspect,
ensuring all built-in analyzers are properly registered and discoverable. Users
can extend or customize this configuration by creating their own registry instances.

Copyright (C) 2025 Marc Rivero López

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

from ..utils.logger import get_logger
from .analyzer_registry import AnalyzerCategory, AnalyzerRegistry

logger = get_logger(__name__)

PE_FORMATS = {"PE", "PE32", "PE32+"}


def create_default_registry() -> AnalyzerRegistry:
    """
    Create and configure the default analyzer registry.

    Instantiates a new AnalyzerRegistry and registers all built-in r2inspect
    analyzers with appropriate metadata, categorization, format support,
    and dependency relationships.

    The registration follows these organizational principles:
        - FORMAT analyzers extract format-specific structures
        - HASHING analyzers compute various hash types
        - DETECTION analyzers identify patterns and signatures
        - METADATA analyzers extract structural information
        - SECURITY analyzers analyze security features
        - SIMILARITY analyzers perform code comparison
        - BEHAVIORAL analyzers detect runtime characteristics

    Returns:
        Fully configured AnalyzerRegistry instance with all built-in analyzers

    Example:
        >>> from r2inspect.registry import create_default_registry
        >>>
        >>> # Create default registry
        >>> registry = create_default_registry()
        >>>
        >>> # Get all analyzers for PE files
        >>> pe_analyzers = registry.get_analyzers_for_format("PE")
        >>>
        >>> # Get only hashing analyzers
        >>> hashers = registry.get_by_category(AnalyzerCategory.HASHING)
        >>>
        >>> # List all registered analyzers
        >>> for analyzer_info in registry.list_analyzers():
        ...     print(f"{analyzer_info['name']}: {analyzer_info['description']}")
    """
    registry = AnalyzerRegistry()

    # =========================================================================
    # FORMAT ANALYZERS
    # Format-specific analyzers for PE, ELF, and Mach-O binaries
    # =========================================================================

    # =========================================================================
    # LAZY LOADING OPTIMIZATION
    # All analyzer registrations now use lazy loading for 80-90% startup
    # time reduction. Modules are imported on first use, not at startup.
    # =========================================================================

    registry.register(
        name="pe_analyzer",
        module_path="r2inspect.modules.pe_analyzer",
        class_name="PEAnalyzer",
        category=AnalyzerCategory.FORMAT,
        file_formats=PE_FORMATS,
        required=True,
        description="PE (Portable Executable) format analyzer for Windows binaries",
    )

    registry.register(
        name="elf_analyzer",
        module_path="r2inspect.modules.elf_analyzer",
        class_name="ELFAnalyzer",
        category=AnalyzerCategory.FORMAT,
        file_formats={"ELF", "ELF32", "ELF64"},
        required=True,
        description="ELF (Executable and Linkable Format) analyzer for Linux/Unix binaries",
    )

    registry.register(
        name="macho_analyzer",
        module_path="r2inspect.modules.macho_analyzer",
        class_name="MachOAnalyzer",
        category=AnalyzerCategory.FORMAT,
        file_formats={"MACH0", "MACH064", "MACH032"},
        required=True,
        description="Mach-O format analyzer for macOS/iOS binaries",
    )

    # =========================================================================
    # HASHING ANALYZERS
    # Cryptographic, fuzzy, and locality-sensitive hashing implementations
    # =========================================================================

    registry.register(
        name="ssdeep",
        module_path="r2inspect.modules.ssdeep_analyzer",
        class_name="SSDeepAnalyzer",
        category=AnalyzerCategory.HASHING,
        file_formats=None,  # Supports all formats
        required=False,
        description="SSDeep fuzzy hashing for file similarity detection",
    )

    registry.register(
        name="tlsh",
        module_path="r2inspect.modules.tlsh_analyzer",
        class_name="TLSHAnalyzer",
        category=AnalyzerCategory.HASHING,
        file_formats=None,
        required=False,
        description="TLSH (Trend Micro Locality Sensitive Hash) for fuzzy matching",
    )

    registry.register(
        name="telfhash",
        module_path="r2inspect.modules.telfhash_analyzer",
        class_name="TelfhashAnalyzer",
        category=AnalyzerCategory.HASHING,
        file_formats={"ELF", "ELF32", "ELF64"},
        required=False,
        description="Telfhash symbol-based hashing for ELF binaries",
    )

    registry.register(
        name="impfuzzy",
        module_path="r2inspect.modules.impfuzzy_analyzer",
        class_name="ImpfuzzyAnalyzer",
        category=AnalyzerCategory.HASHING,
        file_formats=PE_FORMATS,
        required=False,
        description="Impfuzzy import table fuzzy hashing for PE files",
    )

    registry.register(
        name="ccbhash",
        module_path="r2inspect.modules.ccbhash_analyzer",
        class_name="CCBHashAnalyzer",
        category=AnalyzerCategory.HASHING,
        file_formats=None,
        required=False,
        description="CCB (Code Context Block) hashing for code similarity",
    )

    registry.register(
        name="simhash",
        module_path="r2inspect.modules.simhash_analyzer",
        class_name="SimHashAnalyzer",
        category=AnalyzerCategory.HASHING,
        file_formats=None,
        required=False,
        description="SimHash locality-sensitive hashing for near-duplicate detection",
    )

    # =========================================================================
    # DETECTION ANALYZERS
    # Pattern matching, signature detection, and behavioral analysis
    # =========================================================================

    registry.register(
        name="packer_detector",
        module_path="r2inspect.modules.packer_detector",
        class_name="PackerDetector",
        category=AnalyzerCategory.DETECTION,
        file_formats=None,
        required=False,
        description="Packer and obfuscation detection using signatures and heuristics",
    )

    registry.register(
        name="crypto_analyzer",
        module_path="r2inspect.modules.crypto_analyzer",
        class_name="CryptoAnalyzer",
        category=AnalyzerCategory.DETECTION,
        file_formats=None,
        required=False,
        description="Cryptographic constant and algorithm detection",
    )

    registry.register(
        name="anti_analysis",
        module_path="r2inspect.modules.anti_analysis",
        class_name="AntiAnalysisDetector",
        category=AnalyzerCategory.DETECTION,
        file_formats=None,
        required=False,
        description="Anti-debugging and anti-analysis technique detection",
    )

    registry.register(
        name="yara_analyzer",
        module_path="r2inspect.modules.yara_analyzer",
        class_name="YaraAnalyzer",
        category=AnalyzerCategory.DETECTION,
        file_formats=None,
        required=False,
        description="YARA rule-based pattern matching and malware detection",
    )

    # =========================================================================
    # METADATA ANALYZERS
    # Structural metadata extraction (sections, imports, exports, etc.)
    # =========================================================================

    registry.register(
        name="section_analyzer",
        module_path="r2inspect.modules.section_analyzer",
        class_name="SectionAnalyzer",
        category=AnalyzerCategory.METADATA,
        file_formats=None,
        required=False,
        description="Binary section analysis including size, entropy, and permissions",
    )

    registry.register(
        name="import_analyzer",
        module_path="r2inspect.modules.import_analyzer",
        class_name="ImportAnalyzer",
        category=AnalyzerCategory.METADATA,
        file_formats=None,
        required=False,
        description="Import table analysis and external dependency detection",
    )

    registry.register(
        name="export_analyzer",
        module_path="r2inspect.modules.export_analyzer",
        class_name="ExportAnalyzer",
        category=AnalyzerCategory.METADATA,
        file_formats=None,
        required=False,
        description="Export table analysis for shared libraries and DLLs",
    )

    registry.register(
        name="compiler_detector",
        module_path="r2inspect.modules.compiler_detector",
        class_name="CompilerDetector",
        category=AnalyzerCategory.METADATA,
        file_formats=None,
        required=False,
        description="Compiler and linker detection through signature analysis",
    )

    registry.register(
        name="function_analyzer",
        module_path="r2inspect.modules.function_analyzer",
        class_name="FunctionAnalyzer",
        category=AnalyzerCategory.METADATA,
        file_formats=None,
        required=False,
        description="Function discovery and basic block analysis",
    )

    registry.register(
        name="rich_header",
        module_path="r2inspect.modules.rich_header_analyzer",
        class_name="RichHeaderAnalyzer",
        category=AnalyzerCategory.METADATA,
        file_formats=PE_FORMATS,
        required=False,
        description="PE Rich Header parsing for build environment fingerprinting",
    )

    registry.register(
        name="resource_analyzer",
        module_path="r2inspect.modules.resource_analyzer",
        class_name="ResourceAnalyzer",
        category=AnalyzerCategory.METADATA,
        file_formats=PE_FORMATS,
        required=False,
        description="PE resource section analysis (icons, version info, manifests)",
    )

    registry.register(
        name="overlay_analyzer",
        module_path="r2inspect.modules.overlay_analyzer",
        class_name="OverlayAnalyzer",
        category=AnalyzerCategory.METADATA,
        file_formats=PE_FORMATS,
        required=False,
        description="PE overlay data detection and analysis",
    )

    # =========================================================================
    # SECURITY ANALYZERS
    # Security feature and exploit mitigation analysis
    # =========================================================================

    registry.register(
        name="exploit_mitigation",
        module_path="r2inspect.modules.exploit_mitigation_analyzer",
        class_name="ExploitMitigationAnalyzer",
        category=AnalyzerCategory.SECURITY,
        file_formats=PE_FORMATS | {"ELF", "ELF32", "ELF64"},
        required=False,
        description="Exploit mitigation analysis (DEP, ASLR, Stack Canaries, CFG)",
    )

    registry.register(
        name="authenticode",
        module_path="r2inspect.modules.authenticode_analyzer",
        class_name="AuthenticodeAnalyzer",
        category=AnalyzerCategory.SECURITY,
        file_formats=PE_FORMATS,
        required=False,
        description="Authenticode digital signature verification for PE files",
    )

    # =========================================================================
    # SIMILARITY ANALYZERS
    # Code similarity, diffing, and comparison tools
    # =========================================================================

    registry.register(
        name="binlex",
        module_path="r2inspect.modules.binlex_analyzer",
        class_name="BinlexAnalyzer",
        category=AnalyzerCategory.SIMILARITY,
        file_formats=None,
        required=False,
        description="BinLex genetic malware analysis and code extraction",
    )

    registry.register(
        name="binbloom",
        module_path="r2inspect.modules.binbloom_analyzer",
        class_name="BinbloomAnalyzer",
        category=AnalyzerCategory.SIMILARITY,
        file_formats=None,
        required=False,
        description="BinBloom raw binary similarity analysis using bloom filters",
    )

    registry.register(
        name="bindiff",
        module_path="r2inspect.modules.bindiff_analyzer",
        class_name="BinDiffAnalyzer",
        category=AnalyzerCategory.SIMILARITY,
        file_formats=None,
        required=False,
        description="Binary diffing and comparison analysis",
    )

    # =========================================================================
    # BEHAVIORAL ANALYZERS
    # String extraction and behavioral pattern analysis
    # =========================================================================

    registry.register(
        name="string_analyzer",
        module_path="r2inspect.modules.string_analyzer",
        class_name="StringAnalyzer",
        category=AnalyzerCategory.BEHAVIORAL,
        file_formats=None,
        required=False,
        description="String extraction and analysis for URLs, IPs, and indicators",
    )

    # Attempt to load external analyzers via entry points
    try:
        registry.load_entry_points()
    except Exception as exc:
        # Entry points optional; ignore failures for core functionality
        logger.debug(f"Failed to load entry points: {exc}")

    return registry


def get_format_specific_analyzers(file_format: str) -> AnalyzerRegistry:
    """
    Create a registry containing only analyzers for a specific file format.

    Convenience function that creates a default registry and filters it to
    include only analyzers that support the specified format.

    Args:
        file_format: File format identifier (e.g., "PE", "ELF", "MACH0")

    Returns:
        AnalyzerRegistry containing only format-compatible analyzers

    Example:
        >>> pe_registry = get_format_specific_analyzers("PE")
        >>> # Contains only PE-compatible analyzers
        >>> for name in pe_registry:
        ...     print(name)
        pe_analyzer
        impfuzzy
        rich_header
        authenticode
        ...
    """
    default_registry = create_default_registry()
    format_registry = AnalyzerRegistry()

    # Copy only analyzers that support the format
    for name in default_registry:
        metadata = default_registry.get_metadata(name)
        if metadata and metadata.supports_format(file_format):
            format_registry.register(
                name=metadata.name,
                analyzer_class=metadata.analyzer_class,
                category=metadata.category,
                file_formats=metadata.file_formats,
                required=metadata.required,
                dependencies=metadata.dependencies,
                description=metadata.description,
            )

    return format_registry


def get_minimal_registry() -> AnalyzerRegistry:
    """
    Create a minimal registry with only required analyzers.

    Returns a registry containing only analyzers marked as required.
    Useful for lightweight analysis scenarios or resource-constrained
    environments.

    Returns:
        AnalyzerRegistry containing only required analyzers

    Example:
        >>> minimal = get_minimal_registry()
        >>> # Contains only essential format analyzers
        >>> for analyzer_info in minimal.list_analyzers():
        ...     assert analyzer_info['required'] is True
    """
    default_registry = create_default_registry()
    minimal_registry = AnalyzerRegistry()

    # Copy only required analyzers
    for name in default_registry:
        metadata = default_registry.get_metadata(name)
        if metadata and metadata.required:
            minimal_registry.register(
                name=metadata.name,
                analyzer_class=metadata.analyzer_class,
                category=metadata.category,
                file_formats=metadata.file_formats,
                required=metadata.required,
                dependencies=metadata.dependencies,
                description=metadata.description,
            )

    return minimal_registry


def get_category_registry(category: AnalyzerCategory) -> AnalyzerRegistry:
    """
    Create a registry containing only analyzers from a specific category.

    Args:
        category: Category to filter by

    Returns:
        AnalyzerRegistry containing only analyzers in the specified category

    Example:
        >>> hashing_registry = get_category_registry(AnalyzerCategory.HASHING)
        >>> # Contains only hashing analyzers
        >>> for name in hashing_registry:
        ...     print(name)
        ssdeep
        tlsh
        impfuzzy
        ...
    """
    default_registry = create_default_registry()
    category_registry = AnalyzerRegistry()

    # Copy only analyzers in the category
    for name in default_registry:
        metadata = default_registry.get_metadata(name)
        if metadata and metadata.category == category:
            category_registry.register(
                name=metadata.name,
                analyzer_class=metadata.analyzer_class,
                category=metadata.category,
                file_formats=metadata.file_formats,
                required=metadata.required,
                dependencies=metadata.dependencies,
                description=metadata.description,
            )

    return category_registry
