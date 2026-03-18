#!/usr/bin/env python3
"""Protocol building blocks for analyzer-facing interfaces.

Follows the Interface Segregation Principle: each sub-protocol groups
a cohesive set of methods so that consumers can depend only on the
capability slice they actually need.  The composite
``BinaryAnalyzerInterface`` inherits from every sub-protocol to
preserve full backward compatibility.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Sub-protocols (Interface Segregation)
# ---------------------------------------------------------------------------


@runtime_checkable
class CoreQueryProvider(Protocol):
    """Basic file metadata queries."""

    def get_file_info(self) -> dict[str, Any]: ...
    def get_entry_info(self) -> list[dict[str, Any]]: ...
    def get_headers_json(self) -> Any: ...


@runtime_checkable
class SectionProvider(Protocol):
    """Section-level information."""

    def get_sections(self) -> list[dict[str, Any]]: ...


@runtime_checkable
class ImportExportProvider(Protocol):
    """Import, export, and symbol tables."""

    def get_imports(self) -> list[dict[str, Any]]: ...
    def get_exports(self) -> list[dict[str, Any]]: ...
    def get_symbols(self) -> list[dict[str, Any]]: ...


@runtime_checkable
class StringProvider(Protocol):
    """String extraction capabilities."""

    def get_strings(self) -> list[dict[str, Any]]: ...
    def get_strings_basic(self) -> list[dict[str, Any]]: ...
    def get_strings_text(self) -> str: ...


@runtime_checkable
class FunctionProvider(Protocol):
    """Function enumeration and inspection."""

    def get_functions(self) -> list[dict[str, Any]]: ...
    def get_functions_at(self, address: int) -> list[dict[str, Any]]: ...
    def get_function_info(self, address: int) -> list[dict[str, Any]]: ...


@runtime_checkable
class DisassemblyProvider(Protocol):
    """Disassembly and control-flow graph access."""

    def get_disasm(self, address: int | None = None, size: int | None = None) -> Any: ...
    def get_disasm_text(self, address: int | None = None, size: int | None = None) -> str: ...
    def get_cfg(self, address: int | None = None) -> Any: ...


@runtime_checkable
class ByteAccessProvider(Protocol):
    """Raw byte reading from the binary image."""

    def read_bytes(self, address: int, size: int) -> bytes: ...
    def read_bytes_list(self, address: int, size: int) -> list[int]: ...


@runtime_checkable
class SearchProvider(Protocol):
    """Pattern search over binary content."""

    def search_text(self, pattern: str) -> str: ...
    def search_hex(self, hex_pattern: str) -> str: ...
    def search_hex_json(self, pattern: str) -> list[dict[str, Any]]: ...


@runtime_checkable
class PEFormatProvider(Protocol):
    """PE-specific header and resource queries."""

    def get_pe_header(self) -> dict[str, Any]: ...
    def get_pe_optional_header(self) -> dict[str, Any]: ...
    def get_data_directories(self) -> list[dict[str, Any]]: ...
    def get_resources_info(self) -> list[dict[str, Any]]: ...
    def get_pe_security_text(self) -> str: ...
    def get_pe_version_info_text(self) -> str: ...


@runtime_checkable
class TextQueryProvider(Protocol):
    """Text-based information and filtered query access."""

    def get_info_text(self) -> str: ...
    def get_dynamic_info_text(self) -> str: ...
    def get_header_text(self) -> str: ...
    def get_strings_filtered(self, command: str) -> str: ...
    def get_entropy_pattern(self) -> str: ...


@runtime_checkable
class AnalysisProvider(Protocol):
    """Full analysis execution."""

    def analyze_all(self) -> str: ...


# ---------------------------------------------------------------------------
# Composite interface (backward-compatible)
# ---------------------------------------------------------------------------


@runtime_checkable
class BinaryAnalyzerInterface(
    CoreQueryProvider,
    SectionProvider,
    ImportExportProvider,
    StringProvider,
    FunctionProvider,
    DisassemblyProvider,
    ByteAccessProvider,
    SearchProvider,
    PEFormatProvider,
    TextQueryProvider,
    AnalysisProvider,
    Protocol,
):
    """Full binary analysis interface — union of all sub-protocols.

    Existing code that depends on ``BinaryAnalyzerInterface`` keeps
    working unchanged.  New code can narrow its dependency to a single
    sub-protocol (e.g. ``StringProvider``) for better decoupling.
    """


@runtime_checkable
class HashingAnalyzerInterface(Protocol):
    """Protocol defining the interface for hashing analyzers."""

    def analyze(self) -> dict[str, Any]: ...

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> Any: ...


@runtime_checkable
class DetectionEngineInterface(Protocol):
    """Protocol defining the interface for detection engines."""

    def scan(self) -> list[dict[str, Any]]: ...


@runtime_checkable
class FormatAnalyzerInterface(Protocol):
    """Protocol defining the interface for format-specific analyzers."""

    def get_headers(self) -> dict[str, Any]: ...
    def get_resources(self) -> list[dict[str, Any]]: ...
