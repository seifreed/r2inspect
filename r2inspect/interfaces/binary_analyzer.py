#!/usr/bin/env python3
"""
Binary Analyzer Protocol Interface

This module defines the Protocol interface for binary analyzers, providing
structural subtyping (duck typing with type hints) for any component that
analyzes binary files through radare2 or similar tools.

Using Protocol instead of ABC allows for flexible implementation without
requiring inheritance, enabling integration with existing codebases and
third-party libraries.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class BinaryAnalyzerInterface(Protocol):
    """
    Protocol defining the interface for binary file analyzers.

    This protocol establishes a contract for any binary analysis component
    that provides information extraction capabilities. Classes implementing
    this protocol can be used interchangeably without inheritance requirements.

    The @runtime_checkable decorator enables isinstance() and issubclass()
    checks at runtime, facilitating dynamic type validation.

    All methods must be implemented by conforming classes. Methods should
    handle errors gracefully and return empty collections rather than None
    when no data is available.

    Example:
        >>> class R2Analyzer:
        ...     def __init__(self, r2_instance):
        ...         self.r2 = r2_instance
        ...
        ...     def get_file_info(self) -> dict[str, Any]:
        ...         return self.r2.cmdj("ij")
        ...
        ...     # ... implement other methods ...
        >>>
        >>> analyzer = R2Analyzer(r2_instance)
        >>> assert isinstance(analyzer, BinaryAnalyzerInterface)
    """

    def get_file_info(self) -> dict[str, Any]:
        """
        Retrieve general file information.

        Returns a dictionary containing metadata about the analyzed file,
        including but not limited to:
        - File size, architecture, bits (32/64)
        - File format (PE, ELF, Mach-O)
        - Endianness (little/big)
        - Entry point address
        - Compilation timestamps

        Returns:
            Dictionary containing file metadata. Returns empty dict if
            information cannot be retrieved.

        Example:
            >>> info = analyzer.get_file_info()
            >>> print(info['arch'])  # x86, arm, mips, etc.
            >>> print(info['bits'])  # 32 or 64
        """
        ...

    def get_sections(self) -> list[dict[str, Any]]:
        """
        Retrieve all binary sections.

        Returns a list of section dictionaries, each containing:
        - name: Section name (e.g., '.text', '.data', '__text')
        - vaddr: Virtual address where section is loaded
        - paddr: Physical address in file
        - size: Section size in bytes
        - vsize: Virtual size (may differ from physical size)
        - perm: Permissions (r/w/x flags)
        - flags: Additional section flags

        Returns:
            List of section dictionaries. Returns empty list if no sections
            are found or if retrieval fails.

        Example:
            >>> sections = analyzer.get_sections()
            >>> text_sections = [s for s in sections if '.text' in s['name']]
        """
        ...

    def get_imports(self) -> list[dict[str, Any]]:
        """
        Retrieve imported functions and libraries.

        Returns a list of import dictionaries, each containing:
        - name: Function or symbol name
        - libname: Library/DLL name providing the import
        - bind: Binding type (GLOBAL, LOCAL, WEAK)
        - type: Import type (FUNC, OBJECT)
        - plt: PLT/IAT address (if applicable)
        - ordinal: Import ordinal (if applicable, PE files)

        Returns:
            List of import dictionaries. Returns empty list if no imports
            are found or if retrieval fails.

        Example:
            >>> imports = analyzer.get_imports()
            >>> kernel32_imports = [i for i in imports if 'kernel32' in i.get('libname', '').lower()]
        """
        ...

    def get_exports(self) -> list[dict[str, Any]]:
        """
        Retrieve exported functions and symbols.

        Returns a list of export dictionaries, each containing:
        - name: Exported function or symbol name
        - vaddr: Virtual address of the export
        - paddr: Physical address in file
        - bind: Binding type (GLOBAL, LOCAL, WEAK)
        - type: Export type (FUNC, OBJECT)
        - size: Size of exported object (if applicable)

        Returns:
            List of export dictionaries. Returns empty list if no exports
            are found or if retrieval fails.

        Example:
            >>> exports = analyzer.get_exports()
            >>> public_exports = [e for e in exports if e.get('bind') == 'GLOBAL']
        """
        ...

    def get_symbols(self) -> list[dict[str, Any]]:
        """
        Retrieve all symbols from the binary.

        Returns a list of symbol dictionaries, each containing:
        - name: Symbol name
        - vaddr: Virtual address
        - paddr: Physical address
        - bind: Binding type (GLOBAL, LOCAL, WEAK)
        - type: Symbol type (FUNC, OBJECT, SECTION, FILE)
        - size: Symbol size in bytes
        - is_imported: Boolean indicating if symbol is imported

        Returns:
            List of symbol dictionaries. Returns empty list if no symbols
            are found or if retrieval fails.

        Example:
            >>> symbols = analyzer.get_symbols()
            >>> functions = [s for s in symbols if s.get('type') == 'FUNC']
        """
        ...

    def read_bytes(self, address: int, size: int) -> bytes:
        """
        Read raw bytes from a specific address.

        Reads a specified number of bytes from the given virtual address
        in the binary. This method is useful for extracting specific data
        regions, shellcode, or embedded resources.

        Args:
            address: Virtual address to read from
            size: Number of bytes to read

        Returns:
            Bytes object containing the read data. Returns empty bytes
            if read fails or address is invalid.

        Raises:
            ValueError: If size is negative or address is invalid
            MemoryError: If requested size exceeds available memory

        Example:
            >>> data = analyzer.read_bytes(0x401000, 16)
            >>> print(data.hex())  # Print as hexadecimal
        """
        ...

    def execute_command(self, cmd: str) -> Any:
        """
        Execute an analyzer-specific command.

        This method provides a generic interface for executing commands
        specific to the underlying analysis tool (e.g., radare2 commands).
        It enables advanced users to leverage tool-specific functionality
        not exposed through the standard protocol methods.

        Args:
            cmd: Command string to execute

        Returns:
            Command output. Type varies based on command and tool:
            - String for text output
            - Dict for JSON output
            - List for array output
            - None if command produces no output or fails

        Example:
            >>> # radare2 example
            >>> functions = analyzer.execute_command("aflj")  # Returns list[Dict]
            >>> info = analyzer.execute_command("ij")  # Returns Dict
        """
        ...


@runtime_checkable
class HashingAnalyzerInterface(Protocol):
    """
    Protocol defining the interface for hashing analyzers.

    This protocol establishes a contract for analyzers that compute hash
    values for binary files. Implementations can use any hashing algorithm
    (cryptographic, fuzzy, locality-sensitive, etc.).

    Example:
        >>> class TLSHAnalyzer:
        ...     def analyze(self) -> dict[str, Any]:
        ...         return {"hash": "...", "available": True}
        ...
        ...     @staticmethod
        ...     def compare_hashes(h1: str, h2: str) -> int:
        ...         import tlsh
        ...         return tlsh.diff(h1, h2)
        >>>
        >>> analyzer = TLSHAnalyzer()
        >>> assert isinstance(analyzer, HashingAnalyzerInterface)
    """

    def analyze(self) -> dict[str, Any]:
        """
        Perform hash analysis on the target file.

        Returns a standardized dictionary containing:
        - available: Boolean indicating if analysis was successful
        - hash_type: String identifier for hash algorithm
        - hash_value: Calculated hash (or None if unavailable)
        - error: Error message (or None if successful)
        - execution_time: Time taken in seconds (optional)

        Returns:
            Dictionary containing analysis results

        Example:
            >>> result = analyzer.analyze()
            >>> if result['available']:
            ...     print(f"{result['hash_type']}: {result['hash_value']}")
        """
        ...

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> Any:
        """
        Compare two hash values.

        Computes a similarity or distance metric between two hashes.
        The return type and semantics depend on the hash algorithm:
        - Distance metrics: Lower values indicate higher similarity (TLSH)
        - Similarity scores: Higher values indicate higher similarity (SSDeep)

        Args:
            hash1: First hash value
            hash2: Second hash value

        Returns:
            Similarity or distance metric (type depends on algorithm),
            or None if comparison fails

        Example:
            >>> score = TLSHAnalyzer.compare_hashes(hash1, hash2)
            >>> if score is not None and score < 50:
            ...     print("Hashes are similar")
        """
        ...


@runtime_checkable
class DetectionEngineInterface(Protocol):
    """
    Protocol defining the interface for detection engines.

    This protocol establishes a contract for analyzers that perform pattern
    matching, signature detection, or behavioral analysis to identify
    malicious code, libraries, packers, or other characteristics.

    Example:
        >>> class YaraAnalyzer:
        ...     def scan(self) -> list[dict[str, Any]]:
        ...         return [{"rule": "Malware.Trojan", "severity": "high"}]
        >>>
        >>> scanner = YaraAnalyzer()
        >>> assert isinstance(scanner, DetectionEngineInterface)
    """

    def scan(self) -> list[dict[str, Any]]:
        """
        Scan the target file for patterns or signatures.

        Returns a list of detection dictionaries, each containing:
        - name: Detection rule or signature name
        - type: Detection type (yara, signature, pattern, etc.)
        - severity: Severity level (critical, high, medium, low, info)
        - metadata: Additional detection-specific information
        - offset: File offset of match (optional)
        - description: Human-readable description (optional)

        Returns:
            List of detection dictionaries. Returns empty list if no
            detections are found or if scan fails.

        Example:
            >>> detections = scanner.scan()
            >>> critical = [d for d in detections if d['severity'] == 'critical']
        """
        ...


@runtime_checkable
class FormatAnalyzerInterface(Protocol):
    """
    Protocol defining the interface for format-specific analyzers.

    This protocol establishes a contract for analyzers that extract
    information specific to particular binary formats (PE, ELF, Mach-O).

    Example:
        >>> class PEAnalyzer:
        ...     def get_headers(self) -> dict[str, Any]:
        ...         return {"dos_header": {...}, "nt_headers": {...}}
        ...
        ...     def get_resources(self) -> list[dict[str, Any]]:
        ...         return [{"type": "RT_ICON", "size": 1024}]
        >>>
        >>> analyzer = PEAnalyzer()
        >>> assert isinstance(analyzer, FormatAnalyzerInterface)
    """

    def get_headers(self) -> dict[str, Any]:
        """
        Retrieve format-specific headers.

        Returns format-specific header information:
        - PE: DOS header, NT headers, optional headers
        - ELF: ELF header, program headers, section headers
        - Mach-O: Mach header, load commands

        Returns:
            Dictionary containing header information. Returns empty dict
            if headers cannot be parsed.

        Example:
            >>> headers = analyzer.get_headers()
            >>> print(headers['dos_header']['magic'])  # 'MZ' for PE
        """
        ...

    def get_resources(self) -> list[dict[str, Any]]:
        """
        Retrieve embedded resources.

        Returns a list of resource dictionaries containing:
        - name: Resource name or identifier
        - type: Resource type (icon, bitmap, string, version, etc.)
        - size: Resource size in bytes
        - offset: File offset of resource data
        - language: Language identifier (PE files)

        Returns:
            List of resource dictionaries. Returns empty list if no
            resources are found or format doesn't support resources.

        Example:
            >>> resources = analyzer.get_resources()
            >>> icons = [r for r in resources if r['type'] == 'RT_ICON']
        """
        ...
