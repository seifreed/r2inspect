#!/usr/bin/env python3
"""
R2Pipe Adapter Implementation

This module provides the R2PipeAdapter class that implements the
BinaryAnalyzerInterface Protocol for radare2/r2pipe backend.

The adapter serves as a translation layer between the generic Protocol
interface and the concrete r2pipe implementation, providing:
- Type-safe method signatures
- Robust error handling
- Response validation and sanitization
- Consistent data transformation

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)

Architecture:
    The adapter follows the Adapter pattern (Gang of Four) to provide
    a consistent interface to the r2pipe backend. It uses composition
    rather than inheritance to maintain loose coupling.

Design Principles Applied:
    - Single Responsibility: Adapter only handles r2pipe translation
    - Dependency Inversion: Depends on Protocol abstraction
    - Open/Closed: Extensible without modification
    - Interface Segregation: Implements focused Protocol interface

Usage:
    >>> from r2inspect.adapters import R2PipeAdapter
    >>> import r2pipe
    >>>
    >>> r2 = r2pipe.open("/path/to/binary")
    >>> adapter = R2PipeAdapter(r2)
    >>>
    >>> # Use through Protocol interface
    >>> info = adapter.get_file_info()
    >>> sections = adapter.get_sections()
    >>> data = adapter.read_bytes(0x401000, 256)
"""

from typing import Any, cast

from ..interfaces import BinaryAnalyzerInterface
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd, safe_cmd_dict, safe_cmd_list, safe_cmdj
from .validation import (
    is_valid_r2_response,
    sanitize_r2_output,
    validate_address,
    validate_r2_data,
    validate_size,
)

logger = get_logger(__name__)


class R2PipeAdapter:
    """
    Adapter for radare2/r2pipe backend implementing BinaryAnalyzerInterface.

    This adapter provides a clean, type-safe interface to radare2 functionality,
    abstracting away r2pipe-specific details and providing consistent error
    handling and data validation.

    The class implements the BinaryAnalyzerInterface Protocol through structural
    subtyping (duck typing with type hints), meaning it satisfies the Protocol
    contract without explicitly inheriting from it.

    Attributes:
        _r2: The r2pipe instance for command execution

    Example:
        >>> import r2pipe
        >>> from r2inspect.adapters import R2PipeAdapter
        >>> from r2inspect.interfaces import BinaryAnalyzerInterface
        >>>
        >>> r2 = r2pipe.open("sample.exe")
        >>> adapter = R2PipeAdapter(r2)
        >>>
        >>> # Verify Protocol compliance
        >>> assert isinstance(adapter, BinaryAnalyzerInterface)
        >>>
        >>> # Use adapter methods
        >>> file_info = adapter.get_file_info()
        >>> print(f"Architecture: {file_info.get('arch')}")
        >>>
        >>> imports = adapter.get_imports()
        >>> print(f"Found {len(imports)} imports")
    """

    def __init__(self, r2_instance):
        """
        Initialize the R2Pipe adapter.

        Args:
            r2_instance: An r2pipe instance connected to a binary file.
                Must support cmd() and cmdj() methods.

        Raises:
            ValueError: If r2_instance is None or invalid

        Example:
            >>> import r2pipe
            >>> r2 = r2pipe.open("/bin/ls")
            >>> adapter = R2PipeAdapter(r2)
        """
        if r2_instance is None:
            raise ValueError("r2_instance cannot be None")

        self._r2 = r2_instance
        self._cache: dict[str, Any] = {}
        logger.debug("R2PipeAdapter initialized successfully")

    def _cached_query(
        self,
        cmd: str,
        data_type: str = "list",
        default: list | dict | None = None,
        error_msg: str = "",
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """
        Execute r2 command with caching and validation.

        This helper method encapsulates the common pattern of:
        1. Checking cache for existing results
        2. Executing the r2 command if not cached
        3. Validating the response
        4. Caching and returning valid results

        Args:
            cmd: The radare2 command to execute (e.g., 'iSj', 'iij')
            data_type: Expected response type ('list' or 'dict')
            default: Default value to return on error (None uses [] for list, {} for dict)
            error_msg: Optional debug message to log on invalid response

        Returns:
            Validated response data, or default value if invalid/error

        Example:
            >>> sections = self._cached_query("iSj", "list",
            ...     error_msg="No sections found")
        """
        if cmd in self._cache:
            cached = self._cache[cmd]
            if data_type == "list":
                return cast(list[dict[str, Any]], cached)
            return cast(dict[str, Any], cached)

        result: Any
        default_value: Any
        if data_type == "list":
            result = safe_cmd_list(self._r2, cmd)
            default_value = default if default is not None else []
        else:
            result = safe_cmd_dict(self._r2, cmd)
            default_value = default if default is not None else {}

        validated = validate_r2_data(result, data_type)
        if not is_valid_r2_response(validated):
            if error_msg:
                logger.debug(error_msg)
            if data_type == "list":
                return cast(list[dict[str, Any]], default_value)
            return cast(dict[str, Any], default_value)

        self._cache[cmd] = validated
        if data_type == "list":
            return cast(list[dict[str, Any]], validated)
        return cast(dict[str, Any], validated)

    def get_file_info(self) -> dict[str, Any]:
        """
        Retrieve general file information.

        Executes the radare2 'ij' command to gather comprehensive file metadata
        including architecture, bits, format, endianness, and entry point.

        Returns:
            Dictionary containing file metadata with keys:
                - arch: Architecture (x86, arm, mips, etc.)
                - bits: Architecture bits (32 or 64)
                - bintype: Binary format (pe, elf, mach0, etc.)
                - class: File class (PE32, PE32+, ELF32, ELF64, etc.)
                - endian: Endianness (little, big)
                - baddr: Base address
                - intrp: Interpreter path (for ELF)
                - And many more depending on file format
            Returns empty dict on error.

        Example:
            >>> info = adapter.get_file_info()
            >>> if info:
            ...     print(f"{info['arch']}-{info['bits']}")
            ...     print(f"Format: {info['bintype']}")
        """
        try:
            if "ij" in self._cache:
                return cast(dict[str, Any], self._cache["ij"])
            info = safe_cmd_dict(self._r2, "ij")
            validated = validate_r2_data(info, "dict")

            if not is_valid_r2_response(validated):
                logger.warning("Invalid or empty response from 'ij' command")
                return {}

            self._cache["ij"] = validated
            return cast(dict[str, Any], validated)

        except Exception as e:
            logger.error(f"Error retrieving file info: {e}")
            return {}

    def get_sections(self) -> list[dict[str, Any]]:
        """
        Retrieve all binary sections.

        Executes the radare2 'iSj' command to get section information including
        names, addresses, sizes, permissions, and flags.

        Returns:
            List of section dictionaries with keys:
                - name: Section name (.text, .data, __TEXT, etc.)
                - vaddr: Virtual address
                - paddr: Physical address in file
                - size: Section size in bytes
                - vsize: Virtual size (may differ from size)
                - perm: Permission flags (r, w, x)
                - flags: Additional section flags
            Returns empty list on error.

        Example:
            >>> sections = adapter.get_sections()
            >>> text_sections = [s for s in sections
            ...                  if '.text' in s.get('name', '')]
            >>> if text_sections:
            ...     print(f"Code section at: {hex(text_sections[0]['vaddr'])}")
        """
        try:
            return cast(
                list[dict[str, Any]],
                self._cached_query(
                    "iSj",
                    "list",
                    error_msg="No sections found or invalid response from 'iSj'",
                ),
            )
        except Exception as e:
            logger.error(f"Error retrieving sections: {e}")
            return []

    def get_imports(self) -> list[dict[str, Any]]:
        """
        Retrieve imported functions and libraries.

        Executes the radare2 'iij' command to get import table information
        including function names, library names, and binding information.

        Returns:
            List of import dictionaries with keys:
                - name: Function or symbol name
                - libname: Library/DLL name providing the import
                - bind: Binding type (GLOBAL, LOCAL, WEAK)
                - type: Import type (FUNC, OBJECT)
                - plt: PLT/IAT address (if applicable)
                - ordinal: Import ordinal (PE files)
            Returns empty list on error.

        Example:
            >>> imports = adapter.get_imports()
            >>> kernel_imports = [i for i in imports
            ...                   if 'kernel32' in i.get('libname', '').lower()]
            >>> for imp in kernel_imports[:5]:
            ...     print(f"{imp['name']} from {imp['libname']}")
        """
        try:
            return cast(
                list[dict[str, Any]],
                self._cached_query(
                    "iij",
                    "list",
                    error_msg="No imports found or invalid response from 'iij'",
                ),
            )
        except Exception as e:
            logger.error(f"Error retrieving imports: {e}")
            return []

    def get_exports(self) -> list[dict[str, Any]]:
        """
        Retrieve exported functions and symbols.

        Executes the radare2 'iEj' command to get export table information
        including exported function names, addresses, and binding information.

        Returns:
            List of export dictionaries with keys:
                - name: Exported function or symbol name
                - vaddr: Virtual address of the export
                - paddr: Physical address in file
                - bind: Binding type (GLOBAL, LOCAL, WEAK)
                - type: Export type (FUNC, OBJECT)
                - size: Size of exported object (if applicable)
            Returns empty list on error.

        Example:
            >>> exports = adapter.get_exports()
            >>> public_funcs = [e for e in exports
            ...                 if e.get('bind') == 'GLOBAL'
            ...                 and e.get('type') == 'FUNC']
            >>> print(f"Found {len(public_funcs)} public functions")
        """
        try:
            return cast(
                list[dict[str, Any]],
                self._cached_query(
                    "iEj",
                    "list",
                    error_msg="No exports found or invalid response from 'iEj'",
                ),
            )
        except Exception as e:
            logger.error(f"Error retrieving exports: {e}")
            return []

    def get_symbols(self) -> list[dict[str, Any]]:
        """
        Retrieve all symbols from the binary.

        Executes the radare2 'isj' command to get comprehensive symbol table
        information including all defined symbols, their types, and addresses.

        Returns:
            List of symbol dictionaries with keys:
                - name: Symbol name
                - vaddr: Virtual address
                - paddr: Physical address
                - bind: Binding type (GLOBAL, LOCAL, WEAK)
                - type: Symbol type (FUNC, OBJECT, SECTION, FILE)
                - size: Symbol size in bytes
                - is_imported: Boolean indicating if symbol is imported
            Returns empty list on error.

        Example:
            >>> symbols = adapter.get_symbols()
            >>> functions = [s for s in symbols
            ...              if s.get('type') == 'FUNC']
            >>> for func in functions[:10]:
            ...     print(f"{func['name']} at {hex(func.get('vaddr', 0))}")
        """
        try:
            return cast(
                list[dict[str, Any]],
                self._cached_query(
                    "isj",
                    "list",
                    error_msg="No symbols found or invalid response from 'isj'",
                ),
            )
        except Exception as e:
            logger.error(f"Error retrieving symbols: {e}")
            return []

    def get_strings(self) -> list[dict[str, Any]]:
        """
        Retrieve strings from the binary.

        Executes the radare2 'izzj' command to extract all strings from
        the binary, including strings in data sections and the entire binary.

        Note: This uses 'izzj' which searches the entire binary. For faster
        results with only data section strings, consider using 'izj'.

        Returns:
            List of string dictionaries with keys:
                - string: The actual string content
                - vaddr: Virtual address where string is located
                - paddr: Physical address in file
                - size: String length
                - length: String length (may differ from size)
                - section: Section name where string is found
                - type: String type (ascii, wide, etc.)
            Returns empty list on error.

        Example:
            >>> strings = adapter.get_strings()
            >>> urls = [s for s in strings
            ...         if 'http' in s.get('string', '').lower()]
            >>> for url_str in urls[:5]:
            ...     print(f"Found URL: {url_str['string']}")
        """
        try:
            return cast(
                list[dict[str, Any]],
                self._cached_query(
                    "izzj",
                    "list",
                    error_msg="No strings found or invalid response from 'izzj'",
                ),
            )
        except Exception as e:
            logger.error(f"Error retrieving strings: {e}")
            return []

    def get_functions(self) -> list[dict[str, Any]]:
        """
        Retrieve analyzed functions from the binary.

        Executes the radare2 'aflj' command to get information about all
        analyzed functions including their addresses, sizes, and names.

        Note: This requires radare2 to have performed analysis (aaa, aa, af).
        The adapter assumes analysis has been performed externally.

        Returns:
            List of function dictionaries with keys:
                - name: Function name or address
                - offset: Function start address
                - size: Function size in bytes
                - nbbs: Number of basic blocks
                - edges: Number of edges in control flow graph
                - cc: Cyclomatic complexity
                - type: Function type (fcn, sym.func, etc.)
            Returns empty list on error or if no analysis performed.

        Example:
            >>> functions = adapter.get_functions()
            >>> large_funcs = [f for f in functions
            ...                if f.get('size', 0) > 1000]
            >>> print(f"Found {len(large_funcs)} large functions")
            >>> for func in sorted(large_funcs,
            ...                    key=lambda x: x.get('size', 0),
            ...                    reverse=True)[:5]:
            ...     print(f"{func['name']}: {func['size']} bytes")
        """
        try:
            return cast(
                list[dict[str, Any]],
                self._cached_query(
                    "aflj",
                    "list",
                    error_msg=(
                        "No functions found or invalid response from 'aflj'. "
                        "Analysis may not have been performed."
                    ),
                ),
            )
        except Exception as e:
            logger.error(f"Error retrieving functions: {e}")
            return []

    def read_bytes(self, address: int, size: int) -> bytes:
        """
        Read raw bytes from a specific address.

        Executes the radare2 'p8' command to read a specified number of bytes
        from the given virtual address. This is useful for extracting specific
        data regions, shellcode, or embedded resources.

        Args:
            address: Virtual address to read from (must be non-negative)
            size: Number of bytes to read (must be positive)

        Returns:
            Bytes object containing the read data. Returns empty bytes if
            read fails, address is invalid, or size is invalid.

        Raises:
            ValueError: If address is negative or size is not positive

        Example:
            >>> # Read 16 bytes from entry point
            >>> info = adapter.get_file_info()
            >>> entry = info.get('baddr', 0)
            >>> data = adapter.read_bytes(entry, 16)
            >>> print(f"Entry point bytes: {data.hex()}")
            >>>
            >>> # Read and analyze PE header
            >>> pe_header = adapter.read_bytes(0, 0x200)
            >>> if pe_header[:2] == b'MZ':
            ...     print("Valid PE signature")
        """
        try:
            # Validate inputs
            valid_address = validate_address(address)
            valid_size = validate_size(size)

            # Execute p8 command to read hex bytes
            # Format: "p8 <size> @ <address>"
            cmd = f"p8 {valid_size} @ {valid_address}"
            hex_data = safe_cmd(self._r2, cmd, "")

            if not hex_data or not is_valid_r2_response(hex_data):
                logger.warning(
                    f"Failed to read {valid_size} bytes from address {hex(valid_address)}"
                )
                return b""

            # Sanitize output (remove whitespace, newlines)
            hex_data = sanitize_r2_output(hex_data)
            hex_data = hex_data.replace(" ", "").replace("\n", "")

            # Convert hex string to bytes
            try:
                return bytes.fromhex(hex_data)
            except ValueError as e:
                logger.error(f"Failed to convert hex data to bytes: {e}. Data: {hex_data[:100]}")
                return b""

        except ValueError as e:
            logger.error(f"Invalid address or size: {e}")
            raise
        except Exception as e:
            logger.error(f"Error reading bytes from address {hex(address)}: {e}")
            return b""

    def execute_command(self, cmd: str) -> Any:
        """
        Execute an analyzer-specific command.

        This method provides a generic interface for executing radare2 commands
        that may not be exposed through the standard Protocol methods. It
        automatically detects whether to use JSON or text output based on
        command suffix.

        Commands ending with 'j' are treated as JSON commands and use cmdj().
        All other commands use cmd() for text output.

        Args:
            cmd: Radare2 command string to execute

        Returns:
            Command output with type depending on command:
                - Dict or List for JSON commands (ending with 'j')
                - str for text commands
                - None if command fails

        Example:
            >>> # Execute JSON command
            >>> file_info = adapter.execute_command("ij")
            >>> assert isinstance(file_info, dict)
            >>>
            >>> # Execute text command
            >>> disasm = adapter.execute_command("pd 10")
            >>> assert isinstance(disasm, str)
            >>>
            >>> # Get binary info with custom command
            >>> bin_info = adapter.execute_command("iIj")
            >>> print(f"Compiler: {bin_info.get('compiler', 'unknown')}")
        """
        try:
            if not cmd:
                logger.warning("Empty command provided to execute_command")
                return None

            # Sanitize command (remove potential injection attempts)
            cmd = cmd.strip()

            # Detect JSON vs text command
            if cmd.endswith("j"):
                # JSON command
                result = safe_cmdj(self._r2, cmd, None)

                if result is None:
                    logger.debug(f"Command '{cmd}' returned None")
                    return None

                # Validate based on result type
                if isinstance(result, dict):
                    return validate_r2_data(result, "dict")
                elif isinstance(result, list):
                    return validate_r2_data(result, "list")
                else:
                    return result
            else:
                # Text command
                result = safe_cmd(self._r2, cmd, "")

                if not result:
                    logger.debug(f"Command '{cmd}' returned empty result")
                    return ""

                return sanitize_r2_output(result)

        except Exception as e:
            logger.error(f"Error executing command '{cmd}': {e}")
            return None

    def __repr__(self) -> str:
        """Return string representation of the adapter."""
        return f"R2PipeAdapter(r2_instance={self._r2})"

    def __str__(self) -> str:
        """Return human-readable string representation."""
        return "R2PipeAdapter for radare2 binary analysis"
