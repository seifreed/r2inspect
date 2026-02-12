#!/usr/bin/env python3
"""R2Pipe adapter query methods."""

from __future__ import annotations

from typing import Any, cast

from ..interfaces import R2CommandInterface
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd, safe_cmd_dict, safe_cmdj
from .validation import (
    is_valid_r2_response,
    sanitize_r2_output,
    validate_address,
    validate_r2_data,
    validate_size,
)

logger = get_logger(__name__)


class R2PipeQueryMixin(R2CommandInterface):
    """Query helpers for r2pipe-backed adapters."""

    _cache: dict[str, Any]

    def _cached_query(
        self,
        cmd: str,
        data_type: str = "list",
        default: list | dict | None = None,
        error_msg: str = "",
        *,
        cache: bool = True,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        raise NotImplementedError

    def _maybe_force_error(self, method: str) -> None:
        raise NotImplementedError

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
            self._maybe_force_error("get_file_info")
            if "ij" in self._cache:
                return cast(dict[str, Any], self._cache["ij"])
            info = safe_cmd_dict(self, "ij")
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

    def get_functions_at(self, address: int) -> list[dict[str, Any]]:
        """Retrieve functions at a given address using 'aflj @ <addr>'."""
        try:
            self._maybe_force_error("get_functions_at")
            cmd = f"aflj @ {address}"
            data = safe_cmdj(self, cmd, [])
            validated = validate_r2_data(data, "list")
            return cast(list[dict[str, Any]], validated) if validated else []
        except Exception as e:
            logger.error(f"Error retrieving functions at {hex(address)}: {e}")
            return []

    def get_disasm(self, address: int | None = None, size: int | None = None) -> Any:
        """
        Retrieve disassembly as JSON.

        Uses 'pdfj' for function disassembly or 'pdj <size>' for a byte range.
        Optional address uses radare2's '@' seek syntax.
        """
        try:
            self._maybe_force_error("get_disasm")
            if size is None:
                cmd = "pdfj"
                data_type = "dict"
            else:
                cmd = f"pdj {size}"
                data_type = "list"
            if address is not None:
                cmd = f"{cmd} @ {address}"
            return self._cached_query(
                cmd,
                data_type,
                error_msg=f"No disassembly found for '{cmd}'",
                cache=address is None,
            )
        except Exception as e:
            logger.error(f"Error retrieving disassembly: {e}")
            return []

    def get_cfg(self, address: int | None = None) -> Any:
        """
        Retrieve a control-flow graph as JSON.

        Uses 'agj' with optional '@ <address>' seek syntax.
        """
        try:
            self._maybe_force_error("get_cfg")
            cmd = "agj"
            if address is not None:
                cmd = f"{cmd} @ {address}"
            return self._cached_query(
                cmd,
                "list",
                error_msg=f"No CFG data found for '{cmd}'",
                cache=address is None,
            )
        except Exception as e:
            logger.error(f"Error retrieving CFG: {e}")
            return {}

    def analyze_all(self) -> str:
        """Run full analysis (aaa)."""
        try:
            self._maybe_force_error("analyze_all")
            return safe_cmd(self, "aaa", "")
        except Exception as e:
            logger.error(f"Error running analysis: {e}")
            return ""

    def get_info_text(self) -> str:
        """Return textual info output (i)."""
        try:
            self._maybe_force_error("get_info_text")
            return safe_cmd(self, "i", "")
        except Exception as e:
            logger.error(f"Error retrieving info text: {e}")
            return ""

    def get_dynamic_info_text(self) -> str:
        """Return dynamic info output (id)."""
        try:
            self._maybe_force_error("get_dynamic_info_text")
            return safe_cmd(self, "id", "")
        except Exception as e:
            logger.error(f"Error retrieving dynamic info text: {e}")
            return ""

    def get_entropy_pattern(self) -> str:
        """Return entropy pattern output (p=e 100)."""
        try:
            self._maybe_force_error("get_entropy_pattern")
            return safe_cmd(self, "p=e 100", "")
        except Exception as e:
            logger.error(f"Error retrieving entropy pattern: {e}")
            return ""

    def get_pe_version_info_text(self) -> str:
        """Return PE version info text output (iR~version)."""
        try:
            self._maybe_force_error("get_pe_version_info_text")
            return safe_cmd(self, "iR~version", "")
        except Exception as e:
            logger.error(f"Error retrieving PE version info text: {e}")
            return ""

    def get_pe_security_text(self) -> str:
        """Return PE security info text (iHH)."""
        try:
            self._maybe_force_error("get_pe_security_text")
            return safe_cmd(self, "iHH", "")
        except Exception as e:
            logger.error(f"Error retrieving PE security text: {e}")
            return ""

    def get_header_text(self) -> str:
        """Return header text output (ih)."""
        try:
            self._maybe_force_error("get_header_text")
            return safe_cmd(self, "ih", "")
        except Exception as e:
            logger.error(f"Error retrieving header text: {e}")
            return ""

    def get_headers_json(self) -> Any:
        """Return header JSON output (ihj)."""
        try:
            self._maybe_force_error("get_headers_json")
            return safe_cmdj(self, "ihj", None)
        except Exception as e:
            logger.error(f"Error retrieving header JSON: {e}")
            return None

    def get_strings_basic(self) -> list[dict[str, Any]]:
        """Return basic strings list (izj)."""
        try:
            return cast(
                list[dict[str, Any]],
                self._cached_query(
                    "izj",
                    "list",
                    error_msg="No strings found or invalid response from 'izj'",
                ),
            )
        except Exception as e:
            logger.error(f"Error retrieving basic strings: {e}")
            return []

    def get_strings_text(self) -> str:
        """Return raw strings text output (izz~..)."""
        try:
            self._maybe_force_error("get_strings_text")
            return safe_cmd(self, "izz~..", "")
        except Exception as e:
            logger.error(f"Error retrieving strings text: {e}")
            return ""

    def get_strings_filtered(self, command: str) -> str:
        """Return filtered strings output (iz~...)."""
        try:
            self._maybe_force_error("get_strings_filtered")
            return safe_cmd(self, command, "")
        except Exception as e:
            logger.error(f"Error retrieving filtered strings: {e}")
            return ""

    def get_entry_info(self) -> list[dict[str, Any]]:
        """Return entry point info (iej)."""
        try:
            self._maybe_force_error("get_entry_info")
            data = safe_cmdj(self, "iej", [])
            validated = validate_r2_data(data, "list")
            return cast(list[dict[str, Any]], validated) if validated else []
        except Exception as e:
            logger.error(f"Error retrieving entry info: {e}")
            return []

    def get_pe_header(self) -> dict[str, Any]:
        """Return PE header info (ihj) as dict when possible."""
        try:
            self._maybe_force_error("get_pe_header")
            data = safe_cmdj(self, "ihj", {})
            if isinstance(data, list) and data:
                return {"headers": data}
            if isinstance(data, dict):
                return data
            return {}
        except Exception as e:
            logger.error(f"Error retrieving PE header: {e}")
            return {}

    def get_pe_optional_header(self) -> dict[str, Any]:
        """Return PE optional header info (iHj)."""
        try:
            self._maybe_force_error("get_pe_optional_header")
            data = safe_cmdj(self, "iHj", {})
            validated = validate_r2_data(data, "dict")
            return cast(dict[str, Any], validated) if validated else {}
        except Exception as e:
            logger.error(f"Error retrieving PE optional header: {e}")
            return {}

    def get_data_directories(self) -> list[dict[str, Any]]:
        """Return data directories info (iDj)."""
        try:
            self._maybe_force_error("get_data_directories")
            data = safe_cmdj(self, "iDj", [])
            validated = validate_r2_data(data, "list")
            return cast(list[dict[str, Any]], validated) if validated else []
        except Exception as e:
            logger.error(f"Error retrieving data directories: {e}")
            return []

    def get_resources_info(self) -> list[dict[str, Any]]:
        """Return resources info (iRj)."""
        try:
            self._maybe_force_error("get_resources_info")
            data = safe_cmdj(self, "iRj", [])
            validated = validate_r2_data(data, "list")
            return cast(list[dict[str, Any]], validated) if validated else []
        except Exception as e:
            logger.error(f"Error retrieving resources info: {e}")
            return []

    def get_function_info(self, address: int) -> list[dict[str, Any]]:
        """Return function info (afij @ address)."""
        try:
            self._maybe_force_error("get_function_info")
            cmd = f"afij @ {address}"
            data = safe_cmdj(self, cmd, [])
            validated = validate_r2_data(data, "list")
            return cast(list[dict[str, Any]], validated) if validated else []
        except Exception as e:
            logger.error(f"Error retrieving function info: {e}")
            return []

    def get_disasm_text(self, address: int | None = None, size: int | None = None) -> str:
        """Return textual disassembly (pi) for a region."""
        try:
            self._maybe_force_error("get_disasm_text")
            cmd = "pi" if size is None else f"pi {size}"
            if address is not None:
                cmd = f"{cmd} @ {address}"
            return safe_cmd(self, cmd, "")
        except Exception as e:
            logger.error(f"Error retrieving disasm text: {e}")
            return ""

    def search_hex_json(self, pattern: str) -> list[dict[str, Any]]:
        """Return hex search results in JSON (/xj)."""
        try:
            self._maybe_force_error("search_hex_json")
            data = safe_cmdj(self, f"/xj {pattern}", [])
            validated = validate_r2_data(data, "list")
            return cast(list[dict[str, Any]], validated) if validated else []
        except Exception as e:
            logger.error(f"Error searching hex pattern JSON: {e}")
            return []

    def read_bytes_list(self, address: int, size: int) -> list[int]:
        """Read raw bytes and return a list of ints."""
        data = self.read_bytes(address, size)
        return list(data) if data else []

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
            self._maybe_force_error("read_bytes")
            # Validate inputs
            valid_address = validate_address(address)
            valid_size = validate_size(size)

            # Execute p8 command to read hex bytes
            # Format: "p8 <size> @ <address>"
            cmd = f"p8 {valid_size} @ {valid_address}"
            hex_data = safe_cmd(self, cmd, "")

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

    def search_text(self, pattern: str) -> str:
        """Search for text patterns using r2 /c."""
        try:
            self._maybe_force_error("search_text")
            return safe_cmd(self, f"/c {pattern}")
        except Exception as e:
            logger.error(f"Error searching text pattern: {e}")
            return ""

    def search_hex(self, hex_pattern: str) -> str:
        """Search for hex patterns using r2 /x."""
        try:
            self._maybe_force_error("search_hex")
            return safe_cmd(self, f"/x {hex_pattern}")
        except Exception as e:
            logger.error(f"Error searching hex pattern: {e}")
            return ""
