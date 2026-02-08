from __future__ import annotations

from typing import Any

from r2inspect.interfaces.binary_analyzer import BinaryAnalyzerInterface


class _Analyzer:
    def get_file_info(self) -> dict[str, Any]:
        return {"format": "PE"}

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_imports(self) -> list[dict[str, Any]]:
        return []

    def get_exports(self) -> list[dict[str, Any]]:
        return []

    def get_symbols(self) -> list[dict[str, Any]]:
        return []

    def get_strings(self) -> list[dict[str, Any]]:
        return []

    def get_functions(self) -> list[dict[str, Any]]:
        return []

    def get_functions_at(self, _address: int) -> list[dict[str, Any]]:
        return []

    def get_disasm(self, _address: int | None = None, _size: int | None = None) -> Any:
        return {}

    def get_cfg(self, _address: int | None = None) -> Any:
        return {}

    def analyze_all(self) -> str:
        return ""

    def get_info_text(self) -> str:
        return ""

    def get_dynamic_info_text(self) -> str:
        return ""

    def get_entropy_pattern(self) -> str:
        return ""

    def get_pe_version_info_text(self) -> str:
        return ""

    def get_pe_security_text(self) -> str:
        return ""

    def get_header_text(self) -> str:
        return ""

    def get_headers_json(self) -> Any:
        return {}

    def get_strings_basic(self) -> list[dict[str, Any]]:
        return []

    def get_strings_text(self) -> str:
        return ""

    def get_strings_filtered(self, _command: str) -> str:
        return ""

    def get_entry_info(self) -> list[dict[str, Any]]:
        return []

    def get_pe_header(self) -> dict[str, Any]:
        return {}

    def get_pe_optional_header(self) -> dict[str, Any]:
        return {}

    def get_data_directories(self) -> list[dict[str, Any]]:
        return []

    def get_resources_info(self) -> list[dict[str, Any]]:
        return []

    def get_function_info(self, _address: int) -> list[dict[str, Any]]:
        return []

    def get_disasm_text(self, _address: int | None = None, _size: int | None = None) -> str:
        return ""

    def search_text(self, _pattern: str) -> str:
        return ""

    def search_hex(self, _hex_pattern: str) -> str:
        return ""

    def search_hex_json(self, _pattern: str) -> list[dict[str, Any]]:
        return []

    def read_bytes_list(self, _address: int, _size: int) -> list[int]:
        return []

    def read_bytes(self, address: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("size must be non-negative")
        return b""

    def execute_command(self, cmd: str) -> Any:
        return cmd


class _IncompleteAnalyzer:
    def get_file_info(self) -> dict[str, Any]:
        return {}


def test_binary_analyzer_protocol_runtime_checkable():
    analyzer = _Analyzer()
    assert isinstance(analyzer, BinaryAnalyzerInterface)

    incomplete = _IncompleteAnalyzer()
    assert not isinstance(incomplete, BinaryAnalyzerInterface)
