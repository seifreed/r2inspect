"""Shared r2 header parsing helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from ..error_handling import ErrorHandlingStrategy, ErrorPolicy, handle_errors


def parse_pe_header_text(
    r2_instance: Any, safe_cmd_func: Callable[[Any, str], str]
) -> dict[str, Any] | None:
    @handle_errors(ErrorPolicy(ErrorHandlingStrategy.FALLBACK, fallback_value=None))
    def _parse() -> dict[str, Any] | None:
        text_output = safe_cmd_func(r2_instance, "ih")
        if not text_output:
            return None

        result: dict[str, Any] = {
            "nt_headers": {},
            "file_header": {},
            "optional_header": {},
        }
        current_section: str | None = None
        for raw_line in text_output.split("\n"):
            line = raw_line.strip()
            if not line:
                continue

            current_section = _parse_section_header(line, current_section)
            if current_section is not None and ":" in line:
                _parse_key_value_pair(line, result, current_section)

        return result

    return cast(dict[str, Any] | None, _parse())


def _parse_section_header(line: str, current_section: str | None) -> str | None:
    if line == "IMAGE_NT_HEADERS":
        return "nt_headers"
    if line == "IMAGE_FILE_HEADERS":
        return "file_header"
    if line == "IMAGE_OPTIONAL_HEADERS":
        return "optional_header"
    return current_section


def _parse_key_value_pair(
    line: str, result: dict[str, dict[str, Any]], current_section: str
) -> None:
    key, value_raw = line.split(":", 1)
    key = key.strip()
    value_str = value_raw.strip()
    parsed_value: str | int = value_str

    if value_str.startswith("0x"):
        try:
            parsed_value = int(value_str, 16)
        except ValueError:
            pass

    result[current_section][key] = parsed_value


def get_pe_headers(
    r2_instance: Any,
    safe_cmdj_func: Callable[[Any, str, Any], Any],
    safe_cmd_func: Callable[[Any, str], str],
) -> dict[str, Any] | None:
    @handle_errors(ErrorPolicy(ErrorHandlingStrategy.FALLBACK, fallback_value=None))
    def _get_headers() -> dict[str, Any] | None:
        headers_list = (
            r2_instance.get_headers_json()
            if hasattr(r2_instance, "get_headers_json")
            else safe_cmdj_func(r2_instance, "ihj", [])
        )

        if not headers_list or not isinstance(headers_list, list):
            return parse_pe_header_text(r2_instance, safe_cmd_func)

        result: dict[str, Any] = {
            "nt_headers": {},
            "file_header": {},
            "optional_header": {},
        }

        for item in headers_list:
            if not isinstance(item, dict):
                continue

            name = item.get("name", "")
            value = item.get("value", 0)

            if name in [
                "Signature",
                "Machine",
                "NumberOfSections",
                "TimeDateStamp",
                "PointerToSymbolTable",
                "NumberOfSymbols",
                "SizeOfOptionalHeader",
                "Characteristics",
            ]:
                result["file_header"][name] = value
            elif name in [
                "Magic",
                "MajorLinkerVersion",
                "MinorLinkerVersion",
                "SizeOfCode",
                "SizeOfInitializedData",
                "SizeOfUninitializedData",
                "AddressOfEntryPoint",
                "BaseOfCode",
                "BaseOfData",
                "ImageBase",
                "SectionAlignment",
                "FileAlignment",
                "MajorOperatingSystemVersion",
                "MinorOperatingSystemVersion",
                "MajorImageVersion",
                "MinorImageVersion",
                "MajorSubsystemVersion",
                "MinorSubsystemVersion",
                "Win32VersionValue",
                "SizeOfImage",
                "SizeOfHeaders",
                "CheckSum",
                "Subsystem",
                "DllCharacteristics",
                "SizeOfStackReserve",
                "SizeOfStackCommit",
                "SizeOfHeapReserve",
                "SizeOfHeapCommit",
                "LoaderFlags",
                "NumberOfRvaAndSizes",
            ]:
                result["optional_header"][name] = value
            else:
                result["nt_headers"][name] = value

        return result

    return cast(dict[str, Any] | None, _get_headers())


def get_elf_headers(
    r2_instance: Any,
    safe_cmdj_func: Callable[[Any, str, Any], Any],
    safe_cmd_func: Callable[[Any, str], str],
) -> list[dict[str, Any]] | None:
    @handle_errors(ErrorPolicy(ErrorHandlingStrategy.FALLBACK, fallback_value=[]))
    def _get_headers() -> list[dict[str, Any]]:
        headers = _get_headers_json(r2_instance, safe_cmdj_func)
        if headers is not None:
            return headers

        ph_output = (
            r2_instance.get_header_text()
            if hasattr(r2_instance, "get_header_text")
            else safe_cmd_func(r2_instance, "ih")
        )
        if not ph_output:
            return []

        return _parse_elf_headers_text(ph_output)

    return cast(list[dict[str, Any]] | None, _get_headers())


def _get_headers_json(
    r2_instance: Any, safe_cmdj_func: Callable[[Any, str, Any], Any]
) -> list[dict[str, Any]] | None:
    headers = (
        r2_instance.get_headers_json()
        if hasattr(r2_instance, "get_headers_json")
        else safe_cmdj_func(r2_instance, "ihj", None)
    )
    if not headers:
        return None
    if isinstance(headers, dict):
        return [headers]
    if isinstance(headers, list):
        return headers
    return None


def _parse_elf_headers_text(ph_output: str) -> list[dict[str, Any]]:
    headers: list[dict[str, Any]] = []
    for raw_line in ph_output.split("\n"):
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        parsed_key = key.strip().lower()
        parsed_value = value.strip()
        if parsed_key in {"type", "flags", "offset", "vaddr", "paddr", "filesz", "memsz"}:
            headers.append({parsed_key: parsed_value})
    return headers


def get_macho_headers(
    r2_instance: Any,
    safe_cmdj_func: Callable[[Any, str, Any], Any],
    safe_cmd_func: Callable[[Any, str], str],
) -> list[dict[str, Any]] | None:
    @handle_errors(ErrorPolicy(ErrorHandlingStrategy.FALLBACK, fallback_value=[]))
    def _get_headers() -> list[dict[str, Any]]:
        headers = (
            r2_instance.get_headers_json()
            if hasattr(r2_instance, "get_headers_json")
            else safe_cmdj_func(r2_instance, "ihj", None)
        )
        if headers:
            if isinstance(headers, dict):
                return [headers]
            if isinstance(headers, list):
                return headers

        headers_output = (
            r2_instance.get_header_text()
            if hasattr(r2_instance, "get_header_text")
            else safe_cmd_func(r2_instance, "ih")
        )
        if not headers_output:
            return []
        return []

    return cast(list[dict[str, Any]] | None, _get_headers())
