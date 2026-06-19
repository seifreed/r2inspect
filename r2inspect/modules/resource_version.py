"""Version-info parsing helpers for PE resource analysis."""

from __future__ import annotations

from typing import Any

from ..abstractions.coercion_support import coerce_int


def _to_int(value: Any) -> int:
    return coerce_int(value)


class ResourceVersionMixin:
    """VERSION_INFO parsing helpers kept separate from resource orchestration."""

    _cmdj: Any  # provided by host class

    def _read_version_info_data(self, offset: int, size: int) -> list[int] | None:
        offset = _to_int(offset)
        size = _to_int(size)
        if offset < 0 or size <= 0:
            return None
        data = self._cmdj(f"pxj {min(size, 1024)} @ {offset}", [])
        if isinstance(data, (dict, str, bytes)):
            return None
        try:
            data = list(data)
        except TypeError:
            return None
        if (
            not data
            or len(data) < 64
            or not all(isinstance(value, int) and 0 <= value <= 0xFF for value in data)
        ):
            return None
        return data

    def _find_vs_signature(self, data: list[int]) -> int:
        vs_sig = [0xBD, 0x04, 0xEF, 0xFE]
        return self._find_pattern(data, vs_sig)

    def _parse_fixed_file_info(self, data: list[int], sig_pos: int) -> str:
        if sig_pos + 52 > len(data):
            return ""
        file_version_ms = (
            data[sig_pos + 8]
            | (data[sig_pos + 9] << 8)
            | (data[sig_pos + 10] << 16)
            | (data[sig_pos + 11] << 24)
        )
        file_version_ls = (
            data[sig_pos + 12]
            | (data[sig_pos + 13] << 8)
            | (data[sig_pos + 14] << 16)
            | (data[sig_pos + 15] << 24)
        )
        return (
            f"{(file_version_ms >> 16) & 0xFFFF}.{file_version_ms & 0xFFFF}."
            f"{(file_version_ls >> 16) & 0xFFFF}.{file_version_ls & 0xFFFF}"
        )

    def _extract_version_strings(self, data: list[int]) -> dict[str, str]:
        strings: dict[str, str] = {}
        for key in self._version_string_keys():
            value = self._read_version_string_value(data, key)
            if value:
                strings[key] = value
        return strings

    def _version_string_keys(self) -> list[str]:
        return [
            "CompanyName",
            "FileDescription",
            "FileVersion",
            "InternalName",
            "LegalCopyright",
            "OriginalFilename",
            "ProductName",
            "ProductVersion",
        ]

    def _read_version_string_value(self, data: list[int], key: str) -> str:
        key_pattern = list(key.encode("utf-16le"))
        pos = self._find_pattern(data, key_pattern)
        if pos < 0:
            return ""
        value_start = pos + len(key_pattern) + 4
        if value_start >= len(data) - 2:
            return ""
        value_bytes: list[int] = []
        for i in range(value_start, min(value_start + 256, len(data) - 1), 2):
            first = data[i]
            second = data[i + 1]
            if not isinstance(first, int) or not isinstance(second, int):
                return ""
            if first == 0 and second == 0:
                break
            value_bytes.extend([first, second])
        if not value_bytes:
            return ""
        try:
            if not all(0 <= value <= 0xFF for value in value_bytes):
                return ""
            value = bytes(value_bytes).decode("utf-16le", errors="ignore")
            return value if value and value.isprintable() else ""
        except UnicodeDecodeError:
            return ""

    def _find_pattern(self, data: list[int], pattern: list[int]) -> int:
        pattern_len = len(pattern)
        data_len = len(data)
        for i in range(data_len - pattern_len + 1):
            if data[i : i + pattern_len] == pattern:
                return i
        return -1
