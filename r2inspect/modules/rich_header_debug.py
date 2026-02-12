#!/usr/bin/env python3
"""Debug helpers for Rich Header analysis."""

from __future__ import annotations

import struct
from typing import Any, cast

from ..utils.logger import get_logger

logger = get_logger(__name__)


class RichHeaderDebugMixin:
    """Debug and low-level helpers for Rich Header analysis."""

    adapter: Any

    def _debug_file_structure(self) -> None:
        """
        Debug method to analyze file structure when Rich Header is not found.
        """
        try:
            logger.debug("=== DEBUGGING FILE STRUCTURE ===")

            file_size = self._debug_get_file_size()
            logger.debug(f"File size: {file_size} bytes")

            data = self._debug_read_bytes(512)
            if not data:
                return

            if self._debug_has_mz_header(data):
                pe_offset = self._debug_get_pe_offset(data)
                if pe_offset is not None:
                    self._debug_log_stub_analysis(data, pe_offset)

            self._debug_log_extended_patterns()

        except Exception as e:
            logger.debug(f"Debug analysis failed: {e}")

    def _debug_get_file_size(self) -> int:
        return int(self._get_file_info().get("core", {}).get("size", 0))

    def _debug_read_bytes(self, size: int) -> bytes | None:
        if self.adapter is None or not hasattr(self.adapter, "read_bytes"):
            return None
        data = self.adapter.read_bytes(0, size)
        return data if data else None

    @staticmethod
    def _debug_has_mz_header(data: bytes) -> bool:
        if data[:2] == b"MZ":
            logger.debug("Found MZ header at offset 0")
            return True
        return False

    @staticmethod
    def _debug_get_pe_offset(data: bytes) -> int | None:
        if len(data) < 0x3C + 4:
            return None
        pe_offset = int(struct.unpack("<I", data[0x3C : 0x3C + 4])[0])
        logger.debug(f"PE header offset: 0x{pe_offset:x}")
        return pe_offset

    def _debug_log_stub_analysis(self, data: bytes, pe_offset: int) -> None:
        if pe_offset <= 64:
            return
        stub_data = data[64 : min(pe_offset, len(data))]
        logger.debug(f"DOS stub size: {len(stub_data)} bytes")

        rich_pos = stub_data.find(b"Rich")
        dans_pos = stub_data.find(b"DanS")

        if rich_pos != -1:
            logger.debug(f"Found 'Rich' at DOS stub offset: {rich_pos + 64}")
        if dans_pos != -1:
            logger.debug(f"Found 'DanS' at DOS stub offset: {dans_pos + 64}")

        if rich_pos == -1 and dans_pos == -1:
            return

        start = max(0, min(pos for pos in [rich_pos, dans_pos] if pos != -1) - 16)
        end_candidates = [pos for pos in [rich_pos, dans_pos] if pos != -1]
        end = min(len(stub_data), max(end_candidates) + 32)
        hex_dump = stub_data[start:end].hex()
        logger.debug(f"Hex dump around signatures: {hex_dump}")

    def _debug_log_extended_patterns(self) -> None:
        logger.debug("Searching first 2KB for Rich Header patterns...")
        if self.adapter is None or not hasattr(self.adapter, "read_bytes"):
            return
        extended_bytes = self.adapter.read_bytes(0, 2048)
        if not extended_bytes:
            return
        rich_positions, dans_positions = self._find_rich_dans_positions(extended_bytes)

        logger.debug(f"Found 'Rich' at positions: {rich_positions}")
        logger.debug(f"Found 'DanS' at positions: {dans_positions}")

        self._debug_log_candidates(extended_bytes, rich_positions, dans_positions)

    @staticmethod
    def _find_rich_dans_positions(data: bytes) -> tuple[list[int], list[int]]:
        rich_positions: list[int] = []
        dans_positions: list[int] = []
        pos = 0
        while pos < len(data) - 4:
            if data[pos : pos + 4] == b"Rich":
                rich_positions.append(pos)
            if data[pos : pos + 4] == b"DanS":
                dans_positions.append(pos)
            pos += 1
        return rich_positions, dans_positions

    @staticmethod
    def _debug_log_candidates(
        data: bytes, rich_positions: list[int], dans_positions: list[int]
    ) -> None:
        for dans_pos in dans_positions:
            for rich_pos in rich_positions:
                if dans_pos < rich_pos and (rich_pos - dans_pos) < 512:
                    logger.debug(
                        f"Attempting manual extraction at DanS:{dans_pos}, Rich:{rich_pos}"
                    )
                    segment = data[dans_pos : rich_pos + 8]
                    logger.debug(f"Rich Header candidate ({len(segment)} bytes): {segment.hex()}")

    def _read_bytes(self, address: int, size: int) -> bytes:
        if self.adapter is None or not hasattr(self.adapter, "read_bytes"):
            return b""
        return cast(bytes, self.adapter.read_bytes(address, size))

    def _get_file_info(self) -> dict[str, Any]:
        if self.adapter is None or not hasattr(self.adapter, "get_file_info"):
            return {}
        return cast(dict[str, Any], self.adapter.get_file_info())
