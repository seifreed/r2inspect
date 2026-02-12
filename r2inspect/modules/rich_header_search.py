#!/usr/bin/env python3
"""Search helpers for Rich Header analysis."""

from __future__ import annotations

import struct
from typing import Any, cast

from ..utils.logger import get_logger
from .rich_header_domain import (
    build_rich_header_result,
    decode_rich_header,
    validate_decoded_entries,
)

logger = get_logger(__name__)


class RichHeaderSearchMixin:
    """Manual and pattern-based search helpers for Rich Header."""

    adapter: Any

    def _manual_rich_search(self) -> dict[str, Any] | None:
        """
        Manual search for Rich Header in DOS stub area when patterns fail.

        Returns:
            Dictionary containing Rich Header data or None if not found
        """
        try:
            data = self._read_manual_search_bytes()
            if not data:
                return None

            signatures_to_try = [
                (b"Rich", b"DanS"),
                (b"hciR", b"SnaD"),
            ]
            for rich_sig, dans_sig in signatures_to_try:
                offsets = self._find_signature_offsets(data, rich_sig, dans_sig)
                if not offsets:
                    continue
                rich_offsets, dans_offsets = offsets
                rich_data = self._try_signature_pairs(
                    rich_offsets, dans_offsets, rich_sig, dans_sig
                )
                if rich_data:
                    return rich_data

            return self._pattern_based_rich_search(data)

        except Exception as e:
            logger.error(f"Error in manual Rich Header search: {e}")
            return None

    def _read_manual_search_bytes(self) -> bytes | None:
        """Read a larger prefix of the file for manual search."""
        if self.adapter is None or not hasattr(self.adapter, "read_bytes"):
            return None
        data = self.adapter.read_bytes(0, 2048)
        return data if data else None

    def _find_signature_offsets(
        self, data: bytes, rich_sig: bytes, dans_sig: bytes
    ) -> tuple[list[int], list[int]] | None:
        """Find all signature offsets for a Rich/DanS pair."""
        rich_offsets = self._find_all_occurrences(data, rich_sig)
        dans_offsets = self._find_all_occurrences(data, dans_sig)
        logger.debug(f"Manual search found Rich at: {rich_offsets}, DanS at: {dans_offsets}")
        if not rich_offsets or not dans_offsets:
            return None
        return rich_offsets, dans_offsets

    def _find_all_occurrences(self, data: bytes, sig: bytes) -> list[int]:
        """Find all occurrences of a signature."""
        offsets: list[int] = []
        start = 0
        while True:
            pos = data.find(sig, start)
            if pos == -1:
                break
            offsets.append(pos)
            start = pos + 1
        return offsets

    def _try_signature_pairs(
        self,
        rich_offsets: list[int],
        dans_offsets: list[int],
        rich_sig: bytes,
        dans_sig: bytes,
    ) -> dict[str, Any] | None:
        """Try combinations of Rich/DanS offsets for a signature pair."""
        for dans_offset in dans_offsets:
            for rich_offset in rich_offsets:
                if not self._offset_pair_valid(dans_offset, rich_offset, 512):
                    continue
                rich_data = self._try_extract_rich_at_offsets(dans_offset, rich_offset)
                if rich_data:
                    logger.debug(
                        f"Found valid Rich Header with signature pair {rich_sig!r}/{dans_sig!r}"
                    )
                    return rich_data
        return None

    def _offset_pair_valid(self, dans_offset: int, rich_offset: int, max_delta: int) -> bool:
        """Validate signature offset pair distance."""
        return dans_offset < rich_offset and (rich_offset - dans_offset) <= max_delta

    def _pattern_based_rich_search(self, data: bytes) -> dict[str, Any] | None:
        """
        Pattern-based search for Rich Header using structural characteristics.

        Args:
            data: Raw file data to search

        Returns:
            Dictionary containing Rich Header data or None if not found
        """
        try:
            rich_positions = self._find_rich_positions(data)
            for rich_pos in rich_positions:
                if not self._is_valid_rich_key(data, rich_pos):
                    continue
                dans_pos = self._find_dans_before_rich(data, rich_pos)
                if dans_pos is None:
                    continue
                rich_data = self._try_extract_rich_at_offsets(dans_pos, rich_pos)
                if rich_data:
                    logger.debug(
                        f"Pattern-based search found Rich Header at DanS:{dans_pos}, Rich:{rich_pos}"
                    )
                    return rich_data
            return None

        except Exception as e:
            logger.debug(f"Error in pattern-based Rich Header search: {e}")
            return None

    def _find_rich_positions(self, data: bytes) -> list[int]:
        """Find positions of 'Rich' signature."""
        positions: list[int] = []
        for i in range(len(data) - 8):
            if data[i : i + 4] == b"Rich":
                positions.append(i)
        return positions

    def _is_valid_rich_key(self, data: bytes, rich_pos: int) -> bool:
        """Validate potential XOR key after Rich signature."""
        if rich_pos + 8 > len(data):
            return False
        potential_key = struct.unpack("<I", data[rich_pos + 4 : rich_pos + 8])[0]
        return potential_key not in (0, 0xFFFFFFFF)

    def _find_dans_before_rich(self, data: bytes, rich_pos: int) -> int | None:
        """Find DanS signature before Rich within a window."""
        for j in range(max(0, rich_pos - 512), rich_pos):
            if data[j : j + 4] == b"DanS":
                return j
        return None

    def _try_extract_rich_at_offsets(
        self, dans_offset: int, rich_offset: int
    ) -> dict[str, Any] | None:
        """
        Try to extract Rich Header at specific offsets.

        Args:
            dans_offset: Offset of DanS signature
            rich_offset: Offset of Rich signature

        Returns:
            Dictionary containing Rich Header data or None if extraction fails
        """
        try:
            rich_size = rich_offset - dans_offset
            if not self._validate_rich_size(rich_size):
                return None

            xor_key = self._extract_xor_key(rich_offset)
            if xor_key is None:
                return None

            encoded_data = self._extract_encoded_data(dans_offset, rich_size)
            if encoded_data is None:
                return None

            decoded_entries = decode_rich_header(encoded_data, xor_key)
            if not validate_decoded_entries(decoded_entries):
                return None
            logger.debug(
                f"Extracted Rich Header with {len(decoded_entries)} entries, XOR key: 0x{xor_key:08x}"
            )
            return build_rich_header_result(decoded_entries, xor_key)

        except Exception as e:
            logger.debug(f"Error extracting Rich Header: {e}")
            return None

    def _validate_rich_size(self, rich_size: int) -> bool:
        """Validate Rich Header size."""
        return rich_size > 8 and rich_size <= 512

    def _extract_xor_key(self, rich_offset: int) -> int | None:
        """Extract and validate XOR key."""
        xor_key_offset = rich_offset + 4
        if self.adapter is None or not hasattr(self.adapter, "read_bytes_list"):
            return None
        xor_key_bytes = cast(list[int], self.adapter.read_bytes_list(xor_key_offset, 4))

        if not xor_key_bytes or len(xor_key_bytes) < 4:
            return None

        xor_key = struct.unpack("<I", bytes(xor_key_bytes))[0]
        return xor_key if xor_key != 0 else None

    def _extract_encoded_data(self, dans_offset: int, rich_size: int) -> bytes | None:
        """Extract encoded Rich Header data."""
        if self.adapter is None or not hasattr(self.adapter, "read_bytes_list"):
            return None
        encoded_data = cast(list[int], self.adapter.read_bytes_list(dans_offset, rich_size))

        if not encoded_data or len(encoded_data) < 8:
            return None

        return bytes(encoded_data)
