#!/usr/bin/env python3
"""Direct-file and scan helpers for Rich Header analysis."""

from __future__ import annotations

import struct
from typing import Any, cast

from ..adapters.file_system import default_file_system
from ..domain.services.rich_header import decode_rich_header
from ..infrastructure.command_helpers import cmdj as cmdj_helper
from ..infrastructure.logging import get_logger
from ..infrastructure.file_type import is_pe_file
from .rich_header_defaults import DANS_PATTERNS, RICH_PATTERNS

logger = get_logger(__name__)


class RichHeaderDirectMixin:
    """File probing and direct extraction helpers for Rich Header analysis."""

    adapter: Any
    filepath: str | None
    r2: Any
    _manual_rich_search: Any  # provided by RichHeaderSearchMixin
    _try_extract_rich_at_offsets: Any  # provided by RichHeaderSearchMixin

    def _is_pe_file(self) -> bool:
        if not self.adapter:
            logger.error("r2 instance is None")
            return False
        return is_pe_file(self.filepath, self.adapter, self.adapter, logger=logger)

    def _check_magic_bytes(self) -> bool:
        try:
            if not self.filepath:
                return False
            from . import rich_header_analyzer as analyzer_module

            file_system = getattr(analyzer_module, "default_file_system", default_file_system)
            magic = file_system.read_bytes(self.filepath, size=2)
            if magic == b"MZ":
                logger.debug("Found MZ header - likely PE file")
                return True
        except Exception as exc:
            logger.debug("Could not read file magic bytes: %s", exc)
        return False

    @staticmethod
    def _bin_info_has_pe(bin_info: dict[str, Any]) -> bool:
        bin_format = bin_info.get("format", "").lower()
        if "pe" in bin_format:
            logger.debug("PE detected via 'ij' format field")
            return True
        bin_class = bin_info.get("class", "").lower()
        if "pe" in bin_class:
            logger.debug("PE detected via 'ij' class field")
            return True
        return False

    def _extract_rich_header(self) -> dict[str, Any] | None:
        try:
            logger.debug("Trying direct file analysis for Rich Header")
            rich_data = self._direct_file_rich_search()
            if rich_data:
                logger.debug("Successfully found Rich Header via direct file analysis")
                return rich_data

            logger.debug("Direct analysis failed, trying r2pipe search")
            rich_results, dans_results = self._collect_rich_dans_offsets()
            if not rich_results or not dans_results:
                logger.debug("r2pipe patterns not found, trying manual search in DOS stub area")
                return cast(dict[str, Any] | None, self._manual_rich_search())

            rich_data = self._try_rich_dans_combinations(rich_results, dans_results)
            if rich_data:
                return rich_data

            logger.debug("No valid Rich Header found with any strategy")
            return None

        except Exception as exc:
            logger.error("Error extracting Rich Header: %s", exc)
            return None

    def _collect_rich_dans_offsets(
        self,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        rich_results = self._scan_patterns(RICH_PATTERNS, "Rich")
        dans_results = self._scan_patterns(DANS_PATTERNS, "DanS")
        return rich_results, dans_results

    def _scan_patterns(self, patterns: list[str], label: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        from . import rich_header_analyzer as analyzer_module

        cmd_helper = getattr(analyzer_module, "cmdj_helper", cmdj_helper)
        for pattern in patterns:
            try:
                found = cmd_helper(self.adapter, self.adapter, f"/xj {pattern}", {})
                if found:
                    results.extend(found)
                    logger.debug("Found %s pattern %s at %s locations", label, pattern, len(found))
            except Exception as exc:
                logger.debug("Failed %s pattern scan %s: %s", label, pattern, exc)
        return results

    def _try_rich_dans_combinations(
        self, rich_results: list[dict[str, Any]], dans_results: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        for rich_result in rich_results:
            for dans_result in dans_results:
                offsets = self._extract_offsets(rich_result, dans_result)
                if not offsets:
                    continue
                dans_offset, rich_offset = offsets
                if not self._offsets_valid(dans_offset, rich_offset):
                    continue
                rich_data = self._try_extract_rich_at_offsets(dans_offset, rich_offset)
                if rich_data:
                    logger.debug(
                        f"Successfully extracted Rich Header at DanS:{dans_offset}, Rich:{rich_offset}"
                    )
                    return cast(dict[str, Any] | None, rich_data)
        return None

    @staticmethod
    def _extract_offsets(
        rich_result: dict[str, Any], dans_result: dict[str, Any]
    ) -> tuple[int, int] | None:
        rich_offset = rich_result.get("offset")
        dans_offset = dans_result.get("offset")
        if rich_offset is None or dans_offset is None:
            return None
        return dans_offset, rich_offset

    @staticmethod
    def _offsets_valid(dans_offset: int, rich_offset: int) -> bool:
        return dans_offset < rich_offset and (rich_offset - dans_offset) <= 1024

    def _direct_file_rich_search(self) -> dict[str, Any] | None:
        try:
            data = self._read_file_bytes()
            if not data or not self._is_valid_pe_data(data):
                return None

            pe_offset = self._get_pe_offset(data)
            if pe_offset is None:
                return None

            dos_stub = self._get_dos_stub(data, pe_offset)
            if dos_stub is None:
                return None

            rich_pos = self._find_rich_pos(dos_stub)
            if rich_pos is None:
                return None

            xor_key = self._extract_xor_key_from_stub(dos_stub, rich_pos)
            if xor_key is None:
                return None

            dans_pos = self._find_or_estimate_dans(dos_stub, rich_pos)
            if dans_pos is None:
                return None

            encoded_data = self._extract_encoded_from_stub(dos_stub, dans_pos, rich_pos)
            if not encoded_data:
                return None

            entries = decode_rich_header(encoded_data, xor_key)
            if not entries:
                logger.debug("No valid entries decoded from Rich Header")
                return None

            calculated_checksum = self._calculate_rich_checksum(data, pe_offset, entries)
            return self._build_direct_rich_result(
                xor_key,
                calculated_checksum,
                entries,
                encoded_data,
                dos_stub_start=0x40,
                dans_pos=dans_pos,
                rich_pos=rich_pos,
            )

        except Exception as exc:
            logger.error("Error in direct file Rich Header search: %s", exc)
            return None

    def _read_file_bytes(self) -> bytes | None:
        try:
            if not self.filepath:
                return None
            return default_file_system.read_bytes(self.filepath)
        except Exception as exc:
            logger.debug("Could not read file bytes: %s", exc)
            return None

    @staticmethod
    def _is_valid_pe_data(data: bytes) -> bool:
        return len(data) >= 0x40 and data[:2] == b"MZ"

    @staticmethod
    def _get_pe_offset(data: bytes) -> int | None:
        pe_offset = int(struct.unpack("<I", data[0x3C : 0x3C + 4])[0])
        if pe_offset > len(data) - 4:
            return None
        return int(pe_offset)

    @staticmethod
    def _get_dos_stub(data: bytes, pe_offset: int) -> bytes | None:
        dos_stub_start = 0x40
        if pe_offset <= dos_stub_start:
            return None
        return data[dos_stub_start:pe_offset]

    def _find_rich_pos(self, dos_stub: bytes) -> int | None:
        rich_pos = dos_stub.find(b"Rich")
        if rich_pos == -1:
            logger.debug("Rich signature not found in DOS stub")
            return None
        logger.debug("Found Rich signature at DOS stub offset 0x%x", rich_pos)
        return rich_pos

    def _extract_xor_key_from_stub(self, dos_stub: bytes, rich_pos: int) -> int | None:
        if rich_pos + 8 > len(dos_stub):
            logger.debug("Not enough data after Rich signature for XOR key")
            return None
        xor_key = int(struct.unpack("<I", dos_stub[rich_pos + 4 : rich_pos + 8])[0])
        logger.debug("Extracted XOR key: 0x%08x", xor_key)
        return xor_key if xor_key != 0 else None

    def _find_or_estimate_dans(self, dos_stub: bytes, rich_pos: int) -> int | None:
        dans_pos = dos_stub[:rich_pos].rfind(b"DanS")
        if dans_pos != -1:
            logger.debug("Found DanS signature at DOS stub offset 0x%x", dans_pos)
            return dans_pos
        logger.debug("DanS signature not found, trying to find encoded data start")
        return self._estimate_dans_start(dos_stub, rich_pos)

    def _estimate_dans_start(self, dos_stub: bytes, rich_pos: int) -> int | None:
        for start_pos in range(max(0, rich_pos - 512), rich_pos, 4):
            if start_pos + 8 > len(dos_stub):
                continue
            test_data = dos_stub[start_pos:rich_pos]
            if len(test_data) >= 8 and len(test_data) % 8 == 0:
                logger.debug("Estimated Rich Header start at 0x%x", 0x40 + start_pos)
                return start_pos
        logger.debug("Could not determine Rich Header start")
        return None

    def _extract_encoded_from_stub(
        self, dos_stub: bytes, dans_pos: int, rich_pos: int
    ) -> bytes | None:
        encoded_data = dos_stub[dans_pos + 4 : rich_pos]
        if len(encoded_data) == 0 or len(encoded_data) % 8 != 0:
            logger.debug("Invalid encoded data length: %s", len(encoded_data))
            return None
        logger.debug("Extracted %s bytes of encoded data", len(encoded_data))
        return encoded_data

    @staticmethod
    def _build_direct_rich_result(
        xor_key: int,
        calculated_checksum: int,
        entries: list[dict[str, Any]],
        encoded_data: bytes,
        dos_stub_start: int,
        dans_pos: int,
        rich_pos: int,
    ) -> dict[str, Any]:
        rich_absolute_pos = dos_stub_start + rich_pos
        return {
            "xor_key": xor_key,
            "checksum": calculated_checksum,
            "entries": entries,
            "dans_offset": dos_stub_start + dans_pos,
            "rich_offset": rich_absolute_pos,
            "encoded_data": encoded_data.hex(),
            "valid_checksum": calculated_checksum == xor_key,
        }

    @staticmethod
    def _calculate_rich_checksum(data: bytes, pe_offset: int, entries: list[dict[str, Any]]) -> int:
        try:
            checksum = pe_offset
            if len(data) < 0x3C:
                logger.debug("Data too short for Rich checksum: %d bytes", len(data))
                return 0
            for i in range(0x3C):
                checksum = (checksum + data[i]) & 0xFFFFFFFF

            for entry in entries:
                prod_id = entry.get("product_id", 0)
                build_num = entry.get("build_number", 0)
                count = entry.get("count", 0)
                checksum = (checksum + ((prod_id | (build_num << 16)) * count)) & 0xFFFFFFFF

            return checksum
        except Exception as exc:
            logger.debug("Error calculating Rich Header checksum: %s", exc)
            return 0
