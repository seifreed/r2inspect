#!/usr/bin/env python3
"""pefile-based helpers for Rich Header analysis."""

from __future__ import annotations

from typing import Any

from ..domain.services.rich_header import parse_clear_data_entries
from ..infrastructure.logging import get_logger

logger = get_logger(__name__)

try:
    import pefile

    PEFILE_AVAILABLE = True
    logger.debug("pefile library available for Rich Header analysis")
except ImportError:
    PEFILE_AVAILABLE = False
    logger.debug("pefile library not available, using r2pipe fallback")


class RichHeaderPefileMixin:
    """Extract Rich Header data through pefile when available."""

    filepath: Any

    def _extract_rich_header_pefile(self) -> dict[str, Any] | None:
        if not PEFILE_AVAILABLE:
            return None

        pe = None
        try:
            pe = pefile.PE(self.filepath)
            if not self._pefile_has_rich_header(pe):
                logger.debug("No Rich Header found by pefile")
                return None

            rich_hash = pe.get_rich_header_hash()
            if not rich_hash:
                logger.debug("Could not calculate Rich Header hash with pefile")
                return None

            logger.debug("pefile calculated Rich Header hash: %s", rich_hash)
            xor_key = self._pefile_get_xor_key(pe)
            entries = self._pefile_extract_entries(pe)
            if not entries:
                entries = self._pefile_entries_from_clear_data(pe)

            return self._build_pefile_rich_result(pe, xor_key, entries, rich_hash)

        except Exception as exc:
            logger.debug("pefile Rich Header extraction failed: %s", exc)
            return None
        finally:
            if pe is not None:
                try:
                    pe.close()
                except Exception as exc:
                    logger.debug("Failed to close pefile handle: %s", exc)

    @staticmethod
    def _pefile_has_rich_header(pe: Any) -> bool:
        return hasattr(pe, "RICH_HEADER") and bool(pe.RICH_HEADER)

    @staticmethod
    def _pefile_get_xor_key(pe: Any) -> int | None:
        checksum = pe.RICH_HEADER.checksum if hasattr(pe.RICH_HEADER, "checksum") else None
        if not isinstance(checksum, int) or checksum == 0:
            return None
        return checksum

    @staticmethod
    def _pefile_extract_entries(pe: Any) -> list[dict[str, Any]]:
        # pefile exposes RICH_HEADER.values as a flat list of XOR-decoded ints
        # laid out as [prodid, count, prodid, count, ...] — NOT objects with
        # product_id/build_version/count attributes. The previous attribute-based
        # parsing matched nothing, so this primary path always returned [] and
        # entries came solely from the clear-data fallback. Decode each
        # (prodid, count) pair the same way as parse_clear_data_entries.
        entries: list[dict[str, Any]] = []
        values = getattr(pe.RICH_HEADER, "values", None)
        if not isinstance(values, (list, tuple)):
            return entries
        for i in range(0, len(values) - 1, 2):
            prodid, count = values[i], values[i + 1]
            if not (isinstance(prodid, int) and isinstance(count, int)) or count <= 0:
                continue
            entries.append(
                {
                    "product_id": prodid & 0xFFFF,
                    "build_number": (prodid >> 16) & 0xFFFF,
                    "count": count,
                    "prodid": prodid,
                }
            )
        return entries

    @staticmethod
    def _pefile_entries_from_clear_data(pe: Any) -> list[dict[str, Any]]:
        clear_data = getattr(pe.RICH_HEADER, "clear_data", None)
        if not isinstance(clear_data, (bytes, bytearray)):
            return []
        return parse_clear_data_entries(bytes(clear_data))

    @staticmethod
    def _build_pefile_rich_result(
        pe: Any,
        xor_key: int | None,
        entries: list[dict[str, Any]],
        rich_hash: str,
    ) -> dict[str, Any]:
        clear_data = getattr(pe.RICH_HEADER, "clear_data", None)
        clear_data_bytes = clear_data if isinstance(clear_data, (bytes, bytearray)) else None
        return {
            "xor_key": xor_key,
            "checksum": xor_key,
            "entries": entries,
            "richpe_hash": rich_hash,
            "clear_data": clear_data_bytes.hex() if clear_data_bytes is not None else None,
            "method": "pefile",
            "clear_data_bytes": clear_data_bytes,
        }
