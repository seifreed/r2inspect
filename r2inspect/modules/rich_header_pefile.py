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
except ImportError:  # pragma: no cover
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
        return pe.RICH_HEADER.checksum if hasattr(pe.RICH_HEADER, "checksum") else None

    def _pefile_extract_entries(self, pe: Any) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        if not hasattr(pe.RICH_HEADER, "values") or not pe.RICH_HEADER.values:
            return entries
        for entry in pe.RICH_HEADER.values:
            parsed = self._pefile_parse_entry(entry)
            if parsed:
                entries.append(parsed)
        return entries

    @staticmethod
    def _pefile_parse_entry(entry: Any) -> dict[str, Any] | None:
        if not (
            hasattr(entry, "product_id")
            and hasattr(entry, "build_version")
            and hasattr(entry, "count")
        ):
            return None
        prodid = entry.product_id | (entry.build_version << 16)
        return {
            "product_id": entry.product_id,
            "build_number": entry.build_version,
            "count": entry.count,
            "prodid": prodid,
        }

    @staticmethod
    def _pefile_entries_from_clear_data(pe: Any) -> list[dict[str, Any]]:
        if not hasattr(pe.RICH_HEADER, "clear_data"):
            return []
        return parse_clear_data_entries(pe.RICH_HEADER.clear_data)

    @staticmethod
    def _build_pefile_rich_result(
        pe: Any,
        xor_key: int | None,
        entries: list[dict[str, Any]],
        rich_hash: str,
    ) -> dict[str, Any]:
        return {
            "xor_key": xor_key,
            "checksum": xor_key,
            "entries": entries,
            "richpe_hash": rich_hash,
            "clear_data": (
                pe.RICH_HEADER.clear_data.hex() if hasattr(pe.RICH_HEADER, "clear_data") else None
            ),
            "method": "pefile",
            "clear_data_bytes": (
                pe.RICH_HEADER.clear_data if hasattr(pe.RICH_HEADER, "clear_data") else None
            ),
        }
