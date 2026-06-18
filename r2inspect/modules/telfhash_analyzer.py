"""Telfhash analyzer for ELF binaries."""

from collections.abc import Callable
from typing import Any, cast

from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..abstractions.hashing_strategy import R2HashingStrategy, availability_result
from ..infrastructure.file_type import is_elf_file, is_pe_file
from ..infrastructure.logging import get_logger
from ..infrastructure.ssdeep_loader import get_ssdeep
from .telfhash_analysis import (
    analyze_symbols as _analyze_symbols_impl,
    is_elf_binary as _is_elf_binary_impl,
)
from ..domain.formats.telfhash import (
    extract_symbol_names as _extract_symbol_names_impl,
    filter_symbols_for_telfhash as _filter_symbols_for_telfhash_impl,
    normalize_telfhash_value as _normalize_telfhash_value_impl,
    parse_telfhash_result as _parse_telfhash_result_impl,
)
from .telfhash_guard import TELFHASH_AVAILABLE, _safe_telfhash

logger = get_logger(__name__)


class TelfhashAnalyzer(CommandHelperMixin, R2HashingStrategy):
    """Telfhash analyzer for ELF files."""

    def __init__(
        self,
        adapter: Any,
        filepath: str,
        *,
        telfhash_fn: Callable[[str], Any] | None = None,
        telfhash_available: bool | None = None,
    ) -> None:
        """
        Initialize Telfhash analyzer.

        ``telfhash_fn`` / ``telfhash_available`` default to the real
        ``_safe_telfhash`` / ``TELFHASH_AVAILABLE``; tests inject deterministic
        values instead of patching the module.
        """
        super().__init__(adapter=adapter, filepath=filepath)
        self._telfhash_fn: Callable[[str], Any] = telfhash_fn or _safe_telfhash
        self._telfhash_available: bool = (
            TELFHASH_AVAILABLE if telfhash_available is None else telfhash_available
        )

    def _check_library_availability(self) -> tuple[bool, str | None]:
        """Return ``(is_available, error_message)`` for the telfhash library."""
        return availability_result(
            self._telfhash_available,
            "telfhash library not available. Install with: pip install telfhash",
        )

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        """Return ``(hash_value, method_used, error_message)`` for the ELF file."""
        try:
            if not self._is_elf_file():
                return None, None, "File is not an ELF binary"

            telfhash_result = self._telfhash_fn(str(self.filepath))
            logger.debug(
                "Telfhash function returned: %s = %s", type(telfhash_result), telfhash_result
            )

            hash_value, message = _parse_telfhash_result_impl(telfhash_result)

            if message and not hash_value:
                return None, None, message

            if hash_value:
                logger.debug("Telfhash calculated: %s", hash_value)
                return hash_value, "python_library", None
            return None, None, "Telfhash calculation returned no hash"

        except Exception as e:
            logger.error("Error calculating telfhash: %s", e)
            return None, None, f"Telfhash calculation failed: {str(e)}"

    def _get_hash_type(self) -> str:
        return "telfhash"

    def analyze(self) -> dict[str, Any]:
        """Run telfhash analysis and include a telfhash field for compatibility."""
        result = super().analyze()
        if "telfhash" not in result:
            result["telfhash"] = result.get("hash_value")
        return result

    def analyze_symbols(self) -> dict[str, Any]:
        """Detailed telfhash analysis including ELF symbol statistics."""
        return _analyze_symbols_impl(
            self,
            telfhash_available=self._telfhash_available,
            telfhash_fn=self._telfhash_fn,
            logger=logger,
        )

    def _is_elf_file(self) -> bool:
        return _is_elf_binary_impl(
            self,
            logger=logger,
            is_elf_file_fn=is_elf_file,
            is_pe_file_fn=is_pe_file,
        )

    def _has_elf_symbols(self, info_cmd: dict[str, Any] | None) -> bool:
        try:
            symbols = self._cmd_list("isj")
            if not symbols:
                return False
            if not info_cmd or not isinstance(info_cmd.get("bin"), dict):
                return False
            os_info = str(info_cmd["bin"].get("os", "")).lower()
            return "linux" in os_info or "unix" in os_info
        except Exception as exc:
            logger.debug("Failed to inspect ELF symbols: %s", exc)
            return False

    def _get_elf_symbols(self) -> list[dict[str, Any]]:
        """Return all symbols from the ELF file (empty list on failure)."""
        try:
            logger.debug("Extracting symbols from ELF file")
            symbols = self._cmd_list("isj")
            if not symbols:
                logger.warning("No symbols found in ELF file")
                return []

            logger.debug("Found %s total symbols", len(symbols))
            return symbols

        except Exception as e:
            logger.error("Failed to extract symbols: %s", e)
            return []

    def _filter_symbols_for_telfhash(self, symbols: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Keep named, non-LOCAL FUNC/OBJECT symbols telfhash uses."""
        filtered = _filter_symbols_for_telfhash_impl(symbols)
        logger.debug("Filtered %s symbols from %s total", len(filtered), len(symbols))
        return filtered

    def _extract_symbol_names(self, symbols: list[dict[str, Any]]) -> list[str]:
        """Return sorted symbol names for telfhash calculation."""
        names = _extract_symbol_names_impl(symbols)
        logger.debug("Extracted %s symbol names for telfhash", len(names))
        return names

    @staticmethod
    def _normalize_telfhash_value(value: Any) -> str | None:
        return _normalize_telfhash_value_impl(value)

    @staticmethod
    def compare_hashes(
        hash1: str,
        hash2: str,
        *,
        telfhash_available: bool | None = None,
        ssdeep_loader: Callable[[], Any] | None = None,
    ) -> int | None:
        """Return ssdeep-based similarity (0-100) of two telfhash values, or None.

        ``telfhash_available`` / ``ssdeep_loader`` default to the real
        ``TELFHASH_AVAILABLE`` / ``get_ssdeep``; tests inject deterministic
        values instead of patching the module.
        """
        available = TELFHASH_AVAILABLE if telfhash_available is None else telfhash_available
        if not available:
            return None

        if not hash1 or not hash2:
            return None

        try:
            ssdeep_module = (ssdeep_loader or get_ssdeep)()
            if ssdeep_module is None:
                logger.warning("ssdeep library required for telfhash comparison")
                return None
            return cast(int, ssdeep_module.compare(hash1, hash2))
        except Exception as e:
            logger.warning("Telfhash comparison failed: %s", e)
            return None

    @staticmethod
    def is_available() -> bool:
        """Return whether the telfhash library is importable."""
        return TELFHASH_AVAILABLE

    @staticmethod
    def calculate_telfhash_from_file(
        filepath: str,
        *,
        telfhash_fn: Callable[[str], Any] | None = None,
        telfhash_available: bool | None = None,
    ) -> str | None:
        """Calculate telfhash from a file path.

        ``telfhash_fn`` / ``telfhash_available`` default to the real
        ``_safe_telfhash`` / ``TELFHASH_AVAILABLE``; tests inject deterministic
        values instead of patching the module.
        """
        available = TELFHASH_AVAILABLE if telfhash_available is None else telfhash_available
        if not available:
            return None

        try:
            result = (telfhash_fn or _safe_telfhash)(filepath)
            if isinstance(result, list) and len(result) > 0:
                first_entry = result[0]
                if isinstance(first_entry, dict):
                    return TelfhashAnalyzer._normalize_telfhash_value(
                        first_entry.get("telfhash")
                    )
                return TelfhashAnalyzer._normalize_telfhash_value(first_entry)
            elif isinstance(result, dict):
                return TelfhashAnalyzer._normalize_telfhash_value(result.get("telfhash"))
            return TelfhashAnalyzer._normalize_telfhash_value(result)
        except Exception as e:
            logger.warning("Failed to calculate telfhash: %s", e)
            return None
