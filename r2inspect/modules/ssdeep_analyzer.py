"""SSDeep fuzzy hashing and comparison."""

from collections.abc import Callable
from typing import Any

from ..abstractions.hashing_strategy import HashingStrategy, availability_result
from ..infrastructure.file_system import default_file_system
from ..infrastructure.logging import get_logger
from ..infrastructure.ssdeep_loader import get_ssdeep
from .ssdeep_runtime_support import (
    compare_with_library as _compare_with_library_impl,
    is_available as _is_available_impl,
)

logger = get_logger(__name__)
SSDEEP_LIBRARY_AVAILABLE = get_ssdeep() is not None


class SSDeepAnalyzer(HashingStrategy):
    """SSDeep fuzzy hashing analyzer for file similarity detection."""

    def __init__(
        self,
        filepath: str,
        adapter: Any | None = None,
        max_file_size: int = 100 * 1024 * 1024,
        min_file_size: int = 1,
    ) -> None:
        super().__init__(
            filepath=filepath,
            r2_instance=adapter,
            max_file_size=max_file_size,
            min_file_size=min_file_size,
        )

    def _check_library_availability(self) -> tuple[bool, str | None]:
        """Check if the SSDeep Python library is available."""
        return availability_result(
            SSDeepAnalyzer.is_available(),
            "SSDeep not available. Install with: pip install ssdeep",
        )

    def _calculate_hash(
        self, get_ssdeep_fn: Callable[[], Any] | None = None
    ) -> tuple[str | None, str | None, str | None]:
        """
        Calculate SSDeep hash for the file using the Python library.

        Args:
            get_ssdeep_fn: Optional resolver for the ssdeep module, injected by
                tests; defaults to the module-level loader.

        Returns:
            Tuple of (hash_value, method_used, error_message)
        """
        resolve_ssdeep = get_ssdeep_fn if get_ssdeep_fn is not None else get_ssdeep
        ssdeep_module = resolve_ssdeep()
        if ssdeep_module is None:
            return (
                None,
                None,
                "SSDeep library not available. Install with: pip install ssdeep",
            )

        try:
            file_content = default_file_system.read_bytes(self.filepath)
            ssdeep_hash = ssdeep_module.hash(file_content)
            logger.debug("SSDeep hash calculated using Python library: %s", ssdeep_hash)
            return ssdeep_hash, "python_library", None
        except OSError:
            # Fall back to hash_from_file if direct read fails
            try:
                ssdeep_hash = ssdeep_module.hash_from_file(str(self.filepath))
                logger.debug("SSDeep hash calculated using hash_from_file: %s", ssdeep_hash)
                return ssdeep_hash, "python_library", None
            except Exception as lib_error:
                logger.warning("Python ssdeep library failed: %s", lib_error)
                return None, None, f"SSDeep library error: {lib_error}"
        except Exception as e:
            logger.warning("Python ssdeep library failed: %s", e)
            return None, None, f"SSDeep library error: {e}"

    def _get_hash_type(self) -> str:
        """
        Return the hash type identifier.

        Returns:
            Hash type string
        """
        return "ssdeep"

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> int | None:
        """
        Compare two SSDeep hashes and return similarity score.

        Args:
            hash1: First SSDeep hash
            hash2: Second SSDeep hash

        Returns:
            Similarity score (0-100) or None if comparison fails
        """
        if not hash1 or not hash2:
            return None

        return SSDeepAnalyzer._compare_with_library(hash1, hash2)

    @staticmethod
    def _compare_with_library(hash1: str, hash2: str) -> int | None:
        return _compare_with_library_impl(hash1, hash2, get_ssdeep, logger)

    @staticmethod
    def is_available() -> bool:
        """
        Check if the SSDeep Python library is available.

        Returns:
            True if SSDeep is available, False otherwise
        """
        return _is_available_impl(get_ssdeep)
