"""DEPRECATED: Import from r2inspect.domain.formats.crypto instead."""

from ..domain.formats.crypto import (
    CRYPTO_PATTERNS,
    NOISE_PATTERNS,
    consolidate_detections,
    detect_algorithms_from_strings,
)

__all__ = [
    "CRYPTO_PATTERNS",
    "NOISE_PATTERNS",
    "consolidate_detections",
    "detect_algorithms_from_strings",
]
