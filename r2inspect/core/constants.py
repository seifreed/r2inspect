#!/usr/bin/env python3
"""
r2inspect Core Constants - File validation and analysis thresholds

This module contains all constants used for file validation and analysis
configuration in the R2Inspector framework.

Copyright (C) 2025 Marc Rivero Lopez
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

# =============================================================================
# File Validation Constants
# =============================================================================
# These constants define minimum size requirements for file validation
MIN_EXECUTABLE_SIZE_BYTES = 32  # Minimum size for a valid executable
MIN_HEADER_SIZE_BYTES = 16  # Minimum bytes needed to read file header
MIN_INFO_RESPONSE_LENGTH = 10  # Minimum expected length for r2 info response

# =============================================================================
# File Size Thresholds (in MB)
# =============================================================================
# These thresholds control the depth of analysis based on file size
LARGE_FILE_THRESHOLD_MB = 2  # Above this: use standard analysis (aa)
VERY_LARGE_FILE_THRESHOLD_MB = 10  # Above this: use minimal analysis (aa)
HUGE_FILE_THRESHOLD_MB = 50  # Above this: skip automatic analysis

# =============================================================================
# Entropy Analysis Constants
# =============================================================================
# Shannon entropy thresholds for detecting encryption/compression
# Entropy is measured in bits per byte (0-8 scale)
HIGH_ENTROPY_THRESHOLD = 7.0  # Sections above this likely encrypted/compressed
MAX_ENTROPY = 8.0  # Theoretical maximum for uniformly random byte data

# =============================================================================
# Risk Score Thresholds
# =============================================================================
# Risk scores range from 0-100 and categorize the threat level of a binary
RISK_CRITICAL = 80  # Critical risk: highly suspicious/malicious indicators
RISK_HIGH = 65  # High risk: multiple suspicious characteristics
RISK_MEDIUM = 45  # Medium risk: some suspicious features present
RISK_LOW = 25  # Low risk: minor anomalies detected

# =============================================================================
# Packing Detection Constants
# =============================================================================
# Threshold for determining if a binary is likely packed
PACKING_EVIDENCE_THRESHOLD = 50  # Score above this suggests packing

# =============================================================================
# Import Analysis Thresholds
# =============================================================================
# Thresholds for import count anomaly detection
FEW_IMPORTS_THRESHOLD = 10  # Below this: suspiciously few imports (may be packed)
EXCESSIVE_IMPORTS_THRESHOLD = 500  # Above this: unusually high import count

# =============================================================================
# Process Execution Constants
# =============================================================================
# Timeout for external subprocess calls (e.g., YARA, ssdeep)
SUBPROCESS_TIMEOUT_SECONDS = 30  # Maximum seconds to wait for subprocess

# =============================================================================
# Detection Confidence Levels
# =============================================================================
# Confidence scores (0.0-1.0) for different detection methods
# Higher values indicate more reliable detection mechanisms
CONFIDENCE_API = 0.9  # API-based detection (most reliable)
CONFIDENCE_CONSTANT = 0.8  # Magic constant detection (reliable)
CONFIDENCE_STRING = 0.4  # String-based detection (less reliable)

__all__ = [
    # File validation
    "MIN_EXECUTABLE_SIZE_BYTES",
    "MIN_HEADER_SIZE_BYTES",
    "MIN_INFO_RESPONSE_LENGTH",
    # File size thresholds
    "LARGE_FILE_THRESHOLD_MB",
    "VERY_LARGE_FILE_THRESHOLD_MB",
    "HUGE_FILE_THRESHOLD_MB",
    # Entropy analysis
    "HIGH_ENTROPY_THRESHOLD",
    "MAX_ENTROPY",
    # Risk scores
    "RISK_CRITICAL",
    "RISK_HIGH",
    "RISK_MEDIUM",
    "RISK_LOW",
    # Packing detection
    "PACKING_EVIDENCE_THRESHOLD",
    # Import analysis
    "FEW_IMPORTS_THRESHOLD",
    "EXCESSIVE_IMPORTS_THRESHOLD",
    # Process execution
    "SUBPROCESS_TIMEOUT_SECONDS",
    # Detection confidence
    "CONFIDENCE_API",
    "CONFIDENCE_CONSTANT",
    "CONFIDENCE_STRING",
]
