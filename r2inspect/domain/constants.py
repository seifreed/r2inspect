#!/usr/bin/env python3
"""Constants for file validation and analysis thresholds."""

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

# Above this size the whole-file string scan (izzj) -- which includes a PE/ELF
# overlay -- is replaced by the sections-only scan (izj) for the internal
# string consumers (compiler/simhash/bindiff/exploit-mitigation). An overlay-
# heavy 287MB binary returns ~373MB of izzj strings and peaks ~4.6GB RAM. File
# size is a heuristic proxy for overlay-heaviness; tunable via
# R2INSPECT_STRING_SCAN_THRESHOLD_MB. The JSON `strings` output field is
# unaffected (it already uses izj sections).
OVERLAY_STRING_SCAN_THRESHOLD_MB = 100

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

# Above the huge-file threshold the initial `aa` analysis still runs (so function
# discovery works on big binaries) but needs more headroom than the standard
# analysis timeout: aa is linear at ~0.08s/MB, so this covers multi-GB inputs
# while still bounding a genuinely stuck r2. Override with
# R2INSPECT_ANALYSIS_TIMEOUT_SECONDS.
HUGE_FILE_ANALYSIS_TIMEOUT_SECONDS = 300

# Basic `aa` analysis discovers functions from symbols + entrypoint, so on
# symbol-poor binaries (stripped, Delphi, packed) it finds almost nothing -- a
# large binary reporting fewer functions than this almost certainly needs the
# deeper `aaa` reference analysis. Escalation is cheap exactly here: aaa is fast
# when aa found little (few symbols to chase), and is skipped on symbol-rich
# binaries where aa already succeeds and aaa would be slow.
MIN_AA_FUNCTIONS_BEFORE_DEEP = 50

# =============================================================================
# Per-function disassembly cache (shared across similarity analyzers)
# =============================================================================
# binlex, function_analyzer, and simhash each issue identical `pdfj @ <addr>`
# per function; caching dedupes them. Disabled above the function-count gate so
# function-heavy binaries don't accumulate hundreds of MB of cached disasm.
# Both are overridable via R2INSPECT_DISASM_CACHE_MAX_FUNCS / _ENTRIES.
DISASM_CACHE_MAX_FUNCS = 20000  # Cache per-address disasm only at/below this function count
DISASM_CACHE_MAX_ENTRIES = 20000  # Hard cap on cached per-address entries (stop-at-cap)

# =============================================================================
# Test Mode Thresholds (more aggressive to reduce resource usage)
# =============================================================================
# When R2INSPECT_TEST_MODE=1, these thresholds are used instead of the standard ones
# to minimize radare2 resource consumption during automated testing.
TEST_LARGE_FILE_THRESHOLD_MB = 1  # Above this: use minimal analysis (aa) in test mode
TEST_HUGE_FILE_THRESHOLD_MB = 5  # Above this: skip analysis entirely in test mode
TEST_R2_OPEN_TIMEOUT = 10.0  # Shorter timeout for r2pipe.open() in test mode
TEST_R2_CMD_TIMEOUT = 5.0  # Shorter timeout for r2 commands in test mode
TEST_R2_ANALYSIS_TIMEOUT = 15.0  # Shorter timeout for analysis commands in test mode

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
    "OVERLAY_STRING_SCAN_THRESHOLD_MB",
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
    "HUGE_FILE_ANALYSIS_TIMEOUT_SECONDS",
    "MIN_AA_FUNCTIONS_BEFORE_DEEP",
    # Disassembly cache
    "DISASM_CACHE_MAX_FUNCS",
    "DISASM_CACHE_MAX_ENTRIES",
    # Detection confidence
    "CONFIDENCE_API",
    "CONFIDENCE_CONSTANT",
    "CONFIDENCE_STRING",
    # Test mode constants
    "TEST_LARGE_FILE_THRESHOLD_MB",
    "TEST_HUGE_FILE_THRESHOLD_MB",
    "TEST_R2_OPEN_TIMEOUT",
    "TEST_R2_CMD_TIMEOUT",
    "TEST_R2_ANALYSIS_TIMEOUT",
]
