#!/usr/bin/env python3
"""Compatibility shim for r2pipe session management."""

from __future__ import annotations

from ..core import r2_session as _impl

R2Session = _impl.R2Session
r2pipe = _impl.r2pipe
psutil = _impl.psutil
platform = _impl.platform

HUGE_FILE_THRESHOLD_MB = _impl.HUGE_FILE_THRESHOLD_MB
LARGE_FILE_THRESHOLD_MB = _impl.LARGE_FILE_THRESHOLD_MB
MIN_INFO_RESPONSE_LENGTH = _impl.MIN_INFO_RESPONSE_LENGTH
TEST_HUGE_FILE_THRESHOLD_MB = _impl.TEST_HUGE_FILE_THRESHOLD_MB
TEST_LARGE_FILE_THRESHOLD_MB = _impl.TEST_LARGE_FILE_THRESHOLD_MB
TEST_R2_ANALYSIS_TIMEOUT = _impl.TEST_R2_ANALYSIS_TIMEOUT
TEST_R2_CMD_TIMEOUT = _impl.TEST_R2_CMD_TIMEOUT
TEST_R2_OPEN_TIMEOUT = _impl.TEST_R2_OPEN_TIMEOUT

__all__ = [
    "R2Session",
    "r2pipe",
    "psutil",
    "platform",
    "HUGE_FILE_THRESHOLD_MB",
    "LARGE_FILE_THRESHOLD_MB",
    "MIN_INFO_RESPONSE_LENGTH",
    "TEST_HUGE_FILE_THRESHOLD_MB",
    "TEST_LARGE_FILE_THRESHOLD_MB",
    "TEST_R2_ANALYSIS_TIMEOUT",
    "TEST_R2_CMD_TIMEOUT",
    "TEST_R2_OPEN_TIMEOUT",
]
