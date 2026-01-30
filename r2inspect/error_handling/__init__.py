#!/usr/bin/env python3
"""
Unified Error Handling System for r2inspect

This module provides a simplified, policy-based error handling system that
consolidates retry logic, circuit breaking, and fallback strategies into a
single declarative interface.

Copyright (C) 2025 Marc Rivero Lopez

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

Author: Marc Rivero Lopez
"""

from .policies import ErrorHandlingStrategy, ErrorPolicy
from .presets import FAIL_FAST_POLICY, FALLBACK_POLICY, RETRY_POLICY, SAFE_POLICY
from .unified_handler import handle_errors

__all__ = [
    "ErrorHandlingStrategy",
    "ErrorPolicy",
    "handle_errors",
    "SAFE_POLICY",
    "RETRY_POLICY",
    "FAIL_FAST_POLICY",
    "FALLBACK_POLICY",
]
