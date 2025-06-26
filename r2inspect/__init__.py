#!/usr/bin/env python3
"""
r2inspect - Advanced malware analysis tool using radare2 and r2pipe
Professional malware analysis framework powered by radare2

Author: Marc Rivero (@seifreed)
License: GPL-3.0
"""

__version__ = "1.0.0"
__author__ = "Marc Rivero (@seifreed)"
__description__ = "Advanced malware analysis tool using radare2 and r2pipe"

from .core import R2Inspector
from .utils import *
from .modules import *

__all__ = [
    'R2Inspector',
    '__version__',
    '__author__',
    '__description__'
] 