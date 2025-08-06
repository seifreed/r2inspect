#!/usr/bin/env python3
"""
r2inspect - Advanced malware analysis tool using radare2 and r2pipe
Professional malware analysis framework powered by radare2

Author: Marc Rivero (@seifreed)
License: GPL-3.0
"""

from .__version__ import __author__, __author_email__, __license__, __url__, __version__

__description__ = "Advanced malware analysis tool using radare2 and r2pipe"

from .core import R2Inspector
from .modules import *
from .utils import *

__all__ = [
    "R2Inspector",
    "__version__",
    "__author__",
    "__author_email__",
    "__license__",
    "__url__",
    "__description__",
]
