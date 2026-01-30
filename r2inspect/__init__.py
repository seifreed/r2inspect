#!/usr/bin/env python3
"""
r2inspect - Advanced malware analysis tool using radare2 and r2pipe
Professional malware analysis framework powered by radare2

Author: Marc Rivero (@seifreed)
License: GPL-3.0
"""

from .__version__ import __author__, __author_email__, __license__, __url__, __version__

__description__ = "Advanced malware analysis tool using radare2 and r2pipe"

# Avoid importing heavy subpackages at module import time to prevent
# optional dependency errors (e.g., r2pipe) during partial imports
__all__ = [
    "__version__",
    "__author__",
    "__author_email__",
    "__license__",
    "__url__",
    "__description__",
]
