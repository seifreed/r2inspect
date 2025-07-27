#!/usr/bin/env python3
"""
r2inspect - Advanced malware analysis tool using radare2 and r2pipe

Usage:
    python r2inspect.py <file>
    python r2inspect.py -j <file>
    python r2inspect.py --batch <directory>
"""

import sys
from r2inspect.cli import main

if __name__ == "__main__":
    # Call the main CLI function
    main()