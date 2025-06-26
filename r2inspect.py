#!/usr/bin/env python3
"""
r2inspect - Advanced Malware Analysis Tool using Radare2 and r2pipe
Main CLI entry point
"""

import sys
import os

# Add the current directory to Python path to find r2inspect module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from r2inspect.cli import main

if __name__ == '__main__':
    main() 