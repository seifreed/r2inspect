#!/usr/bin/env python3
"""
Logging utilities for r2inspect
"""

import logging
import sys
from pathlib import Path
from typing import Optional

def setup_logger(name: str = 'r2inspect', level: int = logging.INFO) -> logging.Logger:
    """Setup logger with console and file handlers"""
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    # File handler (optional)
    try:
        log_dir = Path.home() / '.r2inspect' / 'logs'
        log_dir.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_dir / 'r2inspect.log')
        file_handler.setLevel(logging.DEBUG)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)
        
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        
    except Exception:
        # Fallback to console only
        formatter = logging.Formatter('%(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    return logger

def get_logger(name: str = 'r2inspect') -> logging.Logger:
    """Get logger instance"""
    return logging.getLogger(name) 