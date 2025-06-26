#!/usr/bin/env python3
"""
R2pipe Helper Functions
"""

import json
import sys
import io
from contextlib import redirect_stderr
from typing import Any, Optional, Union, List, Dict
from .logger import get_logger

logger = get_logger(__name__)

def safe_cmdj(r2_instance, command: str, default: Optional[Any] = None) -> Optional[Any]:
    """
    Safely execute a radare2 JSON command with error handling.
    
    Args:
        r2_instance: The r2pipe instance
        command: The radare2 command to execute
        default: Default value to return on error
        
    Returns:
        JSON result or default value on error
    """
    try:
        # First check if the command would return anything
        if command.endswith('j'):
            # Try the non-JSON version first to check if command is valid
            base_command = command[:-1]
            try:
                test_result = r2_instance.cmd(base_command)
                if not test_result or test_result.strip() == '':
                    logger.debug(f"Command '{base_command}' returned empty result, skipping JSON version")
                    return default
            except Exception:
                # If base command fails, the JSON version will likely fail too
                logger.debug(f"Base command '{base_command}' failed, skipping JSON version")
                return default
        
        # Capture stderr to suppress r2pipe JSON errors
        stderr_capture = io.StringIO()
        with redirect_stderr(stderr_capture):
            result = r2_instance.cmdj(command)
        
        # Check if result is valid
        if result is None:
            return default
            
        return result
        
    except Exception as e:
        # Handle all exceptions (including r2pipe.cmdj.Error and json.JSONDecodeError)
        error_msg = str(e)
        error_type = type(e).__name__
        
        # Suppress common r2pipe JSON errors
        if any(phrase in error_msg for phrase in [
            "Expecting value: line 1 column 1",
            "Extra data: line 1 column 2", 
            "r2pipe.cmdj.Error",
            "JSONDecodeError"
        ]):
            logger.debug(f"Suppressed JSON error for command '{command}': {error_type}")
        else:
            logger.debug(f"Error executing command '{command}': {error_type}: {error_msg}")
            
        return default

def safe_cmd_list(r2_instance, command: str) -> List[Dict[str, Any]]:
    """
    Safely execute a radare2 JSON command expecting a list result.
    
    Args:
        r2_instance: The r2pipe instance
        command: The radare2 command to execute
        
    Returns:
        List result or empty list on error
    """
    result = safe_cmdj(r2_instance, command, [])
    if isinstance(result, list):
        return result
    elif result is None:
        return []
    else:
        logger.debug(f"Command '{command}' returned non-list result: {type(result)}")
        return []

def safe_cmd_dict(r2_instance, command: str) -> Dict[str, Any]:
    """
    Safely execute a radare2 JSON command expecting a dict result.
    
    Args:
        r2_instance: The r2pipe instance
        command: The radare2 command to execute
        
    Returns:
        Dict result or empty dict on error
    """
    result = safe_cmdj(r2_instance, command, {})
    if isinstance(result, dict):
        return result
    elif result is None:
        return {}
    else:
        logger.debug(f"Command '{command}' returned non-dict result: {type(result)}")
        return {}

def safe_cmd(r2_instance, command: str, default: str = "") -> str:
    """
    Safely execute a radare2 command returning text.
    
    Args:
        r2_instance: The r2pipe instance
        command: The radare2 command to execute
        default: Default value to return on error
        
    Returns:
        Command result or default value on error
    """
    try:
        result = r2_instance.cmd(command)
        return result if result is not None else default
    except Exception as e:
        logger.debug(f"Error executing command '{command}': {type(e).__name__}: {str(e)}")
        return default

 