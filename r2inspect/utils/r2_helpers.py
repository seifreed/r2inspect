#!/usr/bin/env python3
"""
R2pipe Helper Functions
"""

from typing import Any, Dict, List, Optional

from .circuit_breaker import CircuitBreakerError, r2_circuit_breaker
from .logger import get_logger
from .retry_manager import RetryConfig, global_retry_manager

logger = get_logger(__name__)


def validate_r2_data(data, expected_type="dict"):
    """
    Validate and clean r2 data to prevent 'str' object has no attribute 'get' errors

    Args:
        data: The data to validate
        expected_type: 'dict' or 'list'

    Returns:
        Cleaned/validated data or appropriate default
    """
    if expected_type == "dict":
        return _validate_dict_data(data)
    elif expected_type == "list":
        return _validate_list_data(data)
    else:
        return data


def _validate_dict_data(data):
    """Validate dictionary data"""
    if isinstance(data, dict):
        return data
    else:
        logger.debug(f"Expected dict but got {type(data)}: {data}")
        return {}


def _validate_list_data(data):
    """Validate and clean list data"""
    if isinstance(data, list):
        return _clean_list_items(data)
    else:
        logger.debug(f"Expected list but got {type(data)}: {data}")
        return []


def _clean_list_items(data):
    """Clean list items and filter out malformed entries"""
    cleaned = []
    for item in data:
        if isinstance(item, dict):
            _clean_html_entities(item)
            cleaned.append(item)
        else:
            logger.debug(f"Filtering out malformed list item: {type(item)} - {item}")
    return cleaned


def _clean_html_entities(item):
    """Clean HTML entities from item names"""
    if "name" in item and isinstance(item["name"], str):
        item["name"] = item["name"].replace("&nbsp;", " ").replace("&amp;", "&")


def safe_cmdj(r2_instance, command: str, default: Optional[Any] = None) -> Optional[Any]:
    """
    Safely execute a radare2 JSON command with circuit breaker protection and retry logic.

    Args:
        r2_instance: The r2pipe instance
        command: The radare2 command to execute
        default: Default value to return on error

    Returns:
        JSON result or default value on error
    """
    command_type = _get_command_type(command)

    def _execute_command():
        """Execute the command with circuit breaker protection"""
        try:
            result = r2_circuit_breaker.execute_command(r2_instance, command, command_type)
            return result if result is not None else default
        except CircuitBreakerError:
            logger.debug(
                f"Circuit breaker open for command type '{command_type}', returning default"
            )
            return default
        except Exception as e:
            return _handle_command_error(e, command, default)

    # Execute with or without retry based on command type
    if global_retry_manager.is_retryable_command(command):
        return _execute_with_retry(_execute_command, command_type, command, default)
    else:
        return _execute_command()


def _handle_command_error(e: Exception, command: str, default: Any) -> Any:
    """Handle command execution errors"""
    if global_retry_manager.is_retryable_error(e):
        raise

    error_msg = str(e)
    error_type = type(e).__name__

    if _is_common_json_error(error_msg):
        logger.debug(f"Common r2pipe JSON parsing issue for command '{command}': {error_type}")
    else:
        logger.warning(f"Unexpected error executing command '{command}': {error_type}: {error_msg}")

    return default


def _execute_with_retry(execute_func, command_type: str, command: str, default: Any) -> Any:
    """Execute function with retry logic"""
    try:
        return global_retry_manager.retry_operation(execute_func, command_type=command_type)
    except Exception as e:
        logger.debug(f"Command '{command}' failed after retries: {e}")
        return default


def _is_common_json_error(error_msg: str) -> bool:
    """Check if error message indicates a common JSON parsing error"""
    return any(
        phrase in error_msg
        for phrase in [
            "Expecting value: line 1 column 1",
            "Extra data: line 1 column 2",
            "r2pipe.cmdj.Error",
            "JSONDecodeError",
            "No JSON object could be decoded",
        ]
    )


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
    return validate_r2_data(result, "list")


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
    return validate_r2_data(result, "dict")


def safe_cmd(r2_instance, command: str, default: str = "") -> str:
    """
    Safely execute a radare2 command returning text with circuit breaker protection and retry logic.

    Args:
        r2_instance: The r2pipe instance
        command: The radare2 command to execute
        default: Default value to return on error

    Returns:
        Command result or default value on error
    """
    # Determine command type for circuit breaker and retry configuration
    command_type = _get_command_type(command)

    def _execute_with_retry():
        """Inner function for retry execution"""
        try:
            # Use circuit breaker to execute command
            result = r2_circuit_breaker.execute_command(r2_instance, command, command_type)
            return result if result is not None else default

        except CircuitBreakerError:
            logger.debug(
                f"Circuit breaker open for command type '{command_type}', returning default"
            )
            return default

        except Exception as e:
            # Check if this is a retryable error
            if global_retry_manager.is_retryable_error(e):
                # Re-raise for retry logic to handle
                raise

            logger.debug(f"Error executing command '{command}': {type(e).__name__}: {str(e)}")
            return default

    # Check if command should be retried
    if global_retry_manager.is_retryable_command(command):
        try:
            return global_retry_manager.retry_operation(
                _execute_with_retry, command_type=command_type
            )
        except Exception as e:
            logger.debug(f"Command '{command}' failed after retries: {e}")
            return default
    else:
        return _execute_with_retry()


def _get_command_type(command: str) -> str:
    """
    Determine command type for circuit breaker categorization

    Args:
        command: The radare2 command

    Returns:
        Command type string
    """
    command = command.strip().lower()

    # Analysis commands
    if command.startswith(("aaa", "aac", "af", "a")):
        return "analysis"

    # Information commands
    elif command.startswith(("i", "ii", "il", "ie", "is", "iz")):
        return "info"

    # Search commands
    elif command.startswith(("/x", "/c", "/r", "/a", "/")):
        return "search"

    # Print commands
    elif command.startswith(("p", "px", "pf", "pd")):
        return "print"

    # Section commands
    elif command.startswith(("S", "iS")):
        return "sections"

    # Function commands
    elif command.startswith(("f", "fl", "fs")):
        return "functions"

    # Memory commands
    elif command.startswith(("dm", "dmi", "dmm")):
        return "memory"

    # Other commands
    else:
        return "generic"


def get_circuit_breaker_stats() -> Dict[str, Any]:
    """Get circuit breaker statistics"""
    return r2_circuit_breaker.get_stats()


def reset_circuit_breakers():
    """Reset all circuit breakers"""
    r2_circuit_breaker.reset_all()
    logger.info("All circuit breakers have been reset")


def get_retry_stats() -> Dict[str, Any]:
    """Get retry statistics"""
    return global_retry_manager.get_stats()


def reset_retry_stats():
    """Reset retry statistics"""
    global_retry_manager.reset_stats()
    logger.info("Retry statistics have been reset")


def configure_retry_for_command_type(
    command_type: str,
    max_attempts: int = 3,
    base_delay: float = 0.1,
    max_delay: float = 5.0,
):
    """
    Configure retry behavior for specific command type

    Args:
        command_type: Type of command ('analysis', 'info', 'search', etc.)
        max_attempts: Maximum retry attempts
        base_delay: Base delay between retries
        max_delay: Maximum delay between retries
    """
    config = RetryConfig(max_attempts=max_attempts, base_delay=base_delay, max_delay=max_delay)
    global_retry_manager.DEFAULT_CONFIGS[command_type] = config
    logger.info(
        f"Updated retry configuration for {command_type}: {max_attempts} attempts, {base_delay}s base delay"
    )


def parse_pe_header_text(r2_instance) -> Optional[Dict[str, Any]]:
    """
    Parse PE header text output from ih command.

    The iHj command doesn't exist in r2, so we parse the text output instead.

    Args:
        r2_instance: The r2pipe instance

    Returns:
        Parsed PE header dict or None on error
    """
    try:
        text_output = safe_cmd(r2_instance, "ih")
        if not text_output:
            return None

        result = {"nt_headers": {}, "file_header": {}, "optional_header": {}}
        lines = text_output.split("\n")
        current_section = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            current_section = _parse_section_header(line, current_section)
            if current_section and ":" in line:
                _parse_key_value_pair(line, result, current_section)

        return result
    except Exception as e:
        logger.debug(f"Could not parse PE header text: {e}")
        return None


def _parse_section_header(line: str, current_section: Optional[str]) -> Optional[str]:
    """Parse section headers from PE header text"""
    if line == "IMAGE_NT_HEADERS":
        return "nt_headers"
    elif line == "IMAGE_FILE_HEADERS":
        return "file_header"
    elif line == "IMAGE_OPTIONAL_HEADERS":
        return "optional_header"
    return current_section


def _parse_key_value_pair(line: str, result: Dict, current_section: str) -> None:
    """Parse key-value pairs from PE header text"""
    key, value = line.split(":", 1)
    key = key.strip()
    value = value.strip()

    # Try to parse hex values
    if value.startswith("0x"):
        try:
            value = int(value, 16)
        except ValueError:
            pass

    result[current_section][key] = value


def get_pe_headers(r2_instance) -> Optional[Dict[str, Any]]:
    """
    Get PE headers information. Parse ihj command output into PE header structure.

    Args:
        r2_instance: The r2pipe instance

    Returns:
        PE headers dict or None on error
    """
    # Get headers list from ihj
    headers_list = safe_cmdj(r2_instance, "ihj", [])

    if not headers_list or not isinstance(headers_list, list):
        # Fallback to parsing text if JSON fails
        return parse_pe_header_text(r2_instance)

    # Parse the list into PE header structure
    result = {"nt_headers": {}, "file_header": {}, "optional_header": {}}

    # Map field names to header sections
    for item in headers_list:
        if not isinstance(item, dict):
            continue

        name = item.get("name", "")
        value = item.get("value", 0)

        # Map to appropriate section based on field name
        if name in [
            "Signature",
            "Machine",
            "NumberOfSections",
            "TimeDateStamp",
            "PointerToSymbolTable",
            "NumberOfSymbols",
            "SizeOfOptionalHeader",
            "Characteristics",
        ]:
            result["file_header"][name] = value
        elif name in [
            "Magic",
            "MajorLinkerVersion",
            "MinorLinkerVersion",
            "SizeOfCode",
            "SizeOfInitializedData",
            "SizeOfUninitializedData",
            "AddressOfEntryPoint",
            "BaseOfCode",
            "BaseOfData",
            "ImageBase",
            "SectionAlignment",
            "FileAlignment",
            "MajorOperatingSystemVersion",
            "MinorOperatingSystemVersion",
            "MajorImageVersion",
            "MinorImageVersion",
            "MajorSubsystemVersion",
            "MinorSubsystemVersion",
            "Win32VersionValue",
            "SizeOfImage",
            "SizeOfHeaders",
            "CheckSum",
            "Subsystem",
            "DllCharacteristics",
            "SizeOfStackReserve",
            "SizeOfStackCommit",
            "SizeOfHeapReserve",
            "SizeOfHeapCommit",
            "LoaderFlags",
            "NumberOfRvaAndSizes",
        ]:
            result["optional_header"][name] = value
        else:
            # Put in nt_headers by default
            result["nt_headers"][name] = value

    return result


def get_elf_headers(r2_instance) -> Optional[List[Dict[str, Any]]]:
    """
    Get ELF program headers. Use ihj command which exists in r2.

    Args:
        r2_instance: The r2pipe instance

    Returns:
        List of ELF headers or empty list on error
    """
    try:
        # First try the correct JSON command
        headers = safe_cmdj(r2_instance, "ihj", None)
        if headers:
            # Convert to list format if needed
            if isinstance(headers, dict):
                return [headers]
            elif isinstance(headers, list):
                return headers

        # Fallback: For ELF files, use text commands
        # Get program headers
        ph_output = safe_cmd(r2_instance, "ih")
        if not ph_output:
            return []

        headers = []
        lines = ph_output.split("\n")

        for line in lines:
            line = line.strip()
            if not line or ":" not in line:
                continue

            # Parse ELF program header entries
            # These typically have format like "Type: LOAD"
            parts = line.split(":", 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()

                # Look for program header entries
                if key.lower() in [
                    "type",
                    "flags",
                    "offset",
                    "vaddr",
                    "paddr",
                    "filesz",
                    "memsz",
                ]:
                    headers.append({key.lower(): value})

        return headers
    except Exception as e:
        logger.debug(f"Could not parse ELF headers: {e}")
        return []


def get_macho_headers(r2_instance) -> Optional[List[Dict[str, Any]]]:
    """
    Get Mach-O load commands. Use ihj command which exists in r2.

    Args:
        r2_instance: The r2pipe instance

    Returns:
        List of Mach-O load commands or empty list on error
    """
    try:
        # First try the correct JSON command
        headers = safe_cmdj(r2_instance, "ihj", None)
        if headers:
            # Convert to list format if needed
            if isinstance(headers, dict):
                return [headers]
            elif isinstance(headers, list):
                return headers

        # Fallback: For Mach-O, try text commands
        headers_output = safe_cmd(r2_instance, "ih")

        if not headers_output:
            return []

        headers = []
        # Parse Mach-O specific header format
        # This would need proper parsing based on actual r2 output for Mach-O files

        return headers
    except Exception as e:
        logger.debug(f"Could not parse Mach-O headers: {e}")
        return []
