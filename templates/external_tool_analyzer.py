#!/usr/bin/env python3
"""
Template: External Tool Analyzer
Category: Similarity/Detection/Metadata
Description: Template for analyzers that wrap external tools or libraries

This template is for creating analyzers that integrate external command-line tools
or Python libraries for specialized analysis. These analyzers handle tool availability
checking, execution, output parsing, and error handling.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0
See LICENSE file for details

Usage:
    1. Copy this file to r2inspect/modules/your_analyzer.py
    2. Replace all [PLACEHOLDER] values
    3. Implement tool availability check in is_available()
    4. Implement tool execution in _execute_tool()
    5. Implement output parsing in _parse_output()
    6. Add error handling for tool failures
    7. Update metadata methods
    8. Add tests in tests/unit/analyzers/test_your_analyzer.py

Example Use Cases:
    - YARA rule scanner
    - SSDeep fuzzy hashing
    - Binlex signature analyzer
    - External disassembler wrapper
    - Sandbox execution analyzer
    - Custom tool integration

Template Pattern:
    1. Check tool availability (library import or CLI command)
    2. Validate input file
    3. Execute tool with proper parameters
    4. Parse tool output
    5. Handle errors gracefully
    6. Return standardized results
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ..abstractions import BaseAnalyzer
from ..utils.logger import get_logger

logger = get_logger(__name__)


class [ANALYZER_NAME]Analyzer(BaseAnalyzer):
    """
    [Short description of external tool integration]

    This analyzer integrates [tool name] to provide [analysis capability].
    It handles tool execution, output parsing, and error management.

    Requirements:
        - [Tool/Library name] must be installed
        - [Specific version requirements if any]
        - [Additional dependencies]

    Features:
        - [Feature 1: e.g., Automatic tool availability checking]
        - [Feature 2: e.g., Output caching]
        - [Feature 3: e.g., Error recovery]

    Attributes:
        r2: R2Pipe instance (optional, for r2 integration)
        config: Configuration dictionary
        filepath: Path to binary file (required)
        tool_path: Path to external tool executable (optional)

    Example:
        >>> analyzer = [ANALYZER_NAME]Analyzer(r2=r2, filepath="/path/to/binary")
        >>> if analyzer.is_available():
        ...     result = analyzer.analyze()
        ...     print(f"Analysis completed: {result['available']}")
    """

    # [TODO: Define tool configuration]
    TOOL_NAME = "[tool_name]"  # Name of external tool/library
    TOOL_COMMAND = "[tool_command]"  # CLI command if applicable
    TOOL_VERSION_MIN = "[min_version]"  # Minimum version required

    def __init__(self, r2=None, config=None, filepath=None, **kwargs):
        """
        Initialize the external tool analyzer.

        Args:
            r2: R2Pipe instance (optional)
            config: Configuration dictionary (optional)
            filepath: Path to binary file (required for most external tools)
            **kwargs: Additional arguments (may include tool_path)
        """
        super().__init__(r2=r2, config=config, filepath=filepath, **kwargs)

        # [TODO: Extract tool-specific configuration]
        # Example:
        # self.tool_path = kwargs.get('tool_path') or self._find_tool_path()
        # self.timeout = config.get('timeout', 60) if config else 60
        # self.max_output_size = config.get('max_output', 10*1024*1024) if config else 10*1024*1024

        # Validate filepath if required
        if not self.filepath:
            self._log_warning("No filepath provided - tool may require it")

    def analyze(self) -> Dict[str, Any]:
        """
        Perform analysis using external tool.

        Checks tool availability, executes tool, parses output, and returns results.

        Returns:
            Dict containing:
                - available: bool - Whether analysis completed
                - tool_version: str - Version of tool used
                - results: Any - Parsed tool output
                - error: str - Error message if failed (optional)

        Example:
            >>> result = analyzer.analyze()
            >>> if result['available']:
            ...     print(f"Tool version: {result['tool_version']}")
            ...     print(f"Results: {result['results']}")
        """
        result = self._init_result_structure({
            'tool_name': self.TOOL_NAME,
            'tool_version': None,
            'results': None,
        })

        # Check tool availability
        if not self.is_available():
            result['error'] = f"{self.TOOL_NAME} is not available"
            self._log_error(f"{self.TOOL_NAME} not found or not functional")
            return result

        # Validate filepath if required
        if not self.filepath or not self.file_exists():
            result['error'] = "Valid file path required for analysis"
            self._log_error("File path not provided or file does not exist")
            return result

        try:
            # Get tool version
            self._log_debug(f"Checking {self.TOOL_NAME} version")
            tool_version = self._get_tool_version()
            result['tool_version'] = tool_version

            # Execute tool
            self._log_debug(f"Executing {self.TOOL_NAME} on {self.filepath}")
            tool_output = self._execute_tool()

            # Parse output
            self._log_debug("Parsing tool output")
            parsed_results = self._parse_output(tool_output)

            result['available'] = True
            result['results'] = parsed_results

            self._log_info(f"{self.TOOL_NAME} analysis completed successfully")

        except subprocess.TimeoutExpired:
            self._log_error(f"{self.TOOL_NAME} execution timed out")
            result['error'] = "Tool execution timed out"
        except subprocess.CalledProcessError as e:
            self._log_error(f"{self.TOOL_NAME} failed with exit code {e.returncode}")
            result['error'] = f"Tool failed: {e.stderr if e.stderr else 'Unknown error'}"
        except Exception as e:
            self._log_error(f"{self.TOOL_NAME} analysis failed: {e}")
            result['error'] = str(e)

        return result

    def _execute_tool(self) -> Any:
        """
        Execute external tool and return raw output.

        [TODO: Implement tool execution]

        This method should:
            1. Construct command with proper arguments
            2. Execute tool with timeout
            3. Capture stdout/stderr
            4. Return raw output for parsing

        Returns:
            Raw tool output (string, bytes, or object depending on tool type)

        Raises:
            subprocess.TimeoutExpired: If tool execution times out
            subprocess.CalledProcessError: If tool returns non-zero exit code
            Exception: For other execution errors

        Example Implementation for CLI Tool:
            >>> def _execute_tool(self) -> str:
            ...     cmd = [
            ...         self.TOOL_COMMAND,
            ...         '--option1', 'value1',
            ...         str(self.filepath)
            ...     ]
            ...
            ...     result = subprocess.run(
            ...         cmd,
            ...         capture_output=True,
            ...         text=True,
            ...         timeout=self.timeout,
            ...         check=True
            ...     )
            ...
            ...     return result.stdout

        Example Implementation for Python Library:
            >>> def _execute_tool(self) -> Any:
            ...     import external_library
            ...
            ...     with open(self.filepath, 'rb') as f:
            ...         data = f.read()
            ...
            ...     result = external_library.analyze(data)
            ...     return result
        """
        # [TODO: Implement tool execution]
        raise NotImplementedError(
            "You must implement _execute_tool() method. "
            "See docstring above for implementation guidance."
        )

        # [TODO: Example template for CLI tool - replace with your implementation]
        # cmd = [
        #     self.TOOL_COMMAND,
        #     # Add tool arguments
        #     str(self.filepath)
        # ]
        #
        # result = subprocess.run(
        #     cmd,
        #     capture_output=True,
        #     text=True,
        #     timeout=60,  # Adjust timeout as needed
        #     check=True
        # )
        #
        # return result.stdout

        # [TODO: Example template for Python library - replace with your implementation]
        # import [library_name]
        #
        # # Open and read file
        # with open(self.filepath, 'rb') as f:
        #     data = f.read()
        #
        # # Execute library function
        # result = [library_name].[function](data)
        #
        # return result

    def _parse_output(self, tool_output: Any) -> Dict[str, Any]:
        """
        Parse tool output into structured format.

        [TODO: Implement output parsing]

        Args:
            tool_output: Raw output from _execute_tool()

        Returns:
            Parsed and structured results dictionary

        Example Implementation for JSON Output:
            >>> def _parse_output(self, tool_output: str) -> Dict[str, Any]:
            ...     import json
            ...     try:
            ...         parsed = json.loads(tool_output)
            ...         return {
            ...             'field1': parsed.get('field1'),
            ...             'field2': parsed.get('field2'),
            ...             'items': parsed.get('items', [])
            ...         }
            ...     except json.JSONDecodeError as e:
            ...         logger.error(f"Failed to parse JSON output: {e}")
            ...         return {'error': 'Invalid JSON output'}

        Example Implementation for Text Output:
            >>> def _parse_output(self, tool_output: str) -> Dict[str, Any]:
            ...     results = {
            ...         'matches': [],
            ...         'total': 0
            ...     }
            ...
            ...     for line in tool_output.strip().split('\\n'):
            ...         if line.startswith('[MATCH]'):
            ...             match_data = line[7:].strip()
            ...             results['matches'].append(match_data)
            ...
            ...     results['total'] = len(results['matches'])
            ...     return results
        """
        # [TODO: Implement output parsing]
        raise NotImplementedError(
            "You must implement _parse_output() method. "
            "Parse tool output into structured dictionary."
        )

        # [TODO: Example template - replace with your implementation]
        # parsed_results = {}
        #
        # # Parse tool output based on format
        # # ... parsing logic ...
        #
        # return parsed_results

    def _get_tool_version(self) -> Optional[str]:
        """
        Get version of external tool.

        [TODO: Implement version detection]

        Returns:
            Version string or None if version cannot be determined

        Example Implementation for CLI Tool:
            >>> def _get_tool_version(self) -> Optional[str]:
            ...     try:
            ...         result = subprocess.run(
            ...             [self.TOOL_COMMAND, '--version'],
            ...             capture_output=True,
            ...             text=True,
            ...             timeout=5
            ...         )
            ...         # Parse version from output
            ...         return result.stdout.strip().split()[1]
            ...     except:
            ...         return None

        Example Implementation for Python Library:
            >>> def _get_tool_version(self) -> Optional[str]:
            ...     try:
            ...         import external_library
            ...         return external_library.__version__
            ...     except:
            ...         return None
        """
        # [TODO: Implement version detection]
        try:
            # [TODO: Example for CLI tool]
            # result = subprocess.run(
            #     [self.TOOL_COMMAND, '--version'],
            #     capture_output=True,
            #     text=True,
            #     timeout=5
            # )
            # return result.stdout.strip()

            # [TODO: Example for Python library]
            # import [library_name]
            # return [library_name].__version__

            return None
        except Exception as e:
            self._log_debug(f"Could not determine tool version: {e}")
            return None

    @staticmethod
    def is_available() -> bool:
        """
        Check if external tool/library is available.

        [TODO: Implement availability check]

        Returns:
            True if tool is available and functional, False otherwise

        Example Implementation for CLI Tool:
            >>> @staticmethod
            ... def is_available() -> bool:
            ...     # Check if command exists
            ...     return shutil.which('tool_command') is not None

        Example Implementation for Python Library:
            >>> @staticmethod
            ... def is_available() -> bool:
            ...     try:
            ...         import external_library
            ...         # Optionally check version
            ...         return True
            ...     except ImportError:
            ...         return False
        """
        # [TODO: Implement availability check]

        # [TODO: Example for CLI tool]
        # return shutil.which('[tool_command]') is not None

        # [TODO: Example for Python library]
        # try:
        #     import [library_name]
        #     return True
        # except ImportError:
        #     return False

        return False  # Replace with actual check

    def _find_tool_path(self) -> Optional[str]:
        """
        Find path to external tool executable.

        Returns:
            Path to tool or None if not found
        """
        # Try to find tool in PATH
        tool_path = shutil.which(self.TOOL_COMMAND)
        if tool_path:
            return tool_path

        # [TODO: Add additional search locations if needed]
        # Example: Check common installation directories
        # common_paths = [
        #     '/usr/local/bin/tool',
        #     '/opt/tool/bin/tool',
        # ]
        # for path in common_paths:
        #     if os.path.exists(path) and os.access(path, os.X_OK):
        #         return path

        return None

    # Metadata methods

    def get_name(self) -> str:
        """Return analyzer name."""
        return "[analyzer_name]"  # [TODO: Update, e.g., "yara_scanner"]

    def get_category(self) -> str:
        """Return analyzer category."""
        return "[category]"  # [TODO: Update - options: "detection", "similarity", "hashing", etc.]

    def get_description(self) -> str:
        """Return analyzer description."""
        return "[Description including tool name and purpose]"  # [TODO: Update]

    def supports_format(self, file_format: str) -> bool:
        """Check if analyzer supports given file format."""
        supported = self.get_supported_formats()
        return file_format.upper() in supported if supported else True

    def get_supported_formats(self) -> Set[str]:
        """Return set of supported file formats."""
        return set()  # [TODO: Update if format-specific]
