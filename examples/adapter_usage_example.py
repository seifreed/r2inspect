#!/usr/bin/env python3
"""
R2PipeAdapter Usage Examples

This file demonstrates practical usage of the R2PipeAdapter with real
and mock implementations.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

# Example 1: Basic Usage with r2pipe
# ====================================

import r2pipe

from r2inspect.adapters import R2PipeAdapter
from r2inspect.interfaces import BinaryAnalyzerInterface

SAMPLE_BINARY = "/bin/ls"


def example_basic_usage():
    """Basic adapter usage with real binary."""
    print("Example 1: Basic Usage")
    print("-" * 60)

    # Open binary with r2pipe
    r2 = r2pipe.open(SAMPLE_BINARY)

    # Create adapter
    adapter = R2PipeAdapter(r2)

    # Verify Protocol compliance
    print(f"Is BinaryAnalyzerInterface: {isinstance(adapter, BinaryAnalyzerInterface)}")

    # Get file information
    info = adapter.get_file_info()
    print("\nFile Info:")
    print(f"  Architecture: {info.get('arch')}")
    print(f"  Bits: {info.get('bits')}")
    print(f"  Format: {info.get('bintype')}")

    # Get sections
    sections = adapter.get_sections()
    print(f"\nSections ({len(sections)} found):")
    for section in sections[:3]:
        print(f"  - {section.get('name'):20s} @ {hex(section.get('vaddr', 0))}")

    # Get imports
    imports = adapter.get_imports()
    print(f"\nImports ({len(imports)} found):")
    for imp in imports[:5]:
        print(f"  - {imp.get('name')}")

    r2.quit()


# Example 2: Using in Analyzer Class
# ===================================


class CustomAnalyzer:
    """Example analyzer using BinaryAnalyzerInterface."""

    def __init__(self, analyzer: BinaryAnalyzerInterface):
        """Initialize with any Protocol-compliant analyzer."""
        self.analyzer = analyzer

    def analyze_code_sections(self):
        """Analyze executable sections."""
        sections = self.analyzer.get_sections()

        code_sections = [
            s for s in sections if "x" in s.get("perm", "") or "text" in s.get("name", "").lower()
        ]

        total_code_size = sum(s.get("size", 0) for s in code_sections)

        return {
            "count": len(code_sections),
            "total_size": total_code_size,
            "sections": code_sections,
        }

    def analyze_imports(self):
        """Analyze import characteristics."""
        imports = self.analyzer.get_imports()

        libraries = set()
        functions = []

        for imp in imports:
            lib = imp.get("libname", "")
            if lib:
                libraries.add(lib.lower())
            func = imp.get("name", "")
            if func:
                functions.append(func)

        return {
            "total_imports": len(imports),
            "unique_libraries": len(libraries),
            "libraries": sorted(libraries),
            "functions": functions[:10],  # First 10 functions
        }


def example_analyzer_usage():
    """Using adapter with custom analyzer."""
    print("\n\nExample 2: Custom Analyzer Usage")
    print("-" * 60)

    r2 = r2pipe.open(SAMPLE_BINARY)
    adapter = R2PipeAdapter(r2)

    analyzer = CustomAnalyzer(adapter)

    # Analyze code sections
    code_analysis = analyzer.analyze_code_sections()
    print("\nCode Section Analysis:")
    print(f"  Count: {code_analysis['count']}")
    print(f"  Total Size: {code_analysis['total_size']:,} bytes")

    # Analyze imports
    import_analysis = analyzer.analyze_imports()
    print("\nImport Analysis:")
    print(f"  Total Imports: {import_analysis['total_imports']}")
    print(f"  Unique Libraries: {import_analysis['unique_libraries']}")
    print(f"  Libraries: {', '.join(import_analysis['libraries'][:5])}")

    r2.quit()


# Example 3: Testing with Mock Implementation
# ============================================


class MockBinaryAnalyzer:
    """Mock implementation for testing without r2pipe."""

    def get_file_info(self):
        return {"arch": "x86", "bits": 64, "bintype": "elf", "class": "ELF64"}

    def get_sections(self):
        return [
            {"name": ".text", "vaddr": 0x1000, "size": 0x2000, "perm": "r-x"},
            {"name": ".data", "vaddr": 0x3000, "size": 0x1000, "perm": "rw-"},
        ]

    def get_imports(self):
        return [
            {"name": "printf", "libname": "libc.so.6"},
            {"name": "malloc", "libname": "libc.so.6"},
        ]

    def get_exports(self):
        return []

    def get_symbols(self):
        return []

    def read_bytes(self, _address, size):
        return b"\x00" * size

    def execute_command(self, _cmd):
        return None


def example_mock_testing():
    """Testing with mock analyzer."""
    print("\n\nExample 3: Mock Testing")
    print("-" * 60)

    # Use mock instead of real r2pipe
    mock_analyzer = MockBinaryAnalyzer()

    # Verify Protocol compliance
    print(f"Is BinaryAnalyzerInterface: {isinstance(mock_analyzer, BinaryAnalyzerInterface)}")

    # Use with custom analyzer
    analyzer = CustomAnalyzer(mock_analyzer)

    # Run analysis
    code_analysis = analyzer.analyze_code_sections()
    print("\nMock Code Analysis:")
    print(f"  Count: {code_analysis['count']}")
    print(f"  Sections: {[s['name'] for s in code_analysis['sections']]}")

    import_analysis = analyzer.analyze_imports()
    print("\nMock Import Analysis:")
    print(f"  Total: {import_analysis['total_imports']}")
    print(f"  Libraries: {import_analysis['libraries']}")


# Example 4: Advanced Usage
# =========================


def example_advanced_usage():
    """Advanced adapter features."""
    print("\n\nExample 4: Advanced Usage")
    print("-" * 60)

    r2 = r2pipe.open(SAMPLE_BINARY)
    adapter = R2PipeAdapter(r2)

    # Read bytes from entry point
    info = adapter.get_file_info()
    entry = info.get("core", {}).get("baddr", 0)

    print(f"\nReading bytes from entry point: {hex(entry)}")
    data = adapter.read_bytes(entry, 16)
    print(f"  Bytes: {data.hex()}")
    print(f"  ASCII: {repr(data)}")

    # Execute custom command
    print("\nExecuting custom command (iIj):")
    binary_info = adapter.execute_command("iIj")
    if binary_info and isinstance(binary_info, dict):
        print(f"  Compiler: {binary_info.get('compiler', 'unknown')}")
        print(f"  Language: {binary_info.get('lang', 'unknown')}")

    # Get strings
    print("\nGetting strings:")
    strings = adapter.get_strings()
    print(f"  Total strings found: {len(strings)}")
    if strings:
        interesting = [s for s in strings if len(s.get("string", "")) > 50]
        print(f"  Long strings (>50 chars): {len(interesting)}")

    # Get functions (requires analysis)
    print("\nGetting functions:")
    functions = adapter.get_functions()
    print(f"  Functions found: {len(functions)}")

    r2.quit()


# Example 5: Error Handling
# ==========================


def example_error_handling():
    """Demonstrating error handling."""
    print("\n\nExample 5: Error Handling")
    print("-" * 60)

    # Test with invalid r2 instance
    print("\nTesting invalid constructor:")
    try:
        adapter = R2PipeAdapter(None)
    except ValueError as e:
        print(f"  ✓ Caught expected error: {e}")

    # Test invalid read_bytes parameters
    r2 = r2pipe.open(SAMPLE_BINARY)
    adapter = R2PipeAdapter(r2)

    print("\nTesting invalid read_bytes:")
    try:
        adapter.read_bytes(-1, 100)
    except ValueError as e:
        print(f"  ✓ Caught negative address: {e}")

    try:
        adapter.read_bytes(0x1000, 0)
    except ValueError as e:
        print(f"  ✓ Caught zero size: {e}")

    r2.quit()


# Main execution
# ==============

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("R2PipeAdapter Usage Examples")
    print("=" * 60)

    try:
        # Example 1: Basic usage
        example_basic_usage()

        # Example 2: Analyzer usage
        example_analyzer_usage()

        # Example 3: Mock testing
        example_mock_testing()

        # Example 4: Advanced features
        example_advanced_usage()

        # Example 5: Error handling
        example_error_handling()

    except Exception as e:
        print(f"\nError running examples: {e}")
        import traceback

        traceback.print_exc()

    print("\n" + "=" * 60)
    print("All examples completed!")
    print("=" * 60 + "\n")
