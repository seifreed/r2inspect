#!/usr/bin/env python3
"""
Example: Using Pydantic Schemas in r2inspect

This example demonstrates how to use type-safe Pydantic schemas
for analyzer results instead of plain dictionaries.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

from r2inspect.schemas import (
    FormatAnalysisResult,
    HashAnalysisResult,
    ResultConverter,
    SecurityAnalysisResult,
    model_to_dict,
    safe_convert,
)

SAMPLE_SSDEEP_HASH = "3:abc:def"


def example_1_basic_usage():
    """Example 1: Basic schema usage"""
    print("=" * 60)
    print("Example 1: Basic Schema Usage")
    print("=" * 60)

    # Create a typed result directly
    result = HashAnalysisResult(
        available=True,
        hash_type="ssdeep",
        hash_value="3:abc123:def456",
        method_used="python_library",
        file_size=1024,
        execution_time=0.25,
    )

    # Access fields with full IDE support
    print(f"Hash Type: {result.hash_type}")
    print(f"Hash Value: {result.hash_value}")
    print(f"File Size: {result.file_size} bytes")
    print(f"Execution Time: {result.execution_time}s")

    # Use helper methods
    if result.is_valid_hash():
        print("✓ Hash is valid")

    # Convert to JSON
    print(f"\nJSON: {result.to_json()[:100]}...")

    print()


def example_2_converting_dicts():
    """Example 2: Converting existing dict results to schemas"""
    print("=" * 60)
    print("Example 2: Converting Dict to Schema")
    print("=" * 60)

    # Simulate legacy analyzer returning dict
    legacy_result = {
        "available": True,
        "hash_type": "tlsh",
        "hash_value": "T1ABC123DEF456...",
        "method_used": "python_library",
        "file_size": 2048,
    }

    # Convert to schema using ResultConverter
    result = ResultConverter.convert_result("tlsh", legacy_result)

    # Now type-safe!
    print(f"Type: {type(result).__name__}")
    print(f"Hash Type: {result.hash_type}")
    print(f"Hash Value: {result.hash_value}")
    print(f"Is Valid: {result.is_valid_hash()}")

    # Convert back to dict if needed
    result_dict = model_to_dict(result)
    print(f"\nBack to dict: {result_dict['hash_type']}")

    print()


def example_3_batch_conversion():
    """Example 3: Converting multiple analyzer results"""
    print("=" * 60)
    print("Example 3: Batch Conversion")
    print("=" * 60)

    # Multiple analyzer results as dicts
    results = {
        "ssdeep": {
            "available": True,
            "hash_type": "ssdeep",
            "hash_value": SAMPLE_SSDEEP_HASH,
            "file_size": 1024,
        },
        "tlsh": {
            "available": True,
            "hash_type": "tlsh",
            "hash_value": "T1234...",
            "file_size": 1024,
        },
        "impfuzzy": {
            "available": False,
            "hash_type": "impfuzzy",
            "error": "Not a PE file",
        },
    }

    # Convert all at once
    converted = ResultConverter.convert_results(results)

    # Process type-safe results
    for name, result in converted.items():
        print(f"\n{name}:")
        print(f"  Type: {type(result).__name__}")
        print(f"  Available: {result.available}")
        if result.available and hasattr(result, "hash_value"):
            print(f"  Hash: {result.hash_value}")
        elif result.error:
            print(f"  Error: {result.error}")

    print()


def example_4_validation():
    """Example 4: Automatic validation"""
    print("=" * 60)
    print("Example 4: Automatic Validation")
    print("=" * 60)

    # Valid data
    try:
        HashAnalysisResult(
            available=True,
            hash_type="ssdeep",
            hash_value=SAMPLE_SSDEEP_HASH,
        )
        print("✓ Valid result created successfully")
    except Exception as e:
        print(f"✗ Error: {e}")

    # Invalid hash type
    try:
        HashAnalysisResult(
            available=True,
            hash_type="invalid_type",  # Will fail
            hash_value="abc",
        )
        print("✓ Created (should not reach here)")
    except Exception:
        print("✓ Validation caught error: hash_type must be valid")

    # Negative file size
    try:
        HashAnalysisResult(
            available=True,
            hash_type="ssdeep",
            file_size=-100,  # Will fail
        )
        print("✓ Created (should not reach here)")
    except Exception:
        print("✓ Validation caught error: file_size must be non-negative")

    # Use safe_convert for graceful handling
    bad_data = {"available": True, "hash_type": "invalid", "file_size": -100}
    result4 = safe_convert(bad_data, HashAnalysisResult, default=None)
    if result4 is None:
        print("✓ safe_convert returned None for invalid data")

    print()


def example_5_format_schema():
    """Example 5: Using format schemas"""
    print("=" * 60)
    print("Example 5: Format Schema")
    print("=" * 60)

    from r2inspect.schemas import SectionInfo, SecurityFeatures

    # Create format result with nested sections
    result = FormatAnalysisResult(
        available=True,
        format="PE32+",
        architecture="x64",
        bits=64,
        entry_point=0x401000,
        sections=[
            SectionInfo(
                name=".text",
                virtual_address=0x1000,
                virtual_size=4096,
                raw_size=4096,
                entropy=6.5,
                is_executable=True,
                is_writable=False,
                is_readable=True,
            ),
            SectionInfo(
                name=".data",
                virtual_address=0x2000,
                virtual_size=2048,
                raw_size=2048,
                entropy=4.2,
                is_executable=False,
                is_writable=True,
                is_readable=True,
            ),
        ],
        security_features=SecurityFeatures(aslr=True, dep=True, guard_cf=True),
    )

    print(f"Format: {result.format}")
    print(f"Architecture: {result.architecture}")
    print(f"Bits: {result.bits}")
    print(f"Is 64-bit: {result.is_64bit()}")

    # Use helper methods
    exec_sections = result.get_executable_sections()
    print(f"\nExecutable sections: {len(exec_sections)}")
    for section in exec_sections:
        print(f"  - {section.name} (entropy: {section.entropy})")

    if result.security_features:
        enabled = result.security_features.get_enabled_features()
        print(f"\nEnabled security features: {', '.join(enabled)}")
        print(f"Security score: {result.security_features.security_score()}%")

    print()


def example_6_security_schema():
    """Example 6: Using security schemas"""
    print("=" * 60)
    print("Example 6: Security Schema")
    print("=" * 60)

    from r2inspect.schemas import MitigationInfo, SecurityIssue

    # Create security result
    result = SecurityAnalysisResult(
        available=True,
        mitigations={
            "ASLR": MitigationInfo(
                enabled=True,
                description="Address Space Layout Randomization",
                high_entropy=True,
            ),
            "DEP": MitigationInfo(enabled=True, description="Data Execution Prevention"),
            "CFG": MitigationInfo(enabled=False, description="Control Flow Guard"),
        },
        issues=[
            SecurityIssue(
                severity="high",
                description="Control Flow Guard not enabled",
                recommendation="Enable /guard:cf compiler flag",
            ),
            SecurityIssue(
                severity="medium",
                description="Stack canary not detected",
                recommendation="Enable /GS compiler flag",
            ),
        ],
        score=65,
    )

    print(f"Security Score: {result.score}/100")

    # Get enabled mitigations
    enabled = result.get_enabled_mitigations()
    print(f"\nEnabled Mitigations: {', '.join(enabled)}")

    # Get disabled mitigations
    disabled = result.get_disabled_mitigations()
    print(f"Disabled Mitigations: {', '.join(disabled)}")

    # Check specific mitigation
    if result.has_mitigation("ASLR"):
        print("\n✓ ASLR is enabled")

    # Get high severity issues
    high_issues = result.get_high_issues()
    print(f"\nHigh Severity Issues: {len(high_issues)}")
    for issue in high_issues:
        print(f"  - {issue.description}")
        print(f"    Recommendation: {issue.recommendation}")

    # Check security threshold
    if result.is_secure(threshold=70):
        print("\n✓ Meets security threshold (70)")
    else:
        print("\n✗ Below security threshold (70)")

    print()


def example_7_ide_support():
    """Example 7: Demonstrating IDE support"""
    print("=" * 60)
    print("Example 7: IDE Support Demo")
    print("=" * 60)

    result = HashAnalysisResult(available=True, hash_type="ssdeep", hash_value=SAMPLE_SSDEEP_HASH)

    # IDE features:
    # 1. Autocomplete - Type "result." and IDE shows all fields
    # 2. Type hints - IDE knows hash_value is Optional[str]
    # 3. Documentation - Hover over field shows description
    # 4. Navigation - Ctrl+Click jumps to definition
    # 5. Refactoring - Rename field updates everywhere

    print("IDE Support Features:")
    print("  1. Autocomplete: Type 'result.' to see all fields")
    print("  2. Type hints: IDE knows types (e.g., hash_value: Optional[str])")
    print("  3. Documentation: Hover over fields for descriptions")
    print("  4. Navigation: Ctrl+Click to jump to schema definition")
    print("  5. Refactoring: Safe renaming across entire codebase")
    print()
    print(f"Example field access: {result.hash_value}")
    print(f"Example method call: {result.is_valid_hash()}")

    print()


def main():
    """Run all examples"""
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 10 + "r2inspect Pydantic Schema Examples" + " " * 12 + "║")
    print("╚" + "=" * 58 + "╝")
    print()

    example_1_basic_usage()
    example_2_converting_dicts()
    example_3_batch_conversion()
    example_4_validation()
    example_5_format_schema()
    example_6_security_schema()
    example_7_ide_support()

    print("=" * 60)
    print("All examples completed successfully!")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()
