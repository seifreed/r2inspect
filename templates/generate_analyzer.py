#!/usr/bin/env python3
"""
Analyzer Generator Script

Generate new analyzers from templates with proper scaffolding.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0

Usage:
    python templates/generate_analyzer.py --name MyAnalyzer --template simple --category format
    python templates/generate_analyzer.py --name PackerDetector --template detection --category detection
"""

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Dict


class AnalyzerGenerator:
    """Generate analyzer from template."""

    TEMPLATE_MAP = {
        "simple": "simple_format_analyzer.py",
        "string": "string_based_analyzer.py",
        "security": "security_analyzer.py",
        "detection": "detection_analyzer.py",
        "external": "external_tool_analyzer.py",
    }

    CATEGORIES = [
        "format",
        "metadata",
        "security",
        "detection",
        "hashing",
        "similarity",
        "behavioral",
    ]

    def __init__(self, name: str, template: str, category: str, output_dir: str = None):
        """
        Initialize generator.

        Args:
            name: Analyzer class name (e.g., "MyAnalyzer")
            template: Template type (simple/string/security/detection/external)
            category: Analyzer category
            output_dir: Output directory (default: r2inspect/modules/)
        """
        self.name = name
        self.template = template
        self.category = category
        self.output_dir = output_dir or "r2inspect/modules"

        # Derived names
        self.class_name = self._to_class_name(name)
        self.snake_name = self._to_snake_case(name)
        self.file_name = f"{self.snake_name}.py"

    def _to_class_name(self, name: str) -> str:
        """Convert name to ClassName format."""
        # Remove "Analyzer" suffix if present
        name = name.replace("Analyzer", "").replace("analyzer", "")
        # Convert to PascalCase
        name = "".join(word.capitalize() for word in re.split(r"[_\s-]", name))
        return f"{name}Analyzer"

    def _to_snake_case(self, name: str) -> str:
        """Convert name to snake_case format."""
        # Remove "Analyzer" suffix
        name = name.replace("Analyzer", "").replace("analyzer", "")
        # Convert to snake_case
        name = re.sub(r"([A-Z])", r"_\1", name).lower().strip("_")
        return name

    def generate(self) -> bool:
        """
        Generate analyzer and test files.

        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate inputs
            if not self._validate():
                return False

            # Generate analyzer file
            print(f"Generating analyzer: {self.class_name}")
            analyzer_path = self._generate_analyzer_file()
            print(f"  ✓ Created: {analyzer_path}")

            # Generate test file
            print(f"Generating test file")
            test_path = self._generate_test_file()
            print(f"  ✓ Created: {test_path}")

            # Print next steps
            self._print_next_steps(analyzer_path, test_path)

            return True

        except Exception as e:
            print(f"❌ Error generating analyzer: {e}", file=sys.stderr)
            return False

    def _validate(self) -> bool:
        """Validate inputs."""
        if self.template not in self.TEMPLATE_MAP:
            print(
                f"❌ Invalid template: {self.template}. "
                f"Choose from: {', '.join(self.TEMPLATE_MAP.keys())}",
                file=sys.stderr,
            )
            return False

        if self.category not in self.CATEGORIES:
            print(
                f"⚠ Warning: Unusual category '{self.category}'. "
                f"Standard categories: {', '.join(self.CATEGORIES)}"
            )

        return True

    def _generate_analyzer_file(self) -> Path:
        """Generate analyzer file from template."""
        # Get template path
        template_dir = Path(__file__).parent
        template_file = template_dir / self.TEMPLATE_MAP[self.template]

        if not template_file.exists():
            raise FileNotFoundError(f"Template not found: {template_file}")

        # Read template
        with open(template_file, "r") as f:
            content = f.read()

        # Replace placeholders
        replacements = {
            "[ANALYZER_NAME]": self.class_name.replace("Analyzer", ""),
            "[analyzer_name]": self.snake_name,
            "[CATEGORY]": self.category,
            "[category]": self.category,
        }

        for placeholder, value in replacements.items():
            content = content.replace(placeholder, value)

        # Write output file
        output_path = Path(self.output_dir) / self.file_name
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            f.write(content)

        return output_path

    def _generate_test_file(self) -> Path:
        """Generate test file."""
        test_template = f"""# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
\"\"\"
Unit tests for {self.class_name}

Tests the {self.class_name} using pytest.
\"\"\"

import pytest
from r2inspect.modules.{self.snake_name} import {self.class_name}


@pytest.mark.unit
class Test{self.class_name}:
    \"\"\"Test suite for {self.class_name}.\"\"\"

    def test_is_available(self):
        \"\"\"Test analyzer reports availability.\"\"\"
        assert {self.class_name}.is_available()

    def test_get_metadata(self):
        \"\"\"Test metadata methods return expected values.\"\"\"
        analyzer = {self.class_name}(r2=None)

        assert analyzer.get_name() == "{self.snake_name}"
        assert analyzer.get_category() == "{self.category}"
        assert isinstance(analyzer.get_description(), str)
        assert isinstance(analyzer.get_supported_formats(), set)

    def test_analyze_without_r2_fails_gracefully(self):
        \"\"\"Test analyze fails gracefully when r2 not provided.\"\"\"
        analyzer = {self.class_name}(r2=None)
        result = analyzer.analyze()

        assert isinstance(result, dict)
        assert 'available' in result
        assert result['available'] is False
        assert 'error' in result

    # TODO: Add more tests for your analyzer's specific functionality
"""

        # Write test file
        test_path = Path(f"tests/unit/analyzers/test_{self.snake_name}.py")
        test_path.parent.mkdir(parents=True, exist_ok=True)

        with open(test_path, "w") as f:
            f.write(test_template)

        return test_path

    def _print_next_steps(self, analyzer_path: Path, test_path: Path):
        """Print next steps for the user."""
        print("\n" + "=" * 70)
        print("✅ Analyzer generated successfully!")
        print("=" * 70)
        print(f"\n📁 Files created:")
        print(f"   • Analyzer: {analyzer_path}")
        print(f"   • Tests: {test_path}")
        print(f"\n📝 Next steps:")
        print(f"   1. Edit {analyzer_path}")
        print(f"      • Implement _perform_analysis() method")
        print(f"      • Replace [TODO] placeholders")
        print(f"      • Add your analysis logic")
        print(f"\n   2. Write tests in {test_path}")
        print(f"      • Add specific test cases")
        print(f"      • Test edge cases")
        print(f"\n   3. Validate your analyzer:")
        print(f"      python templates/validate_analyzer.py {analyzer_path}")
        print(f"\n   4. Run tests:")
        print(f"      pytest {test_path} -v")
        print(f"\n📚 Resources:")
        print(f"   • Template guide: templates/README.md")
        print(f"   • Quick start: templates/QUICK_START.md")
        print(f"   • Testing guide: templates/TESTING_GUIDE.md")
        print(f"   • Examples: templates/examples/")
        print("\n" + "=" * 70 + "\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate new r2inspect analyzer from template",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate simple format analyzer
  python templates/generate_analyzer.py --name DOSHeader --template simple --category format

  # Generate detection analyzer
  python templates/generate_analyzer.py --name PackerDetector --template detection --category detection

  # Generate external tool analyzer
  python templates/generate_analyzer.py --name YARAScanner --template external --category detection

Template types:
  simple     - Simple format analyzer (extract headers/metadata)
  string     - String-based analyzer (process text/patterns)
  security   - Security feature analyzer (check mitigations)
  detection  - Detection analyzer (detect patterns/behaviors)
  external   - External tool analyzer (wrap tools/libraries)

Categories:
  format, metadata, security, detection, hashing, similarity, behavioral
        """,
    )

    parser.add_argument(
        "--name",
        required=True,
        help="Analyzer name (e.g., 'MyAnalyzer', 'dos_header', 'PackerDetector')",
    )

    parser.add_argument(
        "--template",
        required=True,
        choices=["simple", "string", "security", "detection", "external"],
        help="Template type to use",
    )

    parser.add_argument(
        "--category",
        required=True,
        help="Analyzer category (e.g., 'format', 'security', 'detection')",
    )

    parser.add_argument(
        "--output",
        default="r2inspect/modules",
        help="Output directory (default: r2inspect/modules)",
    )

    args = parser.parse_args()

    # Generate analyzer
    generator = AnalyzerGenerator(
        name=args.name, template=args.template, category=args.category, output_dir=args.output
    )

    success = generator.generate()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
