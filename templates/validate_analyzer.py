#!/usr/bin/env python3
"""
Analyzer Validation Script

Validate analyzer implementations against r2inspect standards.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0

Usage:
    python templates/validate_analyzer.py r2inspect/modules/your_analyzer.py
"""

import argparse
import ast
import importlib.util
import sys
from pathlib import Path
from typing import Dict, List, Tuple


class AnalyzerValidator:
    """Validate analyzer implementation."""

    REQUIRED_METHODS = [
        "analyze",
        "get_name",
        "get_category",
        "get_description",
        "is_available",
    ]

    REQUIRED_CATEGORIES = [
        "format",
        "metadata",
        "security",
        "detection",
        "hashing",
        "similarity",
        "behavioral",
        "unknown",
    ]

    def __init__(self, filepath: str):
        """
        Initialize validator.

        Args:
            filepath: Path to analyzer file
        """
        self.filepath = Path(filepath)
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.info: List[str] = []

    def validate(self) -> bool:
        """
        Run all validation checks.

        Returns:
            True if validation passed, False otherwise
        """
        print(f"🔍 Validating: {self.filepath}\n")

        # Check file exists
        if not self.filepath.exists():
            self.errors.append(f"File not found: {self.filepath}")
            self._print_results()
            return False

        # Parse file
        try:
            with open(self.filepath, "r") as f:
                source = f.read()
            tree = ast.parse(source, filename=str(self.filepath))
        except SyntaxError as e:
            self.errors.append(f"Syntax error: {e}")
            self._print_results()
            return False

        # Run checks
        self._check_file_name()
        self._check_imports(tree)
        self._check_class_definition(tree)
        self._check_inheritance(tree)
        self._check_required_methods(tree)
        self._check_docstrings(tree)
        self._check_type_hints(tree)
        self._check_license(source)
        self._check_test_file()

        # Print results
        self._print_results()

        return len(self.errors) == 0

    def _check_file_name(self):
        """Check file naming convention."""
        if not self.filepath.name.endswith("_analyzer.py"):
            self.warnings.append(
                f"File name should end with '_analyzer.py', got: {self.filepath.name}"
            )
        else:
            self.info.append(f"✓ File name follows convention: {self.filepath.name}")

    def _check_imports(self, tree: ast.AST):
        """Check required imports present."""
        imports = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module and "abstractions" in node.module:
                    for alias in node.names:
                        if alias.name == "BaseAnalyzer":
                            imports.add("BaseAnalyzer")

        if "BaseAnalyzer" not in imports:
            self.errors.append("Missing import: BaseAnalyzer from abstractions")
        else:
            self.info.append("✓ BaseAnalyzer imported")

    def _check_class_definition(self, tree: ast.AST):
        """Check analyzer class exists."""
        classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]

        analyzer_classes = [cls for cls in classes if cls.name.endswith("Analyzer")]

        if not analyzer_classes:
            self.errors.append("No class ending with 'Analyzer' found")
            return

        if len(analyzer_classes) > 1:
            self.warnings.append(
                f"Multiple analyzer classes found: {', '.join(c.name for c in analyzer_classes)}"
            )

        self.info.append(f"✓ Analyzer class found: {analyzer_classes[0].name}")

    def _check_inheritance(self, tree: ast.AST):
        """Check class inherits from BaseAnalyzer."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name.endswith("Analyzer"):
                if node.bases:
                    inherits_base = any(
                        (isinstance(base, ast.Name) and base.id == "BaseAnalyzer")
                        for base in node.bases
                    )
                    if inherits_base:
                        self.info.append(f"✓ {node.name} inherits from BaseAnalyzer")
                    else:
                        self.errors.append(
                            f"{node.name} does not inherit from BaseAnalyzer"
                        )
                else:
                    self.errors.append(f"{node.name} has no base classes")

    def _check_required_methods(self, tree: ast.AST):
        """Check required methods are implemented."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name.endswith("Analyzer"):
                methods = {m.name for m in node.body if isinstance(m, ast.FunctionDef)}

                for required in self.REQUIRED_METHODS:
                    if required in methods:
                        self.info.append(f"✓ Method implemented: {required}()")
                    else:
                        self.errors.append(f"Missing required method: {required}()")

    def _check_docstrings(self, tree: ast.AST):
        """Check docstrings present."""
        module_docstring = ast.get_docstring(tree)
        if not module_docstring:
            self.errors.append("Missing module docstring")
        else:
            self.info.append("✓ Module docstring present")

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name.endswith("Analyzer"):
                class_docstring = ast.get_docstring(node)
                if not class_docstring:
                    self.errors.append(f"Missing docstring for class {node.name}")
                else:
                    self.info.append(f"✓ Class docstring present: {node.name}")

                # Check method docstrings
                public_methods = [
                    m for m in node.body
                    if isinstance(m, ast.FunctionDef) and not m.name.startswith("_")
                ]

                for method in public_methods:
                    method_docstring = ast.get_docstring(method)
                    if not method_docstring:
                        self.warnings.append(
                            f"Missing docstring for method: {method.name}()"
                        )

    def _check_type_hints(self, tree: ast.AST):
        """Check type hints present."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name.endswith("Analyzer"):
                for method in node.body:
                    if isinstance(method, ast.FunctionDef):
                        # Check return type
                        if method.name in self.REQUIRED_METHODS:
                            if not method.returns:
                                self.warnings.append(
                                    f"Missing return type hint: {method.name}()"
                                )

    def _check_license(self, source: str):
        """Check GPL license header present."""
        if "GNU General Public License" in source or "GPLv3" in source or "GPL-3.0" in source:
            self.info.append("✓ GPL license header present")
        else:
            self.errors.append("Missing GPL license header in docstring")

        if "Marc Rivero López" in source or "Copyright (C) 2025" in source:
            self.info.append("✓ Copyright notice present")
        else:
            self.warnings.append("Copyright notice not found")

    def _check_test_file(self):
        """Check if corresponding test file exists."""
        test_name = f"test_{self.filepath.stem}.py"
        test_path = Path("tests/unit/analyzers") / test_name

        if test_path.exists():
            self.info.append(f"✓ Test file exists: {test_path}")
        else:
            self.warnings.append(f"Test file not found: {test_path}")

    def _print_results(self):
        """Print validation results."""
        print("=" * 70)

        if self.info:
            print("\n📋 INFO:")
            for msg in self.info:
                print(f"  {msg}")

        if self.warnings:
            print("\n⚠  WARNINGS:")
            for msg in self.warnings:
                print(f"  {msg}")

        if self.errors:
            print("\n❌ ERRORS:")
            for msg in self.errors:
                print(f"  {msg}")

        print("\n" + "=" * 70)

        # Summary
        total_checks = len(self.info) + len(self.warnings) + len(self.errors)
        passed = len(self.info)

        if self.errors:
            print(f"\n❌ VALIDATION FAILED: {len(self.errors)} error(s), "
                  f"{len(self.warnings)} warning(s)")
            print("\nFix errors before submission.")
        elif self.warnings:
            print(f"\n⚠  VALIDATION PASSED WITH WARNINGS: {len(self.warnings)} warning(s)")
            print("\nConsider addressing warnings for better quality.")
        else:
            print(f"\n✅ VALIDATION PASSED: All checks passed!")

        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Validate r2inspect analyzer implementation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python templates/validate_analyzer.py r2inspect/modules/dos_header_analyzer.py
  python templates/validate_analyzer.py r2inspect/modules/stack_protection_analyzer.py

This validator checks:
  • File naming conventions
  • BaseAnalyzer inheritance
  • Required methods implementation
  • Docstring presence
  • Type hints
  • License headers
  • Test file existence
        """,
    )

    parser.add_argument("filepath", help="Path to analyzer file to validate")

    args = parser.parse_args()

    # Validate analyzer
    validator = AnalyzerValidator(args.filepath)
    success = validator.validate()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
