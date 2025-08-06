# Pre-Commit Hooks Configuration for r2inspect

This document describes the pre-commit hooks setup for ensuring code quality and security in the r2inspect project.

## Overview

Pre-commit hooks automatically run quality checks before each commit, ensuring:
- Code formatting consistency
- Security vulnerability detection
- Code quality standards
- Import organization
- Syntax validation

## Installation

1. **Install pre-commit and tools:**
```bash
source venv/bin/activate
pip install pre-commit bandit black ruff mypy pylint pydocstyle isort safety yamllint
```

2. **Install the git hooks:**
```bash
pre-commit install
```

## Configured Hooks

### 1. General File Checks
- **Trailing whitespace removal** - Cleans up unnecessary whitespace
- **End-of-file fixer** - Ensures files end with a newline
- **YAML/JSON/TOML validation** - Checks configuration file syntax
- **Large file detection** - Warns about files >1MB
- **Case conflict detection** - Prevents case-insensitive filesystem issues
- **Merge conflict detection** - Catches unresolved merge markers
- **Private key detection** - Prevents accidental key commits
- **Python AST validation** - Ensures valid Python syntax

### 2. Code Formatting

#### Black (Python Code Formatter)
- Line length: 100 characters
- Consistent style across the codebase
- Auto-formats Python files

#### Ruff (Fast Python Linter & Formatter)
- Combines multiple linting tools
- Auto-fixes common issues
- Checks for:
  - Unused imports
  - Undefined variables
  - Code complexity
  - Style violations

#### isort (Import Sorter)
- Organizes imports alphabetically
- Groups imports by type (standard, third-party, local)
- Black-compatible profile

### 3. Security Scanning

#### Bandit (Security Linter)
- Scans for common security issues
- Configured exceptions for malware analysis tools:
  - MD5/SHA1 hashing (used for file identification)
  - Subprocess calls (needed for r2pipe)
  - Pickle usage (for caching)
- Severity level: Medium and above

### 4. Configuration Files

#### pyproject.toml
Contains tool-specific settings:
- Black formatting rules
- Ruff linting rules
- isort import sorting
- MyPy type checking
- Pylint rules
- Coverage settings

#### .bandit
Security scanning exceptions specific to malware analysis:
- Allows certain hash functions for file identification
- Permits subprocess usage for tool integration
- Excludes test directories

#### .pre-commit-config.yaml
Main configuration file defining all hooks and their versions.

## Usage

### Automatic Checks
Pre-commit hooks run automatically on `git commit`. If issues are found:
1. Files may be auto-fixed (formatting, imports)
2. You'll need to review changes and re-add files
3. Commit again after fixes

### Manual Checks
```bash
# Check all files
pre-commit run --all-files

# Check specific files
pre-commit run --files r2inspect/core.py

# Update hook versions
pre-commit autoupdate

# Skip hooks temporarily (not recommended)
git commit --no-verify
```

## Handling Hook Failures

### Common Issues and Solutions

1. **Formatting Issues**
   - Usually auto-fixed by Black/Ruff
   - Review changes with `git diff`
   - Re-add and commit

2. **Security Warnings**
   - Review Bandit output carefully
   - For false positives, add to `.bandit` exclusions
   - For real issues, fix the security vulnerability

3. **Import Errors**
   - isort will auto-fix most issues
   - Check for circular imports if problems persist

4. **Unused Imports**
   - Ruff removes unused imports automatically
   - Keep imports used for type hints

## Exceptions and Overrides

### File-Specific Ignores
In `pyproject.toml`:
```toml
[tool.ruff.per-file-ignores]
"__init__.py" = ["F401", "F403"]  # Allow unused imports in __init__
"tests/*" = ["ARG", "S101"]       # Allow assertions in tests
```

### Inline Ignores
For specific lines (use sparingly):
```python
import something  # noqa: F401
result = eval(user_input)  # nosec B307
```

## Quality Metrics

The pre-commit setup helps achieve:
- **Code consistency** - All code follows the same style
- **Security awareness** - Catches common vulnerabilities
- **Import organization** - Clean, organized imports
- **Type safety** - Optional type checking with MyPy
- **Documentation** - Enforces docstring standards

## Continuous Improvement

1. **Regular Updates**
   ```bash
   pre-commit autoupdate
   ```

2. **Review Hook Performance**
   ```bash
   time pre-commit run --all-files
   ```

3. **Add Custom Hooks**
   Edit `.pre-commit-config.yaml` to add project-specific checks

## Troubleshooting

### Clean Cache
```bash
pre-commit clean
pre-commit gc
```

### Reinstall Hooks
```bash
pre-commit uninstall
pre-commit install
```

### Debug Specific Hook
```bash
pre-commit run <hook-id> --verbose --all-files
```

## Best Practices

1. **Don't skip hooks** - They're there for a reason
2. **Fix, don't suppress** - Address issues rather than ignoring them
3. **Keep hooks fast** - Remove slow hooks that hinder development
4. **Document exceptions** - Explain why certain checks are disabled
5. **Team agreement** - Ensure all developers use the same configuration

## Related Documentation

- [Black Documentation](https://black.readthedocs.io/)
- [Ruff Documentation](https://docs.astral.sh/ruff/)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Pre-commit Documentation](https://pre-commit.com/)

## Support

For issues with pre-commit hooks:
1. Check this documentation
2. Review hook output carefully
3. Search for specific error messages
4. Ask team members for help
5. Consider adjusting configuration if needed