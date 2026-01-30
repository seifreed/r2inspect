<p align="center">
  <img src="https://img.shields.io/badge/r2inspect-Malware%20Analysis-blue?style=for-the-badge" alt="r2inspect">
</p>

<h1 align="center">r2inspect</h1>

<p align="center">
  <strong>Advanced malware analysis tool powered by radare2 and r2pipe</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/r2inspect/"><img src="https://img.shields.io/pypi/v/r2inspect?style=flat-square&logo=pypi&logoColor=white" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/r2inspect/"><img src="https://img.shields.io/pypi/pyversions/r2inspect?style=flat-square&logo=python&logoColor=white" alt="Python Versions"></a>
  <a href="https://github.com/seifreed/r2inspect/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/r2inspect/actions"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/r2inspect/test.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <a href="https://codecov.io/gh/seifreed/r2inspect"><img src="https://img.shields.io/codecov/c/github/seifreed/r2inspect?style=flat-square" alt="Coverage"></a>
</p>

<p align="center">
  <a href="https://github.com/seifreed/r2inspect/stargazers"><img src="https://img.shields.io/github/stars/seifreed/r2inspect?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/r2inspect/issues"><img src="https://img.shields.io/github/issues/seifreed/r2inspect?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**r2inspect** is a professional malware analysis framework that automates deep static inspection for PE, ELF, and Mach-O binaries using the radare2 ecosystem. It combines format parsing, detection heuristics, and rich reporting to support reverse engineers, incident responders, and threat analysts.

### Key Features

| Feature | Description |
|---------|-------------|
| **Multi-format Support** | PE, ELF, Mach-O format detection and analysis |
| **String Analysis** | ASCII/Unicode extraction with filtering and decoding |
| **Packer Detection** | Evidence-based scoring with entropy and signature checks |
| **Crypto Detection** | API and constant analysis with confidence scoring |
| **Anti-Analysis** | Anti-debug/VM/sandbox indicators with evidence |
| **Hashing Suite** | MD5/SHA, SSDeep, TLSH, MACHOC, RichPE, Telfhash, SimHash |
| **Metadata Analysis** | Sections, imports, exports, resources, overlays |
| **YARA Integration** | Built-in and custom rule scanning |
| **Rich Output** | Console tables, JSON, and CSV exports |

### Supported Formats

```
Windows  PE32 / PE32+ / DLL
Linux    ELF32 / ELF64
macOS    Mach-O / Universal
```

---

## Installation

### From PyPI (Recommended)

```bash
pip install r2inspect
```

### From Source

```bash
git clone https://github.com/seifreed/r2inspect.git
cd r2inspect
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
```

### Requirements

- Python 3.8+
- radare2 installed and in PATH
- libmagic (for file type detection)

---

## Quick Start

```bash
# Basic analysis with rich console output
r2inspect samples/fixtures/hello_pe.exe

# JSON output
r2inspect -j samples/fixtures/hello_pe.exe

# CSV output
r2inspect -c samples/fixtures/hello_pe.exe
```

---

## Usage

### Command Line Interface

```bash
# Full analysis
r2inspect malware.exe

# Save output to file
r2inspect -j malware.exe -o analysis.json

# Analyze a directory (batch mode)
r2inspect --batch ./samples -j -o ./out

# Custom YARA rules
r2inspect --yara /path/to/rules malware.exe
```

### Available Options

| Option | Description |
|--------|-------------|
| `-i, --interactive` | Interactive analysis shell |
| `-j, --json` | Output in JSON format |
| `-c, --csv` | Output in CSV format |
| `-o, --output` | Output file or directory |
| `--batch` | Batch mode for directories |
| `--extensions` | Filter batch by extensions |
| `--yara` | Custom YARA rules directory |
| `-x, --xor` | XOR search string |
| `-v, --verbose` | Verbose output |
| `--quiet` | Suppress non-critical output |
| `--threads` | Parallel threads for batch mode |

---

## Python Library

```python
from r2inspect import R2Inspector
from r2inspect.config import Config

config = Config()
with R2Inspector("malware.exe", config=config) as inspector:
    results = inspector.analyze()
    pe_info = inspector.get_pe_info()
    imports = inspector.get_imports()
```

---

## Examples

### Analyze Multiple Samples

```bash
r2inspect --batch ./samples --extensions "exe,dll" -j -o ./out
```

### Interactive Mode

```
r2inspect> analyze
r2inspect> strings
r2inspect> imports
r2inspect> quit
```

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Support the Project

If you find r2inspect useful, consider supporting its development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

GNU General Public License v3.0

**Attribution Required:**
- Author: **Marc Rivero** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/r2inspect](https://github.com/seifreed/r2inspect)

---

<p align="center">
  <sub>Made with dedication for the reverse engineering and threat intelligence community</sub>
</p>
