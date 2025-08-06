# r2inspect

[![PyPI version](https://badge.fury.io/py/r2inspect.svg)](https://badge.fury.io/py/r2inspect)
[![Python](https://img.shields.io/pypi/pyversions/r2inspect.svg)](https://pypi.org/project/r2inspect/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

**r2inspect** is an advanced malware analysis tool powered by radare2 and r2pipe, designed for security researchers and malware analysts to perform comprehensive static analysis of suspicious files.

## Features

### 🔍 Comprehensive Analysis
- **File Identification**: Automatic file type detection and format analysis
- **Hash Calculation**: MD5, SHA1, SHA256, SHA512, and fuzzy hashing (SSDeep, TLSH)
- **PE/ELF/MachO Analysis**: Deep inspection of executable formats
- **String Extraction**: Advanced string analysis with encoding detection
- **Function Analysis**: Function detection and control flow analysis
- **Import/Export Analysis**: Complete import and export table parsing

### 🛡️ Security Features
- **YARA Integration**: Built-in YARA rules for malware detection
- **Packer Detection**: Identify common packers and obfuscators
- **Compiler Detection**: Recognize compilation signatures
- **Anti-Analysis Detection**: Detect anti-debugging and anti-VM techniques
- **Crypto Detection**: Identify cryptographic algorithms and constants

### 🚀 Advanced Capabilities
- **Batch Processing**: Analyze multiple files with parallel processing
- **Multiple Output Formats**: JSON, CSV, and rich terminal output
- **Docker Support**: Containerized analysis environment
- **Memory Management**: Efficient handling of large files
- **Error Recovery**: Robust error handling with circuit breakers

## Installation

### Prerequisites

r2inspect requires radare2 to be installed on your system:

```bash
# macOS
brew install radare2

# Ubuntu/Debian
apt-get install radare2

# From source
git clone https://github.com/radareorg/radare2
cd radare2
sys/install.sh
```

### Install from PyPI

```bash
pip install r2inspect
```

### Install from source

```bash
git clone https://github.com/seifreed/r2inspect
cd r2inspect
pip install -e .
```

## Quick Start

### Basic Analysis

```bash
# Analyze a single file
r2inspect malware.exe

# JSON output
r2inspect malware.exe --json

# Save to file
r2inspect malware.exe --output analysis.json
```

### Batch Analysis

```bash
# Analyze all files in a directory
r2inspect --batch /path/to/samples/

# Specific file types only
r2inspect --batch /path/to/samples/ --extensions exe,dll,elf

# Parallel processing
r2inspect --batch /path/to/samples/ --threads 10
```

### Docker Usage

```bash
# Using Docker
docker run -v /path/to/samples:/samples r2inspect:latest /samples/malware.exe

# Using docker-compose
docker-compose run r2inspect /samples/malware.exe
```

## Output Example

```
═══════════════════════════════════════════════════════════════════════
                           File Information
═══════════════════════════════════════════════════════════════════════
Format         : PE32+
Architecture   : x86-64
Size           : 1,234,567 bytes
MD5            : d41d8cd98f00b204e9800998ecf8427e
SHA256         : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Threat Level   : High
═══════════════════════════════════════════════════════════════════════
```

## Configuration

Create a custom configuration file:

```python
# config.py
from r2inspect.config import Config

config = Config()
config.max_file_size = 100 * 1024 * 1024  # 100MB
config.analysis_timeout = 300  # 5 minutes
config.enable_yara = True
config.yara_rules_path = "/path/to/custom/rules"
```

## API Usage

```python
from r2inspect import R2Inspector
from r2inspect.config import Config

# Initialize with custom config
config = Config()
inspector = R2Inspector("malware.exe", config=config)

# Perform analysis
with inspector:
    results = inspector.analyze()
    
    # Access specific analysis results
    print(f"File type: {results['file_info']['format']}")
    print(f"SHA256: {results['hashes']['sha256']}")
    
    # Check for packers
    if results['packer_detection']['packed']:
        print(f"Packer detected: {results['packer_detection']['packer_name']}")
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](https://github.com/seifreed/r2inspect/blob/main/LICENSE) file for details.

## Author

**Marc Rivero** ([@seifreed](https://github.com/seifreed))
- Email: mriverolopez@gmail.com
- GitHub: [https://github.com/seifreed](https://github.com/seifreed)

## Acknowledgments

- [radare2](https://github.com/radareorg/radare2) - The powerful reverse engineering framework
- [r2pipe](https://github.com/radareorg/radare2-r2pipe) - Python bindings for radare2
- [YARA](https://github.com/VirusTotal/yara) - Pattern matching engine for malware research

## Support

If you encounter any issues or have questions, please:
1. Check the [documentation](https://github.com/seifreed/r2inspect/blob/main/README.md)
2. Open an [issue](https://github.com/seifreed/r2inspect/issues)
3. Contact the author at mriverolopez@gmail.com

## Disclaimer

This tool is intended for legitimate security research and malware analysis only. Users are responsible for complying with all applicable laws and regulations.
