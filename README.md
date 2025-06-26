# r2inspect

**Advanced Malware Analysis Tool using Radare2 and r2pipe**

A comprehensive, professional-grade malware analysis framework powered by the radare2 reverse engineering toolkit.

## Features

r2inspect provides comprehensive static analysis of PE files with the following capabilities:

### Core Analysis Features
- **PE Structure Analysis**: Headers, sections, imports, exports with detailed metadata consistency
- **String Extraction**: ASCII, Unicode, with pattern matching and XOR obfuscation detection
- **Cryptographic Detection**: Modern API detection (BCrypt/CNG/OpenSSL), constants, algorithms with confidence scoring
- **Packer Detection**: Evidence-based scoring system with multiple indicators (signatures, entropy, imports)
- **Anti-Analysis Detection**: Detailed evidence collection with specific addresses and instruction analysis
- **Section Analysis**: Entropy calculation, permission flags, suspicious characteristics with size ratios
- **YARA Rule Integration**: Built-in and custom rule support
- **XOR String Search**: Find obfuscated strings with advanced pattern matching

### Advanced Hashing & Similarity Analysis

r2inspect implements multiple hashing algorithms for different malware analysis purposes:

| Algorithm | Purpose | Use Case | Output Format |
|-----------|---------|----------|---------------|
| **MD5** | Basic file identification | Quick file fingerprinting | 32-character hex |
| **SHA1** | File integrity verification | Legacy hash verification | 40-character hex |
| **SHA256** | Cryptographic file hashing | Secure file identification | 64-character hex |
| **SHA512** | Enhanced cryptographic hashing | High-security applications | 128-character hex |
| **ImpHash** | Import table hashing | Malware family clustering | 32-character hex |
| **SSDeep** | Fuzzy hashing | Similar file detection | Variable length string |
| **TLSH** | Locality sensitive hashing | Malware variant detection | 70-character string |
| **MACHOC** | Function-level hashing | Code similarity analysis | 64-character hex per function |
| **RichPE** | Rich header hashing | Compiler toolchain identification | 32-character hex |
| **Telfhash** | ELF symbol hashing | Linux malware clustering | Variable length string |
| **Impfuzzy** | Import fuzzing hash | PE import similarity | Variable length string |
| **CCBHash** | Control flow graph hashing | Structural code analysis | Variable length string |
| **SimHash** | Similarity hashing | Document/code similarity | 64-bit integer |
| **Binlex** | N-gram lexical analysis | Instruction pattern matching | SHA256 per n-gram size |

### Enhanced Detection Capabilities

#### Import Risk Scoring System
- **Granular 0-100 point scoring** instead of generic High/Medium/Low
- **Risk categories**: Injection APIs (80-100pts), Anti-analysis (70-90pts), Process manipulation (60-80pts)
- **Descriptive tags**: "Remote Thread Injection", "Anti-Debug", "Memory Manipulation"
- **Contextual descriptions** for each API function

#### Anti-Analysis Detection with Evidence
- **Detailed evidence collection**: Specific addresses, instruction counts, API contexts
- **Multiple evidence types**: API calls, PEB access, RDTSC instructions, CPUID detection
- **Timing analysis**: High-resolution timing checks, performance counter usage
- **VM detection**: Hardware fingerprinting, artifact detection

#### Cryptography Analysis
- **Modern API detection**: BCrypt, CNG, OpenSSL with confidence scoring
- **Constant detection**: S-box patterns, initialization vectors, known constants
- **False positive reduction**: Noise filtering for vtable and destructor strings
- **Evidence consolidation**: Multiple evidence types with weighted confidence

#### Packer Detection
- **Evidence-based scoring**: Requires 50+ points from multiple indicators
- **Multi-factor analysis**: Signatures (40pts), entropy (15pts), sections (10pts), imports (10pts)
- **Entropy thresholds**: Section-by-section analysis with configurable limits
- **Reduced false positives**: No single-indicator detection

### Output Formats
- **Interactive Mode**: Real-time exploration with rich console interface
- **JSON Output**: Machine-readable structured data with detailed metadata
- **CSV Export**: Spreadsheet-compatible format for batch analysis
- **Rich Console**: Colorized tables, progress bars, and formatted summaries
- **Executive Summary**: High-level security assessment with recommendations

### Function Analysis
- **MACHOC Hash Generation**: Function-level similarity detection
- **Cyclomatic Complexity**: Control flow analysis and code complexity metrics
- **Function Classification**: Library, user-defined, and thunk function identification
- **Coverage Analysis**: Statistical analysis of function detection quality
- **Call Graph Analysis**: Function relationship mapping

### Section Analysis Enhancements
- **PE Characteristics Decoding**: Detailed flag interpretation
- **Permission Analysis**: Executable, readable, writable flags from PE headers
- **Size Ratio Analysis**: Virtual vs raw size with specific thresholds (>10x, >5x)
- **Entropy Analysis**: Shannon entropy calculation per section
- **Suspicious Indicators**: Automated detection of anomalous section properties

## Installation

### Prerequisites

- Python 3.13+
- radare2 installed and in PATH
- libmagic (for file type detection)

### Install from PyPI (when available)
```bash
pip install r2inspect
```

### Install from Source
```bash
git clone https://github.com/seifreed/r2inspect.git
cd r2inspect
pip install -e .
```

### Quick Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Install the package
python setup.py install
```

### macOS ARM (Apple Silicon) Setup

For macOS ARM systems, you may need to set specific flags to install the ssdeep library:

```bash
# Set compilation flags for Homebrew paths
export CFLAGS="-I/opt/homebrew/include"
export LDFLAGS="-L/opt/homebrew/lib"

# Install ssdeep library
pip install ssdeep

# Then install r2inspect
pip install -r requirements.txt
python setup.py install
```

**Note**: Make sure you have ssdeep installed via Homebrew first:
```bash
brew install ssdeep
```

### Optional Dependencies

For enhanced functionality, install these optional libraries:

```bash
# TLSH for locality sensitive hashing
pip install python-tlsh

# SSDeep for fuzzy hashing
pip install ssdeep

# Telfhash for ELF analysis
pip install telfhash

# Rich for enhanced console output
pip install rich

# YARA for rule matching
pip install yara-python
```

## Usage

### Basic Analysis
```bash
# Simple analysis with rich console output
r2inspect malware.exe

# JSON output with all hashing algorithms
r2inspect -j malware.exe

# CSV output for batch processing
r2inspect -c malware.exe

# Save to file with executive summary
r2inspect -j malware.exe -o analysis.json
```

### Advanced Analysis Options
```bash
# Full analysis with all modules enabled
r2inspect --full malware.exe

# Enable specific hashing algorithms
r2inspect --enable-tlsh --enable-machoc malware.exe

# Disable packer detection for speed
r2inspect --no-packer malware.exe

# Custom entropy threshold for packer detection
r2inspect --entropy-threshold 7.5 malware.exe

# Enable function analysis with complexity metrics
r2inspect --analyze-functions malware.exe
```

### Batch Processing
```bash
# Process all files in a directory
r2inspect --batch /path/to/malware/samples -j

# Process recursively with custom extensions
r2inspect --batch /path/to/samples --recursive --extensions "exe,dll,scr" -c

# Batch processing with custom output directory
r2inspect --batch /samples -j -o /results

# Process specific file types only
r2inspect --batch /samples --extensions "exe,dll" -j -o /analysis_results

# Generate summary report for batch analysis
r2inspect --batch /samples -j --summary
```

### Advanced Options
```bash
# Interactive mode with command shell
r2inspect -i malware.exe

# Verbose output with debug information
r2inspect -v malware.exe

# Search for XOR'd strings with custom key
r2inspect -x "hidden_string" malware.exe

# Custom YARA rules directory
r2inspect --yara /path/to/rules malware.exe

# Strings analysis only
r2inspect -s malware.exe

# Generate executive summary
r2inspect --executive-summary malware.exe

# Compare with another file using BinDiff
r2inspect --bindiff target.exe reference.exe
```

### Hash-Specific Analysis
```bash
# Generate only specific hashes
r2inspect --hashes "md5,sha256,imphash,ssdeep" malware.exe

# TLSH similarity analysis
r2inspect --tlsh-compare file1.exe file2.exe

# MACHOC function similarity
r2inspect --machoc-similarity malware.exe

# Rich header analysis for PE files
r2inspect --rich-header malware.exe

# Telfhash for ELF files
r2inspect --telfhash linux_malware
```

### Interactive Mode Commands
```
r2inspect> analyze     # Run full analysis
r2inspect> strings     # Show strings with patterns
r2inspect> info        # File information with hashes
r2inspect> pe          # PE structure with metadata
r2inspect> imports     # Import table with risk scoring
r2inspect> exports     # Export table analysis
r2inspect> sections    # Section analysis with entropy
r2inspect> functions   # Function analysis with MACHOC
r2inspect> crypto      # Cryptographic detection
r2inspect> anti        # Anti-analysis techniques
r2inspect> packer      # Packer detection with evidence
r2inspect> hashes      # All hash algorithms
r2inspect> summary     # Executive summary
r2inspect> quit        # Exit
```

## Configuration

r2inspect uses a configuration file located at `~/.r2inspect/config.json`:

```json
{
  "general": {
    "verbose": false,
    "max_strings": 1000,
    "min_string_length": 4,
    "enable_all_hashes": true
  },
  "yara": {
    "rules_path": "rules/yara",
    "enabled": true,
    "timeout": 60
  },
  "packer": {
    "entropy_threshold": 7.0,
    "section_analysis": true,
    "evidence_threshold": 50
  },
  "import_analysis": {
    "risk_scoring": true,
    "granular_scoring": true,
    "api_categories": true
  },
  "anti_analysis": {
    "detailed_evidence": true,
    "instruction_analysis": true,
    "timing_detection": true
  },
  "crypto": {
    "modern_api_detection": true,
    "constant_detection": true,
    "confidence_threshold": 0.5
  },
  "functions": {
    "machoc_hashing": true,
    "complexity_analysis": true,
    "coverage_analysis": true
  },
  "hashing": {
    "enable_tlsh": true,
    "enable_ssdeep": true,
    "enable_machoc": true,
    "enable_rich_header": true,
    "enable_impfuzzy": true
  },
  "output": {
    "json_indent": 2,
    "show_progress": true,
    "color_output": true,
    "executive_summary": false
  }
}
```

## Python API

```python
from r2inspect import R2Inspector
from r2inspect.config import Config

# Initialize with custom configuration
config = Config()
config.enable_all_hashes = True
config.detailed_analysis = True

inspector = R2Inspector('malware.exe', config)

# Run comprehensive analysis
results = inspector.analyze()

# Access specific analysis results
pe_info = inspector.get_pe_info()
imports = inspector.get_imports()
strings = inspector.get_strings()
hashes = inspector.get_all_hashes()

# Advanced analysis
functions = inspector.analyze_functions()
crypto_info = inspector.detect_crypto()
anti_analysis = inspector.detect_anti_analysis()
packer_info = inspector.detect_packer()

# Hash-specific analysis
tlsh_info = inspector.analyze_tlsh()
machoc_hashes = inspector.generate_machoc_hashes()
rich_header = inspector.analyze_rich_header()

# Similarity analysis
similarity = inspector.compare_with('other_file.exe')

# Generate executive summary
summary = inspector.generate_executive_summary(results)

# Clean up
inspector.close()
```

## YARA Rules

r2inspect includes built-in YARA rules for:
- **Packer detection**: UPX, ASPack, Themida, MEW, FSG, PEtite
- **Suspicious API patterns**: Injection, persistence, evasion
- **Cryptographic constants**: AES, DES, RSA, MD5, SHA variants
- **Anti-analysis techniques**: Debugger detection, VM evasion
- **Compiler signatures**: Visual Studio, GCC, Delphi, .NET

Add custom rules to `~/.r2inspect/rules/yara/`

## Key Differentiators

r2inspect stands out in the malware analysis landscape with:

| Feature | Traditional Tools | r2inspect |
|---------|------------------|-----------|
| Backend | Custom parsers | Radare2 ecosystem |
| Output | Text/Basic JSON | JSON/CSV/Rich Console |
| YARA | Basic integration | Advanced rule engine |
| Strings | Simple extraction | Advanced with XOR search |
| Entropy | Basic calculation | Comprehensive per-section |
| Anti-Analysis | Simple detection | Extensive evidence collection |
| Import Analysis | Generic risk levels | Granular 0-100 scoring |
| Hashing | Basic algorithms | 14 specialized algorithms |
| Packer Detection | Simple heuristics | Evidence-based scoring |
| Function Analysis | Limited | MACHOC + complexity metrics |
| Crypto Detection | Pattern matching | Modern APIs + constants |
| Extensibility | Monolithic | Modular architecture |
| Performance | Variable | Optimized with caching |
| Similarity Analysis | None | Multiple algorithms |
| Executive Summary | Manual | Automated assessment |

## Architecture

```
r2inspect/
├── cli.py              # Command-line interface with rich output
├── core.py             # Main analysis engine with all modules
├── config.py           # Configuration management
├── modules/            # Analysis modules
│   ├── pe_analyzer.py          # Enhanced PE analysis
│   ├── string_analyzer.py      # String extraction and analysis
│   ├── crypto_analyzer.py      # Cryptography detection
│   ├── packer_detector.py      # Evidence-based packer detection
│   ├── anti_analysis.py        # Anti-analysis with evidence
│   ├── section_analyzer.py     # Section analysis with entropy
│   ├── import_analyzer.py      # Import risk scoring
│   ├── export_analyzer.py      # Export analysis
│   ├── function_analyzer.py    # Function analysis and MACHOC
│   ├── yara_analyzer.py        # YARA rule integration
│   ├── tlsh_analyzer.py        # TLSH locality sensitive hashing
│   ├── ssdeep_analyzer.py      # SSDeep fuzzy hashing
│   ├── rich_header_analyzer.py # Rich header analysis
│   ├── impfuzzy_analyzer.py    # Import fuzzy hashing
│   ├── ccbhash_analyzer.py     # Control flow graph hashing
│   ├── binlex_analyzer.py      # N-gram lexical analysis
│   ├── simhash_analyzer.py     # Similarity hashing
│   └── bindiff_analyzer.py     # Binary comparison features
└── utils/              # Utilities
    ├── logger.py               # Logging system
    ├── output.py              # Output formatting
    ├── hashing.py             # Hash utilities
    └── r2_helpers.py          # Radare2 helper functions
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Update documentation
6. Submit a pull request

### Development Setup

```bash
# Clone the repository
git clone https://github.com/seifreed/r2inspect.git
cd r2inspect

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt
pip install -e .

# Run tests
python -m pytest tests/

# Run linting
flake8 r2inspect/
black r2inspect/

# Generate documentation
cd docs/
make html
```

## License

GNU General Public License v3.0

## Author

**Marc Rivero** | [@seifreed](https://github.com/seifreed)

## Acknowledgments

- Built on the excellent radare2 framework and ecosystem
- Thanks to the malware analysis and reverse engineering community
- MACHOC algorithm based on Polichombr's approach
- TLSH implementation by Trend Micro
- Rich header analysis techniques from various researchers
- Inspiration from the broader malware analysis tool landscape

## Support

- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Full API documentation available at [docs.r2inspect.com](https://docs.r2inspect.com)
- **Community**: Join our discussions on GitHub
- **Security**: Report security issues privately to security@r2inspect.com

## Roadmap

- [ ] Machine learning-based malware classification
- [ ] Dynamic analysis integration
- [ ] Cloud-based analysis API
- [ ] Integration with threat intelligence platforms
- [ ] Advanced obfuscation detection
- [ ] Automated report generation
- [ ] Plugin system for custom analyzers
- [ ] Web-based interface
- [ ] Docker containerization
- [ ] Kubernetes deployment support

---

*r2inspect - Professional malware analysis for the modern era* 