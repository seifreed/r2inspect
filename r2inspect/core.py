#!/usr/bin/env python3
"""
r2inspect Core - Main analysis engine using r2pipe
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import magic
import r2pipe
from rich.console import Console

from .config import Config
from .modules import (
    AntiAnalysisDetector,
    BinbloomAnalyzer,
    BinDiffAnalyzer,
    BinlexAnalyzer,
    CCBHashAnalyzer,
    CompilerDetector,
    CryptoAnalyzer,
    ELFAnalyzer,
    ExportAnalyzer,
    ImpfuzzyAnalyzer,
    ImportAnalyzer,
    MachOAnalyzer,
    PackerDetector,
    PEAnalyzer,
    RichHeaderAnalyzer,
    SectionAnalyzer,
    SimHashAnalyzer,
    SSDeepAnalyzer,
    StringAnalyzer,
    TelfhashAnalyzer,
    TLSHAnalyzer,
    YaraAnalyzer,
)
from .modules.function_analyzer import FunctionAnalyzer
from .utils.error_handler import ErrorCategory, ErrorSeverity, error_handler
from .utils.hashing import calculate_hashes
from .utils.logger import get_logger
from .utils.magic_detector import detect_file_type
from .utils.memory_manager import MemoryAwareAnalyzer, check_memory_limits, global_memory_monitor
from .utils.r2_helpers import safe_cmdj

console = Console()
logger = get_logger(__name__)


class R2Inspector(MemoryAwareAnalyzer):
    """Main analysis class using radare2 and r2pipe with memory management"""

    def __init__(self, filename: str, config: Config = None, verbose: bool = False):
        logger.debug(f"R2Inspector.__init__ called with filename: {filename}")
        super().__init__(global_memory_monitor)

        self.filename = filename
        self.config = config or Config()
        self.verbose = verbose
        self.r2 = None
        self.file_path = Path(filename)
        self._cleanup_required = False

        logger.debug(f"Starting file validation for: {filename}")
        # Check file size before proceeding
        if not self._validate_file():
            logger.error(f"File validation failed for: {filename}")
            raise ValueError(f"File validation failed: {filename}")
        logger.debug("File validation passed")

        logger.debug("Starting r2pipe initialization")
        # Initialize r2pipe
        self._init_r2pipe()
        logger.debug("r2pipe initialization completed")

        logger.debug("Starting analyzers initialization")
        # Initialize analyzers
        self._init_analyzers()
        logger.debug("All analyzers initialized successfully")

    def _validate_file(self) -> bool:
        """Validate file for analysis with enhanced checks"""
        try:
            if not self.file_path.exists():
                logger.error(f"File does not exist: {self.filename}")
                return False

            file_size = self.file_path.stat().st_size

            # Check for empty files
            if file_size == 0:
                logger.error(f"File is empty: {self.filename}")
                return False

            # Check for extremely small files that are likely corrupted
            if file_size < 32:  # Minimum size for any executable format
                logger.error(f"File too small for analysis ({file_size} bytes): {self.filename}")
                return False

            # Check memory limits
            if not check_memory_limits(file_size_bytes=file_size):
                logger.error(f"File exceeds memory limits: {file_size / 1024 / 1024:.1f}MB")
                return False

            # Basic file readability check
            try:
                with open(self.file_path, "rb") as f:
                    # Try to read first few bytes to ensure file is accessible
                    header = f.read(16)
                    if len(header) < 4:
                        logger.error(f"Cannot read file header: {self.filename}")
                        return False
            except OSError as e:
                logger.error(f"File access error: {self.filename} - {e}")
                return False

            return True

        except Exception as e:
            logger.error(f"Error validating file {self.filename}: {e}")
            return False

    @error_handler(
        category=ErrorCategory.R2PIPE,
        severity=ErrorSeverity.CRITICAL,
        context={"phase": "initialization"},
        fallback_result=None,
    )
    def _init_r2pipe(self):
        """Initialize r2pipe connection"""
        try:
            logger.debug(f"Opening file with radare2: {self.filename}")
            logger.debug("Calling r2pipe.open()...")

            # Use lighter flags for large files
            file_size_mb = self.file_path.stat().st_size / (1024 * 1024)
            if file_size_mb > 2:  # For files larger than 2MB
                flags = ["-2"]  # No stderr, will control analysis manually
                logger.debug(f"Large file ({file_size_mb:.1f}MB), using lighter r2 flags")
            else:
                flags = ["-2"]  # Standard flags

            self.r2 = r2pipe.open(self.filename, flags=flags)
            logger.debug("r2pipe.open() completed successfully")
            self._cleanup_required = True

            # Test basic r2 functionality first
            try:
                info_result = self.r2.cmd("i")
                if not info_result or len(info_result.strip()) < 10:
                    logger.warning(
                        f"r2 basic info command returned minimal data for {self.filename}"
                    )
            except Exception as e:
                logger.error(f"r2 basic info test failed: {e}")
                raise RuntimeError(f"r2 cannot properly analyze this file: {e}")

            # Basic analysis - use lighter analysis for large files
            file_size_mb = self.file_path.stat().st_size / (1024 * 1024)
            try:
                if file_size_mb > 50:  # For very large files (>50MB)
                    logger.debug("Very large file detected, skipping automatic analysis...")
                    # Skip automatic analysis for very large files
                elif file_size_mb > 10:  # For files larger than 10MB
                    logger.debug("Large file detected, using minimal analysis (aa command)...")
                    self.r2.cmd("aa")  # Lighter analysis
                    logger.debug("Light analysis (aa) completed")
                elif file_size_mb > 2:  # For moderately large files
                    logger.debug("Moderate file size, using standard analysis (aa command)...")
                    self.r2.cmd("aa")  # Standard analysis
                    logger.debug("Standard analysis (aa) completed")
                else:
                    logger.debug("Running full analysis (aaa command)...")
                    self.r2.cmd("aaa")  # Analyze all
                    logger.debug("Full analysis (aaa) completed")
            except Exception as e:
                logger.warning(f"Analysis command failed, continuing with basic r2 setup: {e}")
                # Continue without analysis if it fails - some modules may still work

        except Exception as e:
            logger.error(f"Failed to initialize r2pipe: {e}")
            if self.r2:
                self._cleanup()
            raise

    def _init_analyzers(self):
        """Initialize all analysis modules"""
        logger.debug("Initializing PE analyzer...")
        self.pe_analyzer = PEAnalyzer(self.r2, self.config, self.filename)
        logger.debug("PE analyzer initialized")

        logger.debug("Initializing ELF analyzer...")
        self.elf_analyzer = ELFAnalyzer(self.r2, self.config)
        logger.debug("ELF analyzer initialized")

        logger.debug("Initializing Mach-O analyzer...")
        self.macho_analyzer = MachOAnalyzer(self.r2, self.config)
        logger.debug("Mach-O analyzer initialized")

        logger.debug("Initializing string analyzer...")
        self.string_analyzer = StringAnalyzer(self.r2, self.config)
        logger.debug("String analyzer initialized")

        logger.debug("Initializing crypto analyzer...")
        self.crypto_analyzer = CryptoAnalyzer(self.r2, self.config)
        logger.debug("Crypto analyzer initialized")
        self.packer_detector = PackerDetector(self.r2, self.config)
        self.anti_analysis = AntiAnalysisDetector(self.r2, self.config)
        self.section_analyzer = SectionAnalyzer(self.r2, self.config)
        self.import_analyzer = ImportAnalyzer(self.r2, self.config)
        self.export_analyzer = ExportAnalyzer(self.r2, self.config)
        self.yara_analyzer = YaraAnalyzer(self.r2, self.config)
        self.compiler_detector = CompilerDetector(self.r2, self.config)
        self.function_analyzer = FunctionAnalyzer(self.r2)
        self.ssdeep_analyzer = SSDeepAnalyzer(self.filename)
        self.tlsh_analyzer = TLSHAnalyzer(self.r2, self.config)
        self.telfhash_analyzer = TelfhashAnalyzer(self.r2, self.filename)
        self.rich_header_analyzer = RichHeaderAnalyzer(self.r2, self.filename)
        self.impfuzzy_analyzer = ImpfuzzyAnalyzer(self.r2, self.filename)
        self.ccbhash_analyzer = CCBHashAnalyzer(self.r2, self.filename)
        self.binlex_analyzer = BinlexAnalyzer(self.r2, self.filename)
        self.binbloom_analyzer = BinbloomAnalyzer(self.r2, self.filename)
        self.simhash_analyzer = SimHashAnalyzer(self.r2, self.filename)
        self.bindiff_analyzer = BinDiffAnalyzer(self.r2, self.filename)

    def _cleanup(self):
        """Clean up r2pipe instance"""
        if self.r2 and self._cleanup_required:
            try:
                logger.debug("Cleaning up r2pipe instance")
                self.r2.quit()
                self._cleanup_required = False
            except Exception as e:
                logger.debug(f"Error during r2pipe cleanup: {e}")
            finally:
                self.r2 = None

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup"""
        self._cleanup()
        return False

    def __del__(self):
        """Destructor with cleanup"""
        if hasattr(self, "_cleanup_required") and self._cleanup_required:
            self._cleanup()

    @error_handler(
        category=ErrorCategory.ANALYSIS,
        severity=ErrorSeverity.CRITICAL,
        context={"phase": "main_analysis"},
        fallback_result={"error": "Analysis failed"},
    )
    def analyze(self, **options) -> Dict[str, Any]:
        """Perform complete analysis with memory monitoring"""
        # Check initial memory state
        initial_memory = self.memory_monitor.check_memory(force=True)
        logger.debug(
            f"Starting analysis with {initial_memory['process_memory_mb']:.1f}MB memory usage"
        )

        results = {}

        # Check if we should show progress (disable in batch mode to avoid conflicts)
        show_progress = not options.get("batch_mode", False)

        try:
            if show_progress:
                from rich.console import Console
                from rich.progress import Progress, SpinnerColumn, TextColumn

                console = Console()

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                    transient=True,
                ) as progress:
                    results = self._run_analysis_with_progress(progress, options)
            else:
                # Run analysis without progress display for batch mode
                results = self._run_analysis_without_progress(options)

            # Add memory statistics to results
            final_memory = self.memory_monitor.check_memory(force=True)
            results["memory_stats"] = {
                "initial_memory_mb": initial_memory["process_memory_mb"],
                "final_memory_mb": final_memory["process_memory_mb"],
                "memory_used_mb": final_memory["process_memory_mb"]
                - initial_memory["process_memory_mb"],
                "peak_memory_mb": final_memory.get("peak_memory_mb", 0),
                "gc_count": final_memory.get("gc_count", 0),
            }

            return results

        except MemoryError:
            logger.error("Analysis failed due to memory constraints")
            # Force garbage collection and return minimal results
            self.memory_monitor._trigger_gc(aggressive=True)
            return {
                "error": "Memory limit exceeded",
                "memory_stats": self.memory_monitor.check_memory(force=True),
            }

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return {
                "error": str(e),
                "memory_stats": self.memory_monitor.check_memory(force=True),
            }

    def _run_analysis_with_progress(self, progress, options):
        """Run analysis with progress display"""
        results = {}

        # File information
        task = progress.add_task("Analyzing file information...", total=None)
        results["file_info"] = self.get_file_info()
        progress.remove_task(task)

        # Binary format analysis
        task = progress.add_task("Analyzing binary format...", total=None)
        file_format = self._detect_file_format()

        if file_format == "PE":
            results["pe_info"] = self.get_pe_info()
        elif file_format == "ELF":
            results["elf_info"] = self.get_elf_info()
        elif file_format == "Mach-O":
            results["macho_info"] = self.get_macho_info()

        progress.remove_task(task)

        # Strings analysis
        task = progress.add_task("Extracting strings...", total=None)
        results["strings"] = self.get_strings()
        progress.remove_task(task)

        # Security features
        task = progress.add_task("Checking security features...", total=None)
        results["security"] = self.get_security_features()
        progress.remove_task(task)

        # Imports/Exports
        task = progress.add_task("Analyzing imports/exports...", total=None)
        results["imports"] = self.get_imports()
        results["exports"] = self.get_exports()
        progress.remove_task(task)

        # Sections
        task = progress.add_task("Analyzing sections...", total=None)
        results["sections"] = self.get_sections()
        progress.remove_task(task)

        # Packer detection
        if options.get("detect_packer", True):
            task = progress.add_task("Detecting packers...", total=None)
            results["packer"] = self.detect_packer()
            progress.remove_task(task)

        # Crypto detection
        if options.get("detect_crypto", True):
            task = progress.add_task("Detecting crypto...", total=None)
            results["crypto"] = self.detect_crypto()
            progress.remove_task(task)

        # Anti-analysis techniques
        task = progress.add_task("Checking anti-analysis techniques...", total=None)
        results["anti_analysis"] = self.detect_anti_analysis()
        progress.remove_task(task)

        # Compiler detection
        task = progress.add_task("Detecting compiler...", total=None)
        results["compiler"] = self.detect_compiler()
        progress.remove_task(task)

        # Function analysis and MACHOC hashing
        if options.get("analyze_functions", True):
            task = progress.add_task("Analyzing functions (MACHOC)...", total=None)
            results["functions"] = self.analyze_functions()
            progress.remove_task(task)

        # SSDeep fuzzy hashing
        task = progress.add_task("Calculating SSDeep hash...", total=None)
        results["ssdeep"] = self.analyze_ssdeep()
        progress.remove_task(task)

        # TLSH locality sensitive hashing
        task = progress.add_task("Calculating TLSH hashes...", total=None)
        results["tlsh"] = self.analyze_tlsh()
        progress.remove_task(task)

        # Telfhash for ELF files
        if file_format == "ELF":
            task = progress.add_task("Calculating telfhash (ELF)...", total=None)
            results["telfhash"] = self.analyze_telfhash()
            progress.remove_task(task)

        # Rich Header for PE files
        if file_format == "PE":
            task = progress.add_task("Extracting Rich Header (PE)...", total=None)
            results["rich_header"] = self.analyze_rich_header()
            progress.remove_task(task)

            # Impfuzzy for PE files
            task = progress.add_task("Calculating impfuzzy hash (PE)...", total=None)
            results["impfuzzy"] = self.analyze_impfuzzy()
            progress.remove_task(task)

        # CCBHash analysis
        task = progress.add_task("Calculating CCBHash (Control Flow)...", total=None)
        results["ccbhash"] = self.analyze_ccbhash()
        progress.remove_task(task)

        # Binlex analysis
        task = progress.add_task("Calculating Binlex (N-gram signatures)...", total=None)
        results["binlex"] = self.analyze_binlex()
        progress.remove_task(task)

        # Binbloom analysis
        task = progress.add_task("Calculating Binbloom (Bloom filters)...", total=None)
        results["binbloom"] = self.analyze_binbloom()
        progress.remove_task(task)

        # SimHash analysis
        task = progress.add_task("Calculating SimHash (similarity hashing)...", total=None)
        results["simhash"] = self.analyze_simhash()
        progress.remove_task(task)

        # BinDiff analysis
        task = progress.add_task("Generating binary signatures...", total=None)
        results["bindiff"] = self.analyze_bindiff()
        progress.remove_task(task)

        # YARA rules
        task = progress.add_task("Running YARA rules...", total=None)
        results["yara_matches"] = self.run_yara_rules(options.get("custom_yara"))
        progress.remove_task(task)

        # XOR search if specified
        if options.get("xor_search"):
            task = progress.add_task("Searching XOR strings...", total=None)
            results["xor_search"] = self.search_xor(options["xor_search"])
            progress.remove_task(task)

        # Suspicious indicators
        task = progress.add_task("Generating indicators...", total=None)
        results["indicators"] = self.generate_indicators(results)
        progress.remove_task(task)

        return results

    def _run_analysis_without_progress(self, options):
        """Run analysis without progress display for batch mode"""
        results = {}

        # File information
        results["file_info"] = self.get_file_info()

        # Binary format analysis
        file_format = self._detect_file_format()

        if file_format == "PE":
            results["pe_info"] = self.get_pe_info()
        elif file_format == "ELF":
            results["elf_info"] = self.get_elf_info()
        elif file_format == "Mach-O":
            results["macho_info"] = self.get_macho_info()

        # Strings analysis
        results["strings"] = self.get_strings()

        # Security features
        results["security"] = self.get_security_features()

        # Imports/Exports
        results["imports"] = self.get_imports()
        results["exports"] = self.get_exports()

        # Sections
        results["sections"] = self.get_sections()

        # Packer detection
        if options.get("detect_packer", True):
            results["packer"] = self.detect_packer()

        # Crypto detection
        if options.get("detect_crypto", True):
            results["crypto"] = self.detect_crypto()

        # Anti-analysis techniques
        results["anti_analysis"] = self.detect_anti_analysis()

        # Compiler detection
        results["compiler"] = self.detect_compiler()

        # Function analysis and MACHOC hashing
        if options.get("analyze_functions", True):
            results["functions"] = self.analyze_functions()

        # SSDeep fuzzy hashing
        results["ssdeep"] = self.analyze_ssdeep()

        # TLSH locality sensitive hashing
        results["tlsh"] = self.analyze_tlsh()

        # Telfhash for ELF files
        if file_format == "ELF":
            results["telfhash"] = self.analyze_telfhash()

        # Rich Header for PE files
        if file_format == "PE":
            results["rich_header"] = self.analyze_rich_header()

            # Impfuzzy for PE files
            results["impfuzzy"] = self.analyze_impfuzzy()

        # CCBHash analysis
        results["ccbhash"] = self.analyze_ccbhash()

        # Binlex analysis
        results["binlex"] = self.analyze_binlex()

        # Binbloom analysis
        results["binbloom"] = self.analyze_binbloom()

        # SimHash analysis
        results["simhash"] = self.analyze_simhash()

        # BinDiff analysis
        results["bindiff"] = self.analyze_bindiff()

        # YARA rules
        results["yara_matches"] = self.run_yara_rules(options.get("custom_yara"))

        # XOR search if specified
        if options.get("xor_search"):
            results["xor_search"] = self.search_xor(options["xor_search"])

        # Suspicious indicators
        results["indicators"] = self.generate_indicators(results)

        return results

    @error_handler(
        category=ErrorCategory.FILE_ACCESS,
        severity=ErrorSeverity.HIGH,
        context={"analysis_type": "file_info"},
        fallback_result={},
    )
    def get_file_info(self) -> Dict[str, Any]:
        """Get basic file information"""
        info = {}

        try:
            # File size
            info["size"] = self.file_path.stat().st_size
            info["path"] = str(self.file_path.absolute())
            info["name"] = self.file_path.name

            # Enhanced file type detection
            info["mime_type"] = magic.from_file(self.filename, mime=True)
            info["file_type"] = magic.from_file(self.filename)

            # Add enhanced magic byte detection
            enhanced_detection = detect_file_type(self.filename)
            info["enhanced_detection"] = enhanced_detection

            # Override basic detection with enhanced results if more precise
            if enhanced_detection["confidence"] > 0.7:
                info["precise_format"] = enhanced_detection["file_format"]
                info["format_category"] = enhanced_detection["format_category"]
                info["threat_level"] = "High" if enhanced_detection["potential_threat"] else "Low"
                if enhanced_detection["architecture"] != "Unknown":
                    info["detected_architecture"] = enhanced_detection["architecture"]
                if enhanced_detection["bits"] != "Unknown":
                    info["detected_bits"] = enhanced_detection["bits"]

            # Hashes
            hashes = calculate_hashes(self.filename)
            info.update(hashes)

            # Basic info from radare2
            info_cmd = safe_cmdj(self.r2, "ij", {})
            if info_cmd:
                # Architecture info is in 'bin' section, not 'core'
                bin_info = info_cmd.get("bin", {})
                arch = bin_info.get("arch", "Unknown")
                bits = bin_info.get("bits", "Unknown")

                # Fix architecture naming for consistency
                if arch == "x86" and bits == 64:
                    arch = "x86-64"
                elif arch == "x86" and bits == 32:
                    arch = "x86"

                info["architecture"] = arch
                info["bits"] = bits
                info["endian"] = bin_info.get("endian", "Unknown")

        except Exception as e:
            logger.error(f"Error getting file info: {e}")

        return info

    def _detect_file_format(self) -> str:
        """Detect the binary file format using enhanced detection"""
        try:
            # First try radare2's detection
            format_result = self._detect_format_via_r2()
            if format_result:
                return format_result

            # Use enhanced magic byte detection as primary method
            format_result = self._detect_format_via_enhanced_magic()
            if format_result:
                return format_result

            # Fallback to basic magic detection
            format_result = self._detect_format_via_basic_magic()
            if format_result:
                return format_result

        except Exception as e:
            logger.error(f"Error detecting file format: {e}")

        return "Unknown"

    def _detect_format_via_r2(self) -> Optional[str]:
        """Detect format using radare2"""
        info_cmd = safe_cmdj(self.r2, "ij", {})
        if not info_cmd or "bin" not in info_cmd:
            return None

        bin_format = info_cmd["bin"].get("format", "").upper()
        format_map = {"PE": "PE", "ELF": "ELF", "MACH": "Mach-O"}

        for key, value in format_map.items():
            if key in bin_format:
                return value
        return None

    def _detect_format_via_enhanced_magic(self) -> Optional[str]:
        """Detect format using enhanced magic detection"""
        enhanced_detection = detect_file_type(self.filename)
        if enhanced_detection["confidence"] <= 0.7:
            return None

        format_name = enhanced_detection["file_format"]

        # Map enhanced format names to simplified names
        format_map = {
            "PE": "PE",
            "ELF": "ELF",
            "MACHO": "Mach-O",
            "JAVA_CLASS": "Java",
            "DEX": "Android",
        }

        for prefix, result in format_map.items():
            if format_name.startswith(prefix) or format_name == prefix:
                return result

        # Check archive and document formats
        if format_name in ["ZIP", "RAR", "7ZIP"]:
            return "Archive"
        if format_name in ["PDF", "DOC", "DOCX", "RTF"]:
            return "Document"

        return None

    def _detect_format_via_basic_magic(self) -> Optional[str]:
        """Detect format using basic magic library"""
        file_type = magic.from_file(self.filename).lower()

        if "pe32" in file_type or "ms-dos" in file_type:
            return "PE"
        elif "elf" in file_type:
            return "ELF"
        elif "mach-o" in file_type:
            return "Mach-O"

        return None

    def get_pe_info(self) -> Dict[str, Any]:
        """Get PE-specific information"""
        return self.pe_analyzer.analyze()

    def get_elf_info(self) -> Dict[str, Any]:
        """Get ELF-specific information"""
        return self.elf_analyzer.analyze()

    def get_macho_info(self) -> Dict[str, Any]:
        """Get Mach-O-specific information"""
        return self.macho_analyzer.analyze()

    def get_strings(self) -> List[str]:
        """Extract strings from binary"""
        return self.string_analyzer.extract_strings()

    def get_security_features(self) -> Dict[str, bool]:
        """Check security features"""
        return self.pe_analyzer.get_security_features()

    def get_imports(self) -> List[Dict[str, Any]]:
        """Get imported functions"""
        return self.import_analyzer.get_imports()

    def get_exports(self) -> List[Dict[str, Any]]:
        """Get exported functions"""
        return self.export_analyzer.get_exports()

    def get_sections(self) -> List[Dict[str, Any]]:
        """Get section information"""
        return self.section_analyzer.analyze_sections()

    def detect_packer(self) -> Dict[str, Any]:
        """Detect packers"""
        return self.packer_detector.detect()

    @error_handler(
        category=ErrorCategory.ANALYSIS,
        severity=ErrorSeverity.MEDIUM,
        context={"analysis_type": "crypto_detection"},
        fallback_result={
            "algorithms": [],
            "constants": [],
            "error": "Crypto detection failed",
        },
    )
    def detect_crypto(self) -> Dict[str, Any]:
        """Detect cryptographic patterns"""
        return self.crypto_analyzer.detect()

    def detect_anti_analysis(self) -> Dict[str, Any]:
        """Detect anti-analysis techniques"""
        return self.anti_analysis.detect()

    def detect_compiler(self) -> Dict[str, Any]:
        """Detect compiler information"""
        return self.compiler_detector.detect_compiler()

    def run_yara_rules(self, custom_rules_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Run YARA rules against the file"""
        return self.yara_analyzer.scan(custom_rules_path)

    def search_xor(self, search_string: str) -> List[Dict[str, Any]]:
        """Search for XOR'd strings"""
        return self.string_analyzer.search_xor(search_string)

    def generate_indicators(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate suspicious indicators based on analysis results"""
        indicators = []

        # Check for packed files
        if analysis_results.get("packer", {}).get("is_packed"):
            indicators.append(
                {
                    "type": "Packer",
                    "description": f"File appears to be packed with {analysis_results['packer'].get('packer_type', 'Unknown')}",
                    "severity": "Medium",
                }
            )

        # Check for anti-analysis
        anti_analysis = analysis_results.get("anti_analysis", {})
        if anti_analysis.get("anti_debug"):
            indicators.append(
                {
                    "type": "Anti-Debug",
                    "description": "Anti-debugging techniques detected",
                    "severity": "High",
                }
            )

        if anti_analysis.get("anti_vm"):
            indicators.append(
                {
                    "type": "Anti-VM",
                    "description": "Anti-virtualization techniques detected",
                    "severity": "High",
                }
            )

        # Check for suspicious imports
        imports = analysis_results.get("imports", [])
        suspicious_apis = [
            "VirtualAlloc",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "SetThreadContext",
        ]
        for imp in imports:
            if imp.get("name") in suspicious_apis:
                indicators.append(
                    {
                        "type": "Suspicious API",
                        "description": f"Suspicious API call: {imp.get('name')}",
                        "severity": "Medium",
                    }
                )

        # Check YARA matches
        yara_matches = analysis_results.get("yara_matches", [])
        for match in yara_matches:
            indicators.append(
                {
                    "type": "YARA Match",
                    "description": f"YARA rule matched: {match.get('rule', 'Unknown')}",
                    "severity": "High",
                }
            )

        return indicators

    def analyze_functions(self) -> Dict[str, Any]:
        """Perform function analysis including MACHOC hashing"""
        return self.function_analyzer.analyze_functions()

    def analyze_ssdeep(self) -> Dict[str, Any]:
        """Perform SSDeep fuzzy hashing analysis"""
        return self.ssdeep_analyzer.analyze()

    def analyze_tlsh(self) -> Dict[str, Any]:
        """Perform TLSH locality sensitive hashing analysis"""
        return self.tlsh_analyzer.analyze()

    def analyze_telfhash(self) -> Dict[str, Any]:
        """Perform telfhash analysis for ELF files"""
        return self.telfhash_analyzer.analyze()

    def analyze_rich_header(self) -> Dict[str, Any]:
        """Perform Rich Header analysis for PE files"""
        return self.rich_header_analyzer.analyze()

    def analyze_impfuzzy(self) -> Dict[str, Any]:
        """Perform impfuzzy analysis for PE files"""
        return self.impfuzzy_analyzer.analyze()

    def analyze_ccbhash(self) -> Dict[str, Any]:
        """Perform CCBHash (Control Flow Graph Hash) analysis"""
        return self.ccbhash_analyzer.analyze()

    def analyze_binlex(self) -> Dict[str, Any]:
        """Perform Binlex (N-gram lexical analysis) analysis"""
        return self.binlex_analyzer.analyze()

    def analyze_binbloom(self) -> Dict[str, Any]:
        """Perform Binbloom (Bloom filter) analysis"""
        return self.binbloom_analyzer.analyze()

    def analyze_simhash(self) -> Dict[str, Any]:
        """Perform SimHash (similarity hashing) analysis"""
        return self.simhash_analyzer.analyze()

    def analyze_bindiff(self) -> Dict[str, Any]:
        """Perform BinDiff (comparison features) analysis"""
        return self.bindiff_analyzer.analyze()

    def generate_executive_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary for quick consumption"""
        try:
            summary = {
                "file_overview": {},
                "security_assessment": {},
                "threat_indicators": {},
                "technical_details": {},
                "recommendations": [],
            }

            # File Overview
            file_info = analysis_results.get("file_info", {})
            pe_info = analysis_results.get("pe_info", {})

            summary["file_overview"] = {
                "filename": file_info.get("name", "Unknown"),
                "file_type": file_info.get("file_type", "Unknown"),
                "size": file_info.get("size", 0),
                "architecture": file_info.get("architecture", "Unknown"),
                "md5": file_info.get("md5", "Unknown"),
                "sha256": file_info.get("sha256", "Unknown"),
            }

            # Compilation Info
            if "compilation_timestamp" in pe_info:
                summary["file_overview"]["compiled"] = pe_info["compilation_timestamp"]

            rich_header = analysis_results.get("rich_header", {})
            if rich_header.get("available") and rich_header.get("compilers"):
                compilers = rich_header["compilers"][:3]  # Top 3
                summary["file_overview"]["toolset"] = [
                    f"{c.get('compiler_name', 'Unknown')} (Build {c.get('build_number', 0)})"
                    for c in compilers
                ]

            # Security Assessment
            security = analysis_results.get("security", {})
            packer = analysis_results.get("packer", {})

            summary["security_assessment"] = {
                "is_signed": security.get("authenticode", False),
                "is_packed": packer.get("is_packed", False),
                "packer_type": packer.get("packer_type") if packer.get("is_packed") else None,
                "security_features": {
                    "aslr": security.get("aslr", False),
                    "dep": security.get("dep", False),
                    "seh": security.get("seh", False),
                    "guard_cf": security.get("guard_cf", False),
                },
            }

            # Threat Indicators
            anti_analysis = analysis_results.get("anti_analysis", {})
            crypto = analysis_results.get("crypto", {})
            imports = analysis_results.get("imports", [])

            # Count high-risk imports
            high_risk_imports = [imp for imp in imports if imp.get("risk_score", 0) >= 80]

            summary["threat_indicators"] = {
                "anti_debug": anti_analysis.get("anti_debug", False),
                "anti_vm": anti_analysis.get("anti_vm", False),
                "anti_sandbox": anti_analysis.get("anti_sandbox", False),
                "timing_checks": anti_analysis.get("timing_checks", False),
                "crypto_detected": len(crypto.get("algorithms", [])) > 0,
                "high_risk_apis": len(high_risk_imports),
                "suspicious_sections": self._count_suspicious_sections(
                    analysis_results.get("sections", [])
                ),
            }

            # Technical Details
            functions = analysis_results.get("functions", {})
            sections = analysis_results.get("sections", [])

            summary["technical_details"] = {
                "total_functions": functions.get("total_functions", 0),
                "total_imports": len(imports),
                "total_sections": len(sections),
                "entry_point": pe_info.get("entry_point", 0),
                "image_base": pe_info.get("image_base", 0),
            }

            # Add hash information
            if "impfuzzy" in analysis_results:
                impfuzzy = analysis_results["impfuzzy"]
                if impfuzzy.get("available"):
                    summary["technical_details"]["impfuzzy"] = impfuzzy.get("impfuzzy_hash")

            # Recommendations
            summary["recommendations"] = self._generate_recommendations(analysis_results)

            return summary

        except Exception as e:
            logger.error(f"Error generating executive summary: {e}")
            return {"error": str(e)}

    def _count_suspicious_sections(self, sections: List[Dict[str, Any]]) -> int:
        """Count sections with suspicious indicators"""
        count = 0
        for section in sections:
            if section.get("suspicious_indicators"):
                count += 1
        return count

    def _generate_recommendations(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []

        try:
            # Security features recommendations
            security = analysis_results.get("security", {})
            if not security.get("aslr"):
                recommendations.append("Enable ASLR (Address Space Layout Randomization)")
            if not security.get("dep"):
                recommendations.append("Enable DEP/NX (Data Execution Prevention)")
            if not security.get("guard_cf"):
                recommendations.append("Enable Control Flow Guard (CFG)")

            # Packer detection
            packer = analysis_results.get("packer", {})
            if packer.get("is_packed"):
                recommendations.append(
                    f"Binary is packed with {packer.get('packer_type', 'unknown packer')} - investigate further"
                )

            # Anti-analysis detection
            anti_analysis = analysis_results.get("anti_analysis", {})
            if (
                anti_analysis.get("anti_debug")
                or anti_analysis.get("anti_vm")
                or anti_analysis.get("anti_sandbox")
            ):
                recommendations.append("Anti-analysis techniques detected - handle with caution")

            # High-risk imports
            imports = analysis_results.get("imports", [])
            critical_imports = [imp for imp in imports if imp.get("risk_score", 0) >= 90]
            if critical_imports:
                recommendations.append(
                    f"Found {len(critical_imports)} critical-risk API calls - review functionality"
                )

            # Crypto detection
            crypto = analysis_results.get("crypto", {})
            if crypto.get("algorithms"):
                recommendations.append("Cryptographic functions detected - verify legitimate use")

            # Code signing
            if not analysis_results.get("security", {}).get("authenticode"):
                recommendations.append("Binary is not digitally signed - verify authenticity")

        except Exception as e:
            logger.debug(f"Error generating recommendations: {e}")

        return recommendations

    def close(self):
        """Close r2pipe connection"""
        if self.r2:
            self.r2.quit()
