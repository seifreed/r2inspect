#!/usr/bin/env python3
# mypy: ignore-errors
"""
Compiler Detection Module - Identifies compilers used to build binaries
"""

import re
from typing import Any

from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmdj

logger = get_logger(__name__)

# Constants
SECTION_RDATA = ".rdata"
SECTION_EH_FRAME = ".eh_frame"
SECTION_TEXT = ".text"
SECTION_DATA = ".data"
DLL_ADVAPI32 = "advapi32.dll"
DLL_SHELL32 = "shell32.dll"


class CompilerDetector:
    """Detects compiler information from binaries using r2pipe"""

    def __init__(self, r2, config):
        self.r2 = r2
        self.config = config

        # Compiler signatures and patterns
        self.compiler_signatures = {
            # Microsoft Visual C++
            "MSVC": {
                "strings": [
                    r"Microsoft.*Visual.*C\+\+",
                    r"MSVCR\d+\.dll",
                    r"MSVCP\d+\.dll",
                    r"VCRUNTIME\d+\.dll",
                    r"api-ms-win-crt",
                    r"__security_cookie",
                    r"__security_check_cookie",
                ],
                "imports": [
                    "MSVCR80.dll",
                    "MSVCR90.dll",
                    "MSVCR100.dll",
                    "MSVCR110.dll",
                    "MSVCR120.dll",
                    "MSVCR140.dll",
                    "MSVCP80.dll",
                    "MSVCP90.dll",
                    "MSVCP100.dll",
                    "MSVCP110.dll",
                    "MSVCP120.dll",
                    "MSVCP140.dll",
                    "VCRUNTIME140.dll",
                    "VCRUNTIME140_1.dll",
                ],
                "sections": [SECTION_RDATA, ".idata"],
                "rich_header": True,
            },
            # GNU Compiler Collection (GCC)
            "GCC": {
                "strings": [
                    r"GCC:.*\d+\.\d+",
                    r"GNU.*\d+\.\d+",
                    r"__gxx_personality_v0",
                    r"__cxa_finalize",
                    r"__stack_chk_fail",
                    r"_GLOBAL_OFFSET_TABLE_",
                ],
                "imports": ["libgcc_s.so", "libstdc++.so", "libc.so.6", "libm.so.6"],
                "sections": [SECTION_EH_FRAME, ".eh_frame_hdr", ".gcc_except_table"],
                "symbols": ["__gmon_start__", "__libc_start_main"],
            },
            # LLVM Clang
            "Clang": {
                "strings": [
                    r"clang.*\d+\.\d+",
                    r"LLVM.*\d+\.\d+",
                    r"__clang_version__",
                    r"Apple.*clang",
                ],
                "imports": ["libc++.so", "libc++abi.so"],
                "sections": [SECTION_EH_FRAME, ".debug_info"],
                "symbols": ["__cxa_atexit"],
            },
            # Intel C++ Compiler
            "ICC": {
                "strings": [
                    r"Intel.*C\+\+.*Compiler",
                    r"libiomp5\.dll",
                    r"libmmd\.dll",
                ],
                "imports": ["libiomp5.dll", "libmmd.dll"],
                "sections": [],
                "symbols": [],
            },
            # Borland/Embarcadero
            "Borland": {
                "strings": [
                    r"Borland.*C\+\+",
                    r"Embarcadero",
                    r"CodeGear",
                    r"__fastcall",
                ],
                "imports": ["CC3250MT.DLL", "RTL250.BPL"],
                "sections": [".tls"],
                "symbols": [],
            },
            # MinGW
            "MinGW": {
                "strings": [
                    r"mingw",
                    r"MinGW.*\d+\.\d+",
                    r"__mingw_",
                ],
                "imports": [
                    "mingwm10.dll",
                    "libgcc_s_dw2-1.dll",
                    "libgcc_s_sjlj-1.dll",
                ],
                "sections": [],
                "symbols": ["_mingw_"],
            },
            # Delphi/Pascal
            "Delphi": {
                "strings": [
                    r"Delphi.*\d+",
                    r"Object.*Pascal",
                    r"TObject",
                    r"System\.pas",
                ],
                "imports": [],
                "sections": [".itext", ".didata", ".didata2"],
                "symbols": [],
            },
            # .NET Compilers
            "DotNet": {
                "strings": [
                    r"\.NET.*Framework",
                    r"mscorlib",
                    r"System\.",
                    r"Microsoft.*\.NET",
                ],
                "imports": ["mscoree.dll", "mscorwks.dll"],
                "sections": [SECTION_TEXT, ".rsrc", ".reloc"],
                "symbols": ["_CorExeMain", "_CorDllMain"],
            },
            # Go
            "Go": {
                "strings": [
                    r"Go.*build.*ID",
                    r"runtime\..*go\d+",
                    r"main\.main",
                    r"runtime\.main",
                ],
                "imports": [],
                "sections": [".noptrdata", SECTION_DATA, ".bss", ".noptrbss"],
                "symbols": ["main.main", "runtime.main"],
            },
            # Rust
            "Rust": {
                "strings": [
                    r"rustc.*\d+\.\d+",
                    r"rust_begin_unwind",
                    r"rust_panic",
                    r"std::panic",
                ],
                "imports": [],
                "sections": [SECTION_EH_FRAME],
                "symbols": ["rust_begin_unwind", "rust_panic"],
            },
            # AutoIt - Very common in malware (2025)
            "AutoIt": {
                "strings": [
                    r"AutoIt.*v\d+",
                    r"#OnAutoItStartRegister",
                    r"AU3!EA06",
                    r"AUTOIT SCRIPT",
                    r"Aut2Exe",
                    r"AutoIt3\.exe",
                    r"#pragma compile",
                    r"AutoItSetOption",
                ],
                "imports": [DLL_SHELL32, DLL_ADVAPI32, "ole32.dll"],
                "sections": [".autoit", ".au3", SECTION_RDATA],
                "symbols": ["_Au3CheckVersion", "AutoItSetOption"],
            },
            # NSIS - Nullsoft Install System (common in droppers)
            "NSIS": {
                "strings": [
                    r"Nullsoft.*Install.*System",
                    r"NSIS.*\d+\.\d+",
                    r"\$PLUGINSDIR",
                    r"!system",
                    r"makensis",
                    r"\.nsi",
                    r"nsis_error",
                    r"NSIS_MAX_STRLEN",
                ],
                "imports": [DLL_SHELL32, "user32.dll", DLL_ADVAPI32],
                "sections": [".ndata", ".nsis"],
                "symbols": [],
            },
            # Inno Setup - Another popular installer
            "InnoSetup": {
                "strings": [
                    r"Inno.*Setup",
                    r"Jordan Russell",
                    r"{app}\\\\",
                    r"unins\d+\.exe",
                    r"setup\.exe",
                    r"Inno Setup.*\d+\.\d+",
                    r"This.*installation.*was.*corrupted",
                ],
                "imports": [DLL_SHELL32, DLL_ADVAPI32],
                "sections": [SECTION_TEXT, SECTION_RDATA, SECTION_DATA],
                "symbols": [],
            },
            # PyInstaller - Python compiled executables
            "PyInstaller": {
                "strings": [
                    r"PyInstaller",
                    r"pyi-.*-manifest",
                    r"_MEI\d+",
                    r"python\d+\.dll",
                    r"_MEIPASS",
                    r"bootloader",
                    r"pyimod\d+",
                    r"PyRun_SimpleString",
                ],
                "imports": [
                    "python39.dll",
                    "python310.dll",
                    "python311.dll",
                    "python312.dll",
                    "python313.dll",
                    "vcruntime140.dll",
                ],
                "sections": [SECTION_TEXT, SECTION_RDATA, SECTION_DATA],
                "symbols": ["PyRun_SimpleString", "Py_Initialize"],
            },
            # cx_Freeze - Alternative Python compiler
            "cx_Freeze": {
                "strings": [
                    r"cx_Freeze",
                    r"cx_freeze.*\d+\.\d+",
                    r"Console\.py",
                    r"__startup__",
                ],
                "imports": [
                    "python39.dll",
                    "python310.dll",
                    "python311.dll",
                    "python312.dll",
                ],
                "sections": [SECTION_TEXT, SECTION_RDATA],
                "symbols": [],
            },
            # Nim - Modern systems programming language (popular in malware)
            "Nim": {
                "strings": [
                    r"nim.*\d+\.\d+",
                    r"nimgc",
                    r"NimMain",
                    r"nim\.system",
                    r"@m.*\.nim",
                    r"nim_program_result",
                    r"PreMain",
                ],
                "imports": [],
                "sections": [SECTION_TEXT, SECTION_RDATA, SECTION_DATA],
                "symbols": ["NimMain", "nimGC_setStackBottom", "PreMain"],
            },
            # Zig - Modern systems programming language
            "Zig": {
                "strings": [
                    r"zig.*\d+\.\d+",
                    r"zig\.builtin",
                    r"__zig_",
                    r"panic.*zig",
                    r"builtin\.zig",
                ],
                "imports": [],
                "sections": [SECTION_TEXT, SECTION_RDATA],
                "symbols": ["__zig_return_error", "__zig_probe_stack"],
            },
            # Node.js compiled (pkg, nexe, sea)
            "NodeJS": {
                "strings": [
                    r"pkg/prelude",
                    r"nexe/\d+\.\d+",
                    r"NODE_SEA_BLOB",
                    r"v8::internal",
                    r"node\.exe",
                    r"process\.pkg",
                    r"require.*main",
                ],
                "imports": ["node.exe", "v8.dll"],
                "sections": [SECTION_TEXT, SECTION_RDATA],
                "symbols": ["node_main", "v8_init"],
            },
            # Swift (now cross-platform)
            "Swift": {
                "strings": [
                    r"Swift.*\d+\.\d+",
                    r"swiftrt",
                    r"_swift_",
                    r"swift.*runtime",
                    r"Foundation.*Swift",
                ],
                "imports": ["swiftCore.dll"],
                "sections": [SECTION_TEXT, SECTION_RDATA],
                "symbols": ["swift_retain", "swift_release", "_swift_FORCE_LOAD"],
            },
            # TinyCC - Tiny C Compiler (used in exploits)
            "TinyCC": {
                "strings": [
                    r"tcc.*\d+\.\d+",
                    r"Tiny.*C.*Compiler",
                    r"TinyCC",
                    r"Fabrice Bellard",
                ],
                "imports": [],
                "sections": [SECTION_TEXT],
                "symbols": [],
            },
            # FASM - Flat Assembler
            "FASM": {
                "strings": [
                    r"flat.*assembler",
                    r"FASM.*\d+\.\d+",
                    r"Tomasz Grysztar",
                    r"fasm\.exe",
                ],
                "imports": [],
                "sections": [SECTION_TEXT, SECTION_DATA],
                "symbols": [],
            },
        }

        # MSVC version mapping based on runtime libraries
        self.msvc_versions = {
            "MSVCR80.dll": "Visual Studio 2005 (8.0)",
            "MSVCR90.dll": "Visual Studio 2008 (9.0)",
            "MSVCR100.dll": "Visual Studio 2010 (10.0)",
            "MSVCR110.dll": "Visual Studio 2012 (11.0)",
            "MSVCR120.dll": "Visual Studio 2013 (12.0)",
            "MSVCR140.dll": "Visual Studio 2015/2017/2019/2022 (14.x)",
            "VCRUNTIME140.dll": "Visual Studio 2015/2017/2019/2022 (14.x)",
            "VCRUNTIME140_1.dll": "Visual Studio 2019/2022 (14.2+)",
        }

    def detect_compiler(self) -> dict[str, Any]:
        """Main function to detect compiler information"""

        logger.debug("Starting compiler detection...")

        results = {
            "detected": False,
            "compiler": "Unknown",
            "version": "Unknown",
            "confidence": 0.0,
            "details": {},
            "signatures_found": [],
            "rich_header_info": {},
        }

        try:
            # Get file format first
            file_format = self._get_file_format()

            # Gather information from binary
            strings_data = self._get_strings()
            imports_data = self._get_imports()
            sections_data = self._get_sections()
            symbols_data = self._get_symbols()

            # PE-specific analysis
            if file_format == "PE":
                if self._apply_rich_header_detection(results):
                    return results

            # Score each compiler
            compiler_scores = self._score_compilers(
                strings_data, imports_data, sections_data, symbols_data
            )
            self._apply_best_compiler(
                results, compiler_scores, strings_data, imports_data, file_format
            )

            logger.debug(
                f"Compiler detection completed: {results['compiler']} (confidence: {results['confidence']:.2f})"
            )

        except Exception as e:
            logger.error(f"Error during compiler detection: {e}")
            results["error"] = str(e)

        return results

    def _apply_rich_header_detection(self, results: dict[str, Any]) -> bool:
        rich_header = self._analyze_rich_header()
        results["rich_header_info"] = rich_header
        if not (rich_header.get("available") and rich_header.get("compilers")):
            return False

        for compiler_entry in rich_header["compilers"]:
            compiler_name = compiler_entry.get("compiler_name", "")
            if "MSVC" in compiler_name or "Utc" in compiler_name:
                results["detected"] = True
                results["compiler"] = "MSVC"
                results["confidence"] = 0.95
                results["version"] = self._map_msvc_version_from_rich(compiler_name)
                results["details"] = {"detection_method": "Rich Header Analysis"}
                logger.debug(
                    f"Detected {results['compiler']} {results['version']} from Rich Header"
                )
                return True
        return False

    def _map_msvc_version_from_rich(self, compiler_name: str) -> str:
        if "2019" in compiler_name:
            return "Visual Studio 2019"
        if "2022" in compiler_name:
            return "Visual Studio 2022"
        if "1900" in compiler_name:
            return "Visual Studio 2015"
        if "1910" in compiler_name:
            return "Visual Studio 2017"
        return "Visual Studio (version from Rich Header)"

    def _score_compilers(
        self,
        strings_data: list[str],
        imports_data: list[str],
        sections_data: list[str],
        symbols_data: list[str],
    ) -> dict[str, float]:
        compiler_scores: dict[str, float] = {}
        for compiler_name, signatures in self.compiler_signatures.items():
            score = self._calculate_compiler_score(
                compiler_name,
                signatures,
                strings_data,
                imports_data,
                sections_data,
                symbols_data,
            )
            compiler_scores[compiler_name] = score
        return compiler_scores

    def _apply_best_compiler(
        self,
        results: dict[str, Any],
        compiler_scores: dict[str, float],
        strings_data: list[str],
        imports_data: list[str],
        file_format: str,
    ) -> None:
        if not compiler_scores:
            return
        best_compiler = max(compiler_scores, key=compiler_scores.get)
        best_score = compiler_scores[best_compiler]

        if best_score <= 0.3:
            return
        results["detected"] = True
        results["compiler"] = best_compiler
        results["confidence"] = best_score
        results["version"] = self._detect_compiler_version(
            best_compiler, strings_data, imports_data
        )
        results["details"] = {
            "all_scores": compiler_scores,
            "file_format": file_format,
            "detection_method": self._get_detection_method(best_compiler, best_score),
        }

    def _get_file_format(self) -> str:
        """Detect file format (PE, ELF, Mach-O)"""
        try:
            file_info = safe_cmdj(self.r2, "ij", {})  # Get file info in JSON
            if file_info and "bin" in file_info:
                format_info = file_info["bin"].get("class", "").upper()
                if "PE" in format_info:
                    return "PE"
                elif "ELF" in format_info:
                    return "ELF"
                elif "MACH" in format_info:
                    return "Mach-O"
            return "Unknown"
        except Exception as e:
            logger.debug(f"Error detecting file format: {e}")
            return "Unknown"

    def _get_strings(self) -> list[str]:
        """Extract strings from binary"""
        try:
            strings_output = self.r2.cmd("izz~..")  # Get all strings
            strings = []

            for line in strings_output.split("\n"):
                if line.strip():
                    # Extract string content (after the address and size info)
                    parts = line.split(" ", 4)
                    if len(parts) >= 5:
                        string_content = parts[4].strip()
                        strings.append(string_content)

            return strings
        except Exception as e:
            logger.error(f"Error extracting strings: {e}")
            return []

    def _get_imports(self) -> list[str]:
        """Get imported functions and libraries"""
        try:
            imports = []
            imports_data = safe_cmdj(self.r2, "iij", [])  # Get imports in JSON

            if isinstance(imports_data, list):
                for imp in imports_data:
                    if isinstance(imp, dict):
                        # Add library name
                        if "libname" in imp:
                            imports.append(imp["libname"])
                        # Add function name
                        if "name" in imp:
                            imports.append(imp["name"])

            return imports
        except Exception as e:
            logger.error(f"Error getting imports: {e}")
            return []

    def _get_sections(self) -> list[str]:
        """Get section names"""
        try:
            sections = []
            sections_data = safe_cmdj(self.r2, "iSj", [])  # Get sections in JSON

            if isinstance(sections_data, list):
                for section in sections_data:
                    if isinstance(section, dict) and "name" in section:
                        sections.append(section["name"])

            return sections
        except Exception as e:
            logger.error(f"Error getting sections: {e}")
            return []

    def _get_symbols(self) -> list[str]:
        """Get symbol names"""
        try:
            symbols = []
            symbols_data = safe_cmdj(self.r2, "isj", [])  # Get symbols in JSON

            if isinstance(symbols_data, list):
                for symbol in symbols_data:
                    if isinstance(symbol, dict) and "name" in symbol:
                        symbols.append(symbol["name"])

            return symbols
        except Exception as e:
            logger.error(f"Error getting symbols: {e}")
            return []

    def _analyze_rich_header(self) -> dict[str, Any]:
        """Analyze Rich Header for PE files (MSVC specific)"""
        try:
            # Use the RichHeaderAnalyzer module for proper analysis
            from .rich_header_analyzer import RichHeaderAnalyzer

            # Get the file path from r2
            file_info = self.r2.cmdj("ij")
            if not file_info or "core" not in file_info:
                return {}

            filepath = file_info["core"].get("file", "")
            if not filepath:
                return {}

            # Analyze Rich Header
            rich_analyzer = RichHeaderAnalyzer(self.r2, filepath)
            rich_info = rich_analyzer.analyze()

            return rich_info
        except Exception as e:
            logger.error(f"Error analyzing Rich header: {e}")
            return {}

    def _calculate_compiler_score(
        self,
        _compiler_name: str,
        signatures: dict,
        strings_data: list[str],
        imports_data: list[str],
        sections_data: list[str],
        symbols_data: list[str],
    ) -> float:
        """Calculate confidence score for a specific compiler"""

        score = 0.0
        max_score = 0.0

        # Check each signature type
        string_score, string_max = self._check_string_signatures(signatures, strings_data)
        import_score, import_max = self._check_import_signatures(signatures, imports_data)
        section_score, section_max = self._check_section_signatures(signatures, sections_data)
        symbol_score, symbol_max = self._check_symbol_signatures(signatures, symbols_data)

        score = string_score + import_score + section_score + symbol_score
        max_score = string_max + import_max + section_max + symbol_max

        # Normalize score
        if max_score > 0:
            return min(score / max_score, 1.0)

        return 0.0

    def _check_string_signatures(self, signatures: dict, strings_data: list[str]) -> tuple:
        """Check string pattern signatures"""
        if "strings" not in signatures:
            return 0.0, 0.0

        score = 0.0
        max_score = 3.0

        for pattern in signatures["strings"]:
            for string in strings_data:
                if re.search(pattern, string, re.IGNORECASE):
                    score += 3.0 / len(signatures["strings"])
                    break

        return score, max_score

    def _check_import_signatures(self, signatures: dict, imports_data: list[str]) -> tuple:
        """Check import signatures"""
        if "imports" not in signatures:
            return 0.0, 0.0

        score = 0.0
        max_score = 2.0

        for import_name in signatures["imports"]:
            if any(import_name.lower() in imp.lower() for imp in imports_data):
                score += 2.0 / len(signatures["imports"])

        return score, max_score

    def _check_section_signatures(self, signatures: dict, sections_data: list[str]) -> tuple:
        """Check section signatures"""
        if "sections" not in signatures:
            return 0.0, 0.0

        score = 0.0
        max_score = 1.0

        for section_name in signatures["sections"]:
            if any(section_name.lower() in sec.lower() for sec in sections_data):
                score += 1.0 / len(signatures["sections"])

        return score, max_score

    def _check_symbol_signatures(self, signatures: dict, symbols_data: list[str]) -> tuple:
        """Check symbol signatures"""
        if "symbols" not in signatures:
            return 0.0, 0.0

        score = 0.0
        max_score = 1.0

        for symbol_name in signatures["symbols"]:
            if any(symbol_name.lower() in sym.lower() for sym in symbols_data):
                score += 1.0 / len(signatures["symbols"])

        return score, max_score

    def _detect_compiler_version(
        self, compiler: str, strings_data: list[str], imports_data: list[str]
    ) -> str:
        """Detect specific compiler version"""

        version_detectors = {
            "MSVC": self._detect_msvc_version,
            "GCC": self._detect_gcc_version,
            "Clang": self._detect_clang_version,
            "Intel": self._detect_intel_version,
            "Borland": self._detect_borland_version,
            "MinGW": self._detect_mingw_version,
            "Go": self._detect_go_version,
            "Rust": self._detect_rust_version,
            "Delphi": self._detect_delphi_version,
        }

        detector = version_detectors.get(compiler)
        if detector:
            return detector(strings_data, imports_data)

        return "Unknown"

    def _detect_msvc_version(self, strings_data: list[str], imports_data: list[str]) -> str:
        """Detect MSVC version"""
        # Check runtime libraries for MSVC version
        for import_name in imports_data:
            if import_name in self.msvc_versions:
                return self.msvc_versions[import_name]

        # Check version strings
        for string in strings_data:
            match = re.search(r"Microsoft.*Visual.*C\+\+.*(\d+\.\d+)", string, re.IGNORECASE)
            if match:
                return f"Visual Studio {match.group(1)}"

        return "Unknown"

    def _detect_gcc_version(self, strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect GCC version"""
        for string in strings_data:
            match = re.search(r"GCC.*(\d+\.\d+\.\d+)", string, re.IGNORECASE)
            if match:
                return f"GCC {match.group(1)}"
            match = re.search(r"GNU.*(\d+\.\d+)", string, re.IGNORECASE)
            if match:
                return f"GCC {match.group(1)}"
        return "Unknown"

    def _detect_clang_version(self, strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Clang version"""
        for string in strings_data:
            match = re.search(r"clang.*(\d+\.\d+\.\d+)", string, re.IGNORECASE)
            if match:
                return f"Clang {match.group(1)}"
            match = re.search(r"Apple.*clang.*(\d+\.\d+)", string, re.IGNORECASE)
            if match:
                return f"Apple Clang {match.group(1)}"
        return "Unknown"

    def _detect_intel_version(self, _strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Intel version"""
        return "Unknown"

    def _detect_borland_version(self, _strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Borland version"""
        return "Unknown"

    def _detect_mingw_version(self, _strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect MinGW version"""
        return "Unknown"

    def _detect_go_version(self, strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Go version"""
        for string in strings_data:
            match = re.search(r"go(\d+\.\d+\.\d+)", string, re.IGNORECASE)
            if match:
                return f"Go {match.group(1)}"
        return "Unknown"

    def _detect_rust_version(self, strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Rust version"""
        for string in strings_data:
            match = re.search(r"rustc.*(\d+\.\d+\.\d+)", string, re.IGNORECASE)
            if match:
                return f"Rust {match.group(1)}"
        return "Unknown"

    def _detect_delphi_version(self, _strings_data: list[str], _imports_data: list[str]) -> str:
        """Detect Delphi version"""
        return "Unknown"

    def _get_detection_method(self, compiler: str, score: float) -> str:
        """Get description of how compiler was detected"""

        methods = []

        if score > 0.8:
            methods.append("High confidence - Multiple signatures matched")
        elif score > 0.6:
            methods.append("Medium confidence - Some signatures matched")
        else:
            methods.append("Low confidence - Few signatures matched")

        if compiler == "MSVC":
            methods.append("Runtime library analysis")
        elif compiler in ["GCC", "Clang"]:
            methods.append("Symbol and section analysis")
        elif compiler == "DotNet":
            methods.append("CLR metadata analysis")
        elif compiler == "AutoIt":
            methods.append("AU3 signature and string analysis")
        elif compiler in ["NSIS", "InnoSetup"]:
            methods.append("Installer signature analysis")
        elif compiler in ["PyInstaller", "cx_Freeze"]:
            methods.append("Python runtime detection")
        elif compiler == "Nim":
            methods.append("Nim runtime and symbol analysis")
        elif compiler in ["Zig", "Swift", "TinyCC"]:
            methods.append("Modern compiler signature analysis")
        elif compiler == "NodeJS":
            methods.append("Node.js runtime detection")
        elif compiler == "FASM":
            methods.append("Assembly tool signature")

        return " | ".join(methods)
