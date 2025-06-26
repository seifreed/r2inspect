#!/usr/bin/env python3
"""
Compiler Detection Module - Identifies compilers used to build binaries
"""

import re
import json
from typing import Dict, List, Any, Optional, Tuple
from ..utils.logger import get_logger

logger = get_logger(__name__)

class CompilerDetector:
    """Detects compiler information from binaries using r2pipe"""
    
    def __init__(self, r2, config):
        self.r2 = r2
        self.config = config
        
        # Compiler signatures and patterns
        self.compiler_signatures = {
            # Microsoft Visual C++
            'MSVC': {
                'strings': [
                    r'Microsoft.*Visual.*C\+\+',
                    r'MSVCR\d+\.dll',
                    r'MSVCP\d+\.dll',
                    r'VCRUNTIME\d+\.dll',
                    r'api-ms-win-crt',
                    r'__security_cookie',
                    r'__security_check_cookie',
                ],
                'imports': [
                    'MSVCR80.dll', 'MSVCR90.dll', 'MSVCR100.dll', 'MSVCR110.dll', 
                    'MSVCR120.dll', 'MSVCR140.dll', 'MSVCP80.dll', 'MSVCP90.dll',
                    'MSVCP100.dll', 'MSVCP110.dll', 'MSVCP120.dll', 'MSVCP140.dll',
                    'VCRUNTIME140.dll', 'VCRUNTIME140_1.dll'
                ],
                'sections': ['.rdata', '.idata'],
                'rich_header': True
            },
            
            # GNU Compiler Collection (GCC)
            'GCC': {
                'strings': [
                    r'GCC:.*\d+\.\d+',
                    r'GNU.*\d+\.\d+',
                    r'__gxx_personality_v0',
                    r'__cxa_finalize',
                    r'__stack_chk_fail',
                    r'_GLOBAL_OFFSET_TABLE_',
                ],
                'imports': [
                    'libgcc_s.so', 'libstdc++.so', 'libc.so.6', 'libm.so.6'
                ],
                'sections': ['.eh_frame', '.eh_frame_hdr', '.gcc_except_table'],
                'symbols': ['__gmon_start__', '__libc_start_main']
            },
            
            # LLVM Clang
            'Clang': {
                'strings': [
                    r'clang.*\d+\.\d+',
                    r'LLVM.*\d+\.\d+',
                    r'__clang_version__',
                    r'Apple.*clang',
                ],
                'imports': ['libc++.so', 'libc++abi.so'],
                'sections': ['.eh_frame', '.debug_info'],
                'symbols': ['__cxa_atexit']
            },
            
            # Intel C++ Compiler
            'ICC': {
                'strings': [
                    r'Intel.*C\+\+.*Compiler',
                    r'libiomp5\.dll',
                    r'libmmd\.dll',
                ],
                'imports': ['libiomp5.dll', 'libmmd.dll'],
                'sections': [],
                'symbols': []
            },
            
            # Borland/Embarcadero
            'Borland': {
                'strings': [
                    r'Borland.*C\+\+',
                    r'Embarcadero',
                    r'CodeGear',
                    r'__fastcall',
                ],
                'imports': ['CC3250MT.DLL', 'RTL250.BPL'],
                'sections': ['.tls'],
                'symbols': []
            },
            
            # MinGW
            'MinGW': {
                'strings': [
                    r'mingw',
                    r'MinGW.*\d+\.\d+',
                    r'__mingw_',
                ],
                'imports': ['mingwm10.dll', 'libgcc_s_dw2-1.dll', 'libgcc_s_sjlj-1.dll'],
                'sections': [],
                'symbols': ['_mingw_']
            },
            
            # Delphi/Pascal
            'Delphi': {
                'strings': [
                    r'Delphi.*\d+',
                    r'Object.*Pascal',
                    r'TObject',
                    r'System\.pas',
                ],
                'imports': [],
                'sections': ['.itext', '.didata', '.didata2'],
                'symbols': []
            },
            
            # .NET Compilers
            'DotNet': {
                'strings': [
                    r'\.NET.*Framework',
                    r'mscorlib',
                    r'System\.',
                    r'Microsoft.*\.NET',
                ],
                'imports': ['mscoree.dll', 'mscorwks.dll'],
                'sections': ['.text', '.rsrc', '.reloc'],
                'symbols': ['_CorExeMain', '_CorDllMain']
            },
            
            # Go
            'Go': {
                'strings': [
                    r'Go.*build.*ID',
                    r'runtime\..*go\d+',
                    r'main\.main',
                    r'runtime\.main',
                ],
                'imports': [],
                'sections': ['.noptrdata', '.data', '.bss', '.noptrbss'],
                'symbols': ['main.main', 'runtime.main']
            },
            
            # Rust
            'Rust': {
                'strings': [
                    r'rustc.*\d+\.\d+',
                    r'rust_begin_unwind',
                    r'rust_panic',
                    r'std::panic',
                ],
                'imports': [],
                'sections': ['.eh_frame'],
                'symbols': ['rust_begin_unwind', 'rust_panic']
            },
            
            # AutoIt - Very common in malware (2025)
            'AutoIt': {
                'strings': [
                    r'AutoIt.*v\d+',
                    r'#OnAutoItStartRegister',
                    r'AU3!EA06',
                    r'AUTOIT SCRIPT',
                    r'Aut2Exe',
                    r'AutoIt3\.exe',
                    r'#pragma compile',
                    r'AutoItSetOption',
                ],
                'imports': ['shell32.dll', 'advapi32.dll', 'ole32.dll'],
                'sections': ['.autoit', '.au3', '.rdata'],
                'symbols': ['_Au3CheckVersion', 'AutoItSetOption']
            },
            
            # NSIS - Nullsoft Install System (common in droppers)
            'NSIS': {
                'strings': [
                    r'Nullsoft.*Install.*System',
                    r'NSIS.*\d+\.\d+',
                    r'\$PLUGINSDIR',
                    r'!system',
                    r'makensis',
                    r'\.nsi',
                    r'nsis_error',
                    r'NSIS_MAX_STRLEN',
                ],
                'imports': ['shell32.dll', 'user32.dll', 'advapi32.dll'],
                'sections': ['.ndata', '.nsis'],
                'symbols': []
            },
            
            # Inno Setup - Another popular installer
            'InnoSetup': {
                'strings': [
                    r'Inno.*Setup',
                    r'Jordan Russell',
                    r'{app}\\\\',
                    r'unins\d+\.exe',
                    r'setup\.exe',
                    r'Inno Setup.*\d+\.\d+',
                    r'This.*installation.*was.*corrupted',
                ],
                'imports': ['shell32.dll', 'advapi32.dll'],
                'sections': ['.text', '.rdata', '.data'],
                'symbols': []
            },
            
            # PyInstaller - Python compiled executables
            'PyInstaller': {
                'strings': [
                    r'PyInstaller',
                    r'pyi-.*-manifest',
                    r'_MEI\d+',
                    r'python\d+\.dll',
                    r'_MEIPASS',
                    r'bootloader',
                    r'pyimod\d+',
                    r'PyRun_SimpleString',
                ],
                'imports': [
                    'python39.dll', 'python310.dll', 'python311.dll', 
                    'python312.dll', 'python313.dll', 'vcruntime140.dll'
                ],
                'sections': ['.text', '.rdata', '.data'],
                'symbols': ['PyRun_SimpleString', 'Py_Initialize']
            },
            
            # cx_Freeze - Alternative Python compiler
            'cx_Freeze': {
                'strings': [
                    r'cx_Freeze',
                    r'cx_freeze.*\d+\.\d+',
                    r'Console\.py',
                    r'__startup__',
                ],
                'imports': ['python39.dll', 'python310.dll', 'python311.dll', 'python312.dll'],
                'sections': ['.text', '.rdata'],
                'symbols': []
            },
            
            # Nim - Modern systems programming language (popular in malware)
            'Nim': {
                'strings': [
                    r'nim.*\d+\.\d+',
                    r'nimgc',
                    r'NimMain',
                    r'nim\.system',
                    r'@m.*\.nim',
                    r'nim_program_result',
                    r'PreMain',
                ],
                'imports': [],
                'sections': ['.text', '.rdata', '.data'],
                'symbols': ['NimMain', 'nimGC_setStackBottom', 'PreMain']
            },
            
            # Zig - Modern systems programming language  
            'Zig': {
                'strings': [
                    r'zig.*\d+\.\d+',
                    r'zig\.builtin',
                    r'__zig_',
                    r'panic.*zig',
                    r'builtin\.zig',
                ],
                'imports': [],
                'sections': ['.text', '.rdata'],
                'symbols': ['__zig_return_error', '__zig_probe_stack']
            },
            
            # Node.js compiled (pkg, nexe, sea)
            'NodeJS': {
                'strings': [
                    r'pkg/prelude',
                    r'nexe/\d+\.\d+',
                    r'NODE_SEA_BLOB',
                    r'v8::internal',
                    r'node\.exe',
                    r'process\.pkg',
                    r'require.*main',
                ],
                'imports': ['node.exe', 'v8.dll'],
                'sections': ['.text', '.rdata'],
                'symbols': ['node_main', 'v8_init']
            },
            
            # Swift (now cross-platform)
            'Swift': {
                'strings': [
                    r'Swift.*\d+\.\d+',
                    r'swiftrt',
                    r'_swift_',
                    r'swift.*runtime',
                    r'Foundation.*Swift',
                ],
                'imports': ['swiftCore.dll'],
                'sections': ['.text', '.rdata'],
                'symbols': ['swift_retain', 'swift_release', '_swift_FORCE_LOAD']
            },
            
            # TinyCC - Tiny C Compiler (used in exploits)
            'TinyCC': {
                'strings': [
                    r'tcc.*\d+\.\d+',
                    r'Tiny.*C.*Compiler',
                    r'TinyCC',
                    r'Fabrice Bellard',
                ],
                'imports': [],
                'sections': ['.text'],
                'symbols': []
            },
            
            # FASM - Flat Assembler
            'FASM': {
                'strings': [
                    r'flat.*assembler',
                    r'FASM.*\d+\.\d+',
                    r'Tomasz Grysztar',
                    r'fasm\.exe',
                ],
                'imports': [],
                'sections': ['.text', '.data'],
                'symbols': []
            }
        }
        
        # MSVC version mapping based on runtime libraries
        self.msvc_versions = {
            'MSVCR80.dll': 'Visual Studio 2005 (8.0)',
            'MSVCR90.dll': 'Visual Studio 2008 (9.0)', 
            'MSVCR100.dll': 'Visual Studio 2010 (10.0)',
            'MSVCR110.dll': 'Visual Studio 2012 (11.0)',
            'MSVCR120.dll': 'Visual Studio 2013 (12.0)',
            'MSVCR140.dll': 'Visual Studio 2015/2017/2019/2022 (14.x)',
            'VCRUNTIME140.dll': 'Visual Studio 2015/2017/2019/2022 (14.x)',
            'VCRUNTIME140_1.dll': 'Visual Studio 2019/2022 (14.2+)'
        }
    
    def detect_compiler(self) -> Dict[str, Any]:
        """Main function to detect compiler information"""
        
        logger.debug("Starting compiler detection...")
        
        results = {
            'detected': False,
            'compiler': 'Unknown',
            'version': 'Unknown',
            'confidence': 0.0,
            'details': {},
            'signatures_found': [],
            'rich_header_info': {}
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
            if file_format == 'PE':
                rich_header = self._analyze_rich_header()
                results['rich_header_info'] = rich_header
            
            # Score each compiler
            compiler_scores = {}
            
            for compiler_name, signatures in self.compiler_signatures.items():
                score = self._calculate_compiler_score(
                    compiler_name, signatures, strings_data, 
                    imports_data, sections_data, symbols_data
                )
                compiler_scores[compiler_name] = score
            
            # Find best match
            if compiler_scores:
                best_compiler = max(compiler_scores, key=compiler_scores.get)
                best_score = compiler_scores[best_compiler]
                
                if best_score > 0.3:  # Minimum confidence threshold
                    results['detected'] = True
                    results['compiler'] = best_compiler
                    results['confidence'] = best_score
                    
                    # Get specific version if possible
                    version_info = self._detect_compiler_version(
                        best_compiler, strings_data, imports_data
                    )
                    results['version'] = version_info
                    
                    # Additional details
                    results['details'] = {
                        'all_scores': compiler_scores,
                        'file_format': file_format,
                        'detection_method': self._get_detection_method(best_compiler, best_score)
                    }
            
            logger.debug(f"Compiler detection completed: {results['compiler']} (confidence: {results['confidence']:.2f})")
            
        except Exception as e:
            logger.error(f"Error during compiler detection: {e}")
            results['error'] = str(e)
        
        return results
    
    def _get_file_format(self) -> str:
        """Detect file format (PE, ELF, Mach-O)"""
        try:
            file_info = self.r2.cmdj('ij')  # Get file info in JSON
            if file_info and 'bin' in file_info:
                format_info = file_info['bin'].get('class', '').upper()
                if 'PE' in format_info:
                    return 'PE'
                elif 'ELF' in format_info:
                    return 'ELF' 
                elif 'MACH' in format_info:
                    return 'Mach-O'
            return 'Unknown'
        except:
            return 'Unknown'
    
    def _get_strings(self) -> List[str]:
        """Extract strings from binary"""
        try:
            strings_output = self.r2.cmd('izz~..')  # Get all strings
            strings = []
            
            for line in strings_output.split('\n'):
                if line.strip():
                    # Extract string content (after the address and size info)
                    parts = line.split(' ', 4)
                    if len(parts) >= 5:
                        string_content = parts[4].strip()
                        strings.append(string_content)
            
            return strings
        except Exception as e:
            logger.error(f"Error extracting strings: {e}")
            return []
    
    def _get_imports(self) -> List[str]:
        """Get imported functions and libraries"""
        try:
            imports = []
            imports_data = self.r2.cmdj('iij')  # Get imports in JSON
            
            if isinstance(imports_data, list):
                for imp in imports_data:
                    if isinstance(imp, dict):
                        # Add library name
                        if 'libname' in imp:
                            imports.append(imp['libname'])
                        # Add function name
                        if 'name' in imp:
                            imports.append(imp['name'])
            
            return imports
        except Exception as e:
            logger.error(f"Error getting imports: {e}")
            return []
    
    def _get_sections(self) -> List[str]:
        """Get section names"""
        try:
            sections = []
            sections_data = self.r2.cmdj('iSj')  # Get sections in JSON
            
            if isinstance(sections_data, list):
                for section in sections_data:
                    if isinstance(section, dict) and 'name' in section:
                        sections.append(section['name'])
            
            return sections
        except Exception as e:
            logger.error(f"Error getting sections: {e}")
            return []
    
    def _get_symbols(self) -> List[str]:
        """Get symbol names"""
        try:
            symbols = []
            symbols_data = self.r2.cmdj('isj')  # Get symbols in JSON
            
            if isinstance(symbols_data, list):
                for symbol in symbols_data:
                    if isinstance(symbol, dict) and 'name' in symbol:
                        symbols.append(symbol['name'])
            
            return symbols
        except Exception as e:
            logger.error(f"Error getting symbols: {e}")
            return []
    
    def _analyze_rich_header(self) -> Dict[str, Any]:
        """Analyze Rich Header for PE files (MSVC specific)"""
        try:
            # Try to get Rich Header information
            rich_info = {}
            
            # Use r2 to look for Rich header
            rich_output = self.r2.cmd('iHj')  # Headers info
            
            # Parse Rich header data if available
            if rich_output:
                try:
                    rich_data = json.loads(rich_output)
                    if 'rich' in rich_data:
                        rich_info = rich_data['rich']
                except:
                    pass
            
            return rich_info
        except Exception as e:
            logger.error(f"Error analyzing Rich header: {e}")
            return {}
    
    def _calculate_compiler_score(self, compiler_name: str, signatures: Dict, 
                                 strings_data: List[str], imports_data: List[str],
                                 sections_data: List[str], symbols_data: List[str]) -> float:
        """Calculate confidence score for a specific compiler"""
        
        score = 0.0
        max_score = 0.0
        
        # Check string patterns
        if 'strings' in signatures:
            max_score += 3.0
            for pattern in signatures['strings']:
                for string in strings_data:
                    if re.search(pattern, string, re.IGNORECASE):
                        score += 3.0 / len(signatures['strings'])
                        break
        
        # Check imports
        if 'imports' in signatures:
            max_score += 2.0
            for import_name in signatures['imports']:
                if any(import_name.lower() in imp.lower() for imp in imports_data):
                    score += 2.0 / len(signatures['imports'])
        
        # Check sections
        if 'sections' in signatures:
            max_score += 1.0
            for section_name in signatures['sections']:
                if any(section_name.lower() in sec.lower() for sec in sections_data):
                    score += 1.0 / len(signatures['sections'])
        
        # Check symbols
        if 'symbols' in signatures:
            max_score += 1.0
            for symbol_name in signatures['symbols']:
                if any(symbol_name.lower() in sym.lower() for sym in symbols_data):
                    score += 1.0 / len(signatures['symbols'])
        
        # Normalize score
        if max_score > 0:
            return min(score / max_score, 1.0)
        
        return 0.0
    
    def _detect_compiler_version(self, compiler: str, strings_data: List[str], 
                                imports_data: List[str]) -> str:
        """Detect specific compiler version"""
        
        if compiler == 'MSVC':
            # Check runtime libraries for MSVC version
            for import_name in imports_data:
                if import_name in self.msvc_versions:
                    return self.msvc_versions[import_name]
            
            # Check version strings
            for string in strings_data:
                match = re.search(r'Microsoft.*Visual.*C\+\+.*(\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"Visual Studio {match.group(1)}"
        
        elif compiler == 'GCC':
            # Look for GCC version in strings
            for string in strings_data:
                match = re.search(r'GCC.*(\d+\.\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"GCC {match.group(1)}"
                match = re.search(r'GNU.*(\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"GCC {match.group(1)}"
        
        elif compiler == 'Clang':
            # Look for Clang version
            for string in strings_data:
                match = re.search(r'clang.*(\d+\.\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"Clang {match.group(1)}"
                match = re.search(r'Apple.*clang.*(\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"Apple Clang {match.group(1)}"
        
        elif compiler == 'Go':
            # Look for Go version
            for string in strings_data:
                match = re.search(r'go(\d+\.\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"Go {match.group(1)}"
        
        elif compiler == 'Rust':
            # Look for Rust version
            for string in strings_data:
                match = re.search(r'rustc.*(\d+\.\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"Rust {match.group(1)}"
        
        elif compiler == 'AutoIt':
            # Look for AutoIt version
            for string in strings_data:
                match = re.search(r'AutoIt.*v(\d+\.\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"AutoIt v{match.group(1)}"
                match = re.search(r'AutoIt.*(\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"AutoIt {match.group(1)}"
        
        elif compiler == 'NSIS':
            # Look for NSIS version
            for string in strings_data:
                match = re.search(r'NSIS.*(\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"NSIS {match.group(1)}"
                match = re.search(r'Nullsoft.*Install.*System.*(\d+)', string, re.IGNORECASE)
                if match:
                    return f"NSIS {match.group(1)}"
        
        elif compiler == 'InnoSetup':
            # Look for Inno Setup version
            for string in strings_data:
                match = re.search(r'Inno Setup.*(\d+\.\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"Inno Setup {match.group(1)}"
        
        elif compiler == 'PyInstaller':
            # Check Python DLL versions for PyInstaller
            for import_name in imports_data:
                if 'python' in import_name.lower() and '.dll' in import_name.lower():
                    match = re.search(r'python(\d+)\.dll', import_name, re.IGNORECASE)
                    if match:
                        py_version = match.group(1)
                        major = py_version[0]
                        minor = py_version[1:]
                        return f"PyInstaller (Python {major}.{minor})"
            
            # Look for PyInstaller version in strings
            for string in strings_data:
                match = re.search(r'PyInstaller.*(\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"PyInstaller {match.group(1)}"
        
        elif compiler == 'cx_Freeze':
            # Look for cx_Freeze version
            for string in strings_data:
                match = re.search(r'cx_freeze.*(\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"cx_Freeze {match.group(1)}"
        
        elif compiler == 'Nim':
            # Look for Nim version
            for string in strings_data:
                match = re.search(r'nim.*(\d+\.\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"Nim {match.group(1)}"
        
        elif compiler == 'Zig':
            # Look for Zig version
            for string in strings_data:
                match = re.search(r'zig.*(\d+\.\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"Zig {match.group(1)}"
        
        elif compiler == 'NodeJS':
            # Look for Node.js version
            for string in strings_data:
                match = re.search(r'nexe/(\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"Node.js/nexe {match.group(1)}"
                match = re.search(r'node.*(\d+\.\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"Node.js {match.group(1)}"
        
        elif compiler == 'Swift':
            # Look for Swift version
            for string in strings_data:
                match = re.search(r'Swift.*(\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"Swift {match.group(1)}"
        
        elif compiler == 'TinyCC':
            # Look for TinyCC version
            for string in strings_data:
                match = re.search(r'tcc.*(\d+\.\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"TinyCC {match.group(1)}"
        
        elif compiler == 'FASM':
            # Look for FASM version
            for string in strings_data:
                match = re.search(r'FASM.*(\d+\.\d+)', string, re.IGNORECASE)
                if match:
                    return f"FASM {match.group(1)}"
        
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
        
        if compiler == 'MSVC':
            methods.append("Runtime library analysis")
        elif compiler in ['GCC', 'Clang']:
            methods.append("Symbol and section analysis")
        elif compiler == 'DotNet':
            methods.append("CLR metadata analysis")
        elif compiler == 'AutoIt':
            methods.append("AU3 signature and string analysis")
        elif compiler in ['NSIS', 'InnoSetup']:
            methods.append("Installer signature analysis")
        elif compiler in ['PyInstaller', 'cx_Freeze']:
            methods.append("Python runtime detection")
        elif compiler == 'Nim':
            methods.append("Nim runtime and symbol analysis")
        elif compiler in ['Zig', 'Swift', 'TinyCC']:
            methods.append("Modern compiler signature analysis")
        elif compiler == 'NodeJS':
            methods.append("Node.js runtime detection")
        elif compiler == 'FASM':
            methods.append("Assembly tool signature")
        
        return " | ".join(methods) 