#!/usr/bin/env python3
"""
PE Analysis Module using r2pipe
"""

import struct
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmdj, safe_cmd

logger = get_logger(__name__)

class PEAnalyzer:
    """PE file analysis using radare2"""
    
    def __init__(self, r2, config, filepath=None):
        self.r2 = r2
        self.config = config
        self.filepath = filepath
        
    def analyze(self) -> Dict[str, Any]:
        """Perform complete PE analysis"""
        pe_info = {}
        
        try:
            # Get PE headers information
            pe_info.update(self._get_pe_headers())
            
            # Get file characteristics
            pe_info.update(self._get_file_characteristics())
            
            # Get compilation info
            pe_info.update(self._get_compilation_info())
            
            # Get security features
            pe_info['security_features'] = self.get_security_features()
            
            # Get subsystem info
            pe_info.update(self._get_subsystem_info())
            
            # Calculate imphash
            pe_info['imphash'] = self.calculate_imphash()
            
        except Exception as e:
            logger.error(f"Error in PE analysis: {e}")
            pe_info['error'] = str(e)
            
        return pe_info
    
    def _get_pe_headers(self) -> Dict[str, Any]:
        """Extract PE header information"""
        info = {}
        
        try:
            # Get PE information from radare2
            pe_info = safe_cmdj(self.r2, 'ij')
            
            if pe_info and 'bin' in pe_info:
                bin_info = pe_info['bin']
                
                info['architecture'] = bin_info.get('arch', 'Unknown')
                info['machine'] = bin_info.get('machine', 'Unknown')
                info['bits'] = bin_info.get('bits', 0)
                info['endian'] = bin_info.get('endian', 'Unknown')
                
                # Determine PE file type (EXE, DLL, SYS, etc.)
                # First try r2 - it should always tell us the format
                file_type = bin_info.get('class', 'Unknown')
                
                # If r2 doesn't give us specific type info, use magic as fallback
                if file_type in ['PE32+', 'PE32', 'PE', 'Unknown']:
                    try:
                        import magic
                        file_desc = magic.from_file(self.filepath).lower()
                        logger.debug(f"Magic file description: {file_desc}")
                        
                        if 'dll' in file_desc:
                            file_type = 'DLL'
                        elif 'executable' in file_desc and 'dll' not in file_desc:
                            file_type = 'EXE'
                        elif 'driver' in file_desc or 'sys' in file_desc:
                            file_type = 'SYS'
                        else:
                            # Keep the original r2 format info if magic doesn't help
                            file_type = bin_info.get('class', 'PE')
                    except Exception as e:
                        logger.debug(f"Could not use magic for file type: {e}")
                        # Keep the original r2 format info
                        file_type = bin_info.get('class', 'PE')
                
                logger.debug(f"Determined file type: {file_type}")
                info['type'] = file_type
                
                # Determine PE format (PE32/PE32+) based on architecture
                format_name = bin_info.get('format', 'Unknown')
                if format_name == 'Unknown' or not format_name:
                    # Determine format based on bits
                    bits = bin_info.get('bits', 0)
                    if bits == 32:
                        format_name = 'PE32'
                    elif bits == 64:
                        format_name = 'PE32+'
                    else:
                        # Try to determine from optional header
                        try:
                            pe_header = safe_cmdj(self.r2, 'iHj')
                            if pe_header and 'nt_headers' in pe_header:
                                nt_headers = pe_header['nt_headers']
                                if 'optional_header' in nt_headers:
                                    opt_header = nt_headers['optional_header']
                                    magic = opt_header.get('Magic', 0)
                                    if magic == 0x10b:  # IMAGE_NT_OPTIONAL_HDR32_MAGIC
                                        format_name = 'PE32'
                                    elif magic == 0x20b:  # IMAGE_NT_OPTIONAL_HDR64_MAGIC
                                        format_name = 'PE32+'
                                    else:
                                        format_name = 'PE'
                        except:
                            format_name = 'PE'
                
                info['format'] = format_name
                
                # PE specific fields - get more accurate values
                info['image_base'] = bin_info.get('baddr', 0)
                
                # Try to get entry point from different sources
                entry_point = 0
                if 'baddr' in bin_info and 'boffset' in bin_info:
                    entry_point = bin_info.get('baddr', 0) + bin_info.get('boffset', 0)
                
                # Alternative: try to get entry point directly
                try:
                    entry_info = safe_cmdj(self.r2, 'iej')
                    if entry_info and len(entry_info) > 0:
                        entry_point = entry_info[0].get('vaddr', entry_point)
                except Exception as e:
                    logger.debug(f"Could not get entry point from iej: {e}")
                    pass
                
                info['entry_point'] = entry_point
                
                # Get more PE-specific information
                try:
                    pe_header = safe_cmdj(self.r2, 'iHj')
                    if pe_header:
                        # Extract additional PE header fields
                        if 'nt_headers' in pe_header:
                            nt_headers = pe_header['nt_headers']
                            if 'optional_header' in nt_headers:
                                opt_header = nt_headers['optional_header']
                                image_base = opt_header.get('ImageBase', info['image_base'])
                                if image_base and image_base != 0:
                                    info['image_base'] = image_base
                                entry_rva = opt_header.get('AddressOfEntryPoint', 0)
                                if entry_rva and entry_rva != 0:
                                    info['entry_point'] = entry_rva + info['image_base']
                except Exception as e:
                    logger.debug(f"Could not get PE header details from iHj: {e}")
                    pass
                
        except Exception as e:
            logger.error(f"Error getting PE headers: {e}")
            
        return info
    
    def _get_file_characteristics(self) -> Dict[str, Any]:
        """Get file characteristics"""
        characteristics = {}
        
        try:
            # Get file characteristics from PE header
            pe_info = safe_cmdj(self.r2, 'ij')
            
            if pe_info and 'bin' in pe_info:
                bin_info = pe_info['bin']
                
                characteristics['has_debug'] = 'debug' in bin_info
                
                # Better detection using PE header characteristics
                is_dll = False
                is_executable = False
                
                try:
                    pe_header = safe_cmdj(self.r2, 'iHj')
                    if pe_header and 'file_header' in pe_header:
                        file_header = pe_header['file_header']
                        characteristics_flags = file_header.get('Characteristics', 0)
                        
                        # Check specific PE characteristics
                        if isinstance(characteristics_flags, int):
                            is_dll = bool(characteristics_flags & 0x2000)  # IMAGE_FILE_DLL
                            is_executable = bool(characteristics_flags & 0x0002)  # IMAGE_FILE_EXECUTABLE_IMAGE
                except Exception as e:
                    logger.debug(f"Could not get PE characteristics: {e}")
                    # Fallback detection
                    file_type = bin_info.get('type', '').lower()
                    class_type = bin_info.get('class', '').lower()
                    
                    # Check if it's a DLL
                    is_dll = (
                        'dll' in file_type or 
                        'dll' in class_type or
                        'dynamic library' in file_type.lower() or
                        self.filepath.lower().endswith('.dll')
                    )
                    
                    # Check if it's executable
                    is_executable = (
                        'executable' in file_type or
                        'exe' in file_type or
                        self.filepath.lower().endswith('.exe') or
                        (not is_dll)  # If not DLL, likely executable
                    )
                
                characteristics['is_dll'] = is_dll
                characteristics['is_executable'] = is_executable
                
        except Exception as e:
            logger.error(f"Error getting file characteristics: {e}")
            
        return characteristics
    
    def _get_compilation_info(self) -> Dict[str, Any]:
        """Get compilation information"""
        info = {}
        
        try:
            # Try to get timestamp from PE header
            pe_info = safe_cmdj(self.r2, 'ij')
            
            if pe_info and 'bin' in pe_info:
                bin_info = pe_info['bin']
                
                # Check for timestamp
                if 'compiled' in bin_info:
                    info['compile_time'] = bin_info['compiled']
                
                # Check for compiler information in strings
                strings_result = self.r2.cmd('iz~compiler')
                if strings_result:
                    info['compiler_info'] = strings_result.strip()
                
        except Exception as e:
            logger.error(f"Error getting compilation info: {e}")
            
        return info
    
    def get_security_features(self) -> Dict[str, bool]:
        """Check for security features by reading DllCharacteristics flags"""
        features = {
            'aslr': False,
            'dep': False,
            'seh': False,
            'guard_cf': False,
            'authenticode': False
        }
        
        try:
            # Get PE header information to read DllCharacteristics
            pe_header = safe_cmdj(self.r2, 'iHj')
            
            if pe_header and 'nt_headers' in pe_header:
                nt_headers = pe_header['nt_headers']
                if 'optional_header' in nt_headers:
                    opt_header = nt_headers['optional_header']
                    dll_characteristics = opt_header.get('DllCharacteristics', 0)
                    
                    if isinstance(dll_characteristics, int):
                        # Read security flags from DllCharacteristics
                        features['aslr'] = bool(dll_characteristics & 0x0040)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                        features['dep'] = bool(dll_characteristics & 0x0100)   # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                        features['seh'] = not bool(dll_characteristics & 0x0400)  # IMAGE_DLLCHARACTERISTICS_NO_SEH (inverted)
                        features['guard_cf'] = bool(dll_characteristics & 0x4000)  # IMAGE_DLLCHARACTERISTICS_GUARD_CF
                        
                        logger.debug(f"DllCharacteristics: 0x{dll_characteristics:04x}")
                        logger.debug(f"Security features: ASLR={features['aslr']}, DEP={features['dep']}, SEH={features['seh']}, CFG={features['guard_cf']}")
            
            # Fallback to text-based parsing if JSON failed
            if not any(features.values()):
                security_info = safe_cmd(self.r2, 'iHH')
                
                if security_info:
                    # Check for ASLR
                    if 'DLL can move' in security_info or 'DYNAMIC_BASE' in security_info:
                        features['aslr'] = True
                    
                    # Check for DEP/NX
                    if 'NX_COMPAT' in security_info:
                        features['dep'] = True
                    
                    # Check for SEH
                    if 'NO_SEH' not in security_info:
                        features['seh'] = True
                    
                    # Check for Control Flow Guard
                    if 'GUARD_CF' in security_info:
                        features['guard_cf'] = True
            
            # Check for digital signature/authenticode
            try:
                cert_info = safe_cmd(self.r2, 'ic')
                if cert_info and cert_info.strip():
                    features['authenticode'] = True
            except:
                # Alternative check for certificates
                try:
                    # Check if there's a certificate table in the data directories
                    if pe_header and 'nt_headers' in pe_header:
                        nt_headers = pe_header['nt_headers']
                        if 'optional_header' in nt_headers:
                            opt_header = nt_headers['optional_header']
                            data_dirs = opt_header.get('DataDirectory', [])
                            if len(data_dirs) > 4:  # Certificate table is at index 4
                                cert_dir = data_dirs[4]
                                if isinstance(cert_dir, dict) and cert_dir.get('Size', 0) > 0:
                                    features['authenticode'] = True
                except:
                    pass
                
        except Exception as e:
            logger.error(f"Error checking security features: {e}")
            
        return features
    
    def _get_subsystem_info(self) -> Dict[str, Any]:
        """Get subsystem information"""
        info = {}
        
        try:
            pe_info = safe_cmdj(self.r2, 'ij')
            
            if pe_info and 'bin' in pe_info:
                bin_info = pe_info['bin']
                
                # Subsystem type
                subsystem = bin_info.get('subsys', 'Unknown')
                info['subsystem'] = subsystem
                
                # Determine if it's a GUI or console application
                if 'console' in subsystem.lower():
                    info['gui_app'] = False
                elif 'windows' in subsystem.lower():
                    info['gui_app'] = True
                else:
                    info['gui_app'] = None
                    
        except Exception as e:
            logger.error(f"Error getting subsystem info: {e}")
            
        return info
    
    def get_resource_info(self) -> List[Dict[str, Any]]:
        """Get resource information"""
        resources = []
        
        try:
            # Get resources from radare2
            res_info = safe_cmdj(self.r2, 'iRj')
            
            if res_info:
                for resource in res_info:
                    resources.append({
                        'name': resource.get('name', 'Unknown'),
                        'type': resource.get('type', 'Unknown'),
                        'size': resource.get('size', 0),
                        'lang': resource.get('lang', 'Unknown')
                    })
                    
        except Exception as e:
            logger.error(f"Error getting resource info: {e}")
            
        return resources
    
    def get_version_info(self) -> Dict[str, str]:
        """Get version information from resources"""
        version_info = {}
        
        try:
            # Try to extract version info
            version_result = self.r2.cmd('iR~version')
            
            if version_result:
                lines = version_result.strip().split('\n')
                for line in lines:
                    if '=' in line:
                        key, value = line.split('=', 1)
                        version_info[key.strip()] = value.strip()
                        
        except Exception as e:
            logger.error(f"Error getting version info: {e}")
            
        return version_info
    
    def calculate_imphash(self) -> str:
        """Calculate Import Hash (imphash) for PE files
        
        This implementation follows the exact algorithm used by pefile library:
        https://github.com/erocarrera/pefile/blob/master/pefile.py
        
        Returns:
            str: MD5 hash of normalized import names, or empty string if no imports
        """
        try:
            logger.debug("Calculating imphash using pefile-compatible algorithm...")
            
            # Get imports using radare2's import JSON command
            imports = self.r2.cmdj("iij")
            
            if not imports:
                logger.debug("No imports found for imphash calculation")
                return ""
            
            # Build import strings in pefile format: "libname.funcname"
            impstrs = []
            exts = ["ocx", "sys", "dll"]
            
            # Group imports by library
            imports_by_lib = {}
            for imp in imports:
                if isinstance(imp, dict) and 'name' in imp:
                    # Get library name (use 'libname' field from radare2)
                    libname = imp.get('libname', 'unknown')
                    if not libname or libname.strip() == '':
                        libname = 'unknown'
                    
                    # Get function name
                    funcname = imp.get('name', '')
                    if not funcname or funcname.strip() == '':
                        continue
                    
                    # Group by library
                    if libname not in imports_by_lib:
                        imports_by_lib[libname] = []
                    imports_by_lib[libname].append(funcname)
            
            # Process each library following pefile algorithm
            for libname, functions in imports_by_lib.items():
                # Normalize library name (convert to lowercase)
                if isinstance(libname, bytes):
                    libname = libname.decode().lower()
                else:
                    libname = libname.lower()
                
                # Remove extension if it's one of the known types
                parts = libname.rsplit(".", 1)
                if len(parts) > 1 and parts[1] in exts:
                    libname = parts[0]
                
                # Process each function in this library
                for funcname in functions:
                    if not funcname:
                        continue
                    
                    # Normalize function name
                    if isinstance(funcname, bytes):
                        funcname = funcname.decode()
                    
                    # Create the import string in pefile format: "libname.funcname"
                    impstr = f"{libname.lower()}.{funcname.lower()}"
                    impstrs.append(impstr)
            
            if not impstrs:
                logger.debug("No valid import strings found for imphash")
                return ""
            
            # Join with commas and calculate MD5 hash (pefile algorithm)
            imphash_string = ",".join(impstrs)
            imphash = hashlib.md5(imphash_string.encode('utf-8')).hexdigest()
            
            logger.debug(f"Imphash calculated: {imphash} (from {len(impstrs)} imports)")
            return imphash
            
        except Exception as e:
            logger.error(f"Error calculating imphash: {e}")
            return ""