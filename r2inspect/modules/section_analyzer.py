#!/usr/bin/env python3
"""
Section Analysis Module using r2pipe
"""

import math
from typing import Dict, List, Any, Optional
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmdj, safe_cmd

logger = get_logger(__name__)

class SectionAnalyzer:
    """PE sections analysis using radare2"""
    
    def __init__(self, r2, config):
        self.r2 = r2
        self.config = config
        
        # Standard PE section names
        self.standard_sections = [
            '.text', '.data', '.rdata', '.bss', '.idata', '.edata',
            '.rsrc', '.reloc', '.debug', '.pdata', '.xdata'
        ]
    
    def analyze_sections(self) -> List[Dict[str, Any]]:
        """Analyze all sections in the PE file"""
        sections_info = []
        
        try:
            sections = safe_cmdj(self.r2, 'iSj')
            
            if sections:
                for section in sections:
                    section_analysis = self._analyze_single_section(section)
                    sections_info.append(section_analysis)
                    
        except Exception as e:
            logger.error(f"Error analyzing sections: {e}")
            
        return sections_info
    
    def _analyze_single_section(self, section: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single section"""
        analysis = {
            'name': str(section.get('name', 'unknown')),
            'virtual_address': section.get('vaddr', 0),
            'virtual_size': section.get('vsize', 0),
            'raw_size': section.get('size', 0),
            'flags': section.get('flags', ''),
            'entropy': 0.0,
            'is_executable': False,
            'is_writable': False,
            'is_readable': False,
            'suspicious_indicators': [],
            'characteristics': {},
            'pe_characteristics': [],
            'size_ratio': 0.0
        }
        
        try:
            # Parse permission flags from radare2
            flags = str(section.get('flags', ''))
            analysis['is_executable'] = 'x' in flags
            analysis['is_writable'] = 'w' in flags  
            analysis['is_readable'] = 'r' in flags
            
            # Get PE-specific section characteristics
            pe_flags = section.get('perm', '')  # Alternative field for permissions
            if pe_flags:
                analysis['is_executable'] = analysis['is_executable'] or 'x' in pe_flags
                analysis['is_writable'] = analysis['is_writable'] or 'w' in pe_flags
                analysis['is_readable'] = analysis['is_readable'] or 'r' in pe_flags
            
            # Decode PE section characteristics if available
            characteristics_value = section.get('characteristics', 0)
            if isinstance(characteristics_value, int) and characteristics_value > 0:
                analysis['pe_characteristics'] = self._decode_pe_characteristics(characteristics_value)
                
                # Update flags based on PE characteristics
                if 'IMAGE_SCN_MEM_EXECUTE' in analysis['pe_characteristics']:
                    analysis['is_executable'] = True
                if 'IMAGE_SCN_MEM_WRITE' in analysis['pe_characteristics']:
                    analysis['is_writable'] = True
                if 'IMAGE_SCN_MEM_READ' in analysis['pe_characteristics']:
                    analysis['is_readable'] = True
            
            # Calculate size ratio
            vsize = analysis['virtual_size']
            raw_size = analysis['raw_size']
            if raw_size > 0:
                analysis['size_ratio'] = vsize / raw_size if vsize > 0 else 0.0
            
            # Calculate entropy
            analysis['entropy'] = self._calculate_entropy(section)
            
            # Check for suspicious characteristics
            analysis['suspicious_indicators'] = self._check_suspicious_characteristics(section, analysis)
            
            # Get section characteristics
            analysis['characteristics'] = self._get_section_characteristics(section, analysis)
            
        except Exception as e:
            logger.error(f"Error in single section analysis: {e}")
            analysis['error'] = str(e)
            
        return analysis
    
    def _calculate_entropy(self, section: Dict[str, Any]) -> float:
        """Calculate Shannon entropy for section"""
        try:
            vaddr = section.get('vaddr', 0)
            size = section.get('size', 0)
            
            if size == 0 or size > 50000000:  # Skip very large sections (50MB)
                return 0.0
                
            # Read section data (limit to 1MB for performance)
            read_size = min(size, 1048576)
            data_cmd = f"p8 {read_size} @ {vaddr}"
            hex_data = self.r2.cmd(data_cmd)
            
            if not hex_data or not hex_data.strip():
                return 0.0
                
            try:
                data = bytes.fromhex(hex_data.strip())
            except ValueError:
                return 0.0
                
            if len(data) == 0:
                return 0.0
                
            # Calculate byte frequency
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
                
            # Calculate Shannon entropy
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    p = count / data_len
                    entropy -= p * math.log2(p)
                    
            return entropy
            
        except Exception as e:
            logger.error(f"Error calculating entropy: {e}")
            return 0.0
    
    def _check_suspicious_characteristics(self, section: Dict[str, Any], analysis: Dict[str, Any]) -> List[str]:
        """Check for suspicious section characteristics"""
        indicators = []
        
        try:
            name = str(section.get('name', ''))
            vsize = section.get('vsize', 0)
            raw_size = section.get('size', 0)
            entropy = analysis.get('entropy', 0)
            
            # Check for non-standard section names
            if isinstance(name, str) and name not in self.standard_sections and not name.startswith('.'):
                indicators.append('Non-standard section name')
            
            # Check for suspicious section names
            suspicious_names = [
                'upx', 'aspack', 'themida', 'vmprotect', 'armadillo',
                'fsg', 'petite', 'mew', 'packed', 'crypted'
            ]
            
            # Ensure name is a string before checking
            if isinstance(name, str):
                for sus_name in suspicious_names:
                    if sus_name in name.lower():
                        indicators.append(f'Suspicious section name: {sus_name}')
                        break
            
            # Check for writable and executable sections
            if analysis['is_writable'] and analysis['is_executable']:
                indicators.append('Writable and executable section')
            
            # Check for high entropy (possible encryption/compression)
            if entropy > 7.5:
                indicators.append(f'High entropy ({entropy:.2f})')
            elif entropy > 7.0:
                indicators.append(f'Moderate high entropy ({entropy:.2f})')
            
            # Check for large virtual vs raw size difference with specific ratios
            if vsize > 0 and raw_size > 0:
                ratio = vsize / raw_size
                size_diff_ratio = abs(vsize - raw_size) / max(vsize, raw_size)
                
                if ratio > 10:
                    indicators.append(f'Suspicious size ratio: Virtual {ratio:.1f}x larger than raw')
                elif ratio > 5:
                    indicators.append(f'Large size ratio: Virtual {ratio:.1f}x larger than raw')
                elif size_diff_ratio > 0.8:
                    indicators.append(f'Large virtual/raw size difference ({size_diff_ratio:.1f})')
            
            # Check for very small sections
            if raw_size < 100 and raw_size > 0:
                indicators.append('Very small section')
            
            # Check for very large sections (>50MB)
            if raw_size > 52428800:
                indicators.append('Very large section')
            
            # Check for executable sections with low entropy (possible padding/obfuscation)
            if analysis['is_executable'] and entropy < 1.0:
                indicators.append('Executable section with very low entropy')
                
        except Exception as e:
            logger.error(f"Error checking suspicious characteristics: {e}")
            
        return indicators
    
    def _decode_pe_characteristics(self, characteristics: int) -> List[str]:
        """Decode PE section characteristics flags"""
        flags = []
        
        # PE section characteristics constants
        pe_flags = {
            0x00000020: 'IMAGE_SCN_CNT_CODE',
            0x00000040: 'IMAGE_SCN_CNT_INITIALIZED_DATA',
            0x00000080: 'IMAGE_SCN_CNT_UNINITIALIZED_DATA',
            0x00000200: 'IMAGE_SCN_LNK_INFO',
            0x00000800: 'IMAGE_SCN_LNK_REMOVE',
            0x00001000: 'IMAGE_SCN_LNK_COMDAT',
            0x00008000: 'IMAGE_SCN_GPREL',
            0x00020000: 'IMAGE_SCN_MEM_PURGEABLE',
            0x00040000: 'IMAGE_SCN_MEM_16BIT',
            0x00080000: 'IMAGE_SCN_MEM_LOCKED',
            0x00100000: 'IMAGE_SCN_MEM_PRELOAD',
            0x01000000: 'IMAGE_SCN_MEM_EXECUTE',
            0x02000000: 'IMAGE_SCN_MEM_READ',
            0x04000000: 'IMAGE_SCN_MEM_WRITE',
            0x08000000: 'IMAGE_SCN_MEM_SHARED',
            0x10000000: 'IMAGE_SCN_MEM_NOT_CACHED',
            0x20000000: 'IMAGE_SCN_MEM_NOT_PAGED',
            0x40000000: 'IMAGE_SCN_MEM_DISCARDABLE'
        }
        
        for flag_value, flag_name in pe_flags.items():
            if characteristics & flag_value:
                flags.append(flag_name)
        
        return flags
    
    def _get_section_characteristics(self, section: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Get detailed section characteristics"""
        characteristics = {}
        
        try:
            name = str(section.get('name', ''))
            
            # Determine section purpose based on name and characteristics
            if name == '.text':
                characteristics['purpose'] = 'Executable code'
                characteristics['expected_entropy'] = '6.0-7.5'
            elif name == '.data':
                characteristics['purpose'] = 'Initialized data'
                characteristics['expected_entropy'] = '3.0-6.0'
            elif name == '.rdata':
                characteristics['purpose'] = 'Read-only data'
                characteristics['expected_entropy'] = '4.0-6.5'
            elif name == '.bss':
                characteristics['purpose'] = 'Uninitialized data'
                characteristics['expected_entropy'] = '0.0-1.0'
            elif name == '.rsrc':
                characteristics['purpose'] = 'Resources'
                characteristics['expected_entropy'] = '2.0-7.0'
            elif name == '.idata':
                characteristics['purpose'] = 'Import data'
                characteristics['expected_entropy'] = '3.0-5.0'
            elif name == '.edata':
                characteristics['purpose'] = 'Export data'
                characteristics['expected_entropy'] = '3.0-5.0'
            elif name == '.reloc':
                characteristics['purpose'] = 'Relocations'
                characteristics['expected_entropy'] = '2.0-4.0'
            else:
                characteristics['purpose'] = 'Unknown/Custom'
                characteristics['expected_entropy'] = 'Variable'
            
            # Check if entropy matches expected range
            entropy = analysis.get('entropy', 0)
            if characteristics['expected_entropy'] != 'Variable':
                try:
                    min_entropy, max_entropy = map(float, characteristics['expected_entropy'].split('-'))
                    if entropy < min_entropy or entropy > max_entropy:
                        characteristics['entropy_anomaly'] = True
                except:
                    pass
            
            # Additional analysis based on section content
            if analysis['is_executable']:
                characteristics['code_analysis'] = self._analyze_code_section(section)
            
        except Exception as e:
            logger.error(f"Error getting section characteristics: {e}")
            
        return characteristics
    
    def _analyze_code_section(self, section: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze executable code sections"""
        code_info = {}
        
        try:
            vaddr = section.get('vaddr', 0)
            size = section.get('size', 0)
            
            if size == 0:
                return code_info
            
            # Get function count in this section
            functions_cmd = f"aflj @ {vaddr}"
            functions = safe_cmdj(self.r2, functions_cmd)
            
            if functions:
                code_info['function_count'] = len(functions)
                
                # Analyze function characteristics
                if len(functions) > 0:
                    sizes = [f.get('size', 0) for f in functions if f.get('size', 0) > 0]
                    if sizes:
                        code_info['avg_function_size'] = sum(sizes) / len(sizes)
                        code_info['min_function_size'] = min(sizes)
                        code_info['max_function_size'] = max(sizes)
            else:
                code_info['function_count'] = 0
            
            # Check for NOP sleds or padding
            nop_count = len(safe_cmd(self.r2, f'/c nop @ {vaddr}').strip().split('\n')) if safe_cmd(self.r2, f'/c nop @ {vaddr}').strip() else 0
            
            if nop_count > size / 100:  # More than 1% NOPs
                code_info['excessive_nops'] = True
                code_info['nop_ratio'] = nop_count / (size / 4)  # Approximate instruction count
            
        except Exception as e:
            logger.error(f"Error analyzing code section: {e}")
            
        return code_info
    
    def get_section_summary(self) -> Dict[str, Any]:
        """Get summary of all sections"""
        summary = {
            'total_sections': 0,
            'executable_sections': 0,
            'writable_sections': 0,
            'suspicious_sections': 0,
            'high_entropy_sections': 0,
            'avg_entropy': 0.0,
            'section_flags_summary': {}
        }
        
        try:
            sections_info = self.analyze_sections()
            
            if sections_info:
                summary['total_sections'] = len(sections_info)
                
                total_entropy = 0
                flag_counts = {}
                
                for section in sections_info:
                    # Count section types
                    if section.get('is_executable'):
                        summary['executable_sections'] += 1
                    if section.get('is_writable'):
                        summary['writable_sections'] += 1
                    if section.get('suspicious_indicators'):
                        summary['suspicious_sections'] += 1
                    
                    entropy = section.get('entropy', 0)
                    total_entropy += entropy
                    if entropy > 7.0:
                        summary['high_entropy_sections'] += 1
                    
                    # Count flag combinations
                    flags = section.get('flags', '')
                    if flags in flag_counts:
                        flag_counts[flags] += 1
                    else:
                        flag_counts[flags] = 1
                
                summary['avg_entropy'] = total_entropy / len(sections_info)
                summary['section_flags_summary'] = flag_counts
                
        except Exception as e:
            logger.error(f"Error getting section summary: {e}")
            
        return summary 