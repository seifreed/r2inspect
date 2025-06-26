#!/usr/bin/env python3
"""
SimHash Analyzer Module

This module implements SimHash-based binary similarity analysis using both strings and opcodes.
SimHash is a locality-sensitive hash function that maps high-dimensional features to a fixed-size
hash while preserving similarity relationships. It's particularly useful for:

- Detecting similar binaries with small variations
- Clustering functions or binaries by structural similarity
- Efficient similarity matching at scale
- Malware family identification and variant detection

The implementation extracts features from:
1. Strings (function context and embedded data)
2. Instruction mnemonics (structural patterns)
3. Function-level patterns (per-function hashing)
4. Binary-wide signatures (global similarity)

Based on Charikar's SimHash algorithm for near-duplicate detection.
Reference: https://en.wikipedia.org/wiki/SimHash
"""

import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import Counter, defaultdict
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmdj, safe_cmd_list

logger = get_logger(__name__)

# Try to import simhash, fall back to error handling
try:
    from simhash import Simhash
    SIMHASH_AVAILABLE = True
except ImportError:
    logger.warning("simhash not available. Install with: pip install simhash")
    SIMHASH_AVAILABLE = False
    Simhash = None

class SimHashAnalyzer:
    """SimHash-based binary similarity analysis"""
    
    def __init__(self, r2_instance, filepath: str):
        """
        Initialize SimHash analyzer.
        
        Args:
            r2_instance: Active r2pipe instance
            filepath: Path to the binary file being analyzed
        """
        self.r2 = r2_instance
        self.filepath = filepath
        self.min_string_length = 4  # Minimum string length to consider
        self.max_instructions_per_function = 500  # Limit instructions per function
    
    def analyze(self) -> Dict[str, Any]:
        """
        Perform SimHash analysis on the binary.
        
        Returns:
            Dictionary containing SimHash analysis results
        """
        if not SIMHASH_AVAILABLE:
            return {
                'available': False,
                'error': 'simhash library not installed',
                'library_available': False
            }
        
        logger.debug(f"Starting SimHash analysis for {self.filepath}")
        
        results = {
            'available': False,
            'library_available': True,
            'binary_simhash': None,
            'strings_simhash': None,
            'opcodes_simhash': None,
            'combined_simhash': None,
            'function_simhashes': {},
            'total_functions': 0,
            'analyzed_functions': 0,
            'feature_stats': {},
            'similarity_groups': [],
            'error': None
        }
        
        try:
            # Extract features
            strings_features = self._extract_string_features()
            opcodes_features = self._extract_opcodes_features()
            function_features = self._extract_function_features()
            
            if not strings_features and not opcodes_features:
                results['error'] = "No features could be extracted for SimHash"
                logger.debug("No features could be extracted for SimHash")
                return results
            
            # Calculate different SimHash variants
            results['available'] = True
            
            # Strings-only SimHash
            if strings_features:
                strings_simhash = Simhash(strings_features)
                results['strings_simhash'] = {
                    'hash': strings_simhash.value,
                    'hex': hex(strings_simhash.value),
                    'binary': bin(strings_simhash.value),
                    'feature_count': len(strings_features)
                }
            
            # Opcodes-only SimHash
            if opcodes_features:
                opcodes_simhash = Simhash(opcodes_features)
                results['opcodes_simhash'] = {
                    'hash': opcodes_simhash.value,
                    'hex': hex(opcodes_simhash.value),
                    'binary': bin(opcodes_simhash.value),
                    'feature_count': len(opcodes_features)
                }
            
            # Combined SimHash (strings + opcodes)
            combined_features = strings_features + opcodes_features
            if combined_features:
                combined_simhash = Simhash(combined_features)
                results['combined_simhash'] = {
                    'hash': combined_simhash.value,
                    'hex': hex(combined_simhash.value),
                    'binary': bin(combined_simhash.value),
                    'feature_count': len(combined_features)
                }
                results['binary_simhash'] = results['combined_simhash']  # Alias for binary-wide hash
            
            # Function-level SimHashes
            if function_features:
                results['function_simhashes'] = function_features
                results['total_functions'] = len([f for f in function_features.values() if f.get('simhash')])
                results['analyzed_functions'] = len([f for f in function_features.values() if f.get('simhash')])
                
                # Find similar functions
                similar_groups = self._find_similar_functions(function_features)
                results['similarity_groups'] = similar_groups
            
            # Feature statistics
            feature_stats = {
                'total_strings': len(strings_features),
                'total_opcodes': len(opcodes_features),
                'total_features': len(combined_features),
                'unique_strings': len(set(strings_features)) if strings_features else 0,
                'unique_opcodes': len(set(opcodes_features)) if opcodes_features else 0,
            }
            
            # Add frequency analysis
            if combined_features:
                feature_counter = Counter(combined_features)
                feature_stats['most_common_features'] = feature_counter.most_common(10)
                feature_stats['feature_diversity'] = len(set(combined_features)) / len(combined_features)
            
            results['feature_stats'] = feature_stats
            
            logger.debug(f"SimHash analysis completed: {len(combined_features)} total features")
            logger.debug(f"Binary SimHash: {hex(combined_simhash.value) if combined_features else 'N/A'}")
            
        except Exception as e:
            logger.error(f"SimHash analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _extract_string_features(self) -> List[str]:
        """
        Extract string features from the binary.
        
        Returns:
            List of string features
        """
        string_features = []
        
        try:
            # Extract strings using r2pipe
            strings_data = safe_cmd_list(self.r2, 'izj')
            
            if isinstance(strings_data, list):
                for string_entry in strings_data:
                    if isinstance(string_entry, dict) and 'string' in string_entry:
                        string_value = string_entry['string']
                        
                        # Filter strings by length and content
                        if (len(string_value) >= self.min_string_length and 
                            self._is_useful_string(string_value)):
                            
                            # Add string as-is
                            string_features.append(f"STR:{string_value}")
                            
                            # Add string length category
                            length_category = self._get_length_category(len(string_value))
                            string_features.append(f"STRLEN:{length_category}")
                            
                            # Add string type indicators
                            string_type = self._classify_string_type(string_value)
                            if string_type:
                                string_features.append(f"STRTYPE:{string_type}")
            
            # Also extract strings from data sections
            data_strings = self._extract_data_section_strings()
            string_features.extend(data_strings)
            
            logger.debug(f"Extracted {len(string_features)} string features")
            return string_features
            
        except Exception as e:
            logger.debug(f"Error extracting string features: {e}")
            return []
    
    def _extract_opcodes_features(self) -> List[str]:
        """
        Extract opcode/instruction features from the binary.
        
        Returns:
            List of opcode features
        """
        opcode_features = []
        
        try:
            # Ensure analysis is complete
            self.r2.cmd("aaa")
            
            # Extract all functions
            functions = safe_cmd_list(self.r2, 'aflj')
            
            if not functions:
                logger.debug("No functions found for opcode extraction, trying alternative methods")
                # Try alternative function discovery
                functions = safe_cmd_list(self.r2, 'afl')
                if not functions:
                    return []
            
            # Process each function
            for func in functions:
                if not isinstance(func, dict):
                    continue
                
                # Handle both 'offset' and 'addr' fields
                func_addr = func.get('offset') or func.get('addr')
                if func_addr is None:
                    continue
                
                func_name = func.get('name', f"func_{func_addr}")
                
                # Seek to function and extract instructions
                self.r2.cmd(f's {func_addr}')
                
                # Get function instructions
                func_opcodes = self._extract_function_opcodes(func_name)
                if func_opcodes:
                    opcode_features.extend(func_opcodes)
                    logger.debug(f"Extracted {len(func_opcodes)} opcodes from {func_name}")
                
                # Limit total opcodes to avoid memory issues
                if len(opcode_features) > 10000:
                    logger.debug("Opcode feature limit reached, truncating")
                    break
            
            logger.debug(f"Extracted {len(opcode_features)} opcode features from {len(functions)} functions")
            return opcode_features
            
        except Exception as e:
            logger.debug(f"Error extracting opcode features: {e}")
            return []
    
    def _extract_function_features(self) -> Dict[str, Dict[str, Any]]:
        """
        Extract per-function SimHash features.
        
        Returns:
            Dictionary of function features with SimHash values
        """
        function_features = {}
        
        try:
            # Extract all functions
            functions = safe_cmd_list(self.r2, 'aflj')
            
            if not functions:
                return {}
            
            for func in functions:
                if not isinstance(func, dict) or 'offset' not in func:
                    continue
                
                func_addr = func['offset']
                func_name = func.get('name', f"func_{func_addr}")
                func_size = func.get('size', 0)
                
                # Extract features for this specific function
                self.r2.cmd(f's {func_addr}')
                
                func_opcodes = self._extract_function_opcodes(func_name)
                if not func_opcodes:
                    continue
                
                # Create SimHash for this function
                try:
                    func_simhash = Simhash(func_opcodes)
                    
                    function_features[func_name] = {
                        'addr': func_addr,
                        'size': func_size,
                        'simhash': func_simhash.value,
                        'simhash_hex': hex(func_simhash.value),
                        'feature_count': len(func_opcodes),
                        'unique_opcodes': len(set(func_opcodes))
                    }
                    
                except Exception as e:
                    logger.debug(f"Error creating SimHash for function {func_name}: {e}")
                    continue
            
            logger.debug(f"Extracted SimHash features for {len(function_features)} functions")
            return function_features
            
        except Exception as e:
            logger.debug(f"Error extracting function features: {e}")
            return {}
    
    def _extract_function_opcodes(self, func_name: str) -> List[str]:
        """
        Extract opcodes from a specific function.
        
        Args:
            func_name: Function name for logging
            
        Returns:
            List of opcode features
        """
        opcodes = []
        
        try:
            # Method 1: Try pdfj (print disassembly function JSON)
            disasm = safe_cmdj(self.r2, "pdfj", {})
            if disasm and 'ops' in disasm:
                for i, op in enumerate(disasm['ops']):
                    if i >= self.max_instructions_per_function:
                        break
                    
                    if isinstance(op, dict) and 'mnemonic' in op:
                        mnemonic = op['mnemonic'].strip().lower()
                        if mnemonic:
                            # Add basic mnemonic
                            opcodes.append(f"OP:{mnemonic}")
                            
                            # Add opcode type classification
                            op_type = self._classify_opcode_type(mnemonic)
                            if op_type:
                                opcodes.append(f"OPTYPE:{op_type}")
                            
                            # Add instruction patterns (bigrams)
                            if i > 0 and i < len(disasm['ops']) - 1:
                                prev_op = disasm['ops'][i-1]
                                if isinstance(prev_op, dict) and 'mnemonic' in prev_op:
                                    prev_mnemonic = prev_op['mnemonic'].strip().lower()
                                    opcodes.append(f"BIGRAM:{prev_mnemonic}→{mnemonic}")
                
                return opcodes
            
            # Method 2: Fallback to pdj
            disasm_list = safe_cmd_list(self.r2, f"pdj {self.max_instructions_per_function}")
            if isinstance(disasm_list, list):
                for i, op in enumerate(disasm_list):
                    if isinstance(op, dict) and 'mnemonic' in op:
                        mnemonic = op['mnemonic'].strip().lower()
                        if mnemonic:
                            opcodes.append(f"OP:{mnemonic}")
                            
                            op_type = self._classify_opcode_type(mnemonic)
                            if op_type:
                                opcodes.append(f"OPTYPE:{op_type}")
                
                return opcodes
            
        except Exception as e:
            logger.debug(f"Error extracting opcodes from function {func_name}: {e}")
        
        return opcodes
    
    def _extract_data_section_strings(self) -> List[str]:
        """Extract strings from data sections."""
        data_strings = []
        
        try:
            # Get data section strings
            sections = safe_cmd_list(self.r2, 'iSj')
            if isinstance(sections, list):
                for section in sections:
                    if isinstance(section, dict) and section.get('name', '').startswith('.data'):
                        # Extract strings from data section
                        section_addr = section.get('vaddr', 0)
                        section_size = section.get('size', 0)
                        
                        if section_addr and section_size:
                            self.r2.cmd(f's {section_addr}')
                            section_strings = self.r2.cmd(f'ps {min(section_size, 1024)}')
                            
                            if section_strings and len(section_strings.strip()) >= self.min_string_length:
                                data_strings.append(f"DATASTR:{section_strings.strip()}")
        
        except Exception as e:
            logger.debug(f"Error extracting data section strings: {e}")
        
        return data_strings
    
    def _is_useful_string(self, string_value: str) -> bool:
        """Check if a string is useful for SimHash analysis."""
        # Filter out very common or useless strings
        useless_patterns = [
            r'^\s*$',  # Empty or whitespace only
            r'^[0-9]+$',  # Numbers only
            r'^[a-f0-9]{8,}$',  # Hex strings
        ]
        
        import re
        for pattern in useless_patterns:
            if re.match(pattern, string_value, re.IGNORECASE):
                return False
        
        # Check for printable characters
        printable_ratio = sum(1 for c in string_value if c.isprintable()) / len(string_value)
        return printable_ratio > 0.8
    
    def _get_length_category(self, length: int) -> str:
        """Categorize string length."""
        if length < 8:
            return "short"
        elif length < 32:
            return "medium"
        elif length < 128:
            return "long"
        else:
            return "very_long"
    
    def _classify_string_type(self, string_value: str) -> Optional[str]:
        """Classify string type for feature extraction."""
        import re
        
        # URL pattern
        if re.match(r'https?://', string_value, re.IGNORECASE):
            return "url"
        
        # File path pattern
        if re.match(r'[a-z]:\\|/', string_value, re.IGNORECASE):
            return "path"
        
        # Registry key pattern
        if re.match(r'HKEY_|SOFTWARE\\|SYSTEM\\', string_value, re.IGNORECASE):
            return "registry"
        
        # API or function name pattern
        if re.match(r'^[A-Z][a-zA-Z0-9_]*[A-Z]', string_value):
            return "api"
        
        # Error message pattern
        if any(word in string_value.lower() for word in ['error', 'failed', 'exception', 'invalid']):
            return "error"
        
        return None
    
    def _classify_opcode_type(self, mnemonic: str) -> Optional[str]:
        """Classify opcode type for feature extraction."""
        # Control flow instructions
        if mnemonic in ['jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jl', 'jge', 'jle', 'call', 'ret']:
            return "control"
        
        # Data movement
        if mnemonic in ['mov', 'lea', 'push', 'pop', 'xchg']:
            return "data"
        
        # Arithmetic
        if mnemonic in ['add', 'sub', 'mul', 'div', 'inc', 'dec', 'neg']:
            return "arithmetic"
        
        # Logical
        if mnemonic in ['and', 'or', 'xor', 'not', 'shl', 'shr', 'rol', 'ror']:
            return "logical"
        
        # Comparison
        if mnemonic in ['cmp', 'test']:
            return "compare"
        
        # String operations
        if mnemonic.startswith('str') or mnemonic.startswith('rep'):
            return "string"
        
        return "other"
    
    def _find_similar_functions(self, function_features: Dict[str, Dict[str, Any]], 
                              max_distance: int = 10) -> List[Dict[str, Any]]:
        """
        Find groups of similar functions based on SimHash distance.
        
        Args:
            function_features: Dictionary of function features
            max_distance: Maximum Hamming distance for similarity
            
        Returns:
            List of similar function groups
        """
        try:
            if not SIMHASH_AVAILABLE:
                return []
            
            similar_groups = []
            processed_functions = set()
            
            func_names = list(function_features.keys())
            
            for i, func1_name in enumerate(func_names):
                if func1_name in processed_functions:
                    continue
                
                func1_data = function_features[func1_name]
                func1_simhash = Simhash(func1_data['simhash'])
                
                similar_funcs = [func1_name]
                processed_functions.add(func1_name)
                
                # Compare with remaining functions
                for j, func2_name in enumerate(func_names[i+1:], i+1):
                    if func2_name in processed_functions:
                        continue
                    
                    func2_data = function_features[func2_name]
                    func2_simhash = Simhash(func2_data['simhash'])
                    
                    # Calculate Hamming distance
                    distance = func1_simhash.distance(func2_simhash)
                    
                    if distance <= max_distance:
                        similar_funcs.append(func2_name)
                        processed_functions.add(func2_name)
                
                # Add group if it has more than one function
                if len(similar_funcs) > 1:
                    similar_groups.append({
                        'functions': similar_funcs,
                        'count': len(similar_funcs),
                        'representative_hash': hex(func1_data['simhash']),
                        'max_distance': max_distance
                    })
            
            # Sort by group size
            similar_groups.sort(key=lambda x: x['count'], reverse=True)
            
            return similar_groups
            
        except Exception as e:
            logger.error(f"Error finding similar functions: {e}")
            return []
    
    def calculate_similarity(self, other_simhash_value: int, hash_type: str = 'combined') -> Dict[str, Any]:
        """
        Calculate similarity between this binary and another SimHash value.
        
        Args:
            other_simhash_value: SimHash value to compare against
            hash_type: Type of hash to use ('combined', 'strings', 'opcodes')
            
        Returns:
            Dictionary with similarity metrics
        """
        if not SIMHASH_AVAILABLE:
            return {'error': 'simhash library not available'}
        
        try:
            # Get current analysis results
            results = self.analyze()
            
            if not results.get('available'):
                return {'error': 'SimHash analysis not available'}
            
            # Get the appropriate hash
            current_hash = None
            if hash_type == 'combined' and results.get('combined_simhash'):
                current_hash = results['combined_simhash']['hash']
            elif hash_type == 'strings' and results.get('strings_simhash'):
                current_hash = results['strings_simhash']['hash']
            elif hash_type == 'opcodes' and results.get('opcodes_simhash'):
                current_hash = results['opcodes_simhash']['hash']
            
            if current_hash is None:
                return {'error': f'No {hash_type} SimHash available'}
            
            # Calculate distance
            current_simhash = Simhash(current_hash)
            other_simhash = Simhash(other_simhash_value)
            
            distance = current_simhash.distance(other_simhash)
            
            # Interpret similarity
            if distance == 0:
                similarity_level = "identical"
            elif distance <= 5:
                similarity_level = "very_similar"
            elif distance <= 15:
                similarity_level = "similar"
            elif distance <= 25:
                similarity_level = "somewhat_similar"
            else:
                similarity_level = "different"
            
            return {
                'distance': distance,
                'similarity_level': similarity_level,
                'current_hash': hex(current_hash),
                'other_hash': hex(other_simhash_value),
                'hash_type': hash_type
            }
            
        except Exception as e:
            logger.error(f"Error calculating similarity: {e}")
            return {'error': str(e)}
    
    @staticmethod
    def is_available() -> bool:
        """
        Check if SimHash analysis is available.
        
        Returns:
            True if simhash library is available
        """
        return SIMHASH_AVAILABLE
    
    @staticmethod
    def calculate_simhash_from_file(filepath: str) -> Optional[Dict[str, Any]]:
        """
        Calculate SimHash directly from a file path.
        
        Args:
            filepath: Path to the binary file
            
        Returns:
            SimHash analysis results or None if calculation fails
        """
        try:
            import r2pipe
            
            with r2pipe.open(filepath, flags=['-2']) as r2:
                analyzer = SimHashAnalyzer(r2, filepath)
                return analyzer.analyze()
                
        except Exception as e:
            logger.error(f"Error calculating SimHash from file: {e}")
            return None 