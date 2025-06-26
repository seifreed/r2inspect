#!/usr/bin/env python3
"""
Binbloom Analyzer Module

This module implements Binbloom-style function fingerprinting using Bloom filters.
Bloom filters are space-efficient probabilistic data structures that test whether
an element is a member of a set, with possible false positives but no false negatives.

For binary analysis, this creates compact signatures of functions based on their
instruction mnemonics, useful for:
- Fast function similarity detection
- Compact function fingerprinting
- Probabilistic matching with controlled false positive rates
- Efficient clustering of similar functions

Based on Burton Howard Bloom's 1970 paper on space-efficient probabilistic data structures.
Reference: https://en.wikipedia.org/wiki/Bloom_filter
"""

import hashlib
import pickle
import base64
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import Counter, defaultdict
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmdj, safe_cmd_list

logger = get_logger(__name__)

# Try to import pybloom_live, fall back to error handling
try:
    from pybloom_live import BloomFilter
    BLOOM_AVAILABLE = True
except ImportError:
    logger.warning("pybloom-live not available. Install with: pip install pybloom-live")
    BLOOM_AVAILABLE = False
    BloomFilter = None

class BinbloomAnalyzer:
    """Binbloom-style function analysis using Bloom filters"""
    
    def __init__(self, r2_instance, filepath: str):
        """
        Initialize Binbloom analyzer.
        
        Args:
            r2_instance: Active r2pipe instance
            filepath: Path to the binary file being analyzed
        """
        self.r2 = r2_instance
        self.filepath = filepath
        self.default_capacity = 256  # Default Bloom filter capacity
        self.default_error_rate = 0.001  # 0.1% false positive rate
    
    def analyze(self, capacity: Optional[int] = None, error_rate: Optional[float] = None) -> Dict[str, Any]:
        """
        Perform Binbloom analysis on all functions in the binary.
        
        Args:
            capacity: Bloom filter capacity (default: 256)
            error_rate: False positive rate (default: 0.001)
        
        Returns:
            Dictionary containing Binbloom analysis results
        """
        if not BLOOM_AVAILABLE:
            return {
                'available': False,
                'error': 'pybloom-live library not installed',
                'library_available': False
            }
        
        if capacity is None:
            capacity = self.default_capacity
        if error_rate is None:
            error_rate = self.default_error_rate
        
        logger.debug(f"Starting Binbloom analysis for {self.filepath}")
        
        results = {
            'available': False,
            'library_available': True,
            'function_blooms': {},
            'function_signatures': {},
            'total_functions': 0,
            'analyzed_functions': 0,
            'capacity': capacity,
            'error_rate': error_rate,
            'binary_bloom': None,
            'binary_signature': None,
            'similar_functions': [],
            'unique_signatures': 0,
            'bloom_stats': {},
            'error': None
        }
        
        try:
            # Extract all functions
            functions = self._extract_functions()
            if not functions:
                results['error'] = "No functions found in binary"
                logger.debug("No functions found in binary")
                return results
            
            results['total_functions'] = len(functions)
            logger.debug(f"Found {len(functions)} functions to analyze")
            
            # Analyze functions
            function_blooms = {}
            function_signatures = {}
            all_instructions = set()  # For binary-wide bloom
            analyzed_count = 0
            
            for func in functions:
                func_name = func.get('name', f"func_{func.get('addr', 'unknown')}")
                func_addr = func.get('addr')
                
                if func_addr is None:
                    continue
                
                # Create Bloom filter for function
                bloom_result = self._create_function_bloom(func_addr, func_name, capacity, error_rate)
                if bloom_result:
                    bloom_filter, instructions, signature = bloom_result
                    function_blooms[func_name] = bloom_filter
                    function_signatures[func_name] = {
                        'signature': signature,
                        'instruction_count': len(instructions),
                        'unique_instructions': len(set(instructions)),
                        'addr': func_addr,
                        'size': func.get('size', 0)
                    }
                    all_instructions.update(instructions)
                    analyzed_count += 1
            
            if not function_blooms:
                results['error'] = "No functions could be analyzed for Binbloom"
                logger.debug("No functions could be analyzed for Binbloom")
                return results
            
            # Analyze results
            results['available'] = True
            results['function_blooms'] = self._serialize_blooms(function_blooms)
            results['function_signatures'] = function_signatures
            results['analyzed_functions'] = analyzed_count
            
            # Calculate unique signatures
            signatures = set(sig['signature'] for sig in function_signatures.values())
            results['unique_signatures'] = len(signatures)
            
            # Find similar functions (same signature)
            similar_functions = self._find_similar_functions(function_signatures)
            results['similar_functions'] = similar_functions
            
            # Create binary-wide Bloom filter
            if all_instructions:
                binary_bloom = self._create_binary_bloom(all_instructions, capacity * 2, error_rate)
                if binary_bloom:
                    binary_signature = self._bloom_to_signature(binary_bloom, sorted(all_instructions))
                    results['binary_bloom'] = self._serialize_bloom(binary_bloom)
                    results['binary_signature'] = binary_signature
            
            # Calculate Bloom filter statistics
            bloom_stats = self._calculate_bloom_stats(function_blooms, capacity, error_rate)
            results['bloom_stats'] = bloom_stats
            
            logger.debug(f"Binbloom analysis completed: {analyzed_count}/{len(functions)} functions analyzed")
            logger.debug(f"Found {len(signatures)} unique signatures, {len(similar_functions)} similar function groups")
            
        except Exception as e:
            logger.error(f"Binbloom analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _extract_functions(self) -> List[Dict[str, Any]]:
        """
        Extract all functions from the binary.
        
        Returns:
            List of function dictionaries
        """
        try:
            # Ensure analysis is complete
            self.r2.cmd("aaa")
            
            # Get function list
            functions = safe_cmd_list(self.r2, 'aflj')
            
            if not functions:
                logger.debug("No functions found with 'aflj' command")
                return []
            
            # Filter out invalid functions
            valid_functions = []
            for func in functions:
                if func.get('addr') is not None and func.get('size', 0) > 0:
                    valid_functions.append(func)
            
            logger.debug(f"Extracted {len(valid_functions)} valid functions")
            return valid_functions
            
        except Exception as e:
            logger.error(f"Error extracting functions: {e}")
            return []
    
    def _create_function_bloom(self, func_addr: int, func_name: str, capacity: int, 
                             error_rate: float) -> Optional[Tuple[BloomFilter, List[str], str]]:
        """
        Create a Bloom filter for a specific function.
        
        Args:
            func_addr: Function address
            func_name: Function name for logging
            capacity: Bloom filter capacity
            error_rate: False positive rate
            
        Returns:
            Tuple of (BloomFilter, instructions list, signature) or None if failed
        """
        try:
            # Seek to function
            self.r2.cmd(f's {func_addr}')
            
            # Extract instruction mnemonics
            instructions = self._extract_instruction_mnemonics(func_name)
            if not instructions:
                logger.debug(f"No instructions found for function {func_name}")
                return None
            
            # Create Bloom filter
            bloom_filter = BloomFilter(capacity=capacity, error_rate=error_rate)
            
            # Add instructions to Bloom filter
            # Include both individual instructions and instruction patterns
            for instruction in instructions:
                bloom_filter.add(instruction)
            
            # Add instruction bigrams for better differentiation
            for i in range(len(instructions) - 1):
                bigram = f"{instructions[i]}→{instructions[i+1]}"
                bloom_filter.add(bigram)
            
            # Add instruction frequency patterns
            from collections import Counter
            freq_counter = Counter(instructions)
            for instr, count in freq_counter.items():
                if count > 1:  # Only add frequent instructions
                    bloom_filter.add(f"{instr}*{count}")
            
            # Create signature from Bloom filter
            signature = self._bloom_to_signature(bloom_filter, instructions)
            
            logger.debug(f"Created Bloom filter for {func_name}: {len(instructions)} instructions, signature: {signature[:16]}...")
            return bloom_filter, instructions, signature
            
        except Exception as e:
            logger.debug(f"Error creating Bloom filter for function {func_name}: {e}")
            return None
    
    def _extract_instruction_mnemonics(self, func_name: str) -> List[str]:
        """
        Extract instruction mnemonics from current function.
        
        Args:
            func_name: Function name for logging
            
        Returns:
            List of instruction mnemonics
        """
        instructions = []
        
        try:
            # Method 1: Try pdfj (print disassembly function JSON)
            disasm = safe_cmdj(self.r2, "pdfj", {})
            if disasm and 'ops' in disasm:
                for op in disasm['ops']:
                    if isinstance(op, dict) and 'mnemonic' in op:
                        mnemonic = op['mnemonic']
                        if mnemonic:
                            # Clean and normalize mnemonic
                            clean_mnemonic = mnemonic.strip().lower()
                            if clean_mnemonic:
                                instructions.append(clean_mnemonic)
                
                if instructions:
                    logger.debug(f"Extracted {len(instructions)} mnemonics from {func_name} using pdfj")
                    return instructions
            
            # Method 2: Try pdj with instruction limit
            disasm_list = safe_cmd_list(self.r2, "pdj 200")  # Limit to 200 instructions
            if isinstance(disasm_list, list):
                for op in disasm_list:
                    if isinstance(op, dict) and 'mnemonic' in op:
                        mnemonic = op['mnemonic']
                        if mnemonic:
                            # Clean and normalize mnemonic
                            clean_mnemonic = mnemonic.strip().lower()
                            if clean_mnemonic:
                                instructions.append(clean_mnemonic)
                
                if instructions:
                    logger.debug(f"Extracted {len(instructions)} mnemonics from {func_name} using pdj")
                    return instructions
            
            # Method 3: Fallback to text-based extraction
            instructions_text = self.r2.cmd("pi 100")  # Get up to 100 instructions
            if instructions_text and instructions_text.strip():
                lines = instructions_text.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if line:
                        # Extract mnemonic (first word)
                        mnemonic = line.split()[0]
                        if mnemonic:
                            # Clean and normalize mnemonic
                            clean_mnemonic = mnemonic.strip().lower()
                            if clean_mnemonic:
                                instructions.append(clean_mnemonic)
                
                if instructions:
                    logger.debug(f"Extracted {len(instructions)} mnemonics from {func_name} using pi")
                    return instructions
            
        except Exception as e:
            logger.debug(f"Error extracting mnemonics from {func_name}: {e}")
        
        return instructions
    
    def _bloom_to_signature(self, bloom_filter: BloomFilter, instructions: List[str]) -> str:
        """
        Create a deterministic signature from a Bloom filter.
        
        Args:
            bloom_filter: The Bloom filter
            instructions: Original instructions for deterministic hashing
            
        Returns:
            SHA256 signature string
        """
        try:
            # Create a more detailed signature that includes:
            # 1. Unique instructions (sorted)
            # 2. Instruction frequency patterns
            # 3. Instruction sequence patterns (bigrams)
            
            unique_instructions = sorted(set(instructions))
            
            # Calculate instruction frequencies
            from collections import Counter
            freq_counter = Counter(instructions)
            freq_patterns = []
            for instr in unique_instructions:
                count = freq_counter[instr]
                freq_patterns.append(f"{instr}:{count}")
            
            # Create instruction bigrams for sequence patterns
            bigrams = []
            for i in range(len(instructions) - 1):
                bigram = f"{instructions[i]}→{instructions[i+1]}"
                bigrams.append(bigram)
            
            unique_bigrams = sorted(set(bigrams))
            
            # Combine all features for signature
            signature_components = [
                "UNIQ:" + "|".join(unique_instructions),
                "FREQ:" + "|".join(freq_patterns),
                "BIGR:" + "|".join(unique_bigrams[:20])  # Limit bigrams to avoid very long signatures
            ]
            
            combined = "||".join(signature_components)
            
            # Create SHA256 hash
            signature = hashlib.sha256(combined.encode('utf-8')).hexdigest()
            return signature
            
        except Exception as e:
            logger.error(f"Error creating signature from Bloom filter: {e}")
            return ""
    
    def _create_binary_bloom(self, all_instructions: Set[str], capacity: int, 
                           error_rate: float) -> Optional[BloomFilter]:
        """
        Create a binary-wide Bloom filter from all instructions.
        
        Args:
            all_instructions: Set of all instructions in the binary
            capacity: Bloom filter capacity
            error_rate: False positive rate
            
        Returns:
            BloomFilter or None if creation fails
        """
        try:
            bloom_filter = BloomFilter(capacity=capacity, error_rate=error_rate)
            
            for instruction in all_instructions:
                bloom_filter.add(instruction)
            
            return bloom_filter
            
        except Exception as e:
            logger.error(f"Error creating binary Bloom filter: {e}")
            return None
    
    def _serialize_blooms(self, function_blooms: Dict[str, BloomFilter]) -> Dict[str, str]:
        """
        Serialize Bloom filters to base64 strings for storage/transport.
        
        Args:
            function_blooms: Dictionary of function names to Bloom filters
            
        Returns:
            Dictionary of function names to base64-encoded Bloom filters
        """
        serialized = {}
        
        try:
            for func_name, bloom_filter in function_blooms.items():
                # Serialize Bloom filter to bytes then base64
                bloom_bytes = pickle.dumps(bloom_filter)
                bloom_b64 = base64.b64encode(bloom_bytes).decode('utf-8')
                serialized[func_name] = bloom_b64
                
        except Exception as e:
            logger.error(f"Error serializing Bloom filters: {e}")
        
        return serialized
    
    def _serialize_bloom(self, bloom_filter: BloomFilter) -> str:
        """
        Serialize a single Bloom filter to base64 string.
        
        Args:
            bloom_filter: The Bloom filter to serialize
            
        Returns:
            Base64-encoded Bloom filter
        """
        try:
            bloom_bytes = pickle.dumps(bloom_filter)
            return base64.b64encode(bloom_bytes).decode('utf-8')
        except Exception as e:
            logger.error(f"Error serializing Bloom filter: {e}")
            return ""
    
    def _find_similar_functions(self, function_signatures: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Find groups of functions with identical signatures.
        
        Args:
            function_signatures: Dictionary of function signatures
            
        Returns:
            List of similar function groups
        """
        try:
            # Group functions by signature
            signature_groups = defaultdict(list)
            for func_name, func_data in function_signatures.items():
                signature = func_data['signature']
                signature_groups[signature].append(func_name)
            
            # Find groups with more than one function
            similar_groups = []
            for signature, func_names in signature_groups.items():
                if len(func_names) > 1:
                    similar_groups.append({
                        'signature': signature[:16] + "..." if len(signature) > 16 else signature,
                        'functions': func_names,
                        'count': len(func_names)
                    })
            
            # Sort by group size
            similar_groups.sort(key=lambda x: x['count'], reverse=True)
            
            return similar_groups
            
        except Exception as e:
            logger.error(f"Error finding similar functions: {e}")
            return []
    
    def _calculate_bloom_stats(self, function_blooms: Dict[str, BloomFilter], 
                             capacity: int, error_rate: float) -> Dict[str, Any]:
        """
        Calculate statistics about the Bloom filters.
        
        Args:
            function_blooms: Dictionary of Bloom filters
            capacity: Bloom filter capacity
            error_rate: False positive rate
            
        Returns:
            Dictionary of statistics
        """
        try:
            if not function_blooms:
                return {}
            
            # Calculate average fill rate and other stats
            total_bits_set = 0
            total_capacity = 0
            
            for bloom_filter in function_blooms.values():
                # Access internal bit array if available
                if hasattr(bloom_filter, 'bit_array'):
                    bits_set = sum(bloom_filter.bit_array)
                    total_bits_set += bits_set
                    total_capacity += len(bloom_filter.bit_array)
            
            stats = {
                'total_filters': len(function_blooms),
                'configured_capacity': capacity,
                'configured_error_rate': error_rate,
                'average_fill_rate': (total_bits_set / total_capacity) if total_capacity > 0 else 0.0
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error calculating Bloom stats: {e}")
            return {}
    
    def compare_bloom_filters(self, bloom1: BloomFilter, bloom2: BloomFilter) -> float:
        """
        Calculate similarity between two Bloom filters using Jaccard similarity.
        
        Args:
            bloom1: First Bloom filter
            bloom2: Second Bloom filter
            
        Returns:
            Similarity score between 0.0 and 1.0
        """
        try:
            if not hasattr(bloom1, 'bit_array') or not hasattr(bloom2, 'bit_array'):
                return 0.0
            
            # Calculate Jaccard similarity on bit arrays
            bits1 = set(i for i, bit in enumerate(bloom1.bit_array) if bit)
            bits2 = set(i for i, bit in enumerate(bloom2.bit_array) if bit)
            
            if not bits1 and not bits2:
                return 1.0  # Both empty
            
            if not bits1 or not bits2:
                return 0.0  # One empty
            
            intersection = len(bits1.intersection(bits2))
            union = len(bits1.union(bits2))
            
            return intersection / union if union > 0 else 0.0
            
        except Exception as e:
            logger.error(f"Error comparing Bloom filters: {e}")
            return 0.0
    
    @staticmethod
    def is_available() -> bool:
        """
        Check if Binbloom analysis is available.
        
        Returns:
            True if pybloom-live is available
        """
        return BLOOM_AVAILABLE
    
    @staticmethod
    def deserialize_bloom(bloom_b64: str) -> Optional[BloomFilter]:
        """
        Deserialize a Bloom filter from base64 string.
        
        Args:
            bloom_b64: Base64-encoded Bloom filter
            
        Returns:
            BloomFilter or None if deserialization fails
        """
        try:
            bloom_bytes = base64.b64decode(bloom_b64.encode('utf-8'))
            return pickle.loads(bloom_bytes)
        except Exception as e:
            logger.error(f"Error deserializing Bloom filter: {e}")
            return None
    
    @staticmethod
    def calculate_binbloom_from_file(filepath: str, capacity: Optional[int] = None, 
                                   error_rate: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """
        Calculate Binbloom signatures directly from a file path.
        
        Args:
            filepath: Path to the binary file
            capacity: Bloom filter capacity
            error_rate: False positive rate
            
        Returns:
            Binbloom analysis results or None if calculation fails
        """
        try:
            import r2pipe
            
            with r2pipe.open(filepath, flags=['-2']) as r2:
                analyzer = BinbloomAnalyzer(r2, filepath)
                return analyzer.analyze(capacity, error_rate)
                
        except Exception as e:
            logger.error(f"Error calculating Binbloom from file: {e}")
            return None 