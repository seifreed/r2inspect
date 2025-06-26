"""
Function Analysis Module for r2inspect

This module provides function-level analysis capabilities including:
- MACHOC hash generation (based on Polichombr's approach)
- Function similarity analysis
- Instruction pattern extraction
"""

import hashlib
import logging
from typing import Dict, List, Any, Optional
from ..utils.r2_helpers import safe_cmd_list, safe_cmdj

logger = logging.getLogger(__name__)

class FunctionAnalyzer:
    """Analyzer for function-level analysis and hashing"""
    
    def __init__(self, r2_instance):
        self.r2 = r2_instance
        self.functions_cache = None
    
    def analyze_functions(self) -> Dict[str, Any]:
        """
        Perform comprehensive function analysis
        
        Returns:
            Dict containing function analysis results including MACHOC hashes
        """
        try:
            logger.debug("Starting function analysis...")
            
            # Get all functions
            functions = self._get_functions()
            if not functions:
                logger.warning("No functions found for analysis")
                return {
                    'total_functions': 0,
                    'machoc_hashes': {},
                    'function_stats': {},
                    'error': 'No functions detected'
                }
            
            logger.debug(f"Found {len(functions)} functions for analysis")
            
            # Generate MACHOC hashes
            machoc_hashes = self._generate_machoc_hashes(functions)
            
            # Generate function statistics
            function_stats = self._generate_function_stats(functions)
            
            return {
                'total_functions': len(functions),
                'machoc_hashes': machoc_hashes,
                'function_stats': function_stats,
                'functions_analyzed': len(machoc_hashes)
            }
            
        except Exception as e:
            logger.error(f"Error in function analysis: {str(e)}")
            return {
                'total_functions': 0,
                'machoc_hashes': {},
                'function_stats': {},
                'error': f'Function analysis failed: {str(e)}'
            }
    
    def _get_functions(self) -> List[Dict[str, Any]]:
        """Get all functions from the binary"""
        try:
            if self.functions_cache is None:
                # Ensure analysis is complete
                self.r2.cmd("aaa")
                self.functions_cache = safe_cmd_list(self.r2, "aflj")
            
            return self.functions_cache or []
            
        except Exception as e:
            logger.error(f"Error getting functions: {str(e)}")
            return []
    
    def _generate_machoc_hashes(self, functions: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Generate MACHOC hashes for all functions
        
        MACHOC hash is based on the sequence of instruction mnemonics,
        ignoring operands, addresses, and other specifics.
        
        Args:
            functions: List of function dictionaries from radare2
            
        Returns:
            Dict mapping function names to their MACHOC hashes
        """
        machoc_hashes = {}
        failed_functions = 0
        
        logger.debug(f"Starting MACHOC hash generation for {len(functions)} functions")
        
        for i, func in enumerate(functions):
            try:
                func_name = func.get('name', f"func_{func.get('addr', 'unknown')}")
                func_offset = func.get('addr')  # radare2 uses 'addr' not 'offset'
                func_size = func.get('size', 0)
                
                if func_offset is None:
                    logger.warning(f"No address found for function {func_name}")
                    failed_functions += 1
                    continue
                
                logger.debug(f"Processing function {i+1}/{len(functions)}: {func_name} at 0x{func_offset:x} (size: {func_size})")
                
                # Seek to function
                self.r2.cmd(f"s {func_offset}")
                
                # Try multiple approaches to get disassembly
                disasm = None
                mnemonics = []
                
                # Method 1: Try pdfj (print disassembly function JSON)
                try:
                    disasm = safe_cmdj(self.r2, "pdfj", {})
                    if disasm and 'ops' in disasm:
                        logger.debug(f"pdfj succeeded for {func_name}, got {len(disasm['ops'])} instructions")
                        for op in disasm['ops']:
                            if isinstance(op, dict) and 'opcode' in op:
                                opcode = op['opcode']
                                if opcode and opcode.strip():
                                    # Extract mnemonic (first part of opcode)
                                    mnemonic = opcode.strip().split()[0]
                                    if mnemonic:
                                        mnemonics.append(mnemonic)
                except Exception as e:
                    logger.debug(f"pdfj failed for {func_name}: {str(e)}")
                
                # Method 2: Try pdj with size limit if pdfj failed
                if not mnemonics and func_size > 0:
                    try:
                        # Limit to reasonable size to avoid huge functions
                        max_instructions = min(func_size // 4, 1000)  # Rough estimate
                        disasm_list = safe_cmd_list(self.r2, f"pdj {max_instructions}")
                        if isinstance(disasm_list, list):
                            logger.debug(f"pdj succeeded for {func_name}, got {len(disasm_list)} instructions")
                            for op in disasm_list:
                                if isinstance(op, dict) and 'opcode' in op:
                                    opcode = op['opcode']
                                    if opcode and opcode.strip():
                                        # Extract mnemonic (first part of opcode)
                                        mnemonic = opcode.strip().split()[0]
                                        if mnemonic:
                                            mnemonics.append(mnemonic)
                    except Exception as e:
                        logger.debug(f"pdj failed for {func_name}: {str(e)}")
                
                # Method 3: Try basic disassembly with fixed instruction count
                if not mnemonics:
                    try:
                        # Try with smaller instruction count
                        disasm_list = safe_cmd_list(self.r2, "pdj 50")  # Just first 50 instructions
                        if isinstance(disasm_list, list):
                            logger.debug(f"Basic pdj succeeded for {func_name}, got {len(disasm_list)} instructions")
                            for op in disasm_list:
                                if isinstance(op, dict) and 'opcode' in op:
                                    opcode = op['opcode']
                                    if opcode and opcode.strip():
                                        # Extract mnemonic (first part of opcode)
                                        mnemonic = opcode.strip().split()[0]
                                        if mnemonic:
                                            mnemonics.append(mnemonic)
                    except Exception as e:
                        logger.debug(f"Basic pdj failed for {func_name}: {str(e)}")
                
                # Method 4: Fallback to text-based instruction extraction (pi command)
                if not mnemonics:
                    try:
                        # Use pi command which gives clean mnemonics
                        instructions_text = self.r2.cmd("pi 100")  # Get up to 100 instructions
                        if instructions_text and instructions_text.strip():
                            lines = instructions_text.strip().split('\n')
                            logger.debug(f"pi succeeded for {func_name}, got {len(lines)} instruction lines")
                            for line in lines:
                                line = line.strip()
                                if line:
                                    # Extract mnemonic (first word)
                                    mnemonic = line.split()[0]
                                    if mnemonic:
                                        mnemonics.append(mnemonic)
                    except Exception as e:
                        logger.debug(f"pi failed for {func_name}: {str(e)}")
                
                if not mnemonics:
                    logger.warning(f"No mnemonics found for function {func_name} (size: {func_size})")
                    failed_functions += 1
                    continue
                
                # Create mnemonic signature
                mnemonic_signature = ','.join(mnemonics)
                
                # Generate MACHOC hash (SHA256 of mnemonic sequence)
                machoc_hash = hashlib.sha256(mnemonic_signature.encode('utf-8')).hexdigest()
                
                machoc_hashes[func_name] = machoc_hash
                
                logger.debug(f"Generated MACHOC hash for {func_name}: {machoc_hash[:16]}... ({len(mnemonics)} mnemonics)")
                
            except Exception as e:
                logger.error(f"Error generating MACHOC hash for function {func.get('name', 'unknown')}: {str(e)}")
                failed_functions += 1
                continue
        
        success_count = len(machoc_hashes)
        logger.debug(f"Generated MACHOC hashes for {success_count}/{len(functions)} functions ({failed_functions} failed)")
        
        return machoc_hashes
    
    def _generate_function_stats(self, functions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate statistics about functions"""
        try:
            if not functions:
                return {}
            
            # Basic statistics
            total_functions = len(functions)
            sizes = [func.get('size', 0) for func in functions if func.get('size')]
            
            stats = {
                'total_functions': total_functions,
                'functions_with_size': len(sizes),
            }
            
            if sizes:
                stats.update({
                    'avg_function_size': sum(sizes) / len(sizes),
                    'min_function_size': min(sizes),
                    'max_function_size': max(sizes),
                    'total_code_size': sum(sizes)
                })
            
            # Function types/categories
            function_types = {}
            for func in functions:
                func_type = func.get('type', 'unknown')
                function_types[func_type] = function_types.get(func_type, 0) + 1
            
            stats['function_types'] = function_types
            
            # Top functions by size (if available)
            if sizes:
                functions_with_sizes = [(f.get('name', f'func_{f.get("offset", "?")}'), f.get('size', 0)) 
                                      for f in functions if f.get('size')]
                functions_with_sizes.sort(key=lambda x: x[1], reverse=True)
                stats['largest_functions'] = functions_with_sizes[:10]  # Top 10
            
            return stats
            
        except Exception as e:
            logger.error(f"Error generating function stats: {str(e)}")
            return {'error': f'Stats generation failed: {str(e)}'}
    
    def get_function_similarity(self, machoc_hashes: Dict[str, str]) -> Dict[str, List[str]]:
        """
        Find functions with identical MACHOC hashes (potential duplicates or similar functions)
        
        Args:
            machoc_hashes: Dict of function names to MACHOC hashes
            
        Returns:
            Dict mapping MACHOC hashes to lists of function names that share that hash
        """
        try:
            hash_to_functions = {}
            
            for func_name, machoc_hash in machoc_hashes.items():
                if machoc_hash not in hash_to_functions:
                    hash_to_functions[machoc_hash] = []
                hash_to_functions[machoc_hash].append(func_name)
            
            # Only return hashes that have multiple functions (similarities)
            similarities = {h: funcs for h, funcs in hash_to_functions.items() if len(funcs) > 1}
            
            if similarities:
                logger.debug(f"Found {len(similarities)} MACHOC hash collisions indicating similar functions")
            
            return similarities
            
        except Exception as e:
            logger.error(f"Error calculating function similarity: {str(e)}")
            return {}
    
    def generate_machoc_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a summary of MACHOC analysis results"""
        try:
            machoc_hashes = analysis_results.get('machoc_hashes', {})
            
            if not machoc_hashes:
                return {'error': 'No MACHOC hashes available'}
            
            # Find similarities
            similarities = self.get_function_similarity(machoc_hashes)
            
            # Generate summary
            summary = {
                'total_functions_hashed': len(machoc_hashes),
                'unique_machoc_hashes': len(set(machoc_hashes.values())),
                'duplicate_function_groups': len(similarities),
                'total_duplicate_functions': sum(len(funcs) for funcs in similarities.values()),
            }
            
            # Add similarity details if found
            if similarities:
                summary['similarities'] = similarities
                
                # Most common patterns
                pattern_counts = [(len(funcs), hash_val[:16]) for hash_val, funcs in similarities.items()]
                pattern_counts.sort(reverse=True)
                summary['most_common_patterns'] = pattern_counts[:5]  # Top 5
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating MACHOC summary: {str(e)}")
            return {'error': f'Summary generation failed: {str(e)}'}
    
    def _calculate_cyclomatic_complexity(self, func: Dict[str, Any]) -> int:
        """Calculate cyclomatic complexity for a function"""
        try:
            func_addr = func.get('addr')
            if not func_addr:
                return 0
            
            # Seek to function
            self.r2.cmd(f"s {func_addr}")
            
            # Get control flow graph information
            cfg_info = safe_cmdj(self.r2, "agfj", {})
            
            if not cfg_info or not isinstance(cfg_info, list):
                return 0
            
            # For each basic block, count edges
            edges = 0
            nodes = len(cfg_info)
            
            for block in cfg_info:
                if isinstance(block, dict) and 'jump' in block:
                    edges += 1
                if isinstance(block, dict) and 'fail' in block:
                    edges += 1
            
            # Cyclomatic complexity = E - N + 2P (where P=1 for single component)
            # Simplified: edges - nodes + 2
            complexity = max(edges - nodes + 2, 1)
            return complexity
            
        except Exception as e:
            logger.debug(f"Error calculating cyclomatic complexity: {e}")
            return 0
    
    def _classify_function_type(self, func_name: str, func: Dict[str, Any]) -> str:
        """Classify function type based on name and characteristics"""
        try:
            name = func_name.lower()
            
            # Library functions
            if any(prefix in name for prefix in ['lib', 'msvcrt', 'kernel32', 'ntdll', 'user32']):
                return 'library'
            
            # Thunk functions
            if 'thunk' in name or name.startswith('j_') or func.get('size', 0) < 10:
                return 'thunk'
            
            # User functions (main, custom names)
            if any(keyword in name for keyword in ['main', 'sub_', 'fcn.', 'func_']):
                return 'user'
            
            return 'unknown'
            
        except:
            return 'unknown'
    
    def _calculate_std_dev(self, values: List[float]) -> float:
        """Calculate standard deviation"""
        try:
            if len(values) < 2:
                return 0.0
            
            mean = sum(values) / len(values)
            variance = sum((x - mean) ** 2 for x in values) / len(values)
            return variance ** 0.5
            
        except:
            return 0.0
    
    def _analyze_function_coverage(self, functions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze function coverage and detection quality"""
        try:
            coverage = {
                'total_functions': len(functions),
                'functions_with_size': 0,
                'functions_with_blocks': 0,
                'total_code_coverage': 0,
                'avg_function_size': 0
            }
            
            sizes = []
            for func in functions:
                size = func.get('size', 0)
                if size > 0:
                    coverage['functions_with_size'] += 1
                    sizes.append(size)
                
                if func.get('nbbs', 0) > 0:
                    coverage['functions_with_blocks'] += 1
            
            if sizes:
                coverage['total_code_coverage'] = sum(sizes)
                coverage['avg_function_size'] = sum(sizes) / len(sizes)
            
            # Calculate coverage percentage
            if coverage['total_functions'] > 0:
                coverage['size_coverage_percent'] = (coverage['functions_with_size'] / coverage['total_functions']) * 100
                coverage['block_coverage_percent'] = (coverage['functions_with_blocks'] / coverage['total_functions']) * 100
            
            return coverage
            
        except Exception as e:
            logger.debug(f"Error analyzing function coverage: {e}")
            return {} 