#!/usr/bin/env python3
"""
Cryptography Detection Module using r2pipe
"""

import re
import struct
import math
from typing import Dict, List, Any, Optional
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmdj, safe_cmd

logger = get_logger(__name__)

class CryptoAnalyzer:
    """Cryptographic patterns detection using radare2"""
    
    def __init__(self, r2, config):
        self.r2 = r2
        self.config = config
        
        # Known crypto constants
        self.crypto_constants = {
            # AES S-Box
            'aes_sbox': [
                0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
                0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
            ],
            # MD5 constants
            'md5_h': [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            # SHA1 constants  
            'sha1_h': [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            # SHA256 constants
            'sha256_k': [
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
            ],
            # DES S-boxes indicators
            'des_sbox': [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            # RSA common exponents
            'rsa_exponents': [3, 17, 65537]
        }
    
    def detect(self) -> Dict[str, Any]:
        """Detect cryptographic patterns and algorithms"""
        crypto_info = {
            'algorithms': [],
            'constants': [],
            'entropy_analysis': {},
            'suspicious_patterns': []
        }
        
        try:
            # Detect crypto constants
            crypto_info['constants'] = self._detect_crypto_constants()
            
            # Detect algorithms from strings
            crypto_info['algorithms'] = self._detect_crypto_algorithms()
            
            # Analyze entropy
            crypto_info['entropy_analysis'] = self._analyze_entropy()
            
            # Find suspicious patterns
            crypto_info['suspicious_patterns'] = self._find_suspicious_patterns()
            
        except Exception as e:
            logger.error(f"Error in crypto detection: {e}")
            crypto_info['error'] = str(e)
            
        return crypto_info
    
    def _detect_crypto_constants(self) -> List[Dict[str, Any]]:
        """Search for known cryptographic constants"""
        found_constants = []
        
        try:
            for const_name, const_values in self.crypto_constants.items():
                for value in const_values:
                    if isinstance(value, int):
                        # Search for 32-bit integer constants
                        hex_value = f"{value:08x}"
                        search_cmd = f"/x {hex_value}"
                        result = safe_cmd(self.r2, search_cmd)
                        
                        if result and result.strip():
                            found_constants.append({
                                'type': const_name,
                                'value': hex(value),
                                'addresses': self._parse_search_results(result)
                            })
                            
        except Exception as e:
            logger.error(f"Error detecting crypto constants: {e}")
            
        return found_constants
    
    def _detect_crypto_apis(self) -> List[Dict[str, Any]]:
        """Detect cryptographic API calls"""
        crypto_apis = []
        
        try:
            # Get imports
            imports = safe_cmdj(self.r2, 'iij')
            
            if imports:
                # Modern BCrypt/CNG APIs (Windows Vista+)
                bcrypt_apis = {
                    'BCryptOpenAlgorithmProvider': 'BCrypt',
                    'BCryptCreateHash': 'Hash',
                    'BCryptEncrypt': 'BCrypt',
                    'BCryptDecrypt': 'BCrypt',
                    'BCryptGenerateKeyPair': 'BCrypt',
                    'NCryptCreatePersistedKey': 'CNG',
                    'NCryptEncrypt': 'CNG'
                }
                
                # Legacy CryptoAPI
                cryptoapi_apis = {
                    'CryptAcquireContext': 'CryptoAPI',
                    'CryptCreateHash': 'Hash',
                    'CryptHashData': 'Hash',
                    'CryptEncrypt': 'CryptoAPI',
                    'CryptDecrypt': 'CryptoAPI',
                    'CryptGenKey': 'CryptoAPI',
                    'CryptDeriveKey': 'CryptoAPI'
                }
                
                # OpenSSL APIs
                openssl_apis = {
                    'EVP_EncryptInit': 'OpenSSL',
                    'EVP_DecryptInit': 'OpenSSL',
                    'AES_encrypt': 'AES',
                    'AES_decrypt': 'AES',
                    'RSA_public_encrypt': 'RSA',
                    'RSA_private_decrypt': 'RSA',
                    'MD5_Init': 'MD5',
                    'SHA1_Init': 'SHA1',
                    'SHA256_Init': 'SHA256'
                }
                
                all_apis = {**bcrypt_apis, **cryptoapi_apis, **openssl_apis}
                
                for imp in imports:
                    func_name = imp.get('name', '')
                    for api_name, algo_type in all_apis.items():
                        if api_name in func_name:
                            crypto_apis.append({
                                'function': func_name,
                                'algorithm': algo_type,
                                'library': imp.get('libname', 'unknown'),
                                'address': hex(imp.get('plt', 0))
                            })
                            
        except Exception as e:
            logger.error(f"Error detecting crypto APIs: {e}")
            
        return crypto_apis
    
    def _detect_crypto_algorithms(self) -> List[Dict[str, Any]]:
        """Detect crypto algorithms from strings and API calls with confidence scoring"""
        algorithms = []
        detected_algos = {}  # Track duplicates
        
        try:
            # First, check for crypto API calls (highest confidence)
            crypto_apis = self._detect_crypto_apis()
            for api_info in crypto_apis:
                algo_name = api_info['algorithm']
                if algo_name not in detected_algos:
                    detected_algos[algo_name] = []
                detected_algos[algo_name].append({
                    'evidence_type': 'API Call',
                    'evidence': api_info['function'],
                    'confidence': 0.9,
                    'address': api_info['address']
                })
            
            # Second, check for crypto constants (high confidence)
            constants = self._detect_crypto_constants()
            for const_info in constants:
                algo_map = {
                    'aes_sbox': 'AES',
                    'md5_h': 'MD5',
                    'sha1_h': 'SHA1',
                    'sha256_k': 'SHA256',
                    'des_sbox': 'DES'
                }
                
                algo_name = algo_map.get(const_info['type'])
                if algo_name:
                    if algo_name not in detected_algos:
                        detected_algos[algo_name] = []
                    detected_algos[algo_name].append({
                        'evidence_type': 'Crypto Constant',
                        'evidence': f"{const_info['type']}: {const_info['value']}",
                        'confidence': 0.8,
                        'address': const_info['addresses'][0] if const_info['addresses'] else 'N/A'
                    })
            
            # Third, check strings (lower confidence, filter noise)
            strings_result = safe_cmdj(self.r2, 'izj')
            
            if strings_result:
                # More specific patterns to reduce false positives
                crypto_patterns = {
                    'AES': [
                        r'\baes\b', r'\brijndael\b', r'advanced.encryption.standard',
                        r'aes[_-]?(128|192|256)', r'aes[_-]?cbc', r'aes[_-]?ecb'
                    ],
                    'DES': [
                        r'\bdes\b', r'3des', r'triple.des', r'data.encryption.standard'
                    ],
                    'RSA': [
                        r'\brsa\b', r'rsa[_-]?key', r'public.key', r'private.key'
                    ],
                    'MD5': [
                        r'\bmd5\b', r'md5.hash', r'message.digest.5'
                    ],
                    'SHA': [
                        r'\bsha[_-]?1\b', r'\bsha[_-]?256\b', r'\bsha[_-]?512\b',
                        r'secure.hash', r'sha[_-]?hash'
                    ],
                    'RC4': [r'\brc4\b', r'\barcfour\b'],
                    'Blowfish': [r'\bblowfish\b'],
                    'Base64': [r'\bbase64\b', r'base.64'],
                    'OpenSSL': [r'\bopenssl\b', r'\bevp_\w+', r'ssl.ctx'],
                    'BCrypt': [r'\bbcrypt\b', r'bcrypt\w+', r'cng.dll'],
                    'CryptoAPI': [r'crypt32\.dll', r'advapi32\.dll', r'cryptoapi']
                }
                
                # Filter out noise strings (common false positives)
                noise_patterns = [
                    r'vector.deleting.destructor',
                    r'scalar.deleting.destructor',
                    r'std::', r'class', r'struct',
                    r'__', r'@@', r'?', r'vtable'
                ]
                
                for string_info in strings_result:
                    string_val = string_info.get('string', '').lower()
                    
                    # Skip noise strings
                    if any(re.search(noise, string_val, re.IGNORECASE) for noise in noise_patterns):
                        continue
                    
                    # Skip very short strings
                    if len(string_val) < 3:
                        continue
                    
                    for algo_name, patterns in crypto_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, string_val, re.IGNORECASE):
                                if algo_name not in detected_algos:
                                    detected_algos[algo_name] = []
                                detected_algos[algo_name].append({
                                    'evidence_type': 'String Reference',
                                    'evidence': string_val,
                                    'confidence': 0.4,  # Lower confidence for strings
                                    'address': hex(string_info.get('vaddr', 0))
                                })
                                break
            
            # Consolidate results with confidence scoring
            for algo_name, evidences in detected_algos.items():
                # Calculate overall confidence based on evidence types
                max_confidence = max(e['confidence'] for e in evidences)
                evidence_types = set(e['evidence_type'] for e in evidences)
                
                # Boost confidence if multiple evidence types
                if len(evidence_types) > 1:
                    max_confidence = min(max_confidence + 0.2, 0.95)
                
                algorithms.append({
                    'algorithm': algo_name,
                    'confidence': max_confidence,
                    'evidence_count': len(evidences),
                    'evidence_types': list(evidence_types),
                    'evidences': evidences[:3]  # Limit to top 3 evidences
                })
                                
        except Exception as e:
            logger.error(f"Error detecting crypto algorithms: {e}")
            
        return algorithms
    
    def _analyze_entropy(self) -> Dict[str, Any]:
        """Analyze entropy of different sections"""
        entropy_info = {}
        
        try:
            # Get sections information
            sections = safe_cmdj(self.r2, 'iSj')
            
            if sections:
                for section in sections:
                    section_name = section.get('name', 'unknown')
                    section_size = section.get('size', 0)
                    
                    if section_size > 0:
                        # Calculate entropy for this section
                        entropy = self._calculate_section_entropy(section)
                        entropy_info[section_name] = {
                            'entropy': entropy,
                            'size': section_size,
                            'suspicious': entropy > 7.0  # High entropy threshold
                        }
                        
        except Exception as e:
            logger.error(f"Error analyzing entropy: {e}")
            
        return entropy_info
    
    def _calculate_section_entropy(self, section: Dict[str, Any]) -> float:
        """Calculate entropy for a section"""
        try:
            vaddr = section.get('vaddr', 0)
            size = section.get('size', 0)
            
            if size == 0:
                return 0.0
                
            # Read section data
            data_cmd = f"p8 {size} @ {vaddr}"
            hex_data = safe_cmd(self.r2, data_cmd)
            
            if not hex_data:
                return 0.0
                
            # Convert hex to bytes
            try:
                data = bytes.fromhex(hex_data)
            except ValueError:
                return 0.0
                
            # Calculate entropy
            if len(data) == 0:
                return 0.0
                
            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
                
            # Calculate entropy using Shannon entropy formula: -Σ(p * log2(p))
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    p = count / data_len
                    entropy -= p * math.log2(p)
                    
            return entropy
            
        except Exception as e:
            logger.error(f"Error calculating section entropy: {e}")
            return 0.0
    
    def _find_suspicious_patterns(self) -> List[Dict[str, Any]]:
        """Find patterns that might indicate crypto/packing"""
        patterns = []
        
        try:
            # Look for XOR loops (common in crypto and packing)
            xor_patterns = safe_cmd(self.r2, "/c xor")
            if xor_patterns and xor_patterns.strip():
                patterns.append({
                    'type': 'XOR Operations',
                    'description': 'Multiple XOR operations found',
                    'evidence': 'XOR instructions detected'
                })
            
            # Look for bit rotation operations
            rot_patterns = safe_cmd(self.r2, "/c rol,ror")
            if rot_patterns and rot_patterns.strip():
                patterns.append({
                    'type': 'Bit Rotation',
                    'description': 'Bit rotation operations found',
                    'evidence': 'ROL/ROR instructions detected'
                })
            
            # Look for table lookups (S-boxes)
            # This is a simplified check
            mov_patterns = safe_cmd(self.r2, "/c mov.*\\[.*\\+.*\\]")
            if mov_patterns and mov_patterns.strip():
                count = len(mov_patterns.strip().split('\n'))
                if count > 10:  # Threshold for table lookups
                    patterns.append({
                        'type': 'Table Lookups',
                        'description': f'Multiple table lookup patterns found ({count})',
                        'evidence': 'Array/table access patterns'
                    })
                    
        except Exception as e:
            logger.error(f"Error finding suspicious patterns: {e}")
            
        return patterns
    
    def _parse_search_results(self, result: str) -> List[str]:
        """Parse radare2 search results"""
        addresses = []
        
        lines = result.strip().split('\n')
        for line in lines:
            if line.startswith('0x'):
                addr = line.split()[0]
                addresses.append(addr)
                
        return addresses
    
    def detect_crypto_libraries(self) -> List[Dict[str, Any]]:
        """Detect crypto libraries by import analysis"""
        crypto_libs = []
        
        try:
            # Get imports
            imports = safe_cmdj(self.r2, 'iij')
            
            if imports:
                crypto_api_patterns = {
                    'Windows CryptoAPI': [
                        'CryptCreateHash', 'CryptHashData', 'CryptDeriveKey',
                        'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey'
                    ],
                    'OpenSSL': [
                        'EVP_EncryptInit', 'EVP_DecryptInit', 'SSL_new',
                        'RSA_generate_key', 'AES_encrypt'
                    ],
                    'BCrypt': [
                        'BCryptCreateHash', 'BCryptHashData', 'BCryptFinishHash',
                        'BCryptGenerateSymmetricKey', 'BCryptEncrypt'
                    ]
                }
                
                for imp in imports:
                    imp_name = imp.get('name', '')
                    
                    for lib_name, api_list in crypto_api_patterns.items():
                        if any(api in imp_name for api in api_list):
                            crypto_libs.append({
                                'library': lib_name,
                                'api_function': imp_name,
                                'address': hex(imp.get('plt', 0))
                            })
                            
        except Exception as e:
            logger.error(f"Error detecting crypto libraries: {e}")
            
        return crypto_libs 