#!/usr/bin/env python3
"""
Example Analyzer: Stack Protection Analyzer
Category: Security
Description: Complete example implementation checking stack protection mechanisms

This is a complete, working example of a Security Feature Analyzer that evaluates
stack buffer overflow protection mechanisms including stack canaries (GS), SafeSEH,
and related security features.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0
See LICENSE file for details

Purpose:
    - Demonstrates security feature checking
    - Shows multiple heuristic aggregation
    - Illustrates scoring and recommendation generation
    - Provides complete security assessment

Usage:
    >>> from r2inspect.modules.stack_protection_analyzer import StackProtectionAnalyzer
    >>> analyzer = StackProtectionAnalyzer(r2=r2_instance)
    >>> result = analyzer.analyze()
    >>> print(f"Stack Cookies: {result['security_features']['Stack_Cookies']['enabled']}")
    >>> print(f"Security Score: {result['security_score']['percentage']}%")
"""

from typing import Any, Dict, List, Set

from ..abstractions import BaseAnalyzer
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd, safe_cmdj

logger = get_logger(__name__)


class StackProtectionAnalyzer(BaseAnalyzer):
    """
    Analyze stack protection mechanisms in binaries.

    This analyzer evaluates stack buffer overflow protection features including:
        - Stack Cookies (GS flag) - Canary values to detect overwrites
        - SafeSEH - Safe Structured Exception Handler chain validation
        - SEHOP - Structured Exception Handler Overwrite Protection
        - Stack frame validation

    The analyzer provides:
        - Boolean status for each protection mechanism
        - Overall stack protection score
        - Vulnerability identification
        - Actionable security recommendations

    Attributes:
        r2: R2Pipe instance for binary analysis

    Example:
        >>> analyzer = StackProtectionAnalyzer(r2=r2)
        >>> result = analyzer.analyze()
        >>> print(f"Grade: {result['security_score']['grade']}")
        >>> if not result['security_features']['Stack_Cookies']['enabled']:
        ...     print("WARNING: Stack cookies disabled!")
        >>> for rec in result['recommendations']:
        ...     print(f"- {rec['recommendation']}")
    """

    # Security scoring weights
    WEIGHT_STACK_COOKIES = 40  # Most important for stack protection
    WEIGHT_SAFE_SEH = 30  # Important for 32-bit binaries
    WEIGHT_NO_SEH = 20  # Good if SEH not used
    WEIGHT_ADDITIONAL = 10  # Other stack features

    # Confidence thresholds
    CONFIDENCE_HIGH = 80
    CONFIDENCE_MEDIUM = 50

    def __init__(self, r2=None, config=None, filepath=None, **kwargs):
        """
        Initialize the stack protection analyzer.

        Args:
            r2: R2Pipe instance for binary analysis (required)
            config: Configuration dictionary (optional)
            filepath: Path to binary file (optional)
            **kwargs: Additional arguments
        """
        super().__init__(r2=r2, config=config, filepath=filepath, **kwargs)

    def analyze(self) -> Dict[str, Any]:
        """
        Perform comprehensive stack protection analysis.

        Checks multiple stack protection features, calculates security score,
        identifies vulnerabilities, and generates recommendations.

        Returns:
            Dict containing:
                - available: bool - Whether analysis completed
                - security_features: Dict[str, Dict] - Feature status details
                - security_score: Dict - Score, percentage, and grade
                - vulnerabilities: List[Dict] - Identified vulnerabilities
                - recommendations: List[Dict] - Security recommendations
                - binary_info: Dict - Basic binary information
                - error: str - Error message if failed (optional)

        Example:
            >>> result = analyzer.analyze()
            >>> if result['available']:
            ...     score = result['security_score']['percentage']
            ...     grade = result['security_score']['grade']
            ...     print(f"Stack Protection Score: {score}% (Grade: {grade})")
        """
        result = self._init_result_structure({
            'security_features': {},
            'security_score': {},
            'vulnerabilities': [],
            'recommendations': [],
            'binary_info': {}
        })

        # Prerequisite checks
        if not self.r2:
            result['error'] = "R2Pipe instance required for stack protection analysis"
            self._log_error("R2Pipe instance not provided")
            return result

        try:
            # Get basic binary information
            self._log_debug("Getting binary information")
            self._get_binary_info(result)

            # Check stack cookies (GS)
            self._log_debug("Checking stack cookies")
            self._check_stack_cookies(result)

            # Check SafeSEH
            self._log_debug("Checking SafeSEH")
            self._check_safe_seh(result)

            # Check NO_SEH flag
            self._log_debug("Checking NO_SEH flag")
            self._check_no_seh(result)

            # Identify vulnerabilities
            self._log_debug("Identifying vulnerabilities")
            self._identify_vulnerabilities(result)

            # Calculate overall security score
            self._log_debug("Calculating security score")
            self._calculate_security_score(result)

            # Generate recommendations
            self._log_debug("Generating security recommendations")
            self._generate_recommendations(result)

            result['available'] = True
            self._log_info(
                f"Stack protection analysis completed: "
                f"Score {result['security_score'].get('percentage', 0)}% "
                f"(Grade {result['security_score'].get('grade', 'N/A')})"
            )

        except Exception as e:
            self._log_error(f"Stack protection analysis failed: {e}")
            result['error'] = str(e)

        return result

    def _get_binary_info(self, result: Dict[str, Any]) -> None:
        """
        Get basic binary information for context.

        Args:
            result: Result dictionary to update
        """
        try:
            bin_info = safe_cmdj(self.r2, "ij", {})
            if bin_info and 'bin' in bin_info:
                binary_data = bin_info['bin']
                result['binary_info'] = {
                    'format': binary_data.get('class', 'Unknown'),
                    'arch': binary_data.get('arch', 'Unknown'),
                    'bits': binary_data.get('bits', 0),
                    'is_64bit': binary_data.get('bits', 0) == 64
                }
        except Exception as e:
            self._log_error(f"Error getting binary info: {e}")

    def _check_stack_cookies(self, result: Dict[str, Any]) -> None:
        """
        Check for stack cookies (GS security).

        Stack cookies (canaries) are placed before return addresses to detect
        buffer overflows. Enabled with /GS compiler flag in MSVC.

        Args:
            result: Result dictionary to update
        """
        try:
            cookie_found = False
            evidence = []

            # Method 1: Check for security cookie in imports
            imports = safe_cmdj(self.r2, "iij", [])
            if imports:
                for imp in imports:
                    imp_name = imp.get('name', '').lower()
                    if '__security_cookie' in imp_name or '__security_init_cookie' in imp_name:
                        cookie_found = True
                        evidence.append(f"Import: {imp.get('name', '')}")

            # Method 2: Check for GS-related symbols in strings
            if not cookie_found:
                strings = safe_cmdj(self.r2, "izzj", [])
                if strings:
                    gs_indicators = ['__GSHandlerCheck', '__security_check_cookie', '/GS']
                    for s in strings[:200]:  # Check first 200 strings
                        string_val = s.get('string', '')
                        for indicator in gs_indicators:
                            if indicator in string_val:
                                cookie_found = True
                                evidence.append(f"String: {indicator}")
                                break
                        if cookie_found:
                            break

            result['security_features']['Stack_Cookies'] = {
                'enabled': cookie_found,
                'description': 'Stack buffer overflow protection (GS)',
                'evidence': evidence if evidence else ['No stack cookie protection detected'],
                'impact': 'Detects stack buffer overflows by validating canary values'
            }

        except Exception as e:
            self._log_error(f"Error checking stack cookies: {e}")
            result['security_features']['Stack_Cookies'] = {
                'enabled': False,
                'description': 'Stack buffer overflow protection (GS)',
                'error': str(e)
            }

    def _check_safe_seh(self, result: Dict[str, Any]) -> None:
        """
        Check for SafeSEH (Safe Structured Exception Handling).

        SafeSEH validates exception handler chains to prevent SEH overwrites.
        Only relevant for 32-bit binaries. Enabled with /SAFESEH linker flag.

        Args:
            result: Result dictionary to update
        """
        try:
            # SafeSEH only applies to 32-bit binaries
            is_32bit = result.get('binary_info', {}).get('bits', 0) == 32

            if not is_32bit:
                result['security_features']['SafeSEH'] = {
                    'enabled': False,
                    'description': 'Safe Structured Exception Handling',
                    'note': 'Not applicable to 64-bit binaries',
                    'impact': 'N/A for 64-bit'
                }
                return

            # Check for SafeSEH in data directories
            data_dirs = safe_cmdj(self.r2, "iDj", [])
            safe_seh_enabled = False

            if data_dirs and isinstance(data_dirs, list):
                for dd in data_dirs:
                    if isinstance(dd, dict):
                        if dd.get('name') == 'LOAD_CONFIG' and dd.get('vaddr', 0) != 0:
                            safe_seh_enabled = True
                            break

            result['security_features']['SafeSEH'] = {
                'enabled': safe_seh_enabled,
                'description': 'Safe Structured Exception Handling',
                'note': 'Load Configuration present' if safe_seh_enabled else 'No SafeSEH table found',
                'impact': 'Prevents SEH chain overwrites in 32-bit binaries'
            }

        except Exception as e:
            self._log_error(f"Error checking SafeSEH: {e}")
            result['security_features']['SafeSEH'] = {
                'enabled': False,
                'description': 'Safe Structured Exception Handling',
                'error': str(e)
            }

    def _check_no_seh(self, result: Dict[str, Any]) -> None:
        """
        Check for NO_SEH flag.

        NO_SEH flag indicates the binary doesn't use exception handlers,
        eliminating SEH-based attacks.

        Args:
            result: Result dictionary to update
        """
        try:
            # Get optional header for DllCharacteristics
            opt_header = safe_cmdj(self.r2, "iHj", {})
            no_seh_enabled = False

            if opt_header and isinstance(opt_header, dict):
                dll_characteristics = opt_header.get('dll_characteristics', 0)
                # 0x0400 = IMAGE_DLLCHARACTERISTICS_NO_SEH
                no_seh_enabled = bool(dll_characteristics & 0x0400)

            result['security_features']['No_SEH'] = {
                'enabled': no_seh_enabled,
                'description': 'No Structured Exception Handlers',
                'note': 'Binary does not use SEH' if no_seh_enabled else 'Binary uses SEH',
                'impact': 'Eliminates SEH-based attack vectors if enabled'
            }

        except Exception as e:
            self._log_error(f"Error checking NO_SEH: {e}")
            result['security_features']['No_SEH'] = {
                'enabled': False,
                'description': 'No Structured Exception Handlers',
                'error': str(e)
            }

    def _identify_vulnerabilities(self, result: Dict[str, Any]) -> None:
        """
        Identify stack-related vulnerabilities.

        Args:
            result: Result dictionary to update
        """
        vulnerabilities = []

        # Check if stack cookies are disabled
        if not result['security_features'].get('Stack_Cookies', {}).get('enabled'):
            vulnerabilities.append({
                'issue': 'No stack cookie protection',
                'description': 'Binary lacks stack buffer overflow detection (GS flag)',
                'severity': 'high',
                'cwe': 'CWE-121'  # Stack-based Buffer Overflow
            })

        # Check SafeSEH for 32-bit binaries
        is_32bit = result.get('binary_info', {}).get('bits', 0) == 32
        if is_32bit:
            safe_seh = result['security_features'].get('SafeSEH', {})
            no_seh = result['security_features'].get('No_SEH', {})

            if not safe_seh.get('enabled') and not no_seh.get('enabled'):
                vulnerabilities.append({
                    'issue': 'Unsafe exception handling',
                    'description': '32-bit binary lacks SafeSEH and NO_SEH protection',
                    'severity': 'medium',
                    'cwe': 'CWE-694'  # Use of Multiple Resources with Duplicate Identifier
                })

        result['vulnerabilities'] = vulnerabilities

    def _calculate_security_score(self, result: Dict[str, Any]) -> None:
        """
        Calculate overall stack protection score.

        Args:
            result: Result dictionary to update with score
        """
        score = 0
        max_score = 0

        # Stack Cookies weight
        max_score += self.WEIGHT_STACK_COOKIES
        if result['security_features'].get('Stack_Cookies', {}).get('enabled'):
            score += self.WEIGHT_STACK_COOKIES

        # SafeSEH weight (only for 32-bit)
        is_32bit = result.get('binary_info', {}).get('bits', 0) == 32
        if is_32bit:
            max_score += self.WEIGHT_SAFE_SEH
            if result['security_features'].get('SafeSEH', {}).get('enabled'):
                score += self.WEIGHT_SAFE_SEH

        # NO_SEH weight
        max_score += self.WEIGHT_NO_SEH
        if result['security_features'].get('No_SEH', {}).get('enabled'):
            score += self.WEIGHT_NO_SEH

        # Subtract points for vulnerabilities
        for vuln in result.get('vulnerabilities', []):
            if vuln['severity'] == 'high':
                score -= 10
            elif vuln['severity'] == 'medium':
                score -= 5

        # Ensure score doesn't go below 0
        score = max(0, score)

        result['security_score'] = {
            'score': score,
            'max_score': max_score,
            'percentage': round((score / max_score * 100) if max_score > 0 else 0, 1),
            'grade': self._get_security_grade(score, max_score)
        }

    def _get_security_grade(self, score: int, max_score: int) -> str:
        """
        Convert numerical score to letter grade.

        Args:
            score: Achieved score
            max_score: Maximum possible score

        Returns:
            Letter grade (A-F)
        """
        if max_score == 0:
            return "Unknown"

        percentage = (score / max_score) * 100

        if percentage >= 90:
            return "A"
        elif percentage >= 80:
            return "B"
        elif percentage >= 70:
            return "C"
        elif percentage >= 60:
            return "D"
        else:
            return "F"

    def _generate_recommendations(self, result: Dict[str, Any]) -> None:
        """
        Generate security recommendations based on analysis.

        Args:
            result: Result dictionary to update with recommendations
        """
        recommendations = []

        # Check stack cookies
        if not result['security_features'].get('Stack_Cookies', {}).get('enabled'):
            recommendations.append({
                'priority': 'high',
                'feature': 'Stack Cookies',
                'recommendation': 'Enable stack cookies with /GS compiler flag (MSVC) or -fstack-protector (GCC)',
                'impact': 'Detects stack buffer overflows before they can corrupt return addresses',
                'compiler_flags': 'MSVC: /GS, GCC: -fstack-protector-all'
            })

        # Check SafeSEH for 32-bit
        is_32bit = result.get('binary_info', {}).get('bits', 0) == 32
        if is_32bit and not result['security_features'].get('SafeSEH', {}).get('enabled'):
            recommendations.append({
                'priority': 'medium',
                'feature': 'SafeSEH',
                'recommendation': 'Enable SafeSEH with /SAFESEH linker flag (32-bit only)',
                'impact': 'Prevents exception handler chain overwrites',
                'compiler_flags': 'MSVC: /SAFESEH'
            })

        result['recommendations'] = recommendations

    # Metadata methods

    def get_name(self) -> str:
        """Return analyzer name."""
        return "stack_protection"

    def get_category(self) -> str:
        """Return analyzer category."""
        return "security"

    def get_description(self) -> str:
        """Return analyzer description."""
        return "Analyze stack buffer overflow protection mechanisms (Stack Cookies, SafeSEH)"

    def supports_format(self, file_format: str) -> bool:
        """Check if analyzer supports given file format."""
        supported = self.get_supported_formats()
        return file_format.upper() in supported

    def get_supported_formats(self) -> Set[str]:
        """Return set of supported file formats."""
        return {"PE", "PE32", "PE32+"}

    @staticmethod
    def is_available() -> bool:
        """Check if required dependencies are available."""
        return True  # Only requires r2pipe
