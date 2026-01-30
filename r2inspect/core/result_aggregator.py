#!/usr/bin/env python3
"""
r2inspect Core Result Aggregator - Aggregates and summarizes analysis results

This module provides the ResultAggregator class that generates executive
summaries, indicators, and recommendations from analysis results.

Architecture:
    - Aggregator Pattern: Collects and combines results from multiple sources
    - Facade Pattern: Provides simplified summary generation interface

Copyright (C) 2025 Marc Rivero Lopez
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

from typing import Any

from ..utils.logger import get_logger

logger = get_logger(__name__)


class ResultAggregator:
    """
    Aggregates analysis results and generates summaries.

    This class encapsulates the logic for generating executive summaries,
    threat indicators, and security recommendations from analysis results.

    The class is stateless and operates purely on the analysis results
    dictionary passed to its methods.
    """

    def generate_indicators(self, analysis_results: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Generate suspicious indicators based on analysis results.

        Analyzes the results from various analysis stages and identifies
        potential threats or suspicious patterns.

        Args:
            analysis_results: Dictionary containing all analysis results

        Returns:
            List of indicator dictionaries with type, description, and severity
        """
        indicators = []

        # Check for packed files
        if analysis_results.get("packer", {}).get("is_packed"):
            indicators.append(
                {
                    "type": "Packer",
                    "description": f"File appears to be packed with "
                    f"{analysis_results['packer'].get('packer_type', 'Unknown')}",
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

    def generate_executive_summary(self, analysis_results: dict[str, Any]) -> dict[str, Any]:
        """
        Generate executive summary for quick consumption.

        Creates a high-level overview of the analysis results suitable
        for quick review by analysts or automated systems.

        Args:
            analysis_results: Dictionary containing all analysis results

        Returns:
            Dictionary containing structured summary with:
            - file_overview: Basic file information
            - security_assessment: Security feature analysis
            - threat_indicators: Detected threats and risks
            - technical_details: Technical specifications
            - recommendations: Suggested actions
        """
        try:
            return {
                "file_overview": self._build_file_overview(analysis_results),
                "security_assessment": self._build_security_assessment(analysis_results),
                "threat_indicators": self._build_threat_indicators(analysis_results),
                "technical_details": self._build_technical_details(analysis_results),
                "recommendations": self._generate_recommendations(analysis_results),
            }
        except Exception as e:
            logger.error(f"Error generating executive summary: {e}")
            return {"error": str(e)}

    def _build_file_overview(self, analysis_results: dict[str, Any]) -> dict[str, Any]:
        """
        Build the file overview section of the executive summary.

        Extracts basic file information including name, type, size,
        architecture, hashes, compilation time, and toolset.

        Args:
            analysis_results: Dictionary containing all analysis results

        Returns:
            Dictionary with file overview information
        """
        file_info = analysis_results.get("file_info", {})
        pe_info = analysis_results.get("pe_info", {})

        overview = {
            "filename": file_info.get("name", "Unknown"),
            "file_type": file_info.get("file_type", "Unknown"),
            "size": file_info.get("size", 0),
            "architecture": file_info.get("architecture", "Unknown"),
            "md5": file_info.get("md5", "Unknown"),
            "sha256": file_info.get("sha256", "Unknown"),
        }

        # Compilation Info
        if "compilation_timestamp" in pe_info:
            overview["compiled"] = pe_info["compilation_timestamp"]

        # Rich header toolset info
        rich_header = analysis_results.get("rich_header", {})
        if rich_header.get("available") and rich_header.get("compilers"):
            compilers = rich_header["compilers"][:3]  # Top 3
            overview["toolset"] = [
                f"{c.get('compiler_name', 'Unknown')} (Build {c.get('build_number', 0)})"
                for c in compilers
            ]

        return overview

    def _build_security_assessment(self, analysis_results: dict[str, Any]) -> dict[str, Any]:
        """
        Build the security assessment section of the executive summary.

        Extracts security-related information including signing status,
        packer detection, and security feature flags (ASLR, DEP, etc.).

        Args:
            analysis_results: Dictionary containing all analysis results

        Returns:
            Dictionary with security assessment information
        """
        security = analysis_results.get("security", {})
        packer = analysis_results.get("packer", {})

        return {
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

    def _build_threat_indicators(self, analysis_results: dict[str, Any]) -> dict[str, Any]:
        """
        Build the threat indicators section of the executive summary.

        Extracts threat-related indicators including anti-analysis techniques,
        crypto detection, high-risk APIs, and suspicious sections.

        Args:
            analysis_results: Dictionary containing all analysis results

        Returns:
            Dictionary with threat indicator information
        """
        anti_analysis = analysis_results.get("anti_analysis", {})
        crypto = analysis_results.get("crypto", {})
        imports = analysis_results.get("imports", [])

        # Count high-risk imports
        high_risk_imports = [imp for imp in imports if imp.get("risk_score", 0) >= 80]

        return {
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

    def _build_technical_details(self, analysis_results: dict[str, Any]) -> dict[str, Any]:
        """
        Build the technical details section of the executive summary.

        Extracts technical specifications including function count,
        imports, sections, entry point, image base, and hash information.

        Args:
            analysis_results: Dictionary containing all analysis results

        Returns:
            Dictionary with technical details
        """
        functions = analysis_results.get("functions", {})
        sections = analysis_results.get("sections", [])
        imports = analysis_results.get("imports", [])
        pe_info = analysis_results.get("pe_info", {})

        details = {
            "total_functions": functions.get("total_functions", 0),
            "total_imports": len(imports),
            "total_sections": len(sections),
            "entry_point": pe_info.get("entry_point", 0),
            "image_base": pe_info.get("image_base", 0),
        }

        # Add impfuzzy hash if available
        if "impfuzzy" in analysis_results:
            impfuzzy = analysis_results["impfuzzy"]
            if impfuzzy.get("available"):
                details["impfuzzy"] = impfuzzy.get("impfuzzy_hash")

        return details

    def _count_suspicious_sections(self, sections: list[dict[str, Any]]) -> int:
        """
        Count sections with suspicious indicators.

        Args:
            sections: List of section dictionaries from analysis

        Returns:
            Count of sections with suspicious_indicators set
        """
        count = 0
        for section in sections:
            if section.get("suspicious_indicators"):
                count += 1
        return count

    def _generate_recommendations(self, analysis_results: dict[str, Any]) -> list[str]:
        """
        Generate security recommendations based on analysis.

        Analyzes the results and provides actionable security recommendations
        based on identified issues and missing security features.

        Args:
            analysis_results: Dictionary containing all analysis results

        Returns:
            List of recommendation strings
        """
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
                    f"Binary is packed with "
                    f"{packer.get('packer_type', 'unknown packer')} - investigate further"
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


__all__ = ["ResultAggregator"]
