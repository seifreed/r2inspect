#!/usr/bin/env python3
"""Resource analysis helpers."""

from __future__ import annotations

from typing import Any


def run_resource_analysis(analyzer: Any, logger: Any) -> dict[str, Any]:
    """Run resource analysis using the analyzer instance."""
    try:
        result: dict[str, Any] = analyzer._init_result_structure(  # noqa: SLF001
            {
                "has_resources": False,
                "resource_directory": None,
                "total_resources": 0,
                "total_size": 0,
                "resource_types": [],
                "resources": [],
                "version_info": None,
                "manifest": None,
                "icons": [],
                "strings": [],
                "suspicious_resources": [],
                "statistics": {},
            }
        )
        result["available"] = True

        # Get resource directory from data directories
        resource_dir = analyzer._get_resource_directory()  # noqa: SLF001
        if not resource_dir:
            return result

        result["has_resources"] = True
        result["resource_directory"] = resource_dir

        # Parse resource tree using radare2
        resources = analyzer._parse_resources()  # noqa: SLF001
        if resources:
            result["resources"] = resources
            result["total_resources"] = len(resources)

            # Analyze different resource types
            analyzer._analyze_resource_types(result, resources)  # noqa: SLF001

            # Extract specific resource information
            analyzer._extract_version_info(result, resources)  # noqa: SLF001
            analyzer._extract_manifest(result, resources)  # noqa: SLF001
            analyzer._extract_icons(result, resources)  # noqa: SLF001
            analyzer._extract_strings(result, resources)  # noqa: SLF001

            # Calculate statistics
            analyzer._calculate_statistics(result, resources)  # noqa: SLF001

            # Check for suspicious resources
            analyzer._check_suspicious_resources(result, resources)  # noqa: SLF001

        return result

    except Exception as e:
        logger.error(f"Error analyzing resources: {e}")
        result["available"] = False
        result["has_resources"] = False
        result["error"] = str(e)
        return result
