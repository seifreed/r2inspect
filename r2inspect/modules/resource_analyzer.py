"""PE resource analyzer."""

from typing import Any

from ..abstractions import BaseAnalyzer
from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..domain.services.hashing import calculate_hashes_for_bytes
from ..domain.services.resource_analysis import (
    build_icon_entries,
    build_manifest_info,
    build_resource_statistics,
    build_suspicious_resources,
    check_resource_embedded_pe,
    check_resource_entropy,
    check_resource_rcdata,
    check_resource_size,
    decode_resource_text,
    summarize_resource_types,
)
from ..infrastructure.logging import get_logger
from .resource_support import (
    analyze_resource_data as _analyze_resource_data_impl,
    calculate_statistics as _calculate_statistics_impl,
    check_suspicious_resources as _check_suspicious_resources_impl,
    extract_icons as _extract_icons_impl,
    extract_manifest as _extract_manifest_impl,
    extract_strings as _extract_strings_impl,
    extract_version_info as _extract_version_info_impl,
    parse_version_info as _parse_version_info_impl,
    read_resource_as_string as _read_resource_as_string_impl,
)
from .resource_parsing import ResourceParsingMixin
from .resource_version import ResourceVersionMixin
from .domain_helpers import entropy_from_ints
from .pe_resource_defaults import RESOURCE_TYPES
from .string_extraction import split_null_terminated

logger = get_logger(__name__)


_BASE_RESOURCE_RESULT: dict[str, Any] = {
    "available": False,
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


def _normalize_resources(resources: Any) -> list[dict[str, Any]]:
    if not isinstance(resources, list):
        return []
    return [resource for resource in resources if isinstance(resource, dict)]


def run_resource_analysis(analyzer: Any, analysis_logger: Any) -> dict[str, Any]:
    """Run resource analysis through analyzer-owned entrypoints."""
    result: dict[str, Any] = dict(_BASE_RESOURCE_RESULT)
    try:
        result = analyzer._init_result_structure(dict(_BASE_RESOURCE_RESULT))
        result["available"] = True

        resource_dir = analyzer._get_resource_directory()
        if not resource_dir:
            return result

        result["has_resources"] = True
        result["resource_directory"] = resource_dir
        resources = _normalize_resources(analyzer._parse_resources())
        if resources:
            result["resources"] = resources
            result["total_resources"] = len(resources)
            analyzer._analyze_resource_types(result, resources)
            analyzer._extract_version_info(result, resources)
            analyzer._extract_manifest(result, resources)
            analyzer._extract_icons(result, resources)
            analyzer._extract_strings(result, resources)
            analyzer._calculate_statistics(result, resources)
            analyzer._check_suspicious_resources(result, resources)
        else:
            analysis_logger.debug(
                "Resource directory present but no valid resource entries were parsed"
            )
        return result
    except Exception as e:
        analysis_logger.error(
            "Error analyzing resources (resource_dir=%s, parsed=%s): %s",
            bool(result.get("resource_directory")),
            result.get("total_resources", 0),
            e,
        )
        result["available"] = False
        result["has_resources"] = False
        result["error"] = str(e)
        return result


class ResourceAnalyzer(
    ResourceVersionMixin, ResourceParsingMixin, CommandHelperMixin, BaseAnalyzer
):
    """Analyzes resources in PE files."""

    # Resource type constants
    RESOURCE_TYPES = RESOURCE_TYPES

    def __init__(self, adapter: Any) -> None:
        """Initialize the analyzer."""
        super().__init__(adapter=adapter)

    def analyze(self) -> dict[str, Any]:
        """Analyze PE resources."""
        return run_resource_analysis(self, logger)

    def _analyze_resource_data(self, resource: dict[str, Any]) -> None:
        """Analyze resource data (entropy, hashes)."""
        _analyze_resource_data_impl(
            self,
            resource,
            logger=logger,
            calculate_hashes_for_bytes=calculate_hashes_for_bytes,
        )

    def _calculate_entropy(self, data: list[int]) -> float:
        """Calculate Shannon entropy."""
        return round(entropy_from_ints(data), 4)

    def _analyze_resource_types(
        self, result: dict[str, Any], resources: list[dict[str, Any]]
    ) -> None:
        """Analyze resource types and counts."""
        result["resource_types"], result["total_size"] = summarize_resource_types(resources)

    def _extract_version_info(
        self, result: dict[str, Any], resources: list[dict[str, Any]]
    ) -> None:
        """Extract version information from resources."""
        _extract_version_info_impl(self, result, resources, logger=logger)

    def _parse_version_info(self, offset: int, size: int) -> dict[str, Any] | None:
        """Parse VERSION_INFO resource."""
        return _parse_version_info_impl(self, offset, size, logger=logger)

    def _extract_manifest(self, result: dict[str, Any], resources: list[dict[str, Any]]) -> None:
        """Extract manifest from resources."""
        _extract_manifest_impl(self, result, resources, logger=logger)

    def _extract_icons(self, result: dict[str, Any], resources: list[dict[str, Any]]) -> None:
        """Extract icon information from resources."""
        _extract_icons_impl(result, resources)

    def _extract_strings(self, result: dict[str, Any], resources: list[dict[str, Any]]) -> None:
        """Extract string table resources."""
        _extract_strings_impl(
            self,
            result,
            resources,
            logger=logger,
            split_null_terminated=split_null_terminated,
        )

    def _read_resource_as_string(self, offset: int, size: int) -> str | None:
        """Read resource data as string."""
        return _read_resource_as_string_impl(self, offset, size, logger=logger)

    def _calculate_statistics(
        self, result: dict[str, Any], resources: list[dict[str, Any]]
    ) -> None:
        """Calculate resource statistics."""
        _calculate_statistics_impl(result, resources)

    def _check_suspicious_resources(
        self, result: dict[str, Any], resources: list[dict[str, Any]]
    ) -> None:
        """Check for suspicious resources."""
        _check_suspicious_resources_impl(self, result, resources)

    def _check_resource_entropy(self, res: dict[str, Any]) -> list[dict[str, Any]]:
        """Flag high-entropy non-icon resources."""
        return check_resource_entropy(res)

    def _check_resource_size(self, res: dict[str, Any]) -> list[dict[str, Any]]:
        """Flag unusually large resources."""
        return check_resource_size(res)

    def _check_resource_rcdata(self, res: dict[str, Any]) -> list[dict[str, Any]]:
        """Flag large RCDATA resources."""
        return check_resource_rcdata(res)

    def _check_resource_embedded_pe(self, res: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect possible embedded PE files in resource data."""
        if res.get("type_name") not in {"RT_RCDATA", "UNKNOWN"}:
            return []
        try:
            size = int(res.get("size", 0) or 0)
        except (TypeError, ValueError):
            return []
        try:
            offset = int(res.get("offset", 0) or 0)
        except (TypeError, ValueError):
            return []
        if size < 1024:
            return []
        header_data = self._cmdj(f"pxj 2 @ {offset}", [])
        return check_resource_embedded_pe(res, header_data)
