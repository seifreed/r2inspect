# mypy: ignore-errors
"""
PE Resource analyzer module using radare2.
Analyzes resources embedded in PE files.
"""

import hashlib
import logging
import math
from typing import Any

from ..utils.r2_helpers import safe_cmd, safe_cmdj
from ..utils.r2_suppress import silent_cmdj

logger = logging.getLogger(__name__)


class ResourceAnalyzer:
    """Analyzes resources in PE files."""

    # Resource type constants
    RESOURCE_TYPES = {
        1: "RT_CURSOR",
        2: "RT_BITMAP",
        3: "RT_ICON",
        4: "RT_MENU",
        5: "RT_DIALOG",
        6: "RT_STRING",
        7: "RT_FONTDIR",
        8: "RT_FONT",
        9: "RT_ACCELERATOR",
        10: "RT_RCDATA",
        11: "RT_MESSAGETABLE",
        12: "RT_GROUP_CURSOR",
        14: "RT_GROUP_ICON",
        16: "RT_VERSION",
        17: "RT_DLGINCLUDE",
        19: "RT_PLUGPLAY",
        20: "RT_VXD",
        21: "RT_ANICURSOR",
        22: "RT_ANIICON",
        23: "RT_HTML",
        24: "RT_MANIFEST",
    }

    def __init__(self, r2):
        """
        Initialize the Resource analyzer.

        Args:
            r2: Radare2 instance
        """
        self.r2 = r2

    def analyze(self) -> dict[str, Any]:
        """
        Analyze resources in the PE file.

        Returns:
            Dictionary containing resource information
        """
        try:
            result = {
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

            # Get resource directory from data directories
            resource_dir = self._get_resource_directory()
            if not resource_dir:
                return result

            result["has_resources"] = True
            result["resource_directory"] = resource_dir

            # Parse resource tree using radare2
            resources = self._parse_resources()
            if resources:
                result["resources"] = resources
                result["total_resources"] = len(resources)

                # Analyze different resource types
                self._analyze_resource_types(result, resources)

                # Extract specific resource information
                self._extract_version_info(result, resources)
                self._extract_manifest(result, resources)
                self._extract_icons(result, resources)
                self._extract_strings(result, resources)

                # Calculate statistics
                self._calculate_statistics(result, resources)

                # Check for suspicious resources
                self._check_suspicious_resources(result, resources)

            return result

        except Exception as e:
            logger.error(f"Error analyzing resources: {e}")
            return {"has_resources": False, "error": str(e)}

    def _get_resource_directory(self) -> dict[str, Any | None]:
        """Get resource directory information."""
        try:
            # Get data directories
            data_dirs = silent_cmdj(self.r2, "iDj", [])
            if not data_dirs or not isinstance(data_dirs, list):
                return None

            # Find resource directory (index 2)
            for dd in data_dirs:
                if isinstance(dd, dict) and dd.get("name") == "RESOURCE":
                    if dd.get("vaddr", 0) != 0:
                        return {
                            "offset": dd.get("paddr", 0),
                            "size": dd.get("size", 0),
                            "virtual_address": dd.get("vaddr", 0),
                        }

            return None

        except Exception as e:
            logger.error(f"Error getting resource directory: {e}")
            return None

    def _parse_resources(self) -> list[dict[str, Any]]:
        """Parse resources using radare2."""
        try:
            # Use radare2's resource parsing command
            resources = silent_cmdj(self.r2, "iRj", [])
            if not resources:
                return []

            parsed_resources = []

            for res in resources:
                if not isinstance(res, dict):
                    continue

                resource_info = {
                    "name": res.get("name", ""),
                    "type": res.get("type", ""),
                    "type_id": res.get("type_id", 0),
                    "type_name": self._get_resource_type_name(res.get("type_id", 0)),
                    "language": res.get("lang", ""),
                    "offset": res.get("paddr", 0),
                    "size": res.get("size", 0),
                    "virtual_address": res.get("vaddr", 0),
                    "entropy": 0.0,
                    "hashes": {},
                }

                # Calculate entropy and hashes for the resource
                if resource_info["size"] > 0 and resource_info["offset"] > 0:
                    self._analyze_resource_data(resource_info)

                parsed_resources.append(resource_info)

            return parsed_resources

        except Exception as e:
            logger.error(f"Error parsing resources: {e}")
            # Fallback to manual parsing if iRj fails
            return self._parse_resources_manual()

    def _parse_resources_manual(self) -> list[dict[str, Any]]:
        """Manually parse resources if radare2 command fails."""
        try:
            rsrc_section = self._get_rsrc_section()
            if not rsrc_section:
                return []

            rsrc_offset = rsrc_section.get("paddr", 0)
            if rsrc_offset == 0:
                return []

            dir_data = silent_cmdj(self.r2, f"pxj 16 @ {rsrc_offset}", [])
            if not self._is_valid_dir_header(dir_data):
                return []

            total_entries = self._get_dir_total_entries(dir_data)
            return self._parse_dir_entries(rsrc_offset, total_entries)

        except Exception as e:
            logger.error(f"Error in manual resource parsing: {e}")
            return []

    def _get_rsrc_section(self) -> dict[str, Any] | None:
        """Return the .rsrc section dictionary, if present."""
        sections = silent_cmdj(self.r2, "iSj", [])
        if not sections or not isinstance(sections, list):
            return None
        for section in sections:
            if isinstance(section, dict) and ".rsrc" in section.get("name", ""):
                return section
        return None

    def _is_valid_dir_header(self, dir_data: list[int] | None) -> bool:
        """Validate resource directory header data length."""
        return bool(dir_data) and len(dir_data) >= 16

    def _get_dir_total_entries(self, dir_data: list[int]) -> int:
        """Compute total entries from IMAGE_RESOURCE_DIRECTORY header bytes."""
        num_named_entries = dir_data[12] | (dir_data[13] << 8)
        num_id_entries = dir_data[14] | (dir_data[15] << 8)
        return num_named_entries + num_id_entries

    def _parse_dir_entries(self, rsrc_offset: int, total_entries: int) -> list[dict[str, Any]]:
        """Parse a limited number of directory entries."""
        resources: list[dict[str, Any]] = []
        entry_offset = rsrc_offset + 16
        for i in range(min(total_entries, 20)):
            entry_data = silent_cmdj(self.r2, f"pxj 8 @ {entry_offset}", [])
            resource = self._parse_dir_entry(rsrc_offset, entry_data, i)
            if resource:
                resources.append(resource)
            entry_offset += 8
        return resources

    def _parse_dir_entry(
        self, rsrc_offset: int, entry_data: list[int], index: int
    ) -> dict[str, Any] | None:
        """Parse a single directory entry."""
        if not entry_data or len(entry_data) < 8:
            return None

        name_or_id = (
            entry_data[0] | (entry_data[1] << 8) | (entry_data[2] << 16) | (entry_data[3] << 24)
        )
        offset_to_data = (
            entry_data[4] | (entry_data[5] << 8) | (entry_data[6] << 16) | (entry_data[7] << 24)
        )

        if name_or_id & 0x80000000:
            resource_name = f"Named_{index}"
        else:
            resource_name = self._get_resource_type_name(name_or_id)

        type_id = name_or_id & 0x7FFFFFFF
        return {
            "name": resource_name,
            "type_id": type_id,
            "type_name": self._get_resource_type_name(type_id),
            "offset": rsrc_offset + (offset_to_data & 0x7FFFFFFF),
            "is_directory": bool(offset_to_data & 0x80000000),
            "size": 0,
            "entropy": 0.0,
            "hashes": {},
        }

    def _get_resource_type_name(self, type_id: int) -> str:
        """Get resource type name from ID."""
        return self.RESOURCE_TYPES.get(type_id, f"UNKNOWN_{type_id}")

    def _analyze_resource_data(self, resource: dict[str, Any]):
        """Analyze resource data (entropy, hashes)."""
        try:
            offset = resource["offset"]
            size = min(resource["size"], 65536)  # Limit to 64KB for analysis

            if offset == 0 or size == 0:
                return

            # Read resource data
            data = silent_cmdj(self.r2, f"pxj {size} @ {offset}", [])
            if not data:
                return

            # Calculate entropy
            resource["entropy"] = self._calculate_entropy(data)

            # Calculate hashes
            try:
                data_bytes = bytes(data)
                resource["hashes"] = {
                    "md5": hashlib.md5(data_bytes, usedforsecurity=False).hexdigest(),
                    "sha1": hashlib.sha1(data_bytes, usedforsecurity=False).hexdigest(),
                    "sha256": hashlib.sha256(data_bytes).hexdigest(),
                }
            except Exception as e:
                logger.debug(f"Error calculating resource hashes: {e}")
                resource["hashes"] = {}

        except Exception as e:
            logger.error(f"Error analyzing resource data: {e}")

    def _calculate_entropy(self, data: list[int]) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        # Count byte frequencies
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in freq.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    def _analyze_resource_types(self, result: dict[str, Any], resources: list[dict[str, Any]]):
        """Analyze resource types and counts."""
        type_counts = {}
        type_sizes = {}

        for res in resources:
            type_name = res.get("type_name", "UNKNOWN")
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
            type_sizes[type_name] = type_sizes.get(type_name, 0) + res.get("size", 0)

        result["resource_types"] = [
            {
                "type": type_name,
                "count": count,
                "total_size": type_sizes.get(type_name, 0),
            }
            for type_name, count in type_counts.items()
        ]

        result["total_size"] = sum(type_sizes.values())

    def _extract_version_info(self, result: dict[str, Any], resources: list[dict[str, Any]]):
        """Extract version information from resources."""
        for res in resources:
            if res.get("type_name") == "RT_VERSION":
                try:
                    version_data = self._parse_version_info(res["offset"], res["size"])
                    if version_data:
                        result["version_info"] = version_data
                        break
                except Exception as e:
                    logger.debug(f"Error extracting version info from resource: {e}")

    def _parse_version_info(self, offset: int, size: int) -> dict[str, Any | None]:
        """Parse VERSION_INFO resource."""
        try:
            if offset == 0 or size < 64:
                return None

            data = self._read_version_info_data(offset, size)
            if not data:
                return None

            version_info = {
                "signature": "",
                "file_version": "",
                "product_version": "",
                "file_flags": [],
                "file_os": "",
                "file_type": "",
                "strings": {},
            }

            sig_pos = self._find_vs_signature(data)
            if sig_pos >= 0:
                file_version = self._parse_fixed_file_info(data, sig_pos)
                if file_version:
                    version_info["file_version"] = file_version

            version_info["strings"] = self._extract_version_strings(data)

            return version_info if version_info["strings"] else None

        except Exception as e:
            logger.error(f"Error parsing version info: {e}")
            return None

    def _read_version_info_data(self, offset: int, size: int) -> list[int] | None:
        """Read VERSION_INFO data with size limit."""
        data = silent_cmdj(self.r2, f"pxj {min(size, 1024)} @ {offset}", [])
        if not data or len(data) < 64:
            return None
        return data

    def _find_vs_signature(self, data: list[int]) -> int:
        """Find VS_FIXEDFILEINFO signature in VERSION_INFO."""
        vs_sig = [0xBD, 0x04, 0xEF, 0xFE]
        return self._find_pattern(data, vs_sig)

    def _parse_fixed_file_info(self, data: list[int], sig_pos: int) -> str:
        """Parse version numbers from VS_FIXEDFILEINFO."""
        if sig_pos + 52 > len(data):
            return ""
        file_version_ms = (
            data[sig_pos + 8]
            | (data[sig_pos + 9] << 8)
            | (data[sig_pos + 10] << 16)
            | (data[sig_pos + 11] << 24)
        )
        file_version_ls = (
            data[sig_pos + 12]
            | (data[sig_pos + 13] << 8)
            | (data[sig_pos + 14] << 16)
            | (data[sig_pos + 15] << 24)
        )
        return (
            f"{(file_version_ms >> 16) & 0xFFFF}.{file_version_ms & 0xFFFF}."
            f"{(file_version_ls >> 16) & 0xFFFF}.{file_version_ls & 0xFFFF}"
        )

    def _extract_version_strings(self, data: list[int]) -> dict[str, str]:
        """Extract string table values from VERSION_INFO."""
        strings: dict[str, str] = {}
        for key in self._version_string_keys():
            value = self._read_version_string_value(data, key)
            if value:
                strings[key] = value
        return strings

    def _version_string_keys(self) -> list[str]:
        """Keys commonly stored in VERSION_INFO resources."""
        return [
            "CompanyName",
            "FileDescription",
            "FileVersion",
            "InternalName",
            "LegalCopyright",
            "OriginalFilename",
            "ProductName",
            "ProductVersion",
        ]

    def _read_version_string_value(self, data: list[int], key: str) -> str:
        """Read a UTF-16LE string value for a given key."""
        key_pattern = list(key.encode("utf-16le"))
        pos = self._find_pattern(data, key_pattern)
        if pos < 0:
            return ""
        value_start = pos + len(key_pattern) + 4
        if value_start >= len(data) - 2:
            return ""
        value_bytes: list[int] = []
        for i in range(value_start, min(value_start + 256, len(data) - 1), 2):
            if data[i] == 0 and data[i + 1] == 0:
                break
            value_bytes.extend([data[i], data[i + 1]])
        if not value_bytes:
            return ""
        try:
            value = bytes(value_bytes).decode("utf-16le", errors="ignore")
            return value if value and value.isprintable() else ""
        except UnicodeDecodeError:
            return ""

    def _extract_manifest(self, result: dict[str, Any], resources: list[dict[str, Any]]):
        """Extract manifest from resources."""
        for res in resources:
            if res.get("type_name") == "RT_MANIFEST":
                try:
                    manifest_data = self._read_resource_as_string(res["offset"], res["size"])
                    if manifest_data:
                        result["manifest"] = {
                            "content": manifest_data[:2048],  # Limit to first 2KB
                            "size": res["size"],
                            "requires_admin": "requireAdministrator" in manifest_data,
                            "requires_elevation": "highestAvailable" in manifest_data,
                            "dpi_aware": "dpiAware" in manifest_data,
                        }
                        break
                except Exception as e:
                    logger.debug(f"Error extracting manifest from resource: {e}")

    def _extract_icons(self, result: dict[str, Any], resources: list[dict[str, Any]]):
        """Extract icon information from resources."""
        icons = []

        for res in resources:
            if res.get("type_name") in ["RT_ICON", "RT_GROUP_ICON"]:
                icon_info = {
                    "type": res["type_name"],
                    "size": res["size"],
                    "offset": res["offset"],
                    "entropy": res.get("entropy", 0.0),
                }

                # Check if icon might be suspicious (e.g., very high entropy)
                if icon_info["entropy"] > 7.5:
                    icon_info["suspicious"] = "High entropy (possibly encrypted)"

                icons.append(icon_info)

        result["icons"] = icons

    def _extract_strings(self, result: dict[str, Any], resources: list[dict[str, Any]]):
        """Extract string table resources."""
        strings = []

        for res in resources:
            if res.get("type_name") == "RT_STRING":
                try:
                    string_data = self._read_resource_as_string(res["offset"], res["size"])
                    if string_data:
                        # Extract individual strings (simplified)
                        extracted = [s for s in string_data.split("\0") if s and len(s) > 3]
                        strings.extend(extracted[:20])  # Limit to 20 strings per resource
                except Exception as e:
                    logger.debug(f"Error extracting strings from resource: {e}")

        result["strings"] = strings[:50]  # Limit total to 50 strings

    def _read_resource_as_string(self, offset: int, size: int) -> str | None:
        """Read resource data as string."""
        try:
            if offset == 0 or size == 0:
                return None

            # Limit size to prevent memory issues
            read_size = min(size, 8192)

            # Read data
            data = silent_cmdj(self.r2, f"pxj {read_size} @ {offset}", [])
            if not data:
                return None

            # Try to decode as UTF-16 LE first (common for Windows resources)
            try:
                text = bytes(data).decode("utf-16le", errors="ignore")
                if text and any(c.isprintable() for c in text):
                    return text
            except (UnicodeDecodeError, TypeError):
                pass

            # Try UTF-8
            try:
                text = bytes(data).decode("utf-8", errors="ignore")
                if text and any(c.isprintable() for c in text):
                    return text
            except (UnicodeDecodeError, TypeError):
                pass

            # Try ASCII
            try:
                text = bytes(data).decode("ascii", errors="ignore")
                if text and any(c.isprintable() for c in text):
                    return text
            except (UnicodeDecodeError, TypeError):
                pass

            return None

        except Exception as e:
            logger.error(f"Error reading resource as string: {e}")
            return None

    def _calculate_statistics(self, result: dict[str, Any], resources: list[dict[str, Any]]):
        """Calculate resource statistics."""
        if not resources:
            return

        sizes = [res["size"] for res in resources if res["size"] > 0]
        entropies = [res["entropy"] for res in resources if res["entropy"] > 0]

        result["statistics"] = {
            "total_resources": len(resources),
            "total_size": sum(sizes),
            "average_size": sum(sizes) // len(sizes) if sizes else 0,
            "max_size": max(sizes) if sizes else 0,
            "min_size": min(sizes) if sizes else 0,
            "average_entropy": sum(entropies) / len(entropies) if entropies else 0,
            "max_entropy": max(entropies) if entropies else 0,
            "unique_types": len({res["type_name"] for res in resources}),
        }

    def _check_suspicious_resources(self, result: dict[str, Any], resources: list[dict[str, Any]]):
        """Check for suspicious resources."""
        suspicious: list[dict[str, Any]] = []

        for res in resources:
            suspicious.extend(self._check_resource_entropy(res))
            suspicious.extend(self._check_resource_size(res))
            suspicious.extend(self._check_resource_rcdata(res))
            suspicious.extend(self._check_resource_embedded_pe(res))

        result["suspicious_resources"] = suspicious

    def _check_resource_entropy(self, res: dict[str, Any]) -> list[dict[str, Any]]:
        """Flag high-entropy non-icon resources."""
        if res.get("entropy", 0) <= 7.5:
            return []
        if res["type_name"] in ["RT_ICON", "RT_BITMAP"]:
            return []
        return [
            {
                "resource": res["name"] or res["type_name"],
                "reason": "High entropy (possibly encrypted/packed)",
                "entropy": res["entropy"],
                "size": res["size"],
            }
        ]

    def _check_resource_size(self, res: dict[str, Any]) -> list[dict[str, Any]]:
        """Flag unusually large resources."""
        if res["size"] <= 1024 * 1024:
            return []
        return [
            {
                "resource": res["name"] or res["type_name"],
                "reason": "Unusually large resource",
                "size": res["size"],
            }
        ]

    def _check_resource_rcdata(self, res: dict[str, Any]) -> list[dict[str, Any]]:
        """Flag large RCDATA resources."""
        if res["type_name"] != "RT_RCDATA" or res["size"] <= 10240:
            return []
        return [
            {
                "resource": res["name"] or res["type_name"],
                "reason": "Large RCDATA resource (may contain embedded data)",
                "size": res["size"],
                "entropy": res.get("entropy", 0),
            }
        ]

    def _check_resource_embedded_pe(self, res: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect possible embedded PE files in resource data."""
        if res["type_name"] not in ["RT_RCDATA", "UNKNOWN"]:
            return []
        if res["size"] <= 1024 or res["offset"] <= 0:
            return []
        header_data = silent_cmdj(self.r2, f"pxj 2 @ {res['offset']}", [])
        if not header_data or len(header_data) < 2:
            return []
        if header_data[0] == 0x4D and header_data[1] == 0x5A:
            return [
                {
                    "resource": res["name"] or res["type_name"],
                    "reason": "Possible embedded PE file",
                    "size": res["size"],
                }
            ]
        return []

    def _find_pattern(self, data: list[int], pattern: list[int]) -> int:
        """Find a byte pattern in data. Returns position or -1 if not found."""
        pattern_len = len(pattern)
        data_len = len(data)

        for i in range(data_len - pattern_len + 1):
            if data[i : i + pattern_len] == pattern:
                return i
        return -1
