"""
PE Resource analyzer module using radare2.
Analyzes resources embedded in PE files.
"""

import hashlib
import logging
import math
from typing import Any, Dict, List, Optional

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

    def analyze(self) -> Dict[str, Any]:
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

    def _get_resource_directory(self) -> Optional[Dict[str, Any]]:
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

    def _parse_resources(self) -> List[Dict[str, Any]]:
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

    def _parse_resources_manual(self) -> List[Dict[str, Any]]:
        """Manually parse resources if radare2 command fails."""
        try:
            resources = []

            # Get resource section
            sections = silent_cmdj(self.r2, "iSj", [])
            if not sections or not isinstance(sections, list):
                return []

            rsrc_section = None
            for section in sections:
                if isinstance(section, dict) and ".rsrc" in section.get("name", ""):
                    rsrc_section = section
                    break

            if not rsrc_section:
                return []

            # Read resource directory header
            rsrc_offset = rsrc_section.get("paddr", 0)
            if rsrc_offset == 0:
                return []

            # Read first 16 bytes of resource directory
            dir_data = silent_cmdj(self.r2, f"pxj 16 @ {rsrc_offset}", [])
            if dir_data and len(dir_data) >= 16:
                # Parse IMAGE_RESOURCE_DIRECTORY
                # characteristics = (
                #     dir_data[0] | (dir_data[1] << 8) | (dir_data[2] << 16) | (dir_data[3] << 24)
                # )
                # timestamp = (
                #     dir_data[4] | (dir_data[5] << 8) | (dir_data[6] << 16) | (dir_data[7] << 24)
                # )
                # major_version = dir_data[8] | (dir_data[9] << 8)
                # minor_version = dir_data[10] | (dir_data[11] << 8)
                num_named_entries = dir_data[12] | (dir_data[13] << 8)
                num_id_entries = dir_data[14] | (dir_data[15] << 8)

                total_entries = num_named_entries + num_id_entries

                # Parse each directory entry (simplified)
                entry_offset = rsrc_offset + 16
                for i in range(min(total_entries, 20)):  # Limit to 20 entries
                    entry_data = silent_cmdj(self.r2, f"pxj 8 @ {entry_offset}", [])
                    if entry_data and len(entry_data) >= 8:
                        name_or_id = (
                            entry_data[0]
                            | (entry_data[1] << 8)
                            | (entry_data[2] << 16)
                            | (entry_data[3] << 24)
                        )
                        offset_to_data = (
                            entry_data[4]
                            | (entry_data[5] << 8)
                            | (entry_data[6] << 16)
                            | (entry_data[7] << 24)
                        )

                        # Check if it's a named entry or ID entry
                        if name_or_id & 0x80000000:
                            # Named entry (string name)
                            resource_name = f"Named_{i}"
                        else:
                            # ID entry
                            resource_type = self._get_resource_type_name(name_or_id)
                            resource_name = resource_type

                        resources.append(
                            {
                                "name": resource_name,
                                "type_id": name_or_id & 0x7FFFFFFF,
                                "type_name": self._get_resource_type_name(name_or_id & 0x7FFFFFFF),
                                "offset": rsrc_offset + (offset_to_data & 0x7FFFFFFF),
                                "is_directory": bool(offset_to_data & 0x80000000),
                                "size": 0,  # Would need further parsing to get actual size
                                "entropy": 0.0,
                                "hashes": {},
                            }
                        )

                    entry_offset += 8

            return resources

        except Exception as e:
            logger.error(f"Error in manual resource parsing: {e}")
            return []

    def _get_resource_type_name(self, type_id: int) -> str:
        """Get resource type name from ID."""
        return self.RESOURCE_TYPES.get(type_id, f"UNKNOWN_{type_id}")

    def _analyze_resource_data(self, resource: Dict[str, Any]):
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

    def _calculate_entropy(self, data: List[int]) -> float:
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

    def _analyze_resource_types(self, result: Dict[str, Any], resources: List[Dict[str, Any]]):
        """Analyze resource types and counts."""
        type_counts = {}
        type_sizes = {}

        for res in resources:
            type_name = res.get("type_name", "UNKNOWN")
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
            type_sizes[type_name] = type_sizes.get(type_name, 0) + res.get("size", 0)

        result["resource_types"] = [
            {"type": type_name, "count": count, "total_size": type_sizes.get(type_name, 0)}
            for type_name, count in type_counts.items()
        ]

        result["total_size"] = sum(type_sizes.values())

    def _extract_version_info(self, result: Dict[str, Any], resources: List[Dict[str, Any]]):
        """Extract version information from resources."""
        for res in resources:
            if res.get("type_name") == "RT_VERSION":
                try:
                    version_data = self._parse_version_info(res["offset"], res["size"])
                    if version_data:
                        result["version_info"] = version_data
                        break
                except:
                    pass

    def _parse_version_info(self, offset: int, size: int) -> Optional[Dict[str, Any]]:
        """Parse VERSION_INFO resource."""
        try:
            if offset == 0 or size < 64:
                return None

            # Read version info data
            data = silent_cmdj(self.r2, f"pxj {min(size, 1024)} @ {offset}", [])
            if not data or len(data) < 64:
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

            # Look for VS_VERSION_INFO signature
            vs_sig = [0xBD, 0x04, 0xEF, 0xFE]  # VS_FIXEDFILEINFO signature
            sig_pos = self._find_pattern(data, vs_sig)

            if sig_pos >= 0:
                # Parse VS_FIXEDFILEINFO structure (simplified)
                info_start = sig_pos
                if info_start + 52 <= len(data):
                    # Extract version numbers (simplified)
                    file_version_ms = (
                        data[info_start + 8]
                        | (data[info_start + 9] << 8)
                        | (data[info_start + 10] << 16)
                        | (data[info_start + 11] << 24)
                    )
                    file_version_ls = (
                        data[info_start + 12]
                        | (data[info_start + 13] << 8)
                        | (data[info_start + 14] << 16)
                        | (data[info_start + 15] << 24)
                    )

                    version_info["file_version"] = (
                        f"{(file_version_ms >> 16) & 0xFFFF}.{file_version_ms & 0xFFFF}.{(file_version_ls >> 16) & 0xFFFF}.{file_version_ls & 0xFFFF}"
                    )

            # Extract string information (simplified)
            string_keys = [
                "CompanyName",
                "FileDescription",
                "FileVersion",
                "InternalName",
                "LegalCopyright",
                "OriginalFilename",
                "ProductName",
                "ProductVersion",
            ]

            for key in string_keys:
                key_bytes = key.encode("utf-16le")
                key_pattern = list(key_bytes)
                pos = self._find_pattern(data, key_pattern)
                if pos >= 0:
                    # Try to extract the value (simplified)
                    value_start = pos + len(key_pattern) + 4  # Skip key and some padding
                    if value_start < len(data) - 2:
                        # Look for null terminator
                        value_bytes = []
                        for i in range(value_start, min(value_start + 256, len(data) - 1), 2):
                            if data[i] == 0 and data[i + 1] == 0:
                                break
                            value_bytes.extend([data[i], data[i + 1]])

                        if value_bytes:
                            try:
                                value = bytes(value_bytes).decode("utf-16le", errors="ignore")
                                if value and value.isprintable():
                                    version_info["strings"][key] = value
                            except:
                                pass

            return version_info if version_info["strings"] else None

        except Exception as e:
            logger.error(f"Error parsing version info: {e}")
            return None

    def _extract_manifest(self, result: Dict[str, Any], resources: List[Dict[str, Any]]):
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
                except:
                    pass

    def _extract_icons(self, result: Dict[str, Any], resources: List[Dict[str, Any]]):
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

    def _extract_strings(self, result: Dict[str, Any], resources: List[Dict[str, Any]]):
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
                except:
                    pass

        result["strings"] = strings[:50]  # Limit total to 50 strings

    def _read_resource_as_string(self, offset: int, size: int) -> Optional[str]:
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
            except:
                pass

            # Try UTF-8
            try:
                text = bytes(data).decode("utf-8", errors="ignore")
                if text and any(c.isprintable() for c in text):
                    return text
            except:
                pass

            # Try ASCII
            try:
                text = bytes(data).decode("ascii", errors="ignore")
                if text and any(c.isprintable() for c in text):
                    return text
            except:
                pass

            return None

        except Exception as e:
            logger.error(f"Error reading resource as string: {e}")
            return None

    def _calculate_statistics(self, result: Dict[str, Any], resources: List[Dict[str, Any]]):
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

    def _check_suspicious_resources(self, result: Dict[str, Any], resources: List[Dict[str, Any]]):
        """Check for suspicious resources."""
        suspicious = []

        for res in resources:
            # Check for high entropy resources (might be encrypted)
            if res.get("entropy", 0) > 7.5 and res["type_name"] not in ["RT_ICON", "RT_BITMAP"]:
                suspicious.append(
                    {
                        "resource": res["name"] or res["type_name"],
                        "reason": "High entropy (possibly encrypted/packed)",
                        "entropy": res["entropy"],
                        "size": res["size"],
                    }
                )

            # Check for unusually large resources
            if res["size"] > 1024 * 1024:  # > 1MB
                suspicious.append(
                    {
                        "resource": res["name"] or res["type_name"],
                        "reason": "Unusually large resource",
                        "size": res["size"],
                    }
                )

            # Check for RCDATA resources (often used to store arbitrary data)
            if res["type_name"] == "RT_RCDATA" and res["size"] > 10240:  # > 10KB
                suspicious.append(
                    {
                        "resource": res["name"] or res["type_name"],
                        "reason": "Large RCDATA resource (may contain embedded data)",
                        "size": res["size"],
                        "entropy": res.get("entropy", 0),
                    }
                )

            # Check for executable resources
            if res["type_name"] in ["RT_RCDATA", "UNKNOWN"]:
                # Check if it might be a PE file
                if res["size"] > 1024 and res["offset"] > 0:
                    header_data = silent_cmdj(self.r2, f"pxj 2 @ {res['offset']}", [])
                    if header_data and len(header_data) >= 2:
                        if header_data[0] == 0x4D and header_data[1] == 0x5A:  # MZ header
                            suspicious.append(
                                {
                                    "resource": res["name"] or res["type_name"],
                                    "reason": "Possible embedded PE file",
                                    "size": res["size"],
                                }
                            )

        result["suspicious_resources"] = suspicious

    def _find_pattern(self, data: List[int], pattern: List[int]) -> int:
        """Find a byte pattern in data. Returns position or -1 if not found."""
        pattern_len = len(pattern)
        data_len = len(data)

        for i in range(data_len - pattern_len + 1):
            if data[i : i + pattern_len] == pattern:
                return i
        return -1
