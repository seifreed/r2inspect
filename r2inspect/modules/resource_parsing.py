"""Parsing helpers for PE resource analysis."""

from __future__ import annotations

from typing import Any


class ResourceParsingMixin:
    """Resource directory discovery and parsing helpers."""

    RESOURCE_TYPES: dict[int, str]
    _cmdj: Any  # provided by host class
    _analyze_resource_data: Any  # provided by host class

    def _get_resource_directory(self) -> dict[str, Any] | None:
        try:
            data_dirs = self._cmdj("iDj", [])
            if not data_dirs or not isinstance(data_dirs, list):
                return None

            for dd in data_dirs:
                if (
                    isinstance(dd, dict)
                    and dd.get("name") == "RESOURCE"
                    and dd.get("vaddr", 0) != 0
                ):
                    return {
                        "offset": dd.get("paddr", 0),
                        "size": dd.get("size", 0),
                        "virtual_address": dd.get("vaddr", 0),
                    }
            return None
        except Exception:
            return None

    def _parse_resources(self) -> list[dict[str, Any]]:
        try:
            resources = self._cmdj("iRj", [])
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
                if resource_info["size"] > 0 and resource_info["offset"] > 0:
                    self._analyze_resource_data(resource_info)
                parsed_resources.append(resource_info)

            return parsed_resources
        except Exception:
            return self._parse_resources_manual()

    def _parse_resources_manual(self) -> list[dict[str, Any]]:
        try:
            rsrc_section = self._get_rsrc_section()
            if not rsrc_section:
                return []

            rsrc_offset = rsrc_section.get("paddr", 0)
            if rsrc_offset == 0:
                return []

            dir_data = self._cmdj(f"pxj 16 @ {rsrc_offset}", [])
            if not self._is_valid_dir_header(dir_data):
                return []

            total_entries = self._get_dir_total_entries(dir_data)
            return self._parse_dir_entries(rsrc_offset, total_entries)
        except Exception:
            return []

    def _get_rsrc_section(self) -> dict[str, Any] | None:
        sections = self._cmdj("iSj", [])
        if not sections or not isinstance(sections, list):
            return None
        for section in sections:
            if isinstance(section, dict) and ".rsrc" in section.get("name", ""):
                return section
        return None

    def _is_valid_dir_header(self, dir_data: list[int] | None) -> bool:
        return bool(dir_data and len(dir_data) >= 16)

    def _get_dir_total_entries(self, dir_data: list[int]) -> int:
        num_named_entries = dir_data[12] | (dir_data[13] << 8)
        num_id_entries = dir_data[14] | (dir_data[15] << 8)
        return num_named_entries + num_id_entries

    def _parse_dir_entries(self, rsrc_offset: int, total_entries: int) -> list[dict[str, Any]]:
        resources: list[dict[str, Any]] = []
        entry_offset = rsrc_offset + 16
        for i in range(min(total_entries, 20)):
            entry_data = self._cmdj(f"pxj 8 @ {entry_offset}", [])
            resource = self._parse_dir_entry(rsrc_offset, entry_data, i)
            if resource:
                resources.append(resource)
            entry_offset += 8
        return resources

    def _parse_dir_entry(
        self, rsrc_offset: int, entry_data: list[int], index: int
    ) -> dict[str, Any] | None:
        if not entry_data or len(entry_data) < 8:
            return None
        name_or_id = (
            entry_data[0] | (entry_data[1] << 8) | (entry_data[2] << 16) | (entry_data[3] << 24)
        )
        offset_to_data = (
            entry_data[4] | (entry_data[5] << 8) | (entry_data[6] << 16) | (entry_data[7] << 24)
        )
        resource_name = (
            f"Named_{index}"
            if name_or_id & 0x80000000
            else self._get_resource_type_name(name_or_id)
        )
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
        return self.RESOURCE_TYPES.get(type_id, f"UNKNOWN_{type_id}")
