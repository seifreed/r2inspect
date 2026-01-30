#!/usr/bin/env python3
# mypy: ignore-errors
"""
PE Analysis Module using r2pipe
"""

import hashlib
from typing import Any

from ..abstractions import BaseAnalyzer
from ..registry import create_default_registry
from ..utils.logger import get_logger
from ..utils.r2_helpers import get_pe_headers, safe_cmd, safe_cmdj

logger = get_logger(__name__)

# Constants
PE32_PLUS = "PE32+"


class PEAnalyzer(BaseAnalyzer):
    """PE file analysis using radare2"""

    def __init__(self, r2, config, filepath=None):
        super().__init__(r2=r2, config=config, filepath=filepath)

    def get_category(self) -> str:
        return "format"

    def get_description(self) -> str:
        return "Comprehensive analysis of PE (Portable Executable) format including headers, security features, and embedded analyzers"

    def supports_format(self, file_format: str) -> bool:
        return file_format.upper() in {"PE", "PE32", "PE32+", "DLL", "EXE"}

    def analyze(self) -> dict[str, Any]:
        """Perform complete PE analysis"""
        result = self._init_result_structure(
            {
                "architecture": "Unknown",
                "bits": 0,
                "type": "Unknown",
                "format": "PE",
                "security_features": {},
                "imphash": "",
            }
        )

        try:
            self._log_info("Starting PE analysis")

            # Get PE headers information
            result.update(self._get_pe_headers())

            # Get file characteristics
            result.update(self._get_file_characteristics())

            # Get compilation info
            result.update(self._get_compilation_info())

            # Get security features
            result["security_features"] = self.get_security_features()

            # Get subsystem info
            result.update(self._get_subsystem_info())

            # Calculate imphash
            result["imphash"] = self.calculate_imphash()

            # Get registry for dynamic analyzer lookup
            registry = create_default_registry()

            self._run_optional_analyzers(result, registry)

            result["available"] = True
            self._log_info("PE analysis completed successfully")

        except Exception as e:
            result["error"] = str(e)
            self._log_error(f"PE analysis failed: {e}")

        return result

    def _run_optional_analyzers(self, result: dict[str, Any], registry) -> None:
        analyzers = [
            ("analyze_authenticode", "authenticode", "authenticode"),
            ("analyze_overlay", "overlay_analyzer", "overlay"),
            ("analyze_resources", "resource_analyzer", "resources"),
            ("analyze_mitigations", "exploit_mitigation", "exploit_mitigations"),
        ]

        for config_key, analyzer_name, result_key in analyzers:
            if not getattr(self.config, config_key, False):
                continue
            analyzer_class = registry.get_analyzer_class(analyzer_name)
            if not analyzer_class:
                continue
            analyzer = analyzer_class(self.r2)
            result[result_key] = analyzer.analyze()

    def _get_pe_headers(self) -> dict[str, Any]:
        """Extract PE header information"""
        info = {}

        try:
            # Get PE information from radare2
            pe_info = safe_cmdj(self.r2, "ij")

            if pe_info and "bin" in pe_info:
                bin_info = pe_info["bin"]

                info["architecture"] = bin_info.get("arch", "Unknown")
                info["machine"] = bin_info.get("machine", "Unknown")
                info["bits"] = bin_info.get("bits", 0)
                info["endian"] = bin_info.get("endian", "Unknown")

                pe_header = self._fetch_pe_header()
                info["type"] = self._determine_pe_file_type(bin_info)
                info["format"] = self._determine_pe_format(bin_info, pe_header)

                info["image_base"] = bin_info.get("baddr", 0)
                info["entry_point"] = self._get_entry_point(bin_info)
                self._update_optional_header_info(info, pe_header)

        except Exception as e:
            logger.error(f"Error getting PE headers: {e}")

        return info

    def _fetch_pe_header(self) -> dict[str, Any] | None:
        try:
            return get_pe_headers(self.r2)
        except Exception as e:
            logger.debug(f"Could not get PE header details: {e}")
            return None

    def _determine_pe_file_type(self, bin_info: dict[str, Any]) -> str:
        file_type = bin_info.get("class", "Unknown")
        if file_type not in [PE32_PLUS, "PE32", "PE", "Unknown"]:
            logger.debug(f"Determined file type: {file_type}")
            return file_type

        try:
            import magic

            file_desc = magic.from_file(self.filepath).lower()
            logger.debug(f"Magic file description: {file_desc}")
            if "dll" in file_desc:
                file_type = "DLL"
            elif "executable" in file_desc and "dll" not in file_desc:
                file_type = "EXE"
            elif "driver" in file_desc or "sys" in file_desc:
                file_type = "SYS"
            else:
                file_type = bin_info.get("class", "PE")
        except Exception as e:
            logger.debug(f"Could not use magic for file type: {e}")
            file_type = bin_info.get("class", "PE")

        logger.debug(f"Determined file type: {file_type}")
        return file_type

    def _determine_pe_format(
        self, bin_info: dict[str, Any], pe_header: dict[str, Any] | None
    ) -> str:
        format_name = bin_info.get("format", "Unknown")
        if format_name and format_name != "Unknown":
            return format_name

        bits = bin_info.get("bits", 0)
        if bits == 32:
            return "PE32"
        if bits == 64:
            return PE32_PLUS

        if pe_header:
            opt_header = pe_header.get("optional_header", {})
            magic = opt_header.get("Magic", 0)
            if magic == 0x10B:
                return "PE32"
            if magic == 0x20B:
                return PE32_PLUS
        return "PE"

    def _get_entry_point(self, bin_info: dict[str, Any]) -> int:
        entry_point = 0
        if "baddr" in bin_info and "boffset" in bin_info:
            entry_point = bin_info.get("baddr", 0) + bin_info.get("boffset", 0)

        try:
            entry_info = safe_cmdj(self.r2, "iej")
            if entry_info:
                entry_point = entry_info[0].get("vaddr", entry_point)
        except Exception as e:
            logger.debug(f"Could not get entry point from iej: {e}")

        return entry_point

    def _update_optional_header_info(
        self, info: dict[str, Any], pe_header: dict[str, Any] | None
    ) -> None:
        if not pe_header:
            return
        opt_header = pe_header.get("optional_header", {})
        image_base = opt_header.get("ImageBase", info.get("image_base", 0))
        if image_base:
            info["image_base"] = image_base
        entry_rva = opt_header.get("AddressOfEntryPoint", 0)
        if entry_rva:
            info["entry_point"] = entry_rva + info["image_base"]

    def _get_file_characteristics(self) -> dict[str, Any]:
        """Get file characteristics"""
        characteristics = {}

        try:
            # Get file characteristics from PE header
            pe_info = safe_cmdj(self.r2, "ij")

            if pe_info and "bin" in pe_info:
                bin_info = pe_info["bin"]

                characteristics["has_debug"] = "debug" in bin_info

                # Better detection using PE header characteristics
                is_dll = False
                is_executable = False

                try:
                    pe_header = get_pe_headers(self.r2)
                    if pe_header and "file_header" in pe_header:
                        file_header = pe_header["file_header"]
                        characteristics_flags = file_header.get("Characteristics", 0)

                        # Check specific PE characteristics
                        if isinstance(characteristics_flags, int):
                            is_dll = bool(characteristics_flags & 0x2000)  # IMAGE_FILE_DLL
                            is_executable = bool(
                                characteristics_flags & 0x0002
                            )  # IMAGE_FILE_EXECUTABLE_IMAGE
                except Exception as e:
                    logger.debug(f"Could not get PE characteristics: {e}")
                    # Fallback detection
                    file_type = bin_info.get("type", "").lower()
                    class_type = bin_info.get("class", "").lower()

                    # Check if it's a DLL
                    is_dll = (
                        "dll" in file_type
                        or "dll" in class_type
                        or "dynamic library" in file_type.lower()
                        or self.filepath.lower().endswith(".dll")
                    )

                    # Check if it's executable
                    is_executable = (
                        "executable" in file_type
                        or "exe" in file_type
                        or self.filepath.lower().endswith(".exe")
                        or (not is_dll)  # If not DLL, likely executable
                    )

                characteristics["is_dll"] = is_dll
                characteristics["is_executable"] = is_executable

        except Exception as e:
            logger.error(f"Error getting file characteristics: {e}")

        return characteristics

    def _get_compilation_info(self) -> dict[str, Any]:
        """Get compilation information"""
        info = {}

        try:
            # Try to get timestamp from PE header
            pe_info = safe_cmdj(self.r2, "ij")

            if pe_info and "bin" in pe_info:
                bin_info = pe_info["bin"]

                # Check for timestamp
                if "compiled" in bin_info:
                    info["compile_time"] = bin_info["compiled"]

                # Check for compiler information in strings
                strings_result = self.r2.cmd("iz~compiler")
                if strings_result:
                    info["compiler_info"] = strings_result.strip()

        except Exception as e:
            logger.error(f"Error getting compilation info: {e}")

        return info

    def get_security_features(self) -> dict[str, bool]:
        """Check for security features by reading DllCharacteristics flags"""
        features = {
            "aslr": False,
            "dep": False,
            "seh": False,
            "guard_cf": False,
            "authenticode": False,
        }

        try:
            pe_header = get_pe_headers(self.r2)
            self._apply_security_flags_from_header(features, pe_header)

            if not any(features.values()):
                security_info = safe_cmd(self.r2, "iHH")
                self._apply_security_flags_from_text(features, security_info)

            self._apply_authenticode_feature(features, pe_header)

        except Exception as e:
            logger.error(f"Error checking security features: {e}")

        return features

    def _apply_security_flags_from_header(
        self, features: dict[str, bool], pe_header: dict[str, Any] | None
    ) -> None:
        if not pe_header:
            return
        opt_header = pe_header.get("optional_header", {})
        dll_characteristics = opt_header.get("DllCharacteristics", 0)
        if not isinstance(dll_characteristics, int):
            return

        features["aslr"] = bool(dll_characteristics & 0x0040)
        features["dep"] = bool(dll_characteristics & 0x0100)
        features["seh"] = not bool(dll_characteristics & 0x0400)
        features["guard_cf"] = bool(dll_characteristics & 0x4000)

        logger.debug(f"DllCharacteristics: 0x{dll_characteristics:04x}")
        logger.debug(
            "Security features: ASLR=%s, DEP=%s, SEH=%s, CFG=%s",
            features["aslr"],
            features["dep"],
            features["seh"],
            features["guard_cf"],
        )

    def _apply_security_flags_from_text(
        self, features: dict[str, bool], security_info: str | None
    ) -> None:
        if not security_info:
            return
        if "DLL can move" in security_info or "DYNAMIC_BASE" in security_info:
            features["aslr"] = True
        if "NX_COMPAT" in security_info:
            features["dep"] = True
        if "NO_SEH" not in security_info:
            features["seh"] = True
        if "GUARD_CF" in security_info:
            features["guard_cf"] = True

    def _apply_authenticode_feature(
        self, features: dict[str, bool], pe_header: dict[str, Any] | None
    ) -> None:
        try:
            cert_info = safe_cmd(self.r2, "ic")
            if cert_info and cert_info.strip():
                features["authenticode"] = True
                return
        except Exception as e:
            logger.debug(f"Could not get certificate info via ic command: {e}")

        if self._has_certificate_table(pe_header):
            features["authenticode"] = True

    def _has_certificate_table(self, pe_header: dict[str, Any] | None) -> bool:
        if not pe_header:
            return False
        try:
            opt_header = pe_header.get("optional_header", {})
            data_dirs = opt_header.get("DataDirectory", [])
            if len(data_dirs) <= 4:
                return False
            cert_dir = data_dirs[4]
            return isinstance(cert_dir, dict) and cert_dir.get("Size", 0) > 0
        except (KeyError, TypeError, IndexError) as e:
            logger.debug(f"Could not check certificate table in data directories: {e}")
            return False

    def _get_subsystem_info(self) -> dict[str, Any]:
        """Get subsystem information"""
        info = {}

        try:
            pe_info = safe_cmdj(self.r2, "ij")

            if pe_info and "bin" in pe_info:
                bin_info = pe_info["bin"]

                # Subsystem type
                subsystem = bin_info.get("subsys", "Unknown")
                info["subsystem"] = subsystem

                # Determine if it's a GUI or console application
                if "console" in subsystem.lower():
                    info["gui_app"] = False
                elif "windows" in subsystem.lower():
                    info["gui_app"] = True
                else:
                    info["gui_app"] = None

        except Exception as e:
            logger.error(f"Error getting subsystem info: {e}")

        return info

    def get_resource_info(self) -> list[dict[str, Any]]:
        """Get resource information"""
        resources = []

        try:
            # Get resources from radare2
            res_info = safe_cmdj(self.r2, "iRj")

            if res_info:
                for resource in res_info:
                    resources.append(
                        {
                            "name": resource.get("name", "Unknown"),
                            "type": resource.get("type", "Unknown"),
                            "size": resource.get("size", 0),
                            "lang": resource.get("lang", "Unknown"),
                        }
                    )

        except Exception as e:
            logger.error(f"Error getting resource info: {e}")

        return resources

    def get_version_info(self) -> dict[str, str]:
        """Get version information from resources"""
        version_info = {}

        try:
            # Try to extract version info
            version_result = self.r2.cmd("iR~version")

            if version_result:
                lines = version_result.strip().split("\n")
                for line in lines:
                    if "=" in line:
                        key, value = line.split("=", 1)
                        version_info[key.strip()] = value.strip()

        except Exception as e:
            logger.error(f"Error getting version info: {e}")

        return version_info

    def _fetch_imports(self) -> list[dict]:
        """Fetch imports from radare2.

        Returns:
            list[dict]: List of import dictionaries from radare2
        """
        imports = safe_cmdj(self.r2, "iij", [])
        return imports if imports else []

    def _group_imports_by_library(self, imports: list[dict]) -> dict[str, list[str]]:
        """Group imports by their library name.

        Args:
            imports: List of import dictionaries from radare2

        Returns:
            dict mapping library names to lists of function names
        """
        imports_by_lib: dict[str, list[str]] = {}

        for imp in imports:
            if not isinstance(imp, dict) or "name" not in imp:
                continue

            # Get library name (use 'libname' field from radare2)
            libname = imp.get("libname", "unknown")
            if not libname or libname.strip() == "":
                libname = "unknown"

            # Get function name
            funcname = imp.get("name", "")
            if not funcname or funcname.strip() == "":
                continue

            # Group by library
            if libname not in imports_by_lib:
                imports_by_lib[libname] = []
            imports_by_lib[libname].append(funcname)

        return imports_by_lib

    def _normalize_library_name(self, lib_name: str, extensions: list[str]) -> str:
        """Normalize library name for imphash calculation.

        Args:
            lib_name: The library name to normalize
            extensions: List of extensions to strip (e.g., ['dll', 'ocx', 'sys'])

        Returns:
            Normalized library name (lowercase, extension stripped if applicable)
        """
        # Handle bytes input
        if isinstance(lib_name, bytes):
            lib_name = lib_name.decode()

        lib_name = lib_name.lower()

        # Remove extension if it's one of the known types
        parts = lib_name.rsplit(".", 1)
        if len(parts) > 1 and parts[1] in extensions:
            lib_name = parts[0]

        return lib_name

    def _compute_imphash(self, import_strings: list[str]) -> str:
        """Compute MD5 hash from import strings.

        Args:
            import_strings: List of normalized "libname.funcname" strings

        Returns:
            MD5 hash as hexadecimal string, or empty string if no imports
        """
        if not import_strings:
            return ""

        imphash_string = ",".join(import_strings)
        return hashlib.md5(imphash_string.encode("utf-8"), usedforsecurity=False).hexdigest()

    def calculate_imphash(self) -> str:
        """Calculate Import Hash (imphash) for PE files.

        This implementation follows the exact algorithm used by pefile library:
        https://github.com/erocarrera/pefile/blob/master/pefile.py

        Returns:
            str: MD5 hash of normalized import names, or empty string if no imports
        """
        try:
            logger.debug("Calculating imphash using pefile-compatible algorithm...")

            imports = self._fetch_imports()
            if not imports:
                logger.debug("No imports found for imphash calculation")
                return ""

            imports_by_lib = self._group_imports_by_library(imports)
            extensions = ["ocx", "sys", "dll"]

            # Build import strings in pefile format: "libname.funcname"
            impstrs = []
            for libname, functions in imports_by_lib.items():
                normalized_lib = self._normalize_library_name(libname, extensions)

                for funcname in functions:
                    if not funcname:
                        continue

                    # Normalize function name
                    if isinstance(funcname, bytes):
                        funcname = funcname.decode()

                    # Create the import string in pefile format: "libname.funcname"
                    impstr = f"{normalized_lib}.{funcname.lower()}"
                    impstrs.append(impstr)

            if not impstrs:
                logger.debug("No valid import strings found for imphash")
                return ""

            imphash = self._compute_imphash(impstrs)
            logger.debug(f"Imphash calculated: {imphash} (from {len(impstrs)} imports)")
            return imphash

        except Exception as e:
            logger.error(f"Error calculating imphash: {e}")
            return ""
