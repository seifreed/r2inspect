#!/usr/bin/env python3
"""
YARA Analysis Module
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yara

from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmdj

logger = get_logger(__name__)

# Constants
YARA_EXT = "*.yar"
YARA_YARA_EXT = "*.yara"


class YaraAnalyzer:
    """YARA rules analysis"""

    def __init__(self, r2, config, filepath=None):
        self.r2 = r2
        self.config = config
        self.rules_path = config.get_yara_rules_path()
        self.filepath = filepath  # Store filepath directly to avoid r2 dependency

    def scan(self, custom_rules_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Scan file with YARA rules"""
        matches = []

        try:
            # Use stored filepath first, fallback to r2 if needed
            file_path = self.filepath

            if not file_path:
                # Try to get file path from r2 as fallback
                file_info = safe_cmdj(self.r2, "ij", {})
                if file_info and "core" in file_info:
                    file_path = file_info["core"].get("file", "")

            if not file_path or not os.path.exists(file_path):
                logger.debug(f"File not accessible for YARA scan: {file_path}")
                return matches

            # Use custom rules path if provided
            rules_path = custom_rules_path or self.rules_path

            if not os.path.exists(rules_path):
                logger.warning(f"YARA rules path not found: {rules_path}")
                return matches

            # Compile and run YARA rules
            rules = self._compile_rules(rules_path)
            if rules:
                yara_matches = rules.match(file_path)
                matches = self._process_matches(yara_matches)

        except Exception as e:
            logger.error(f"Error in YARA scan: {e}")

        return matches

    def _compile_rules(self, rules_path: str) -> Optional[yara.Rules]:
        """Compile YARA rules from directory or file - supports ANY YARA file the user places"""
        try:
            rules_dict = {}

            if os.path.isfile(rules_path):
                # Single rule file
                logger.info(f"Loading single YARA file: {rules_path}")
                with open(rules_path, encoding="utf-8", errors="ignore") as f:
                    rules_dict["single_rule"] = f.read()
            elif os.path.isdir(rules_path):
                # Directory of rule files - scan for ALL YARA extensions
                yara_extensions = [YARA_EXT, YARA_YARA_EXT, "*.rule", "*.rules"]
                rules_found = []

                for extension in yara_extensions:
                    for rule_file in Path(rules_path).glob(extension):
                        rules_found.append(rule_file)

                # Also scan recursively for nested directories
                for extension in yara_extensions:
                    for rule_file in Path(rules_path).rglob(extension):
                        if rule_file not in rules_found:
                            rules_found.append(rule_file)

                logger.debug(f"Found {len(rules_found)} YARA rule files in {rules_path}")

                for rule_file in rules_found:
                    try:
                        logger.debug(f"Loading YARA file: {rule_file.name}")
                        with open(rule_file, encoding="utf-8", errors="ignore") as f:
                            content = f.read().strip()
                            if content:  # Only add non-empty files
                                # Use relative path as key to handle nested directories
                                relative_path = rule_file.relative_to(Path(rules_path))
                                rules_dict[str(relative_path)] = content
                            else:
                                logger.warning(f"Empty YARA file: {rule_file}")
                    except Exception as e:
                        logger.warning(f"Failed to read YARA file {rule_file}: {e}")
                        continue
            else:
                logger.error(f"YARA rules path is neither file nor directory: {rules_path}")
                return None

            if not rules_dict:
                logger.warning(f"No valid YARA rules found in: {rules_path}")
                return None

            logger.debug(f"Successfully loaded {len(rules_dict)} YARA rule source(s)")
            return yara.compile(sources=rules_dict)

        except Exception as e:
            logger.error(f"Error compiling YARA rules: {e}")
            return None

    def _process_matches(self, yara_matches: List) -> List[Dict[str, Any]]:
        """Process YARA matches into structured format"""
        matches = []

        try:
            for match in yara_matches:
                match_info = {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags),
                    "meta": dict(match.meta),
                    "strings": [],
                }

                # Process string matches
                for string_match in match.strings:
                    string_info = {
                        "identifier": string_match.identifier,
                        "instances": [],
                    }

                    for instance in string_match.instances:
                        instance_info = {
                            "offset": instance.offset,
                            "matched_data": instance.matched_data.decode("utf-8", errors="ignore"),
                        }

                        # Handle different YARA versions - some have length attribute, some don't
                        if hasattr(instance, "length"):
                            instance_info["length"] = instance.length
                        else:
                            instance_info["length"] = len(instance.matched_data)

                        string_info["instances"].append(instance_info)

                    match_info["strings"].append(string_info)

                matches.append(match_info)

        except Exception as e:
            logger.error(f"Error processing YARA matches: {e}")

        return matches

    def create_default_rules(self):
        """Create default YARA rules if none exist"""
        try:
            rules_dir = Path(self.rules_path)
            rules_dir.mkdir(parents=True, exist_ok=True)

            # Create basic malware detection rules
            default_rules = {
                "packer_detection.yar": """
rule UPX_Packer
{
    strings:
        $upx1 = "UPX!"
        $upx2 = "$Info: This file is packed with the UPX"
    condition:
        any of ($upx*)
}

rule Generic_Packer
{
    strings:
        $s1 = "This program cannot be run in DOS mode"
        $s2 = "PE"
        $packer1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? }  // Common packer stub
        $packer2 = { 55 8B EC 83 EC ?? 53 56 57 }
    condition:
        all of ($s*) and filesize < 100KB and any of ($packer*)
}
""",
                "suspicious_apis.yar": """
rule Suspicious_Process_APIs
{
    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "WriteProcessMemory"
        $api3 = "VirtualAllocEx"
        $api4 = "SetThreadContext"
    condition:
        2 of ($api*)
}

rule Anti_Debug_APIs
{
    strings:
        $api1 = "IsDebuggerPresent"
        $api2 = "CheckRemoteDebuggerPresent"
        $api3 = "OutputDebugString"
    condition:
        any of ($api*)
}
""",
                "crypto_detection.yar": """
rule Crypto_Constants
{
    strings:
        $md5_1 = { 01 23 45 67 }
        $md5_2 = { 89 AB CD EF }
        $sha1_1 = { 67 45 23 01 }
        $sha1_2 = { EF CD AB 89 }
    condition:
        any of them
}
""",
            }

            for filename, content in default_rules.items():
                rule_file = rules_dir / filename
                if not rule_file.exists():
                    with open(rule_file, "w") as f:
                        f.write(content)

        except Exception as e:
            logger.error(f"Error creating default rules: {e}")

    def validate_rules(self, rules_path: str) -> Dict[str, Any]:
        """Validate YARA rules syntax"""
        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "rules_count": 0,
        }

        try:
            rules = self._compile_rules(rules_path)
            if rules:
                validation_result["valid"] = True
                # Count rules (this is a simplified count)
                if os.path.isdir(rules_path):
                    yar_files = list(Path(rules_path).glob(YARA_EXT))
                    yara_files = list(Path(rules_path).glob(YARA_YARA_EXT))
                    validation_result["rules_count"] = len(yar_files) + len(yara_files)
                else:
                    validation_result["rules_count"] = 1
            else:
                validation_result["valid"] = False
                validation_result["errors"].append("Failed to compile rules")

        except Exception as e:
            validation_result["valid"] = False
            validation_result["errors"].append(str(e))

        return validation_result

    def list_available_rules(self, rules_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all available YARA rules in the rules directory"""
        rules_path = rules_path or self.rules_path
        available_rules = []

        try:
            if not os.path.exists(rules_path):
                logger.warning(f"YARA rules path not found: {rules_path}")
                return available_rules

            if os.path.isfile(rules_path):
                # Single file
                stat = os.stat(rules_path)
                available_rules.append(
                    {
                        "name": Path(rules_path).name,
                        "path": rules_path,
                        "size": stat.st_size,
                        "modified": stat.st_mtime,
                        "type": "single_file",
                    }
                )
            elif os.path.isdir(rules_path):
                # Directory
                yara_extensions = [YARA_EXT, YARA_YARA_EXT, "*.rule", "*.rules"]

                for extension in yara_extensions:
                    for rule_file in Path(rules_path).rglob(extension):
                        try:
                            stat = rule_file.stat()
                            relative_path = rule_file.relative_to(Path(rules_path))

                            available_rules.append(
                                {
                                    "name": rule_file.name,
                                    "path": str(rule_file),
                                    "relative_path": str(relative_path),
                                    "size": stat.st_size,
                                    "modified": stat.st_mtime,
                                    "type": "directory_file",
                                }
                            )
                        except Exception as e:
                            logger.warning(f"Error reading file info for {rule_file}: {e}")
                            continue

            logger.info(f"Found {len(available_rules)} YARA rule files total")

        except Exception as e:
            logger.error(f"Error listing YARA rules: {e}")

        return available_rules
