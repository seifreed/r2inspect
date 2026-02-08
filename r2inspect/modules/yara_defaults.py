#!/usr/bin/env python3
"""Default YARA rule content."""

DEFAULT_YARA_RULES = {
    "packer_detection.yar": """
rule UPX_Packed
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
