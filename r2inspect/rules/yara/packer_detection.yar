
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
