
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
