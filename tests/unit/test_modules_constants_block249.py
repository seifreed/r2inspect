from r2inspect.modules import (
    anti_analysis_domain,
    compiler_signatures,
    crypto_constants,
    pe_resource_defaults,
    rich_header_defaults,
    rich_header_domain,
    yara_defaults,
)


def test_module_constant_imports():
    assert "IsDebuggerPresent" in anti_analysis_domain.ANTI_DEBUG_APIS
    assert "VMware" in anti_analysis_domain.VM_ARTIFACTS
    assert "sample" in anti_analysis_domain.SANDBOX_INDICATORS
    assert "VirtualAllocEx" in anti_analysis_domain.INJECTION_APIS
    assert "Process/Thread" in anti_analysis_domain.SUSPICIOUS_API_CATEGORIES
    assert "GetTickCount" in anti_analysis_domain.TIMING_APIS
    assert anti_analysis_domain.ENVIRONMENT_CHECK_COMMANDS

    assert compiler_signatures.COMPILER_SIGNATURES

    assert crypto_constants.CRYPTO_CONSTANTS
    assert pe_resource_defaults.RESOURCE_TYPES
    assert rich_header_defaults.RICH_PATTERNS
    assert rich_header_defaults.DANS_PATTERNS
    assert rich_header_domain.COMPILER_PRODUCTS

    assert yara_defaults.DEFAULT_YARA_RULES
