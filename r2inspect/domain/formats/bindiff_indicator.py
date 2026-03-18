"""Indicator and signature helpers for BinDiff domain analysis."""

from __future__ import annotations

from typing import Any


CRYPTO_TERMS = [
    "encrypt",
    "decrypt",
    "cipher",
    "hash",
    "md5",
    "sha",
    "aes",
    "rsa",
    "key",
    "crypto",
]
NETWORK_TERMS = [
    "http",
    "tcp",
    "udp",
    "socket",
    "connect",
    "download",
    "upload",
    "url",
]
PERSIST_TERMS = [
    "startup",
    "autorun",
    "service",
    "registry",
    "schedule",
    "task",
]
SUSPICIOUS_APIS = [
    "CreateRemoteThread",
    "WriteProcessMemory",
    "VirtualAllocEx",
    "SetWindowsHookEx",
    "GetKeyState",
    "GetAsyncKeyState",
    "CreateService",
]
CRYPTO_APIS = [
    "CryptAcquireContext",
    "CryptCreateHash",
    "CryptEncrypt",
    "CryptDecrypt",
]
NETWORK_APIS = [
    "WSAStartup",
    "socket",
    "connect",
    "send",
    "recv",
    "InternetOpen",
    "HttpOpenRequest",
    "HttpSendRequest",
]


def has_crypto_indicators(text: str) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in CRYPTO_TERMS)


def has_network_indicators(text: str) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in NETWORK_TERMS)


def has_persistence_indicators(text: str) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in PERSIST_TERMS)


def is_suspicious_api(api: str) -> bool:
    lowered = api.lower()
    return any(sus_api.lower() in lowered for sus_api in SUSPICIOUS_APIS)


def is_crypto_api(api: str) -> bool:
    lowered = api.lower()
    return any(crypto_api.lower() in lowered for crypto_api in CRYPTO_APIS)


def is_network_api(api: str) -> bool:
    lowered = api.lower()
    return any(net_api.lower() in lowered for net_api in NETWORK_APIS)


def build_struct_signature(struct_features: dict[str, Any]) -> str:
    return (
        f"{struct_features.get('file_type', '')}-"
        f"{struct_features.get('architecture', '')}-"
        f"{len(struct_features.get('section_names', []))}"
    )


def build_function_signature(func_features: dict[str, Any]) -> str:
    return (
        f"{func_features.get('function_count', 0)}-"
        f"{len(func_features.get('function_names', []))}"
    )


def build_string_signature(string_features: dict[str, Any]) -> str:
    return (
        f"{string_features.get('total_strings', 0)}-"
        f"{len(string_features.get('api_strings', []))}-"
        f"{len(string_features.get('path_strings', []))}"
    )


def build_behavioral_signature(behavioral_features: dict[str, Any]) -> str:
    return (
        f"{behavioral_features.get('crypto_indicators', 0)}-"
        f"{behavioral_features.get('network_indicators', 0)}-"
        f"{behavioral_features.get('suspicious_apis', 0)}"
    )
