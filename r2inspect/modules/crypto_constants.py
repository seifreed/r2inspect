#!/usr/bin/env python3
"""Static crypto constants used by analyzers."""

CRYPTO_CONSTANTS = {
    "aes_sbox": [
        0x63,
        0x7C,
        0x77,
        0x7B,
        0xF2,
        0x6B,
        0x6F,
        0xC5,
        0x30,
        0x01,
        0x67,
        0x2B,
        0xFE,
        0xD7,
        0xAB,
        0x76,
    ],
    "md5_h": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
    "sha1_h": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
    "sha256_k": [
        0x428A2F98,
        0x71374491,
        0xB5C0FBCF,
        0xE9B5DBA5,
        0x3956C25B,
        0x59F111F1,
        0x923F82A4,
        0xAB1C5ED5,
    ],
    "des_sbox": [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    # Only the distinctive F4 exponent (65537). The small valid exponents 3 and
    # 17 are searched as the 32-bit words 03 00 00 00 / 11 00 00 00, which occur
    # in virtually every binary -> they reported "0x3"/"0x11" crypto constants on
    # benign PE/ELF. 65537 (01 00 01 00) is a meaningful RSA marker.
    "rsa_exponents": [65537],
}
