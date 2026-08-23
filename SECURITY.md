# Security Policy

## Supported versions

Security fixes are applied to the latest release and the `main` branch.

## Reporting a vulnerability

Do not open a public issue for a vulnerability. Use GitHub's private security
advisory form for this repository and include:

- affected version and platform;
- a minimal reproducer or sample characteristics;
- expected and observed behavior;
- security impact;
- any suggested mitigation.

Do not attach live malware unless the maintainer explicitly requests a secure
transfer. Reports are acknowledged as soon as practical. A fix, advisory, and
release are coordinated before public disclosure.

## Scope

In scope are command execution, path traversal, unsafe archive or rule loading,
privilege boundary violations, denial of service from malformed input, secret
exposure, and supply-chain compromise. Detector false positives and false
negatives are quality issues unless they cross a security boundary.
