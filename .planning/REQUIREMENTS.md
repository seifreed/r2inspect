# Requirements: r2inspect v1.4 Governance Operations Hardening

**Defined:** 2026-03-01
**Core Value:** Mantener entregas pequenas, verificables y acumulables.

## v1 Requirements

### Governance Operations

- [ ] **GOV-01**: Operator can set and inspect governance exception retention policy by scope (global/project/requirement family) with transparent auditability.
- [ ] **GOV-02**: Expired governance exceptions are clearly reported and cannot be silently ignored during reporting.

### Traceability Controls

- [ ] **TRC-01**: Operator can run commands with a `--readonly` mode that suppresses traceability snapshot persistence.
- [ ] **TRC-02**: In readonly mode, delta reports still compute and emit full added/removed/changed output while marking persistence as intentionally suppressed.

## v2 Requirements

### Future Enhancements

- **POL-01**: Add centralized exception policy templates per team/project.
- **POL-02**: Add retention policy diff audit in milestone summaries.

## Out of Scope

| Feature | Reason |
|---------|--------|
| Full ALM platform replication inside the quick workflow | Scope would exceed current governance operations milestone |
| Automatic mutation of planning artifacts from remediation hints without explicit approval | Requires approval workflow and explicit user confirmation |
| Historical forensic export format conversion | Nice-to-have, not required for v1.4 governance hardening |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| GOV-01 | 9 | Pending |
| GOV-02 | 9 | Pending |
| TRC-01 | 10 | Pending |
| TRC-02 | 10 | Pending |

**Coverage:**
- v1 requirements: 4 total
- Mapped to phases: 4
- Unmapped: 0
- Coverage: 100%

---
*Requirements defined: 2026-03-01*
*Last updated: 2026-03-01 after opening v1.4*
