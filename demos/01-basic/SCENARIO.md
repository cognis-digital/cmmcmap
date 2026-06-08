# Demo 01 - Basic: Mapping a small CUI enclave

This scenario models a realistic small-business CUI enclave seeking CMMC
Level 2 readiness. The stack (`stack.json`) declares the security-relevant
components the organization already runs:

| Component       | Role      | Capabilities (tags)              |
|-----------------|-----------|----------------------------------|
| Okta            | idp       | mfa, sso, rbac                   |
| AWS GovCloud    | cloud     | kms, cloudtrail, at_rest, fips   |
| CrowdStrike     | edr       | edr                              |
| Splunk          | siem      | siem, audit                      |
| Tenable Nessus  | scanner   | patching                         |

Note there is **no** VPN, MDM/config baseline, incident-response, or media
sanitization tooling declared - so cmmcmap should report those practices as
`partial` or `planned`.

## Run it

```bash
# Human-readable mapping
python -m cmmcmap --format table map demos/01-basic/stack.json

# Coverage scorecard
python -m cmmcmap --format table coverage demos/01-basic/stack.json

# OSCAL-flavored SSP skeleton (JSON)
python -m cmmcmap ssp demos/01-basic/stack.json
```

## Expected

- IA.L2-3.5.3 (MFA) -> **satisfied** (Okta)
- SC.L2-3.13.11 (FIPS crypto) -> **satisfied** (AWS GovCloud provides kms + fips)
- AC.L2-3.1.12 (remote access) -> **partial/planned** (no VPN declared)
- MP.L2-3.8.3 (media sanitization) -> **planned**
- IR.L2-3.6.1 (incident handling) -> **planned**

The coverage score is the weighted fraction of practices met
(satisfied = 1.0, partial = 0.5, planned = 0).
