# Deep demo — stack-aware 800-171 gap assessment + SSP

A small Defense Industrial Base (DIB) contractor handles Controlled
Unclassified Information (CUI) on **AWS GovCloud** + **Microsoft 365 GCC High**,
with endpoints managed by **Intune**. They need a CMMC Level 2 self-assessment,
a SPRS score, an SSP skeleton, and a POA&M of what is still open.

`inventory.json` describes their actual technology stack as evidence keys.
Notable gaps deliberately baked in:

- `fips_crypto: false` / `fips_140: false` → **3.13.11** (FIPS-validated crypto,
  weight 5) is NOT met — a classic, high-impact CMMC finding.
- `application_allowlist: false` → **3.4.8** (app allow-listing, weight 5) NOT met.
- Several `"planned"` values (PAM, USB control, IR tabletop, continuous
  monitoring, removable-media control, log integrity) → **PARTIAL** (half credit).
- `na: ["3.13.14", "3.1.16", "3.1.17"]` marks VoIP + wireless as not applicable.

## Run it

```bash
# Full assessment table (exits 1 because gaps exist)
python -m cmmcmap assess cmmcmap/demos/02-deep/inventory.json --name "Acme Defense Widgets"

# Just the SPRS score
python -m cmmcmap score cmmcmap/demos/02-deep/inventory.json

# Generate the System Security Plan skeleton (Markdown)
python -m cmmcmap ssp cmmcmap/demos/02-deep/inventory.json --name "Acme Defense Widgets" -o SSP.md

# Plan of Action & Milestones, highest-impact first
python -m cmmcmap poam cmmcmap/demos/02-deep/inventory.json

# Machine-readable bundle (findings + score + POA&M)
python -m cmmcmap assess cmmcmap/demos/02-deep/inventory.json --format json
```

The SPRS score starts at 110 and subtracts each unmet control's DoD Assessment
Methodology weight (1/3/5); PARTIAL controls deduct half. A perfect environment
scores 110; this demo deliberately lands below that with a concrete POA&M.
