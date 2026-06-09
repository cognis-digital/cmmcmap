"""CMMCMAP - NIST SP 800-171 / CMMC Level 2 self-assessment engine.

A zero-install, standard-library-only tool that bundles the real
110-control NIST SP 800-171 catalog (14 control families), performs a
stack-aware gap assessment against an inventory you describe, and emits a
System Security Plan (SSP) skeleton plus a Plan of Action & Milestones
(POA&M). Defensive / compliance use only.

The catalog mirrors NIST SP 800-171 Rev. 2 requirement identifiers
(3.1.1 ... 3.14.3) and the DoD Assessment Methodology point weights
(1 / 3 / 5) used to compute the 110-point SPRS-style score.
"""
from .core import (
    TOOL_NAME,
    TOOL_VERSION,
    Control,
    Family,
    Status,
    GapFinding,
    CATALOG,
    FAMILIES,
    list_controls,
    assess,
    score_sprs,
    build_ssp,
    build_poam,
    render_table,
    render_json,
)

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Control",
    "Family",
    "Status",
    "GapFinding",
    "CATALOG",
    "FAMILIES",
    "list_controls",
    "assess",
    "score_sprs",
    "build_ssp",
    "build_poam",
    "render_table",
    "render_json",
]
