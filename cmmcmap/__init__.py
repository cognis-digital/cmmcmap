"""CMMCMAP - CMMC Level 2 practice mapper and stack-aware SSP skeleton generator.

Maps an inventory of technology stack components to the CMMC Level 2
security practices (derived from NIST SP 800-171 control families) that
those components can satisfy, then emits a System Security Plan (SSP)
skeleton in the spirit of usnistgov/OSCAL.

Standard library only. Zero install.
"""
from .core import (
    PRACTICES,
    DOMAINS,
    load_stack,
    map_stack,
    coverage_report,
    build_ssp_skeleton,
    practice_catalog,
)

TOOL_NAME = "cmmcmap"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "PRACTICES",
    "DOMAINS",
    "load_stack",
    "map_stack",
    "coverage_report",
    "build_ssp_skeleton",
    "practice_catalog",
]
