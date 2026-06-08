"""Core engine for CMMCMAP.

Real logic, no stubs:
  * A curated catalog of representative CMMC Level 2 practices keyed by their
    official identifiers (e.g. AC.L2-3.1.1), each tagged with the kinds of
    stack capabilities that can implement them.
  * A capability inference engine that derives capabilities from a declared
    technology stack (components + their roles/tags).
  * A mapper that assigns each practice an implementation status
    (satisfied / partial / planned) based on capability coverage.
  * An OSCAL-flavored SSP skeleton builder.

Stack input format (JSON):
  {
    "system_name": "Acme CUI Enclave",
    "components": [
      {"name": "Okta", "role": "idp", "tags": ["mfa", "sso"]},
      {"name": "AWS GovCloud", "role": "cloud", "tags": ["kms", "cloudtrail"]}
    ]
  }
"""
from __future__ import annotations

import json
from typing import Dict, List, Any

# ---------------------------------------------------------------------------
# CMMC Level 2 domains (NIST SP 800-171 control families)
# ---------------------------------------------------------------------------
DOMAINS: Dict[str, str] = {
    "AC": "Access Control",
    "AU": "Audit and Accountability",
    "CM": "Configuration Management",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MP": "Media Protection",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}

# ---------------------------------------------------------------------------
# Practice catalog. Each practice lists the capability keys that can satisfy
# it. A practice is 'satisfied' when ALL required capabilities are present,
# 'partial' when SOME are present, and 'planned' when NONE are.
# ---------------------------------------------------------------------------
PRACTICES: Dict[str, Dict[str, Any]] = {
    "AC.L2-3.1.1": {
        "domain": "AC",
        "title": "Limit system access to authorized users",
        "caps": ["identity_provider", "access_control"],
    },
    "AC.L2-3.1.5": {
        "domain": "AC",
        "title": "Employ least privilege",
        "caps": ["rbac"],
    },
    "AC.L2-3.1.12": {
        "domain": "AC",
        "title": "Monitor and control remote access sessions",
        "caps": ["vpn", "session_logging"],
    },
    "AU.L2-3.3.1": {
        "domain": "AU",
        "title": "Create and retain system audit logs",
        "caps": ["audit_logging"],
    },
    "AU.L2-3.3.5": {
        "domain": "AU",
        "title": "Correlate audit review and analysis",
        "caps": ["siem"],
    },
    "CM.L2-3.4.1": {
        "domain": "CM",
        "title": "Establish and maintain baseline configurations",
        "caps": ["config_management"],
    },
    "CM.L2-3.4.2": {
        "domain": "CM",
        "title": "Enforce security configuration settings",
        "caps": ["config_management", "policy_enforcement"],
    },
    "IA.L2-3.5.3": {
        "domain": "IA",
        "title": "Use multifactor authentication",
        "caps": ["mfa"],
    },
    "IA.L2-3.5.1": {
        "domain": "IA",
        "title": "Identify system users and processes",
        "caps": ["identity_provider"],
    },
    "IR.L2-3.6.1": {
        "domain": "IR",
        "title": "Establish incident-handling capability",
        "caps": ["incident_response"],
    },
    "MP.L2-3.8.3": {
        "domain": "MP",
        "title": "Sanitize media before disposal or reuse",
        "caps": ["media_sanitization"],
    },
    "SC.L2-3.13.8": {
        "domain": "SC",
        "title": "Encrypt CUI in transit",
        "caps": ["tls", "encryption_in_transit"],
    },
    "SC.L2-3.13.11": {
        "domain": "SC",
        "title": "Employ FIPS-validated cryptography",
        "caps": ["fips_crypto", "kms"],
    },
    "SC.L2-3.13.16": {
        "domain": "SC",
        "title": "Protect confidentiality of CUI at rest",
        "caps": ["encryption_at_rest"],
    },
    "SI.L2-3.14.1": {
        "domain": "SI",
        "title": "Identify and correct system flaws",
        "caps": ["vuln_management", "patching"],
    },
    "SI.L2-3.14.2": {
        "domain": "SI",
        "title": "Provide malicious-code protection",
        "caps": ["endpoint_protection"],
    },
}

# ---------------------------------------------------------------------------
# Capability inference. Maps component roles and free-form tags to the
# normalized capability keys used by the practice catalog.
# ---------------------------------------------------------------------------
_ROLE_CAPS: Dict[str, List[str]] = {
    "idp": ["identity_provider", "access_control", "rbac"],
    "siem": ["siem", "audit_logging", "session_logging"],
    "cloud": ["audit_logging", "encryption_at_rest", "encryption_in_transit"],
    "edr": ["endpoint_protection"],
    "vpn": ["vpn", "session_logging", "encryption_in_transit"],
    "scanner": ["vuln_management", "patching"],
    "mdm": ["config_management", "policy_enforcement"],
    "ticketing": ["incident_response"],
}

_TAG_CAPS: Dict[str, str] = {
    "mfa": "mfa",
    "sso": "identity_provider",
    "rbac": "rbac",
    "kms": "kms",
    "fips": "fips_crypto",
    "tls": "tls",
    "cloudtrail": "audit_logging",
    "audit": "audit_logging",
    "siem": "siem",
    "vpn": "vpn",
    "patch": "patching",
    "patching": "patching",
    "av": "endpoint_protection",
    "antivirus": "endpoint_protection",
    "edr": "endpoint_protection",
    "wipe": "media_sanitization",
    "sanitize": "media_sanitization",
    "ir": "incident_response",
    "baseline": "config_management",
    "hardening": "policy_enforcement",
    "at_rest": "encryption_at_rest",
    "in_transit": "encryption_in_transit",
}


class StackError(ValueError):
    """Raised when a stack definition is malformed."""


def load_stack(raw: str) -> Dict[str, Any]:
    """Parse and validate a stack JSON document."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise StackError(f"invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise StackError("stack must be a JSON object")
    comps = data.get("components")
    if not isinstance(comps, list) or not comps:
        raise StackError("stack must contain a non-empty 'components' list")
    for c in comps:
        if not isinstance(c, dict) or "name" not in c:
            raise StackError("each component needs at least a 'name'")
    data.setdefault("system_name", "Unnamed System")
    return data


def _component_caps(comp: Dict[str, Any]) -> set:
    caps: set = set()
    role = str(comp.get("role", "")).lower().strip()
    if role in _ROLE_CAPS:
        caps.update(_ROLE_CAPS[role])
    for tag in comp.get("tags", []) or []:
        key = str(tag).lower().strip()
        if key in _TAG_CAPS:
            caps.add(_TAG_CAPS[key])
    return caps


def _stack_capability_index(stack: Dict[str, Any]) -> Dict[str, List[str]]:
    """Return {capability: [component names that provide it]}."""
    index: Dict[str, List[str]] = {}
    for comp in stack["components"]:
        name = comp["name"]
        for cap in _component_caps(comp):
            index.setdefault(cap, [])
            if name not in index[cap]:
                index[cap].append(name)
    return index


def map_stack(stack: Dict[str, Any]) -> Dict[str, Any]:
    """Map the stack to every practice and assign an implementation status."""
    cap_index = _stack_capability_index(stack)
    have = set(cap_index)
    results: List[Dict[str, Any]] = []
    for pid, spec in PRACTICES.items():
        required = spec["caps"]
        met = [c for c in required if c in have]
        if len(met) == len(required):
            status = "satisfied"
        elif met:
            status = "partial"
        else:
            status = "planned"
        providers = sorted({n for c in met for n in cap_index.get(c, [])})
        missing = [c for c in required if c not in have]
        results.append(
            {
                "id": pid,
                "domain": spec["domain"],
                "title": spec["title"],
                "status": status,
                "required_caps": required,
                "missing_caps": missing,
                "providers": providers,
            }
        )
    results.sort(key=lambda r: r["id"])
    return {
        "system_name": stack["system_name"],
        "capabilities": cap_index,
        "practices": results,
    }


def coverage_report(mapping: Dict[str, Any]) -> Dict[str, Any]:
    """Summarize coverage overall and per domain."""
    practices = mapping["practices"]
    total = len(practices)
    counts = {"satisfied": 0, "partial": 0, "planned": 0}
    per_domain: Dict[str, Dict[str, int]] = {}
    for p in practices:
        counts[p["status"]] += 1
        d = per_domain.setdefault(
            p["domain"], {"satisfied": 0, "partial": 0, "planned": 0, "total": 0}
        )
        d[p["status"]] += 1
        d["total"] += 1
    # weighted score: satisfied=1.0, partial=0.5, planned=0
    score = (counts["satisfied"] + 0.5 * counts["partial"]) / total if total else 0.0
    return {
        "system_name": mapping["system_name"],
        "total_practices": total,
        "counts": counts,
        "coverage_score": round(score, 3),
        "per_domain": per_domain,
    }


def build_ssp_skeleton(mapping: Dict[str, Any]) -> Dict[str, Any]:
    """Emit an OSCAL-flavored SSP skeleton from a mapping."""
    impl_reqs = []
    for p in mapping["practices"]:
        if p["status"] == "satisfied":
            statement = (
                "Implemented by: " + ", ".join(p["providers"]) + "."
            )
        elif p["status"] == "partial":
            statement = (
                "Partially implemented by: "
                + ", ".join(p["providers"])
                + ". Remaining capabilities required: "
                + ", ".join(p["missing_caps"])
                + "."
            )
        else:
            statement = (
                "Not yet implemented. Required capabilities: "
                + ", ".join(p["required_caps"])
                + "."
            )
        impl_reqs.append(
            {
                "control-id": p["id"],
                "props": [
                    {"name": "implementation-status", "value": p["status"]},
                    {"name": "domain", "value": DOMAINS.get(p["domain"], p["domain"])},
                ],
                "statements": [
                    {"statement-id": p["id"] + "_smt", "description": statement}
                ],
            }
        )
    return {
        "system-security-plan": {
            "metadata": {
                "title": mapping["system_name"] + " - CMMC Level 2 SSP",
                "oscal-flavor": "cmmcmap-1.0",
                "frameworks": ["CMMC 2.0 Level 2", "NIST SP 800-171 Rev 2"],
            },
            "control-implementation": {
                "description": "Generated by cmmcmap from declared technology stack.",
                "implemented-requirements": impl_reqs,
            },
        }
    }


def practice_catalog() -> List[Dict[str, Any]]:
    """Return the full practice catalog as a list."""
    return [
        {
            "id": pid,
            "domain": spec["domain"],
            "domain_name": DOMAINS.get(spec["domain"], spec["domain"]),
            "title": spec["title"],
            "required_caps": spec["caps"],
        }
        for pid, spec in sorted(PRACTICES.items())
    ]
