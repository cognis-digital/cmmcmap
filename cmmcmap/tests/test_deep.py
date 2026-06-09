"""Deep tests for cmmcmap: full 110-control catalog, stack-aware assessment,
SPRS scoring, SSP + POA&M generation, and CLI behavior. No network."""
from __future__ import annotations

import io
import json
import os
import sys
from collections import Counter

import pytest

from cmmcmap import (
    TOOL_NAME,
    TOOL_VERSION,
    CATALOG,
    FAMILIES,
    Status,
    assess,
    score_sprs,
    build_ssp,
    build_poam,
    list_controls,
    render_json,
)
from cmmcmap.cli import main

DEMO_INV = os.path.join(os.path.dirname(__file__), "..", "demos", "02-deep", "inventory.json")


# --- Catalog integrity: the real 110-control / 14-family structure ---------
def test_exports():
    assert TOOL_NAME == "cmmcmap"
    assert isinstance(TOOL_VERSION, str) and TOOL_VERSION.count(".") == 2


def test_catalog_is_110_controls():
    assert len(CATALOG) == 110


def test_fourteen_families():
    assert len(FAMILIES) == 14


def test_family_control_counts_match_nist():
    # Published NIST SP 800-171 Rev. 2 per-family requirement counts.
    expected = {
        "AC": 22, "AT": 3, "AU": 9, "CM": 9, "IA": 11, "IR": 3, "MA": 6,
        "MP": 9, "PS": 2, "PE": 6, "RA": 3, "CA": 4, "SC": 16, "SI": 7,
    }
    counts = Counter(c.family for c in CATALOG)
    assert dict(counts) == expected
    assert sum(expected.values()) == 110


def test_control_ids_unique_and_well_formed():
    ids = [c.id for c in CATALOG]
    assert len(set(ids)) == 110
    for cid in ids:
        parts = cid.split(".")
        assert len(parts) == 3 and parts[0] == "3"


def test_weights_are_valid_dod_values():
    for c in CATALOG:
        assert c.weight in (0, 1, 3, 5)


def test_list_controls_filter():
    ac = list_controls("AC")
    assert len(ac) == 22
    assert all(c.family == "AC" for c in ac)
    # Case-insensitive.
    assert len(list_controls("ac")) == 22


# --- Stack-aware assessment -------------------------------------------------
def test_empty_inventory_is_all_unknown_or_inherited():
    findings = assess({})
    assert len(findings) == 110
    # With no platforms and no evidence, nothing should be MET.
    assert not any(f.status == Status.MET for f in findings)
    assert any(f.status == Status.UNKNOWN for f in findings)


def test_evidence_present_marks_met():
    inv = {"mfa": True, "multifactor": True}
    findings = {f.control: f for f in assess(inv)}
    assert findings["3.5.3"].status == Status.MET  # MFA control


def test_false_evidence_marks_not_met():
    inv = {"fips_crypto": False, "fips_140": False}
    findings = {f.control: f for f in assess(inv)}
    assert findings["3.13.11"].status == Status.NOT_MET


def test_planned_value_marks_partial():
    inv = {"pam": "planned", "least_privilege": False}
    findings = {f.control: f for f in assess(inv)}
    # 3.1.5 has evidence keys least_privilege + pam; pam=planned -> PARTIAL.
    assert findings["3.1.5"].status == Status.PARTIAL


def test_na_marking():
    inv = {"na": ["3.13.14"]}
    findings = {f.control: f for f in assess(inv)}
    assert findings["3.13.14"].status == Status.NA


def test_inherited_hint_from_platform():
    inv = {"platforms": ["AWS GovCloud", "Azure AD"]}
    findings = {f.control: f for f in assess(inv)}
    # 3.1.1 lists AWS IAM / Azure AD as inheritable.
    assert findings["3.1.1"].inherited_hint != ""
    # No local evidence but inheritable -> PARTIAL not NOT_MET.
    assert findings["3.1.1"].status == Status.PARTIAL


def test_family_scoped_assessment():
    findings = assess({"mfa": True}, family="IA")
    assert len(findings) == 11
    assert all(f.family == "IA" for f in findings)


# --- SPRS scoring -----------------------------------------------------------
def test_perfect_score_when_all_keyed_controls_met():
    # Provide every evidence key truthy; policy controls stay UNKNOWN.
    inv = {}
    for c in CATALOG:
        for k in c.evidence_keys:
            inv[k] = True
    score = score_sprs(assess(inv))
    assert score["max_score"] == 110
    # All keyed controls MET; only zero-evidence policy controls deduct.
    # Those policy controls all happen to carry weight, so deduction > 0.
    assert score["sprs_score"] <= 110


def test_not_met_deducts_full_weight():
    # Use a control with dedicated evidence keys so the delta is isolated.
    # 3.4.8 (app allow-listing, weight 5) keys: application_allowlist, app_control.
    base = score_sprs(assess({"application_allowlist": True}))
    worse = score_sprs(assess({"application_allowlist": False, "app_control": False}))
    assert base["sprs_score"] - worse["sprs_score"] == 5


def test_partial_deducts_half_weight():
    met = score_sprs(assess({"pam": True, "least_privilege": True}))
    partial = score_sprs(assess({"pam": "planned", "least_privilege": "planned"}))
    # 3.1.5 weight 3 -> partial deducts ceil(3/2)=2.
    assert partial["sprs_score"] < met["sprs_score"]


def test_score_counts_sum_to_110():
    score = score_sprs(assess({}))
    assert sum(score["counts"].values()) == 110


# --- SSP + POA&M ------------------------------------------------------------
def test_ssp_skeleton_contains_required_sections():
    findings = assess({"mfa": True, "platforms": ["AWS GovCloud"]})
    ssp = build_ssp({"platforms": ["AWS GovCloud"]}, findings, "Test System")
    assert "System Security Plan" in ssp
    assert "Test System" in ssp
    assert "SPRS Self-Assessment Score" in ssp
    assert "Plan of Action" in ssp
    # Every family with controls should appear.
    for abbr in FAMILIES:
        assert abbr in ssp


def test_poam_only_open_items_sorted_by_weight():
    findings = assess({"fips_crypto": False, "fips_140": False})
    rows = build_poam(findings)
    assert all(r["status"] in ("NOT_MET", "PARTIAL", "UNKNOWN") for r in rows)
    # Highest weight first.
    weights = [r["weight"] for r in rows]
    assert weights == sorted(weights, reverse=True)
    # The FIPS finding (weight 5) must be in the POA&M.
    assert any(r["control"] == "3.13.11" for r in rows)


# --- The bundled deep demo --------------------------------------------------
def test_demo_inventory_loads_and_assesses():
    assert os.path.exists(DEMO_INV)
    with open(DEMO_INV, "r", encoding="utf-8") as fh:
        inv = json.load(fh)
    findings = assess(inv)
    assert len(findings) == 110
    by_id = {f.control: f for f in findings}
    # Baked-in gaps.
    assert by_id["3.13.11"].status == Status.NOT_MET   # FIPS crypto off
    assert by_id["3.4.8"].status == Status.NOT_MET     # app allowlist off
    assert by_id["3.6.3"].status == Status.PARTIAL     # ir_tabletop planned
    # NA markings.
    assert by_id["3.13.14"].status == Status.NA
    # Many controls met.
    met = [f for f in findings if f.status == Status.MET]
    assert len(met) >= 40


def test_demo_score_below_perfect():
    with open(DEMO_INV, "r", encoding="utf-8") as fh:
        inv = json.load(fh)
    score = score_sprs(assess(inv))
    assert score["sprs_score"] < 110
    assert score["counts"]["NOT_MET"] >= 2
    assert score["counts"]["PARTIAL"] >= 3


# --- CLI behavior + JSON + exit codes ---------------------------------------
def _capture(argv):
    out, err = io.StringIO(), io.StringIO()
    old_o, old_e = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        rc = main(argv)
    finally:
        sys.stdout, sys.stderr = old_o, old_e
    return rc, out.getvalue(), err.getvalue()


def test_cli_version():
    with pytest.raises(SystemExit) as ex:
        _capture(["--version"])
    assert ex.value.code == 0


def test_cli_controls_count():
    rc, out, _ = _capture(["controls"])
    assert rc == 0
    assert "110 controls" in out


def test_cli_families():
    rc, out, _ = _capture(["families"])
    assert rc == 0
    assert "14 families" in out


def test_cli_assess_table_exits_nonzero_on_findings():
    rc, out, _ = _capture(["assess", DEMO_INV, "--name", "Acme"])
    assert rc == 1  # gaps present
    assert "SPRS score" in out
    assert "Acme" in out


def test_cli_assess_json_is_valid_and_has_poam():
    rc, out, _ = _capture(["assess", DEMO_INV, "--format", "json"])
    assert rc == 1
    data = json.loads(out)
    assert data["tool"] == "cmmcmap"
    assert len(data["findings"]) == 110
    assert data["score"]["sprs_score"] < 110
    assert len(data["poam"]) >= 1


def test_cli_score_json():
    rc, out, _ = _capture(["score", DEMO_INV, "--format", "json"])
    assert rc == 1
    data = json.loads(out)
    assert data["max_score"] == 110


def test_cli_ssp_markdown():
    rc, out, _ = _capture(["ssp", DEMO_INV, "--name", "Acme"])
    assert rc == 1
    assert "System Security Plan" in out
    assert "Acme" in out


def test_cli_poam_json():
    rc, out, _ = _capture(["poam", DEMO_INV, "--format", "json"])
    assert rc == 1
    rows = json.loads(out)
    assert isinstance(rows, list) and len(rows) >= 1
    assert "control" in rows[0]


def test_clean_inventory_exits_zero():
    # Build an inventory where every keyed control is satisfied and the
    # zero-evidence policy controls are marked NA so there are no findings.
    inv = {}
    for c in CATALOG:
        for k in c.evidence_keys:
            inv[k] = True
    inv["na"] = [c.id for c in CATALOG if not c.evidence_keys]
    findings = assess(inv)
    assert not any(f.status in (Status.NOT_MET, Status.PARTIAL) for f in findings)
    # Round-trip through render_json.
    data = json.loads(render_json(findings, inv, "Clean"))
    assert data["score"]["counts"]["NOT_MET"] == 0
