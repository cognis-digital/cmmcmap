"""Smoke tests for cmmcmap. No network. Standard library only."""
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cmmcmap import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    CATALOG,
    FAMILIES,
    assess,
    build_poam,
    build_ssp,
    list_controls,
    score_sprs,
)
from cmmcmap.core import Status, has_findings  # noqa: E402
from cmmcmap import cli  # noqa: E402


INVENTORY = {
    "system_name": "Test Enclave",
    "platforms": ["AWS GovCloud", "Okta"],
    "iam": True,
    "access_control": "Okta RBAC + AWS IAM",
    "mfa": True,
    "multifactor": "Okta Verify enforced for admin + remote",
    "fips_crypto": True,
    "fips_140": "AWS KMS FIPS endpoints",
    "siem": "Splunk Enterprise",
    "audit": True,
    "patching": "Tenable Nessus weekly",
    "vpn": "planned",
    "remote_access_monitoring": "planned",
    "media_sanitization": False,
}


class TestCore(unittest.TestCase):
    def test_meta(self):
        self.assertEqual(TOOL_NAME, "cmmcmap")
        self.assertTrue(TOOL_VERSION)

    def test_catalog_is_full_800171(self):
        self.assertEqual(len(CATALOG), 110)
        self.assertEqual(len(FAMILIES), 14)
        # DoD Assessment Methodology weights; 3.12.4 (SSP) carries no points
        self.assertTrue(all(c.weight in (0, 1, 3, 5) for c in CATALOG))

    def test_family_filter(self):
        ac = list_controls("AC")
        self.assertTrue(ac)
        self.assertTrue(all(c.family == "AC" for c in ac))

    def test_assess_statuses(self):
        by = {f.control: f for f in assess(INVENTORY)}
        # MFA evidence present -> met
        self.assertEqual(by["3.5.3"].status, Status.MET)
        # FIPS crypto evidence present -> met
        self.assertEqual(by["3.13.11"].status, Status.MET)
        # VPN marked planned -> partial
        self.assertEqual(by["3.1.12"].status, Status.PARTIAL)
        # media_sanitization explicitly false -> not met
        self.assertEqual(by["3.8.3"].status, Status.NOT_MET)

    def test_na_respected(self):
        inv = dict(INVENTORY)
        inv["na"] = ["3.8.3"]
        by = {f.control: f for f in assess(inv)}
        self.assertEqual(by["3.8.3"].status, Status.NA)

    def test_sprs_score_shape(self):
        findings = assess(INVENTORY)
        score = score_sprs(findings)
        self.assertEqual(score["max_score"], 110)
        self.assertLessEqual(score["sprs_score"], 110)
        counts = score["counts"]
        self.assertEqual(sum(counts.values()), score["assessed_controls"])

    def test_poam_only_open_controls(self):
        rows = build_poam(assess(INVENTORY))
        self.assertTrue(rows)
        self.assertTrue(all(r["status"] in ("NOT_MET", "PARTIAL", "UNKNOWN")
                            for r in rows))
        # highest-impact first
        weights = [r["weight"] for r in rows]
        self.assertEqual(weights, sorted(weights, reverse=True))

    def test_ssp_mentions_system_and_score(self):
        findings = assess(INVENTORY)
        ssp = build_ssp(INVENTORY, findings, system_name="Test Enclave")
        self.assertIn("Test Enclave", ssp)
        self.assertIn("System Security Plan", ssp)

    def test_has_findings(self):
        self.assertTrue(has_findings(assess(INVENTORY)))


class TestCLI(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = cli.main(argv)
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        return code, out.getvalue(), err.getvalue()

    def setUp(self):
        self.inv_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "_tmp_inventory.json"
        )
        with open(self.inv_path, "w", encoding="utf-8") as fh:
            json.dump(INVENTORY, fh)

    def tearDown(self):
        if os.path.exists(self.inv_path):
            os.remove(self.inv_path)

    def test_controls_json(self):
        code, out, _ = self._run(["controls", "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out)), 110)

    def test_families_json(self):
        code, out, _ = self._run(["families", "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out)), 14)

    def test_assess_table_exit_one_on_gaps(self):
        code, out, _ = self._run(["assess", self.inv_path, "--format", "table"])
        self.assertEqual(code, 1)  # open findings -> nonzero
        self.assertIn("3.5.3", out)

    def test_score_json(self):
        code, out, _ = self._run(["score", self.inv_path, "--format", "json"])
        self.assertEqual(code, 1)
        self.assertIn("sprs_score", json.loads(out))

    def test_ssp_runs(self):
        code, out, _ = self._run(["ssp", self.inv_path, "--name", "Test Enclave"])
        self.assertEqual(code, 1)
        self.assertIn("Test Enclave", out)

    def test_poam_runs(self):
        code, out, _ = self._run(["poam", self.inv_path, "--format", "json"])
        self.assertEqual(code, 1)
        self.assertTrue(json.loads(out))

    def test_missing_file_exit_two(self):
        code, _, err = self._run(["assess", "/no/such/file.json"])
        self.assertEqual(code, 2)
        self.assertIn("error", err.lower())


if __name__ == "__main__":
    unittest.main()
