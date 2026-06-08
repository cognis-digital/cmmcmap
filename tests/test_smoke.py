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
    load_stack,
    map_stack,
    coverage_report,
    build_ssp_skeleton,
    practice_catalog,
)
from cmmcmap.core import StackError  # noqa: E402
from cmmcmap import cli  # noqa: E402


STACK = json.dumps({
    "system_name": "Test Enclave",
    "components": [
        {"name": "Okta", "role": "idp", "tags": ["mfa", "sso", "rbac"]},
        {"name": "AWS GovCloud", "role": "cloud",
         "tags": ["kms", "cloudtrail", "at_rest", "fips"]},
        {"name": "Splunk", "role": "siem", "tags": ["siem", "audit"]},
    ],
})


class TestCore(unittest.TestCase):
    def test_meta(self):
        self.assertEqual(TOOL_NAME, "cmmcmap")
        self.assertTrue(TOOL_VERSION)

    def test_catalog_nonempty(self):
        cat = practice_catalog()
        self.assertGreater(len(cat), 10)
        self.assertTrue(all("id" in p and "required_caps" in p for p in cat))

    def test_load_rejects_bad_json(self):
        with self.assertRaises(StackError):
            load_stack("{not json")

    def test_load_rejects_empty_components(self):
        with self.assertRaises(StackError):
            load_stack(json.dumps({"components": []}))

    def test_load_rejects_component_without_name(self):
        with self.assertRaises(StackError):
            load_stack(json.dumps({"components": [{"role": "idp"}]}))

    def test_map_assigns_statuses(self):
        mapping = map_stack(load_stack(STACK))
        by_id = {p["id"]: p for p in mapping["practices"]}
        # MFA satisfied via Okta
        self.assertEqual(by_id["IA.L2-3.5.3"]["status"], "satisfied")
        self.assertIn("Okta", by_id["IA.L2-3.5.3"]["providers"])
        # FIPS crypto satisfied (kms + fips from AWS GovCloud)
        self.assertEqual(by_id["SC.L2-3.13.11"]["status"], "satisfied")
        # No VPN -> remote access not satisfied
        self.assertNotEqual(by_id["AC.L2-3.1.12"]["status"], "satisfied")
        # No media sanitization -> planned
        self.assertEqual(by_id["MP.L2-3.8.3"]["status"], "planned")

    def test_coverage_score_bounds(self):
        rep = coverage_report(map_stack(load_stack(STACK)))
        self.assertEqual(
            rep["counts"]["satisfied"]
            + rep["counts"]["partial"]
            + rep["counts"]["planned"],
            rep["total_practices"],
        )
        self.assertGreaterEqual(rep["coverage_score"], 0.0)
        self.assertLessEqual(rep["coverage_score"], 1.0)

    def test_ssp_structure(self):
        ssp = build_ssp_skeleton(map_stack(load_stack(STACK)))
        root = ssp["system-security-plan"]
        reqs = root["control-implementation"]["implemented-requirements"]
        self.assertEqual(len(reqs), len(practice_catalog()))
        self.assertTrue(all("control-id" in r for r in reqs))


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
        self.stack_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "_tmp_stack.json"
        )
        with open(self.stack_path, "w", encoding="utf-8") as fh:
            fh.write(STACK)

    def tearDown(self):
        if os.path.exists(self.stack_path):
            os.remove(self.stack_path)

    def test_catalog_json(self):
        code, out, _ = self._run(["catalog"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertGreater(len(data), 10)

    def test_map_table(self):
        code, out, _ = self._run(["--format", "table", "map", self.stack_path])
        self.assertEqual(code, 0)
        self.assertIn("IA.L2-3.5.3", out)

    def test_coverage_json(self):
        code, out, _ = self._run(["coverage", self.stack_path])
        self.assertEqual(code, 0)
        self.assertIn("coverage_score", json.loads(out))

    def test_ssp_json(self):
        code, out, _ = self._run(["ssp", self.stack_path])
        self.assertEqual(code, 0)
        self.assertIn("system-security-plan", json.loads(out))

    def test_missing_file_nonzero(self):
        code, _, err = self._run(["map", "/no/such/file.json"])
        self.assertNotEqual(code, 0)
        self.assertIn("error", err)


if __name__ == "__main__":
    unittest.main()
