"""Hardening tests: input validation, error handling, and edge-case paths."""
from __future__ import annotations

import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cmmcmap import assess
from cmmcmap.core import Status, build_poam, score_sprs
from cmmcmap import cli


def _run(argv):
    """Capture CLI output and return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        code = cli.main(argv)
    finally:
        sys.stdout, sys.stderr = old_out, old_err
    return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------------------
# core.py: platforms / na normalization
# ---------------------------------------------------------------------------

class TestPlatformsNormalization(unittest.TestCase):
    """'platforms' field must be usable as a list; bare string must not be
    iterated character by character."""

    def test_platforms_as_string_produces_valid_finding(self):
        # Before the fix, a string "Azure AD" would be iterated as
        # individual characters, never matching any known platform.
        findings = assess({"platforms": "Azure AD"})
        self.assertEqual(len(findings), 110)
        by_id = {f.control: f for f in findings}
        # 3.1.1 should get an inherited_hint from AWS IAM / AWS GovCloud.
        self.assertIn("Azure AD", by_id["3.1.1"].inherited_hint)

    def test_platforms_as_non_list_non_string_is_ignored(self):
        # A numeric or boolean platforms value must not crash; it is silently
        # treated as an empty list.
        findings = assess({"platforms": 42})
        self.assertEqual(len(findings), 110)

    def test_platforms_as_proper_list_still_works(self):
        findings = assess({"platforms": ["Azure AD", "Okta"]})
        by_id = {f.control: f for f in findings}
        self.assertIn("Azure AD", by_id["3.1.1"].inherited_hint)


class TestNaNormalization(unittest.TestCase):
    """'na' field must be a list of control IDs; a bare string ID must work."""

    def test_na_as_string_marks_control_na(self):
        # Before the fix, "3.1.1" as a string would be iterated as characters
        # "3", ".", "1", ".", "1" — none of which match a real control ID.
        findings = assess({"na": "3.1.1"})
        by_id = {f.control: f for f in findings}
        self.assertEqual(by_id["3.1.1"].status, Status.NA)

    def test_na_as_non_list_non_string_is_ignored(self):
        # A numeric na value must not crash.
        findings = assess({"na": 0})
        self.assertEqual(len(findings), 110)
        # No control should be NA from a non-list/non-string value.
        self.assertFalse(any(f.status == Status.NA for f in findings))

    def test_na_as_proper_list_still_works(self):
        findings = assess({"na": ["3.1.1", "3.5.3"]})
        by_id = {f.control: f for f in findings}
        self.assertEqual(by_id["3.1.1"].status, Status.NA)
        self.assertEqual(by_id["3.5.3"].status, Status.NA)


# ---------------------------------------------------------------------------
# cli.py: invalid --family validation
# ---------------------------------------------------------------------------

class TestFamilyValidation(unittest.TestCase):
    """Unknown --family abbreviation must exit 2 with a clear error message."""

    def test_controls_invalid_family_exits_two(self):
        code, _, err = _run(["controls", "--family", "ZZ"])
        self.assertEqual(code, 2)
        self.assertIn("unknown family", err.lower())

    def test_controls_invalid_family_mentions_known_families(self):
        code, _, err = _run(["controls", "--family", "UNKNOWN_FAM"])
        self.assertEqual(code, 2)
        # The error should hint at valid choices.
        self.assertIn("AC", err)

    def test_assess_invalid_family_exits_two(self):
        inv_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "_tmp_fam_test.json"
        )
        try:
            with open(inv_path, "w", encoding="utf-8") as fh:
                json.dump({"mfa": True}, fh)
            code, _, err = _run(["assess", inv_path, "--family", "NOTREAL"])
            self.assertEqual(code, 2)
            self.assertIn("error", err.lower())
        finally:
            if os.path.exists(inv_path):
                os.remove(inv_path)

    def test_controls_valid_family_still_works(self):
        code, out, _ = _run(["controls", "--family", "AC"])
        self.assertEqual(code, 0)
        self.assertIn("AC", out)

    def test_controls_family_case_insensitive(self):
        # List should accept lowercase too (maps to .upper() inside core).
        code, out, _ = _run(["controls", "--family", "ac"])
        self.assertEqual(code, 0)
        self.assertIn("AC", out)


# ---------------------------------------------------------------------------
# cli.py + core.py: edge cases — empty inventory, malformed JSON, array JSON
# ---------------------------------------------------------------------------

class TestEdgeCases(unittest.TestCase):

    def setUp(self):
        self.tmp = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "_tmp_edge.json"
        )

    def tearDown(self):
        if os.path.exists(self.tmp):
            os.remove(self.tmp)

    def _write(self, data):
        with open(self.tmp, "w", encoding="utf-8") as fh:
            fh.write(data)

    def test_empty_json_object_is_valid(self):
        """An empty {} inventory is valid and should produce 110 findings."""
        self._write("{}")
        code, out, _ = _run(["assess", self.tmp])
        # Empty inventory -> only UNKNOWN controls (not in FAIL_STATUSES) -> exit 0.
        self.assertEqual(code, 0)

    def test_malformed_json_exits_two_with_error(self):
        self._write("{not valid json")
        code, _, err = _run(["assess", self.tmp])
        self.assertEqual(code, 2)
        self.assertIn("error", err.lower())

    def test_json_array_exits_two_with_error(self):
        """A JSON array instead of object must fail cleanly with exit 2."""
        self._write(json.dumps([{"mfa": True}]))
        code, _, err = _run(["assess", self.tmp])
        self.assertEqual(code, 2)
        self.assertIn("error", err.lower())

    def test_score_empty_inventory_exits_zero(self):
        """score on empty inventory: UNKNOWN is not a FAIL status so exit 0."""
        self._write("{}")
        code, out, _ = _run(["score", self.tmp, "--format", "json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["max_score"], 110)
        self.assertGreater(data["counts"]["UNKNOWN"], 0)

    def test_poam_empty_inventory_has_items(self):
        """An empty inventory produces UNKNOWN findings -> non-empty POA&M."""
        findings = assess({})
        rows = build_poam(findings)
        self.assertTrue(rows)
        self.assertTrue(all(r["status"] in ("NOT_MET", "PARTIAL", "UNKNOWN")
                            for r in rows))

    def test_score_sprs_empty_findings_list(self):
        """score_sprs([]) must not crash; all counts should be zero."""
        score = score_sprs([])
        self.assertEqual(score["assessed_controls"], 0)
        self.assertEqual(score["sprs_score"], 110)
        self.assertEqual(sum(score["counts"].values()), 0)


if __name__ == "__main__":
    unittest.main()
