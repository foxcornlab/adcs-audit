#!/usr/bin/env python3
"""Tests for adcsaudit.py — positive, negative, and CLI behaviour."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
MODULE_PATH = HERE.parent / "adcsaudit.py"

spec = importlib.util.spec_from_file_location("adcsaudit", MODULE_PATH)
adcsaudit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adcsaudit)


def run_cli(*argv, cwd=HERE.parent):
    return subprocess.run(
        [sys.executable, str(MODULE_PATH)] + list(argv),
        capture_output=True, text=True, cwd=cwd, timeout=30,
    )


class SddlParserTest(unittest.TestCase):
    def test_parse_aces(self):
        sddl = "O:DAG:DAD:AI(A;;GA;;;AU)(A;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;AU)"
        aces = adcsaudit.parse_acl(sddl)
        self.assertEqual(len(aces), 2)
        self.assertEqual(aces[0]["account"], "AU")
        self.assertIn("GA", aces[0]["rights"])
        self.assertEqual(aces[1]["object"],
                         "0e10c968-78fb-11d2-90d4-00c04f79dc55")

    def test_empty_string(self):
        self.assertEqual(adcsaudit.parse_acl(""), [])
        self.assertEqual(adcsaudit.parse_acl(None), [])


class SidNameTest(unittest.TestCase):
    def test_well_known(self):
        self.assertEqual(adcsaudit.sid_to_name("WD"), "Everyone")
        self.assertEqual(adcsaudit.sid_to_name("AU"), "Authenticated Users")

    def test_domain_rid(self):
        sid = "S-1-5-21-1004336348-1177238915-682003330-513"
        self.assertEqual(adcsaudit.sid_to_name(sid), "Domain Users")

    def test_unknown_sid_is_none(self):
        sid = "S-1-5-21-1004336348-1177238915-682003330-1101"
        self.assertIsNone(adcsaudit.sid_to_name(sid))


class LowPrivGrantsTest(unittest.TestCase):
    def test_enroll_right_detected(self):
        entry = {"attrs": {"nTSecurityDescriptor": [
            "(A;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;AU)"]}}
        self.assertEqual(adcsaudit._low_priv_grants(entry, "Enroll"),
                         ["Authenticated Users"])

    def test_generic_all_implies_enroll(self):
        entry = {"attrs": {"nTSecurityDescriptor": ["(A;;GA;;;WD)"]}}
        self.assertEqual(adcsaudit._low_priv_grants(entry, "Enroll"),
                         ["Everyone"])

    def test_admin_enroll_not_flagged(self):
        entry = {"attrs": {"nTSecurityDescriptor": [
            "(A;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DA)"]}}
        self.assertEqual(adcsaudit._low_priv_grants(entry, "Enroll"), [])

    def test_no_descriptor(self):
        self.assertEqual(adcsaudit._low_priv_grants({"attrs": {}}, "Enroll"), [])


class FlagTest(unittest.TestCase):
    def test_named_flag(self):
        entry = {"attrs": {"msPKI-Certificate-Name-Flag":
                           ["ENROLLEE_SUPPLIES_SUBJECT"]}}
        self.assertEqual(adcsaudit._attr_flag(entry, "msPKI-Certificate-Name-Flag"), 0x1)

    def test_hex_flag(self):
        entry = {"attrs": {"msPKI-Certificate-Name-Flag": ["0x00000001"]}}
        self.assertEqual(adcsaudit._attr_flag(entry, "msPKI-Certificate-Name-Flag"), 1)

    def test_missing(self):
        self.assertEqual(adcsaudit._attr_flag({"attrs": {}}, "msPKI-Certificate-Name-Flag"), 0)


class LdifParserTest(unittest.TestCase):
    def test_parse_simple(self):
        ldif = ("dn: CN=Test,CN=Templates\n"
                "objectClass: pKICertificateTemplate\n"
                "name: Test\n"
                "\n"
                "dn: CN=Other\n"
                "name: Other\n")
        entries = adcsaudit.parse_ldif(ldif)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["dn"], "CN=Test,CN=Templates")
        self.assertEqual(entries[0]["attrs"]["name"], ["Test"])

    def test_malformed_raises(self):
        with self.assertRaises(adcsaudit.InputError):
            adcsaudit.parse_ldif("orphan line without entry header\n")


class AuditTest(unittest.TestCase):
    def run_audit(self, name):
        entries = json.loads((FIXTURES / name).read_text())
        del adcsaudit.FINDINGS[:]
        return adcsaudit.audit(entries)

    def test_esc1_esc8_found(self):
        findings = self.run_audit("esc1_esc8.json")
        ids = {f["id"] for f in findings}
        self.assertIn("ESC1", ids)
        self.assertIn("ESC8", ids)
        esc1 = [f for f in findings if f["id"] == "ESC1"][0]
        self.assertEqual(esc1["level"], "high")
        self.assertIn("Authenticated Users", esc1["detail"])

    def test_clean_template(self):
        findings = self.run_audit("clean_template.json")
        self.assertEqual(findings, [])


class CliTest(unittest.TestCase):
    def test_findings_exit_code_1(self):
        proc = run_cli("--offline", str(FIXTURES / "esc1_esc8.json"))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("ESC1", proc.stdout)

    def test_clean_exit_code_0(self):
        proc = run_cli("--offline", str(FIXTURES / "clean_template.json"))
        self.assertEqual(proc.returncode, 0)
        self.assertIn("no findings", proc.stdout)

    def test_json_output(self):
        proc = run_cli("--offline", str(FIXTURES / "esc1_esc8.json"), "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["count"], len(payload["findings"]))
        self.assertGreater(payload["count"], 0)

    def test_malformed_json_exit_2_no_traceback(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{not json at all")
            bad = fh.name
        try:
            proc = run_cli("--offline", bad)
            self.assertEqual(proc.returncode, 2)
            self.assertNotIn("Traceback", proc.stderr)
            self.assertIn("error", proc.stderr.lower())
        finally:
            os.unlink(bad)

    def test_json_wrong_shape_exit_2(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"unexpected": "shape"}, fh)
            bad = fh.name
        try:
            proc = run_cli("--offline", bad)
            self.assertEqual(proc.returncode, 2)
            self.assertNotIn("Traceback", proc.stderr)
        finally:
            os.unlink(bad)

    def test_missing_file_exit_2(self):
        proc = run_cli("--offline", "/nonexistent/path/thing.json")
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr)

    def test_no_target_exit_2(self):
        proc = run_cli()
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr)

    def test_help(self):
        proc = run_cli("--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--offline", proc.stdout)


if __name__ == "__main__":
    unittest.main()
