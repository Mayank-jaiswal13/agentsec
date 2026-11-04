#!/usr/bin/env python3
"""Tests for piiguard."""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import piiguard as pg  # noqa: E402

EX = os.path.join(ROOT, "examples")


def _ensure_examples():
    """Regenerate card-bearing fixtures (PANs built at runtime via make_luhn)."""
    gen = os.path.join(EX, "make_examples.py")
    if os.path.isfile(gen):
        import runpy
        runpy.run_path(gen, run_name="__main__")


def setUpModule():
    _ensure_examples()


def run_main(argv):
    buf = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(err):
        code = pg.main(argv)
    return code, buf.getvalue(), err.getvalue()


def rules_in(text, source="t"):
    return {f.rule for f in pg.scan_text(text, source)}


class TestLuhn(unittest.TestCase):
    def test_make_and_check(self):
        pan = pg.make_luhn("411111111111", 16)
        self.assertEqual(len(pan), 16)
        self.assertTrue(pg.luhn_ok(pan))

    def test_reject_all_same(self):
        self.assertFalse(pg.luhn_ok("0000000000000000"))

    def test_reject_bad_checksum(self):
        self.assertFalse(pg.luhn_ok("4111111111111112"))

    def test_reject_short(self):
        self.assertFalse(pg.luhn_ok("411111111111"))


class TestEmail(unittest.TestCase):
    def test_basic(self):
        self.assertIn("PG01", rules_in("reach me at alice@example.com thanks"))

    def test_masked_report(self):
        fs = pg.scan_text("bob.smith@example.org", "t")
        d = [f for f in fs if f.rule == "PG01"][0].to_dict()
        self.assertIn("***@", d["match"])
        self.assertNotIn("bob.smith", d["match"])

    def test_skip_image_ext_domain(self):
        self.assertNotIn("PG01", rules_in("see icon@cdn.png in assets"))


class TestPhone(unittest.TestCase):
    def test_nanp_dashed(self):
        self.assertIn("PG02", rules_in("call 555-555-0142 please"))

    def test_nanp_plus(self):
        self.assertIn("PG02", rules_in("mobile +1-555-555-0199"))

    def test_parens(self):
        self.assertIn("PG02", rules_in("office (312) 555-0199"))

    def test_reject_timestamp(self):
        self.assertNotIn("PG02", rules_in("unix 1700000000 seconds"))


class TestSSN(unittest.TestCase):
    def test_labeled(self):
        self.assertIn("PG03", rules_in("SSN " + "-".join(["219", "09", "9999"]) + " on file"))

    def test_dashed_with_context(self):
        self.assertIn("PG03", rules_in("social security " + "-".join(["457", "55", "5462"])))

    def test_reject_invalid_area(self):
        self.assertNotIn("PG03", rules_in("SSN " + "-".join(["000", "12", "3456"])))

    def test_reject_666(self):
        self.assertNotIn("PG03", rules_in("SSN " + "-".join(["666", "12", "3456"])))

    def test_bare_digits_need_label(self):
        self.assertNotIn("PG03", rules_in("id 219099999 unrelated"))


class TestCard(unittest.TestCase):
    def test_visa(self):
        pan = pg.make_luhn("411111111111", 16)
        self.assertIn("PG04", rules_in("card " + pan))

    def test_spaced(self):
        pan = pg.make_luhn("411111111111", 16)
        spaced = " ".join(pan[i:i + 4] for i in range(0, 16, 4))
        self.assertIn("PG04", rules_in("pay with " + spaced))

    def test_reject_non_luhn(self):
        self.assertNotIn("PG04", rules_in("card 4111111111111112"))

    def test_mask_last4(self):
        pan = pg.make_luhn("411111111111", 16)
        f = [x for x in pg.scan_text(pan, "t") if x.rule == "PG04"][0]
        self.assertTrue(f.to_dict()["match"].endswith(pan[-4:]))


class TestGovId(unittest.TestCase):
    def test_passport(self):
        self.assertIn("PG05", rules_in("Passport number A12345678"))

    def test_dl(self):
        self.assertIn("PG05", rules_in("Driver's license DL# S123-4567-8901"))

    def test_national_id(self):
        self.assertIn("PG05", rules_in("National ID: NID-FAKE-998877"))


class TestBank(unittest.TestCase):
    def test_iban(self):
        self.assertIn("PG06", rules_in("wire to GB82WEST12345698765432"))

    def test_reject_bad_iban(self):
        self.assertNotIn("PG06", rules_in("wire to GB00WEST12345698765432"))

    def test_routing_json(self):
        self.assertIn("PG06", rules_in('{"routing_number": "021000021"}'))

    def test_account_json(self):
        self.assertIn("PG06", rules_in('{"account_number": "123456789012"}'))


class TestDOBAddressMedical(unittest.TestCase):
    def test_dob_iso(self):
        self.assertIn("PG07", rules_in("DOB 1985-03-14"))

    def test_dob_named(self):
        self.assertIn("PG07", rules_in("date of birth: March 14, 1985"))

    def test_address(self):
        self.assertIn("PG08", rules_in("mail 123 Example Street, Springfield, IL 62701"))

    def test_mrn(self):
        self.assertIn("PG09", rules_in("MRN MRN-FAKE-7788"))

    def test_npi_json(self):
        self.assertIn("PG09", rules_in('{"npi": "1234567890"}'))


class TestTranscriptParsing(unittest.TestCase):
    def test_openai_tool_args(self):
        pan = pg.make_luhn("411111111111", 16)
        doc = {
            "messages": [
                {"role": "user", "content": "hi"},
                {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "1",
                        "type": "function",
                        "function": {
                            "name": "pay",
                            "arguments": json.dumps({"card": pan}),
                        },
                    }],
                },
            ]
        }
        segs = pg.extract_segments(doc, "x")
        tools = [s for s in segs if s.tool == "pay"]
        self.assertTrue(tools)
        self.assertIn("PG04", {f.rule for f in pg.scan_text(tools[0].text, "x")})

    def test_anthropic_tool_result(self):
        doc = {
            "messages": [{
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": "t1",
                    "content": "email alice@example.com",
                }],
            }]
        }
        segs = pg.extract_segments(doc, "x")
        self.assertTrue(any("alice@example.com" in s.text for s in segs))


class TestRedact(unittest.TestCase):
    def test_redact_email(self):
        raw = "Contact alice@example.com today"
        out = pg.redact_text(raw, None)
        self.assertNotIn("alice@example.com", out)
        self.assertIn("[REDACTED:PG01:", out)

    def test_redact_preserves_other(self):
        raw = "hello world"
        self.assertEqual(pg.redact_text(raw, None), raw)


class TestCLI(unittest.TestCase):
    def test_list_rules(self):
        code, out, _ = run_main(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertIn("PG01", out)
        self.assertIn("PG10", out)

    def test_clean_exit0(self):
        code, out, _ = run_main([os.path.join(EX, "clean_openai.json"), "--disable", "PG10"])
        self.assertEqual(code, 0)
        self.assertIn("no PII findings", out)

    def test_risky_exit1(self):
        code, out, _ = run_main([os.path.join(EX, "risky_openai.json"), "--disable", "PG10"])
        self.assertEqual(code, 1)
        self.assertIn("PG03", out)
        self.assertIn("PG04", out)

    def test_json_output(self):
        code, out, _ = run_main([
            os.path.join(EX, "risky.jsonl"), "--json", "--disable", "PG10",
        ])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["tool"], "piiguard")
        rules = {f["rule"] for f in data["findings"]}
        self.assertTrue({"PG01", "PG03"} & rules)

    def test_plaintext_as_text(self):
        code, out, _ = run_main([
            os.path.join(EX, "risky_plaintext.txt"), "--as-text", "--disable", "PG10",
        ])
        self.assertEqual(code, 1)
        self.assertIn("PG01", out)
        self.assertIn("PG08", out)

    def test_fail_on_none(self):
        code, _, _ = run_main([
            os.path.join(EX, "risky_openai.json"), "--fail-on", "none", "--disable", "PG10",
        ])
        self.assertEqual(code, 0)

    def test_fail_on_critical(self):
        code, _, _ = run_main([
            os.path.join(EX, "risky_plaintext.txt"), "--as-text",
            "--fail-on", "critical", "--disable", "PG10",
        ])
        # plaintext has high/medium only
        self.assertEqual(code, 0)

    def test_min_severity(self):
        code, out, _ = run_main([
            os.path.join(EX, "risky_plaintext.txt"), "--as-text",
            "--min-severity", "high", "--disable", "PG10", "--json",
        ])
        data = json.loads(out)
        self.assertTrue(all(f["severity"] in ("high", "critical") for f in data["findings"]))

    def test_redact_cli(self):
        src = os.path.join(EX, "risky_plaintext.txt")
        with tempfile.TemporaryDirectory() as td:
            dest = os.path.join(td, "out.txt")
            code, _, err = run_main([src, "--as-text", "--redact", dest, "--disable", "PG10"])
            self.assertEqual(code, 1, err)
            with open(dest, encoding="utf-8") as f:
                body = f.read()
            self.assertNotIn("carol.demo@example.net", body)
            self.assertIn("[REDACTED:PG01:", body)

    def test_missing_path(self):
        code, _, err = run_main(["/nonexistent/piiguard-nope.json"])
        self.assertEqual(code, 2)
        self.assertIn("not found", err)

    def test_no_args(self):
        code, _, err = run_main([])
        self.assertEqual(code, 2)

    def test_disable_rule(self):
        code, out, _ = run_main([
            os.path.join(EX, "risky.jsonl"), "--disable", "PG01", "PG03", "PG10",
            "--fail-on", "any",
        ])
        self.assertEqual(code, 0)
        self.assertIn("no PII findings", out)

    def test_anthropic_example(self):
        code, out, _ = run_main([
            os.path.join(EX, "risky_anthropic.json"), "--disable", "PG10",
        ])
        self.assertEqual(code, 1)
        self.assertIn("PG04", out)
        self.assertIn("PG05", out)

    def test_inventory_default_no_fail(self):
        code, out, _ = run_main([
            os.path.join(EX, "clean_openai.json"), "--fail-on", "high",
        ])
        self.assertEqual(code, 0)
        self.assertIn("PG10", out)


class TestIbanHelper(unittest.TestCase):
    def test_known_valid(self):
        self.assertTrue(pg._iban_plausible("GB82WEST12345698765432"))

    def test_known_invalid(self):
        self.assertFalse(pg._iban_plausible("GB00WEST12345698765432"))


class TestMask(unittest.TestCase):
    def test_short(self):
        self.assertEqual(pg._mask_match("PG05", "AB"), "****")


if __name__ == "__main__":
    unittest.main()
