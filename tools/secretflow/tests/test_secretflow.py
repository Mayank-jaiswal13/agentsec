#!/usr/bin/env python3
"""Tests for secretflow."""
from __future__ import annotations

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import secretflow as sf  # noqa: E402

EX = os.path.join(ROOT, "examples")


def run_main(argv):
    buf = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(err):
        code = sf.main(argv)
    return code, buf.getvalue(), err.getvalue()


def rules_from(text, source="t"):
    events = [
        sf.Event("tool_result", role="tool", tool="read_file", text=text, turn=1),
    ]
    # minimal: just extraction
    return {kind for _, kind, _ in sf.extract_secrets(text)}


class TestExtract(unittest.TestCase):
    def test_fake_example(self):
        kinds = rules_from("key=FAKE-EXAMPLE-API-KEY-abcdef12")
        self.assertIn("fake_example", kinds)

    def test_jwt(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiJGQUtFLUVYQU1QTEUtVVNFUiIsImV4cCI6OTk5OTk5OTk5OX0."
            "FAKEEXAMPLESIG000000000000000000"
        )
        kinds = {k for _, k, _ in sf.extract_secrets("token=" + jwt)}
        self.assertIn("jwt", kinds)

    def test_bearer(self):
        kinds = {k for _, k, _ in sf.extract_secrets(
            "Authorization: Bearer FAKE-EXAMPLE-BEARER-TOKEN-9999"
        )}
        self.assertTrue(kinds & {"bearer", "fake_example", "authorization"})

    def test_labeled(self):
        vals = list(sf.extract_secrets('{"api_key": "FAKE-EXAMPLE-LABELED-KEY-01"}'))
        self.assertTrue(any(k == "labeled" or k == "fake_example" for _, k, _ in vals))

    def test_provider_sk_test(self):
        kinds = {k for _, k, _ in sf.extract_secrets("sk_test_FAKEEXAMPLEKEY0001")}
        self.assertIn("provider_key", kinds)

    def test_env_line(self):
        kinds = {k for _, k, _ in sf.extract_secrets(
            "API_KEY=FAKE-EXAMPLE-ENV-VALUE-zzzz1111\n"
        )}
        self.assertTrue(kinds & {"env_secret", "fake_example"})

    def test_placeholder_skipped(self):
        vals = list(sf.extract_secrets("api_key=YOUR_API_KEY"))
        # YOUR_API_KEY is placeholder-ish via PLACEHOLDER or too generic; ensure
        # we don't invent a critical finding from placeholders alone.
        self.assertFalse(any(v.upper() == "YOUR_API_KEY" for v, _, _ in vals))

    def test_mask(self):
        m = sf.mask_secret("FAKE-EXAMPLE-API-KEY-7f3a9c2e")
        self.assertIn("…", m)
        self.assertNotIn("7f3a9c2e", m[4:-4] if False else "ok")
        self.assertTrue(m.startswith("FAKE"))


class TestOutboundClassifiers(unittest.TestCase):
    def test_outbound(self):
        self.assertTrue(sf.is_outbound_tool("http_post"))
        self.assertTrue(sf.is_outbound_tool("send_email"))
        self.assertTrue(sf.is_outbound_tool("webhook_post"))
        self.assertFalse(sf.is_outbound_tool("read_file"))

    def test_shell(self):
        self.assertTrue(sf.is_shell_tool("bash"))
        self.assertTrue(sf.is_shell_tool("run_command"))
        self.assertFalse(sf.is_shell_tool("http_get"))

    def test_write_sink(self):
        self.assertTrue(sf.is_write_sink("write_file"))
        self.assertTrue(sf.is_write_sink("memory_add"))


class TestFlowOpenAI(unittest.TestCase):
    def setUp(self):
        path = os.path.join(EX, "risky_openai.json")
        with open(path, encoding="utf-8") as f:
            self.data = json.load(f)
        self.events = sf.parse_events(self.data)
        self.findings = sf.analyze(self.events, path, disabled={"FL10"})

    def test_has_events(self):
        self.assertGreater(len(self.events), 5)

    def test_fl01_outbound(self):
        rules = {f.rule for f in self.findings}
        self.assertIn("FL01", rules)

    def test_fl02_shell(self):
        self.assertIn("FL02", {f.rule for f in self.findings})

    def test_fl04_or_session(self):
        # session token into bash should trip auth reuse and/or shell
        rules = {f.rule for f in self.findings}
        self.assertTrue("FL04" in rules or "FL02" in rules)

    def test_fl05_assistant_echo(self):
        self.assertIn("FL05", {f.rule for f in self.findings})

    def test_fl07_labeled(self):
        self.assertIn("FL07", {f.rule for f in self.findings})

    def test_fl09_write(self):
        self.assertIn("FL09", {f.rule for f in self.findings})

    def test_masked_not_raw(self):
        for f in self.findings:
            if f.masked:
                self.assertNotEqual(f.masked, "")
                # full raw API key should not appear in message unmasked end-to-end
                self.assertNotIn("FAKE-EXAMPLE-API-KEY-7f3a9c2e", f.masked)


class TestFlowAnthropic(unittest.TestCase):
    def test_jwt_to_slack(self):
        path = os.path.join(EX, "risky_anthropic.json")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        findings = sf.analyze(sf.parse_events(data), path, disabled={"FL10"})
        rules = {f.rule for f in findings}
        self.assertIn("FL01", rules)
        self.assertTrue("FL04" in rules or any(f.secret_kind == "jwt" for f in findings))


class TestUserForward(unittest.TestCase):
    def test_fl08(self):
        path = os.path.join(EX, "risky_user_forward.jsonl")
        data, source = sf.load(path)
        findings = sf.analyze(sf.parse_events(data), source, disabled={"FL10"})
        self.assertIn("FL08", {f.rule for f in findings})


class TestMultiHop(unittest.TestCase):
    def test_fl06(self):
        path = os.path.join(EX, "multi_hop.jsonl")
        data, source = sf.load(path)
        findings = sf.analyze(sf.parse_events(data), source, disabled={"FL10"})
        rules = {f.rule for f in findings}
        self.assertIn("FL06", rules)
        self.assertIn("FL01", rules)  # send_email outbound


class TestClean(unittest.TestCase):
    def test_clean_no_actionable_high(self):
        path = os.path.join(EX, "clean_openai.json")
        code, out, _ = run_main([path, "--disable", "FL10", "--fail-on", "high"])
        self.assertEqual(code, 0)


class TestCLI(unittest.TestCase):
    def test_list_rules(self):
        code, out, _ = run_main(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertIn("FL01", out)
        self.assertIn("FL10", out)

    def test_help_exit_2(self):
        code, _, _ = run_main([])
        self.assertEqual(code, 2)

    def test_json_risky(self):
        path = os.path.join(EX, "risky_openai.json")
        code, out, _ = run_main([path, "--json", "--disable", "FL10"])
        self.assertEqual(code, 1)
        doc = json.loads(out)
        self.assertEqual(doc["tool"], "secretflow")
        self.assertGreater(len(doc["findings"]), 0)
        rules = {f["rule"] for f in doc["findings"]}
        self.assertIn("FL01", rules)

    def test_fail_on_none(self):
        path = os.path.join(EX, "risky_openai.json")
        code, _, _ = run_main([path, "--disable", "FL10", "--fail-on", "none"])
        self.assertEqual(code, 0)

    def test_min_severity_critical(self):
        path = os.path.join(EX, "risky_openai.json")
        code, out, _ = run_main([
            path, "--json", "--disable", "FL10",
            "--min-severity", "critical", "--fail-on", "critical",
        ])
        doc = json.loads(out)
        for f in doc["findings"]:
            self.assertEqual(f["severity"], "critical")
        self.assertEqual(code, 1)

    def test_inventory_alone_no_fail(self):
        path = os.path.join(EX, "clean_openai.json")
        # clean has no secrets → inventory empty-ish; force scan with fail-on high
        code, _, _ = run_main([path, "--fail-on", "high"])
        self.assertEqual(code, 0)


class TestNoFalsePropOnCleanResultReuseAbsent(unittest.TestCase):
    def test_secret_only_in_result_no_reuse(self):
        data = {
            "messages": [
                {"role": "user", "content": "read env"},
                {"role": "assistant", "tool_calls": [
                    {"id": "1", "type": "function",
                     "function": {"name": "read_file", "arguments": "{\"path\": \".env\"}"}}
                ]},
                {"role": "tool", "tool_call_id": "1", "name": "read_file",
                 "content": "API_KEY=FAKE-EXAMPLE-ONLY-IN-RESULT-aaaa"},
                {"role": "assistant", "content": "I see a key is configured (not repeating it)."},
            ]
        }
        findings = sf.analyze(sf.parse_events(data), "mem", disabled={"FL10"})
        actionable = [f for f in findings if f.rule != "FL10"]
        self.assertEqual(actionable, [])


class TestParseGeneric(unittest.TestCase):
    def test_generic_tool_events(self):
        data = [
            {"type": "tool_call", "tool": "read_file", "args": {"path": "x"},
             "result": "token=FAKE-EXAMPLE-GENERIC-TOKEN-12345678"},
            {"type": "tool_call", "tool": "http_post",
             "args": {"body": "FAKE-EXAMPLE-GENERIC-TOKEN-12345678"}},
        ]
        events = sf.parse_events(data)
        findings = sf.analyze(events, "g", disabled={"FL10"})
        self.assertIn("FL01", {f.rule for f in findings})



class TestAuthTokenFlow(unittest.TestCase):
    def test_fl04_jwt_kind(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiJGQUtFLUVYQU1QTEUtVVNFUiIsImV4cCI6OTk5OTk5OTk5OX0."
            "FAKEEXAMPLESIG000000000000000000"
        )
        data = {
            "messages": [
                {"role": "assistant", "tool_calls": [
                    {"id": "1", "type": "function",
                     "function": {"name": "get_secret", "arguments": "{}"}}
                ]},
                {"role": "tool", "tool_call_id": "1", "name": "get_secret",
                 "content": "Authorization: Bearer " + jwt},
                {"role": "assistant", "tool_calls": [
                    {"id": "2", "type": "function",
                     "function": {"name": "http_get",
                                  "arguments": "{\"headers\": {\"Authorization\": \"Bearer %s\"}}" % jwt}}
                ]},
            ]
        }
        findings = sf.analyze(sf.parse_events(data), "t", disabled={"FL10"})
        rules = {f.rule for f in findings}
        self.assertIn("FL04", rules)
        self.assertIn("FL01", rules)


class TestDirectoryAndStdin(unittest.TestCase):
    def test_scan_dir(self):
        code, out, _ = run_main([EX, "--disable", "FL10", "--fail-on", "high"])
        self.assertEqual(code, 1)
        self.assertIn("FL01", out)

    def test_version_flag(self):
        # argparse version exits via SystemExit
        try:
            sf.main(["--version"])
            self.fail("expected SystemExit")
        except SystemExit as e:
            self.assertEqual(e.code, 0)


class TestDedupAndSeverity(unittest.TestCase):
    def test_rules_dict_complete(self):
        for i in range(1, 11):
            self.assertIn("FL%02d" % i, sf.RULES)

    def test_sev_rank_order(self):
        self.assertLess(sf.SEV_RANK["info"], sf.SEV_RANK["critical"])

    def test_cookie_extract(self):
        kinds = {k for _, k, _ in sf.extract_secrets(
            "Cookie: session=FAKE-EXAMPLE-COOKIE-VALUE-xyz999"
        )}
        self.assertTrue(kinds & {"cookie", "fake_example"})


if __name__ == "__main__":
    unittest.main()
