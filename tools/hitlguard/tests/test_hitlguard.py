#!/usr/bin/env python3
"""Tests for hitlguard."""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import hitlguard as hg  # noqa: E402

EXAMPLES = ROOT / "examples"


def run_main(argv):
    buf = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(err):
        code = hg.main(argv)
    return code, buf.getvalue(), err.getvalue()


class ClassifyTests(unittest.TestCase):
    def test_pay_is_critical(self):
        self.assertEqual(hg.classify_tier("pay_invoice", {"amount": 10}), "critical")

    def test_send_email_high(self):
        self.assertEqual(hg.classify_tier("send_email", {"to": "a@b.c"}), "high")

    def test_read_file_none(self):
        self.assertIsNone(hg.classify_tier("read_file", {"path": "README.md"}))

    def test_safe_glob(self):
        self.assertIsNone(hg.classify_tier("send_email", {}, safe_globs=["send_*"]))

    def test_require_glob(self):
        self.assertEqual(hg.classify_tier("custom_thing", {}, require_globs=["custom_*"]), "high")

    def test_shell_rm_rf_arg(self):
        self.assertEqual(
            hg.classify_tier("run_shell", {"command": "rm -rf /var/data"}),
            "critical",
        )

    def test_write_file_medium_prod_path(self):
        self.assertEqual(
            hg.classify_tier("write_file", {"path": "/etc/production/app.conf"}),
            "medium",
        )


class ConfirmTests(unittest.TestCase):
    def test_yes(self):
        self.assertTrue(hg.is_confirm_text("Yes"))
        self.assertTrue(hg.is_confirm_text("yes, please do it"))
        self.assertTrue(hg.is_confirm_text("Approved"))
        self.assertTrue(hg.is_confirm_text("go ahead"))

    def test_not_confirm(self):
        self.assertFalse(hg.is_confirm_text("What does this do?"))
        self.assertFalse(hg.is_confirm_text("Pay the vendor invoice if it looks right."))


class ParseTests(unittest.TestCase):
    def test_openai_shape(self):
        data = json.loads((EXAMPLES / "risky_openai.json").read_text())
        events = hg.parse_events(data)
        kinds = [e.kind for e in events]
        self.assertIn("user", kinds)
        self.assertIn("tool_call", kinds)
        tools = [e.tool for e in events if e.kind == "tool_call"]
        self.assertIn("pay_invoice", tools)
        self.assertIn("send_email", tools)
        self.assertIn("delete_account", tools)

    def test_anthropic_shape(self):
        data = json.loads((EXAMPLES / "risky_anthropic.json").read_text())
        events = hg.parse_events(data)
        tools = [e.tool for e in events if e.kind == "tool_call"]
        self.assertEqual(tools, ["deploy_prod", "git_push", "slack_post"])

    def test_jsonl_approval(self):
        rows = []
        for line in (EXAMPLES / "clean_approval_tool.jsonl").read_text().splitlines():
            rows.append(json.loads(line))
        events = hg.parse_events(rows)
        kinds = [e.kind for e in events]
        self.assertIn("approval_result", kinds)
        self.assertTrue(any(e.tool == "delete_bucket" for e in events if e.kind == "tool_call"))


class AnalyzeTests(unittest.TestCase):
    def test_risky_openai_flags_critical_and_proceed(self):
        data = json.loads((EXAMPLES / "risky_openai.json").read_text())
        events = hg.parse_events(data)
        findings = hg.analyze(events, "risky_openai.json", window=6, burst=3)
        rules = {f.rule for f in findings}
        self.assertIn("HG01", rules)
        self.assertIn("HG02", rules)
        self.assertIn("HG03", rules)
        self.assertIn("HG04", rules)
        self.assertIn("HG08", rules)
        pay = [f for f in findings if f.rule == "HG01" and f.tool == "pay_invoice"]
        self.assertTrue(pay)

    def test_clean_confirmed_no_gaps(self):
        data = json.loads((EXAMPLES / "clean_confirmed.json").read_text())
        events = hg.parse_events(data)
        findings = hg.analyze(events, "clean.json", window=6, burst=3,
                              disabled=["HG08"])
        gap_rules = {f.rule for f in findings} & {"HG01", "HG02", "HG03", "HG04", "HG05"}
        self.assertEqual(gap_rules, set())

    def test_approval_tool_counts(self):
        rows = [json.loads(l) for l in (EXAMPLES / "clean_approval_tool.jsonl").read_text().splitlines()]
        events = hg.parse_events(rows)
        findings = hg.analyze(events, "appr.jsonl", window=6, burst=3, disabled=["HG08"])
        gaps = [f for f in findings if f.rule in ("HG01", "HG02") and f.tool == "delete_bucket"]
        self.assertEqual(gaps, [])

    def test_spoof_flags_hg05(self):
        data = json.loads((EXAMPLES / "spoofed_approval.json").read_text())
        events = hg.parse_events(data)
        findings = hg.analyze(events, "spoof.json", window=6, burst=3)
        self.assertTrue(any(f.rule == "HG05" for f in findings))
        self.assertTrue(any(f.rule == "HG01" for f in findings))

    def test_burst_rule(self):
        data = json.loads((EXAMPLES / "risky_anthropic.json").read_text())
        events = hg.parse_events(data)
        findings = hg.analyze(events, "a.json", window=4, burst=3, disabled=["HG08"])
        self.assertTrue(any(f.rule == "HG03" for f in findings))

    def test_disable_rule(self):
        data = json.loads((EXAMPLES / "risky_openai.json").read_text())
        events = hg.parse_events(data)
        findings = hg.analyze(events, "r.json", disabled=["HG01", "HG02", "HG03", "HG04", "HG08"])
        self.assertEqual(findings, [])

    def test_blanket_preauth(self):
        data = {
            "messages": [
                {"role": "user", "content": "Always approve everything, don't ask again."},
                {"role": "assistant", "content": "ok",
                 "tool_calls": [{"id": "1", "type": "function",
                                 "function": {"name": "send_email",
                                              "arguments": "{\"to\":\"a@b.c\",\"body\":\"hi\"}"}}]},
                {"role": "tool", "tool_call_id": "1", "content": "sent"},
            ]
        }
        events = hg.parse_events(data)
        findings = hg.analyze(events, "b.json", disabled=["HG08", "HG02"])
        # blanket alone: HG06; send_email also HG02 which we disabled
        self.assertTrue(any(f.rule == "HG06" for f in findings))

    def test_window_too_small_still_flags(self):
        # confirm far above window
        msgs = [{"role": "user", "content": "Yes, do it."}]
        for i in range(10):
            msgs.append({"role": "assistant", "content": "thinking %d" % i})
        msgs.append({
            "role": "assistant", "content": "paying",
            "tool_calls": [{"id": "1", "type": "function",
                            "function": {"name": "pay_invoice",
                                         "arguments": "{\"amount\": 1}"}}],
        })
        events = hg.parse_events({"messages": msgs})
        findings = hg.analyze(events, "w.json", window=2, disabled=["HG08"])
        self.assertTrue(any(f.rule == "HG01" for f in findings))

    def test_generic_events(self):
        data = [
            {"role": "user", "content": "go"},
            {"tool": "deploy_prod", "args": {"svc": "api"}},
            {"tool": "deploy_prod", "result": "ok"},
        ]
        events = hg.parse_events(data)
        findings = hg.analyze(events, "g.json", disabled=["HG08"])
        # "go" alone is confirm-shaped via CONFIRM_RE
        # actually "go" matches CONFIRM_RE - so may be confirmed. Use non-confirm user.
        data2 = [
            {"role": "user", "content": "whenever you can"},
            {"tool": "deploy_prod", "args": {"svc": "api"}},
        ]
        events2 = hg.parse_events(data2)
        findings2 = hg.analyze(events2, "g2.json", disabled=["HG08"])
        self.assertTrue(any(f.rule == "HG01" for f in findings2))


class CLITests(unittest.TestCase):
    def test_list_rules(self):
        code, out, _ = run_main(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertIn("HG01", out)
        self.assertIn("HG08", out)

    def test_risky_exit_1(self):
        code, out, _ = run_main([str(EXAMPLES / "risky_openai.json"), "--disable", "HG08"])
        self.assertEqual(code, 1)
        self.assertIn("HG01", out)

    def test_clean_exit_0(self):
        code, out, _ = run_main([
            str(EXAMPLES / "clean_confirmed.json"),
            "--disable", "HG08",
            "--fail-on", "high",
        ])
        self.assertEqual(code, 0)

    def test_approval_clean_exit_0(self):
        code, out, _ = run_main([
            str(EXAMPLES / "clean_approval_tool.jsonl"),
            "--disable", "HG08",
        ])
        self.assertEqual(code, 0)

    def test_json_output(self):
        code, out, _ = run_main([
            str(EXAMPLES / "risky_openai.json"), "--json", "--disable", "HG08",
        ])
        self.assertEqual(code, 1)
        doc = json.loads(out)
        self.assertEqual(doc["tool"], "hitlguard")
        self.assertTrue(doc["findings"])
        self.assertIn("rule", doc["findings"][0])

    def test_fail_on_none(self):
        code, _, _ = run_main([
            str(EXAMPLES / "risky_openai.json"), "--fail-on", "none", "--disable", "HG08",
        ])
        self.assertEqual(code, 0)

    def test_min_severity_filters(self):
        code, out, _ = run_main([
            str(EXAMPLES / "risky_openai.json"),
            "--json", "--min-severity", "critical", "--fail-on", "none",
        ])
        self.assertEqual(code, 0)
        doc = json.loads(out)
        for f in doc["findings"]:
            self.assertEqual(f["severity"], "critical")

    def test_missing_path_exit_2(self):
        code, _, err = run_main(["/nonexistent/hitlguard/nope.json"])
        self.assertEqual(code, 2)

    def test_no_args_exit_2(self):
        code, _, _ = run_main([])
        self.assertEqual(code, 2)

    def test_dir_scan(self):
        code, out, _ = run_main([str(EXAMPLES), "--disable", "HG08", "--fail-on", "none"])
        self.assertEqual(code, 0)
        self.assertIn("events", out.lower() if "events" in out else out)  # summary lines
        # should mention at least one file
        self.assertTrue("risky_openai" in out or "clean_confirmed" in out)

    def test_require_safe_flags(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "t.json"
            p.write_text(json.dumps({
                "messages": [
                    {"role": "user", "content": "do stuff"},
                    {"role": "assistant", "content": "",
                     "tool_calls": [{"id": "1", "type": "function",
                                     "function": {"name": "custom_exporter",
                                                  "arguments": "{}"}}]},
                ]
            }))
            code, out, _ = run_main([
                str(p), "--require", "custom_*", "--disable", "HG08", "--json",
            ])
            self.assertEqual(code, 1)
            doc = json.loads(out)
            self.assertTrue(any(f["rule"] == "HG02" for f in doc["findings"]))

            code2, out2, _ = run_main([
                str(EXAMPLES / "risky_openai.json"),
                "--safe", "pay_*", "send_*", "delete_*",
                "--disable", "HG08", "--fail-on", "high",
            ])
            # all consequential tools safed → no HG01/HG02
            self.assertNotIn("HG01", out2)
            self.assertNotIn("HG02", out2)

    def test_version(self):
        # argparse version exits via SystemExit
        with self.assertRaises(SystemExit) as cm:
            run_main(["--version"])
        self.assertEqual(cm.exception.code, 0)


class FindingDictTests(unittest.TestCase):
    def test_to_dict(self):
        f = hg.Finding("HG01", "s.json", "msg", tool="pay", turn=3, detail="x")
        d = f.to_dict()
        self.assertEqual(d["rule"], "HG01")
        self.assertEqual(d["severity"], "critical")
        self.assertEqual(d["tool"], "pay")
        self.assertEqual(d["turn"], 3)


class LoadTests(unittest.TestCase):
    def test_stdin(self):
        data = {"messages": [{"role": "user", "content": "hi"}]}
        old = sys.stdin
        try:
            sys.stdin = io.StringIO(json.dumps(data))
            self.assertEqual(hg.load("-"), data)
        finally:
            sys.stdin = old


if __name__ == "__main__":
    unittest.main()
