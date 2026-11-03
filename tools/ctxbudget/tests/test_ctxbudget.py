#!/usr/bin/env python3
"""Tests for ctxbudget."""
from __future__ import annotations

import base64
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import ctxbudget as cb  # noqa: E402

EX = os.path.join(ROOT, "examples")


def run_main(argv):
    buf = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(err):
        code = cb.main(argv)
    return code, buf.getvalue(), err.getvalue()


def budgets(**overrides):
    b = {
        "max_bytes": cb.DEFAULT_MAX_BYTES,
        "critical_bytes": cb.DEFAULT_CRITICAL_BYTES,
        "share": cb.DEFAULT_SHARE,
        "blob_bytes": cb.DEFAULT_BLOB_BYTES,
        "line_bytes": cb.DEFAULT_LINE_BYTES,
        "flood_count": cb.DEFAULT_FLOOD_COUNT,
        "flood_min_bytes": cb.DEFAULT_FLOOD_MIN_BYTES,
        "total_bytes": cb.DEFAULT_TOTAL_BYTES,
        "max_depth": cb.DEFAULT_MAX_DEPTH,
    }
    b.update(overrides)
    return b


class TestClassify(unittest.TestCase):
    def test_max_bytes(self):
        ev = cb.ResultEvent("t", "dump", 0, "A" * 120_000)
        fs = cb.classify_result(ev, total_bytes=120_000, budgets=budgets())
        self.assertIn("CB01", {f.rule for f in fs})
        self.assertNotIn("CB02", {f.rule for f in fs})

    def test_critical_bytes(self):
        ev = cb.ResultEvent("t", "dump", 0, "B" * 520_000)
        fs = cb.classify_result(ev, total_bytes=520_000, budgets=budgets())
        self.assertIn("CB02", {f.rule for f in fs})
        self.assertNotIn("CB01", {f.rule for f in fs})  # critical supersedes

    def test_blob_base64(self):
        blob = base64.b64encode(os.urandom(9000)).decode("ascii")
        ev = cb.ResultEvent("t", "art", 0, "payload " + blob)
        fs = cb.classify_result(ev, total_bytes=ev.nbytes, budgets=budgets())
        self.assertIn("CB04", {f.rule for f in fs})

    def test_long_line(self):
        ev = cb.ResultEvent("t", "cat", 0, "X" * 40_000)
        fs = cb.classify_result(ev, total_bytes=40_000, budgets=budgets())
        self.assertIn("CB05", {f.rule for f in fs})

    def test_null_bytes(self):
        ev = cb.ResultEvent("t", "bin", 0, "a\x00b\x00c")
        fs = cb.classify_result(ev, total_bytes=5, budgets=budgets())
        self.assertIn("CB06", {f.rule for f in fs})

    def test_deep_json(self):
        deep = {}
        cur = deep
        for _ in range(40):
            cur["n"] = {}
            cur = cur["n"]
        cur["leaf"] = 1
        ev = cb.ResultEvent("t", "tree", 0, json.dumps(deep))
        fs = cb.classify_result(ev, total_bytes=ev.nbytes, budgets=budgets())
        self.assertIn("CB09", {f.rule for f in fs})

    def test_disable_rule(self):
        # Multi-line filler avoids CB04 (hex/base64) and CB05 (long line).
        ev = cb.ResultEvent("t", "dump", 0, ("row\n" * 30_000))
        fs = cb.classify_result(ev, total_bytes=ev.nbytes, budgets=budgets(),
                                disabled=["CB01"])
        self.assertEqual(fs, [])

    def test_small_clean(self):
        ev = cb.ResultEvent("t", "list", 0, '{"ok": true}')
        fs = cb.classify_result(ev, total_bytes=12, budgets=budgets())
        self.assertEqual(fs, [])


class TestAnalyzeRun(unittest.TestCase):
    def test_share(self):
        big = cb.ResultEvent("t", "big", 0, "A" * 80_000)
        small = cb.ResultEvent("t", "small", 1, "hi")
        fs = cb.analyze_run([big, small], budgets(share=0.5), disabled=["CB10"])
        rules = {f.rule for f in fs}
        self.assertIn("CB03", rules)

    def test_flood(self):
        events = [
            cb.ResultEvent("t", "read_log", i, "Z" * 25_000) for i in range(6)
        ]
        fs = cb.analyze_run(events, budgets(), disabled=["CB01", "CB03", "CB08", "CB10"])
        self.assertIn("CB07", {f.rule for f in fs})

    def test_total_budget(self):
        events = [cb.ResultEvent("t", "a", 0, "A" * 600_000)]
        fs = cb.analyze_run(events, budgets(total_bytes=100_000), disabled=["CB02", "CB03", "CB10"])
        self.assertIn("CB08", {f.rule for f in fs})

    def test_inventory(self):
        events = [cb.ResultEvent("t", "a", 0, "hello")]
        fs = cb.analyze_run(events, budgets())
        self.assertIn("CB10", {f.rule for f in fs})
        self.assertEqual(fs[0].severity, "info")


class TestExtraction(unittest.TestCase):
    def test_openai_clean(self):
        events = cb.load_events(os.path.join(EX, "clean_openai.json"))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].tool, "list_issues")
        self.assertLess(events[0].nbytes, 1000)

    def test_openai_risky(self):
        events = cb.load_events(os.path.join(EX, "risky_openai.json"))
        tools = {e.tool for e in events}
        self.assertIn("dump_db", tools)
        self.assertIn("read_log", tools)
        self.assertGreaterEqual(len(events), 10)

    def test_anthropic(self):
        events = cb.load_events(os.path.join(EX, "risky_anthropic.json"))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].tool, "export_records")
        self.assertGreater(events[0].nbytes, 100_000)

    def test_jsonl_generic(self):
        events = cb.load_events(os.path.join(EX, "generic_results.jsonl"))
        tools = {e.tool for e in events}
        self.assertIn("fetch_raw", tools)
        self.assertIn("ping", tools)
        self.assertIn("search", tools)


class TestCLI(unittest.TestCase):
    def test_list_rules(self):
        code, out, _ = run_main(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertIn("CB01", out)
        self.assertIn("CB10", out)

    def test_clean_passes(self):
        code, out, _ = run_main([
            os.path.join(EX, "clean_openai.json"),
            "--min-severity", "low",  # hide CB10 info inventory
        ])
        self.assertEqual(code, 0)
        # With min-severity low, CB10 (info) is hidden; may show "No findings"
        self.assertTrue("finding" in out.lower() or "ctxbudget" in out)

    def test_risky_fails(self):
        code, out, _ = run_main([os.path.join(EX, "risky_openai.json")])
        self.assertEqual(code, 1)
        self.assertIn("CB02", out)
        self.assertIn("CB01", out)

    def test_json_output(self):
        code, out, _ = run_main([
            os.path.join(EX, "clean_openai.json"), "--json", "--min-severity", "low"
        ])
        data = json.loads(out)
        self.assertEqual(data["tool"], "ctxbudget")
        self.assertEqual(data["results"], 1)
        # no high+ findings
        self.assertTrue(all(f["severity"] in ("low", "medium", "info") for f in data["findings"])
                        or data["findings"] == [])
        self.assertEqual(code, 0)

    def test_fail_on_none(self):
        code, _, _ = run_main([os.path.join(EX, "risky_openai.json"), "--fail-on", "none"])
        self.assertEqual(code, 0)

    def test_min_severity_critical(self):
        code, out, _ = run_main([
            os.path.join(EX, "risky_openai.json"), "--min-severity", "critical", "--json"
        ])
        data = json.loads(out)
        self.assertTrue(all(f["severity"] == "critical" for f in data["findings"]))
        self.assertEqual(code, 1)

    def test_disable_cli(self):
        code, out, _ = run_main([
            os.path.join(EX, "generic_results.jsonl"),
            "--disable", "CB01", "CB03", "CB08", "CB10",
            "--json",
        ])
        data = json.loads(out)
        rules = {f["rule"] for f in data["findings"]}
        self.assertNotIn("CB01", rules)
        self.assertNotIn("CB10", rules)

    def test_missing_path(self):
        code, _, err = run_main(["/nonexistent/ctxbudget-nope.json"])
        self.assertEqual(code, 2)

    def test_no_args_help(self):
        code, out, err = run_main([])
        self.assertEqual(code, 2)

    def test_dir_scan(self):
        code, out, _ = run_main([EX, "--fail-on", "none", "--min-severity", "critical"])
        self.assertEqual(code, 0)
        self.assertIn("ctxbudget", out)

    def test_stdin(self):
        payload = json.dumps({
            "tool": "x", "result": "Y" * 120_000
        })
        with mock.patch("sys.stdin", io.StringIO(payload)):
            code, out, _ = run_main(["-", "--json"])
        data = json.loads(out)
        self.assertEqual(data["results"], 1)
        self.assertEqual(code, 1)

    def test_anthropic_cli(self):
        code, out, _ = run_main([os.path.join(EX, "risky_anthropic.json"), "--json"])
        data = json.loads(out)
        rules = {f["rule"] for f in data["findings"]}
        self.assertIn("CB01", rules)
        self.assertEqual(code, 1)

    def test_version_exit(self):
        with self.assertRaises(SystemExit) as cm:
            cb.main(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_bad_share(self):
        code, _, err = run_main([
            os.path.join(EX, "clean_openai.json"), "--share", "2"
        ])
        self.assertEqual(code, 2)

    def test_custom_max_bytes(self):
        # Make clean example fail with tiny budget
        code, out, _ = run_main([
            os.path.join(EX, "clean_openai.json"),
            "--max-bytes", "10",
            "--critical-bytes", "1000000",
            "--total-bytes", "1000000",
            "--disable", "CB10", "CB03",
            "--json",
        ])
        data = json.loads(out)
        self.assertIn("CB01", {f["rule"] for f in data["findings"]})
        self.assertEqual(code, 1)


class TestHelpers(unittest.TestCase):
    def test_rules_complete(self):
        for i in range(1, 11):
            self.assertIn("CB%02d" % i, cb.RULES)

    def test_sev_rank_order(self):
        self.assertLess(cb.SEV_RANK["info"], cb.SEV_RANK["critical"])

    def test_text_of_list(self):
        self.assertIn("hi", cb._text_of([{"type": "text", "text": "hi"}]))

    def test_json_depth(self):
        self.assertEqual(cb._json_depth(1), 1)
        self.assertGreaterEqual(cb._json_depth({"a": {"b": {"c": 1}}}), 3)

    def test_max_line_bytes(self):
        self.assertEqual(cb._max_line_bytes("ab\n" + "c" * 10), 10)

    def test_finding_to_dict(self):
        f = cb.Finding("CB01", "s", "m", tool="t", turn=2, nbytes=9)
        d = f.to_dict()
        self.assertEqual(d["rule"], "CB01")
        self.assertEqual(d["turn"], 2)
        self.assertEqual(d["bytes"], 9)


if __name__ == "__main__":
    unittest.main()
