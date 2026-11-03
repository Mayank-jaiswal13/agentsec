#!/usr/bin/env python3
"""Tests for fetchfence."""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import fetchfence as ff  # noqa: E402

EX = os.path.join(ROOT, "examples")


def run_main(argv):
    buf = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(err):
        code = ff.main(argv)
    return code, buf.getvalue(), err.getvalue()


class TestClassify(unittest.TestCase):
    def test_metadata_ip(self):
        fs = ff.classify_url("http://169.254.169.254/latest/meta-data/", "t")
        rules = {f.rule for f in fs}
        self.assertIn("FF01", rules)
        self.assertIn("FF07", rules)  # http
        self.assertIn("FF08", rules)  # IP literal

    def test_loopback_host(self):
        fs = ff.classify_url("https://localhost/admin", "t")
        self.assertIn("FF02", {f.rule for f in fs})

    def test_private_ip(self):
        fs = ff.classify_url("https://10.0.0.5/x", "t")
        self.assertIn("FF03", {f.rule for f in fs})
        self.assertIn("FF08", {f.rule for f in fs})

    def test_file_scheme(self):
        fs = ff.classify_url("file:///etc/passwd", "t")
        self.assertIn("FF04", {f.rule for f in fs})

    def test_userinfo(self):
        fs = ff.classify_url("https://user:FAKE-EXAMPLE-password@example.com/", "t")
        self.assertIn("FF05", {f.rule for f in fs})

    def test_callback_host(self):
        fs = ff.classify_url("https://webhook.site/FAKE-EXAMPLE-callback-001", "t")
        self.assertIn("FF06", {f.rule for f in fs})

    def test_cleartext(self):
        fs = ff.classify_url("http://docs.example.com/a", "t")
        self.assertEqual({f.rule for f in fs}, {"FF07"})

    def test_punycode(self):
        fs = ff.classify_url("https://xn--exmple-cua.com/", "t")
        self.assertIn("FF09", {f.rule for f in fs})

    def test_shortener(self):
        fs = ff.classify_url("https://bit.ly/FAKE-EXAMPLE-short", "t")
        self.assertIn("FF10", {f.rule for f in fs})

    def test_secret_query(self):
        fs = ff.classify_url(
            "https://docs.example.com/g?api_key=FAKE-EXAMPLE-KEY-12345678", "t"
        )
        self.assertIn("FF11", {f.rule for f in fs})

    def test_admin_port_private(self):
        fs = ff.classify_url("https://10.1.2.3:6379/info", "t")
        self.assertIn("FF12", {f.rule for f in fs})

    def test_internal_suffix(self):
        fs = ff.classify_url("https://status.corp.internal/health", "t")
        self.assertIn("FF13", {f.rule for f in fs})

    def test_allow_host_skips_most(self):
        fs = ff.classify_url(
            "http://docs.example.com/a", "t", allow_hosts=["docs.example.com"]
        )
        self.assertEqual(fs, [])

    def test_allow_host_still_flags_userinfo_and_scheme(self):
        fs = ff.classify_url(
            "file://docs.example.com/secret",
            "t",
            allow_hosts=["docs.example.com"],
        )
        self.assertIn("FF04", {f.rule for f in fs})

    def test_disable_rule(self):
        fs = ff.classify_url("http://docs.example.com/a", "t", disabled=["FF07"])
        self.assertEqual(fs, [])

    def test_mask_url_redacts_userinfo_and_secret(self):
        masked = ff._mask_url(
            "https://user:FAKE-EXAMPLE-password@example.com/x?token=FAKE-EXAMPLE-TOK-999"
        )
        self.assertIn("***:***@", masked)
        self.assertIn("FAKE-EXAMPLE-REDACTED", masked)
        self.assertNotIn("FAKE-EXAMPLE-password", masked)

    def test_google_metadata_host(self):
        fs = ff.classify_url("http://metadata.google.internal/computeMetadata/v1/", "t")
        self.assertIn("FF01", {f.rule for f in fs})

    def test_ipv6_loopback(self):
        fs = ff.classify_url("http://[::1]:9200/_cat", "t")
        rules = {f.rule for f in fs}
        self.assertIn("FF02", rules)
        self.assertIn("FF12", rules)


class TestFetchToolDetection(unittest.TestCase):
    def test_webfetch(self):
        self.assertTrue(ff.is_fetch_tool("WebFetch"))
        self.assertTrue(ff.is_fetch_tool("web_fetch"))
        self.assertTrue(ff.is_fetch_tool("browse_page"))
        self.assertTrue(ff.is_fetch_tool("http_get"))
        self.assertFalse(ff.is_fetch_tool("send_email"))
        self.assertFalse(ff.is_fetch_tool("read_file"))


class TestExtraction(unittest.TestCase):
    def test_openai_example(self):
        events = ff.load_events(os.path.join(EX, "risky_openai.json"))
        urls = [e.url for e in events]
        self.assertEqual(len(events), 4)
        self.assertTrue(any("169.254.169.254" in u for u in urls))
        self.assertTrue(any("webhook.site" in u for u in urls))

    def test_anthropic_example(self):
        events = ff.load_events(os.path.join(EX, "risky_anthropic.json"))
        self.assertGreaterEqual(len(events), 4)
        schemes = set()
        for e in events:
            if e.url.startswith("file:"):
                schemes.add("file")
        self.assertIn("file", schemes)

    def test_jsonl_generic(self):
        events = ff.load_events(os.path.join(EX, "generic_fetches.jsonl"))
        # search_docs has no URL — should not appear; two fetch tools should
        tools = {e.tool for e in events}
        self.assertIn("http_request", tools)
        self.assertIn("open_url", tools)
        self.assertNotIn("search_docs", tools)

    def test_url_list(self):
        events = ff.load_events(os.path.join(EX, "urls.txt"), as_urls=True)
        self.assertEqual(len(events), 3)

    def test_extract_nested_args(self):
        args = {"request": {"url": "https://example.com/a"}, "timeout": 5}
        found = ff.extract_urls_from_args(args)
        self.assertEqual(found[0][0], "https://example.com/a")


class TestCLI(unittest.TestCase):
    def test_list_rules(self):
        code, out, _ = run_main(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertIn("FF01", out)
        self.assertIn("FF13", out)

    def test_risky_openai_fails(self):
        code, out, _ = run_main([os.path.join(EX, "risky_openai.json")])
        self.assertEqual(code, 1)
        self.assertIn("FF01", out)
        self.assertIn("FF06", out)

    def test_clean_openai_passes(self):
        code, out, _ = run_main([os.path.join(EX, "clean_openai.json")])
        self.assertEqual(code, 0)
        self.assertIn("No destination-risk findings", out)

    def test_json_output(self):
        code, out, _ = run_main([os.path.join(EX, "clean_openai.json"), "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["tool"], "fetchfence")
        self.assertEqual(data["findings"], [])
        self.assertGreaterEqual(data["fetches"], 1)

    def test_fail_on_none(self):
        code, _, _ = run_main([os.path.join(EX, "risky_openai.json"), "--fail-on", "none"])
        self.assertEqual(code, 0)

    def test_min_severity_filters(self):
        code, out, _ = run_main([
            os.path.join(EX, "risky_openai.json"), "--min-severity", "critical", "--json"
        ])
        data = json.loads(out)
        self.assertTrue(all(f["severity"] == "critical" for f in data["findings"]))
        self.assertEqual(code, 1)  # still has critical FF01

    def test_allow_host_cli(self):
        # webhook still high; allow the docs host from call_4
        code, out, _ = run_main([
            os.path.join(EX, "risky_openai.json"),
            "--allow-host", "docs.example.com",
            "--json",
        ])
        data = json.loads(out)
        hosts = {f.get("host") for f in data["findings"]}
        self.assertNotIn("docs.example.com", hosts)

    def test_disable_cli(self):
        code, out, _ = run_main([
            os.path.join(EX, "clean_openai.json"),  # no findings anyway
            "--disable", "FF07",
            "--list-rules",
        ])
        # list-rules short-circuits; just ensure disable doesn't crash on risky
        code, out, _ = run_main([
            os.path.join(EX, "urls.txt"), "--as-urls", "--disable", "FF02", "FF07", "FF12",
            "--json",
        ])
        data = json.loads(out)
        rules = {f["rule"] for f in data["findings"]}
        self.assertNotIn("FF02", rules)
        self.assertNotIn("FF07", rules)

    def test_missing_path(self):
        code, _, err = run_main(["/nonexistent/fetchfence-nope.json"])
        self.assertEqual(code, 2)

    def test_no_args_help(self):
        code, out, err = run_main([])
        self.assertEqual(code, 2)

    def test_dir_scan(self):
        code, out, _ = run_main([EX, "--fail-on", "none"])
        self.assertEqual(code, 0)
        self.assertIn("fetchfence", out)

    def test_stdin_urls(self):
        with mock.patch("sys.stdin", io.StringIO("https://example.com\nhttp://127.0.0.1/\n")):
            code, out, _ = run_main(["-", "--as-urls", "--json"])
        data = json.loads(out)
        self.assertEqual(data["fetches"], 2)
        self.assertEqual(code, 1)  # loopback high

    def test_anthropic_cli(self):
        code, out, _ = run_main([os.path.join(EX, "risky_anthropic.json"), "--json"])
        data = json.loads(out)
        rules = {f["rule"] for f in data["findings"]}
        self.assertIn("FF04", rules)
        self.assertIn("FF13", rules)
        self.assertEqual(code, 1)

    def test_version_exit(self):
        # argparse --version raises SystemExit
        with self.assertRaises(SystemExit) as cm:
            ff.main(["--version"])
        self.assertEqual(cm.exception.code, 0)


class TestHelpers(unittest.TestCase):
    def test_rules_complete(self):
        for i in range(1, 14):
            self.assertIn("FF%02d" % i, ff.RULES)

    def test_sev_rank_order(self):
        self.assertLess(ff.SEV_RANK["info"], ff.SEV_RANK["critical"])

    def test_placeholder_skipped(self):
        self.assertEqual(ff.classify_url("https://example.com", "t", ), [])  # wait example.com is fine
        self.assertEqual(ff.classify_url("TODO", "t"), [])
        self.assertEqual(ff.classify_url("${API_URL}", "t"), [])

    def test_text_of_list(self):
        self.assertIn("hi", ff._text_of([{"type": "text", "text": "hi"}]))

    def test_parse_args_string(self):
        self.assertEqual(ff._parse_args('{"url":"https://a"}')["url"], "https://a")
        self.assertEqual(ff._parse_args("not-json")["_"], "not-json")


if __name__ == "__main__":
    unittest.main()
