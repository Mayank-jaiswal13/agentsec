#!/usr/bin/env python3
"""Tests for pathfence."""
from __future__ import annotations

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import pathfence as pf  # noqa: E402

EX = os.path.join(ROOT, "examples")


def run_main(argv):
    buf = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(err):
        code = pf.main(argv)
    return code, buf.getvalue(), err.getvalue()


class TestClassify(unittest.TestCase):
    def test_env_file(self):
        fs = pf.classify_path("../../.env", "t")
        rules = {f.rule for f in fs}
        self.assertIn("PF01", rules)
        self.assertIn("PF06", rules)

    def test_aws_credentials(self):
        fs = pf.classify_path("/home/app/.aws/credentials", "t")
        self.assertIn("PF03", {f.rule for f in fs})

    def test_ssh_key(self):
        fs = pf.classify_path("~/.ssh/id_rsa", "t")
        self.assertIn("PF02", {f.rule for f in fs})

    def test_kube_config(self):
        fs = pf.classify_path("/home/runner/.kube/config", "t")
        self.assertIn("PF03", {f.rule for f in fs})

    def test_browser_cookies(self):
        fs = pf.classify_path(
            "/home/runner/.config/google-chrome/Default/Cookies", "t"
        )
        self.assertIn("PF04", {f.rule for f in fs})

    def test_shadow(self):
        fs = pf.classify_path("/etc/shadow", "t")
        self.assertIn("PF05", {f.rule for f in fs})

    def test_traversal(self):
        fs = pf.classify_path("../../../etc/passwd", "t")
        rules = {f.rule for f in fs}
        self.assertIn("PF06", rules)
        self.assertIn("PF05", rules)

    def test_outside_workspace(self):
        fs = pf.classify_path(
            "/etc/hosts", "t", workspaces=["/srv/app", "/workspace/project"]
        )
        self.assertIn("PF07", {f.rule for f in fs})

    def test_inside_workspace_no_pf07(self):
        fs = pf.classify_path(
            "/srv/app/src/main.py", "t", workspaces=["/srv/app"]
        )
        self.assertNotIn("PF07", {f.rule for f in fs})

    def test_broad_home(self):
        fs = pf.classify_path("~/", "t")
        self.assertIn("PF08", {f.rule for f in fs})

    def test_write_sensitive(self):
        fs = pf.classify_path("/etc/shadow", "t", op="write")
        rules = {f.rule for f in fs}
        self.assertIn("PF05", rules)
        self.assertIn("PF09", rules)

    def test_docker_sock(self):
        fs = pf.classify_path("/var/run/docker.sock", "t")
        self.assertIn("PF10", {f.rule for f in fs})

    def test_windows_sam(self):
        fs = pf.classify_path(r"C:\Windows\System32\config\SAM", "t")
        self.assertIn("PF11", {f.rule for f in fs})

    def test_clean_relative(self):
        fs = pf.classify_path("src/helpers/util.py", "t")
        self.assertEqual(fs, [])

    def test_allow_path_skips_most(self):
        fs = pf.classify_path(
            "/home/app/.aws/credentials",
            "t",
            allow_paths=["/home/app/.aws/*"],
        )
        self.assertEqual(fs, [])

    def test_allow_path_still_flags_traversal(self):
        fs = pf.classify_path(
            "/srv/app/../.env",
            "t",
            allow_paths=["/srv/app/*", "/srv/app/../.env"],
        )
        self.assertIn("PF06", {f.rule for f in fs})

    def test_disable_rule(self):
        fs = pf.classify_path("~/", "t", disabled=["PF08"])
        self.assertEqual(fs, [])

    def test_pem_basename(self):
        fs = pf.classify_path("certs/prod-server.pem", "t")
        self.assertIn("PF01", {f.rule for f in fs})

    def test_proc_self(self):
        fs = pf.classify_path("/proc/self/environ", "t")
        self.assertIn("PF10", {f.rule for f in fs})

    def test_placeholder_ignored(self):
        fs = pf.classify_path("path/to/file", "t")
        self.assertEqual(fs, [])


class TestToolDetection(unittest.TestCase):
    def test_file_tools(self):
        self.assertTrue(pf.is_file_tool("read_file"))
        self.assertTrue(pf.is_file_tool("Write"))
        self.assertTrue(pf.is_file_tool("apply_patch"))
        self.assertTrue(pf.is_file_tool("Bash"))
        self.assertFalse(pf.is_file_tool("send_email"))
        self.assertFalse(pf.is_file_tool("WebFetch"))

    def test_write_tools(self):
        self.assertTrue(pf.is_write_tool("write_file"))
        self.assertTrue(pf.is_write_tool("Delete"))
        self.assertFalse(pf.is_write_tool("read_file"))

    def test_shell_tools(self):
        self.assertTrue(pf.is_shell_tool("Bash"))
        self.assertTrue(pf.is_shell_tool("run_command"))
        self.assertFalse(pf.is_shell_tool("read_file"))


class TestExtraction(unittest.TestCase):
    def test_openai_risky(self):
        events = pf.load_events(os.path.join(EX, "risky_openai.json"))
        paths = [e.path for e in events]
        self.assertGreaterEqual(len(events), 4)
        self.assertTrue(any(".aws/credentials" in p for p in paths))
        self.assertTrue(any(".env" in p for p in paths))
        self.assertTrue(any("id_rsa" in p for p in paths))
        self.assertTrue(any("shadow" in p for p in paths))

    def test_openai_clean(self):
        events = pf.load_events(os.path.join(EX, "clean_openai.json"))
        self.assertEqual(len(events), 2)
        for e in events:
            self.assertIn("src/helpers/util.py", e.path)

    def test_anthropic_risky(self):
        events = pf.load_events(os.path.join(EX, "risky_anthropic.json"))
        self.assertGreaterEqual(len(events), 4)
        joined = " ".join(e.path for e in events)
        self.assertIn("kube", joined)
        self.assertIn("Cookies", joined)
        self.assertIn("docker.sock", joined)

    def test_jsonl_generic(self):
        events = pf.load_events(os.path.join(EX, "generic_paths.jsonl"))
        paths = [e.path for e in events]
        self.assertTrue(any(".env.production" in p for p in paths))
        self.assertTrue(any("/etc/passwd" in p for p in paths))
        # search_docs has no path — should not appear
        self.assertFalse(any(e.tool == "search_docs" for e in events))

    def test_path_list(self):
        events = pf.load_events(os.path.join(EX, "paths.txt"), as_paths=True)
        self.assertGreaterEqual(len(events), 4)
        self.assertTrue(any("docker.sock" in e.path for e in events))

    def test_shell_path_extraction(self):
        args = {"command": "cat ~/.ssh/id_rsa && less /etc/shadow"}
        paths = pf.extract_paths_from_args(args, "Bash")
        joined = " ".join(p for p, _ in paths)
        self.assertIn("id_rsa", joined)
        self.assertIn("shadow", joined)


class TestCLI(unittest.TestCase):
    def test_list_rules(self):
        code, out, _ = run_main(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertIn("PF01", out)
        self.assertIn("PF12", out)

    def test_risky_openai_fails(self):
        code, out, _ = run_main([os.path.join(EX, "risky_openai.json"), "--disable", "PF12"])
        self.assertEqual(code, 1)
        self.assertIn("PF03", out)
        self.assertIn("PF02", out)

    def test_clean_openai_passes(self):
        code, out, _ = run_main([
            os.path.join(EX, "clean_openai.json"),
            "--disable", "PF12",
            "--fail-on", "high",
        ])
        self.assertEqual(code, 0)

    def test_json_output(self):
        code, out, _ = run_main([
            os.path.join(EX, "risky_openai.json"),
            "--json",
            "--disable", "PF12",
        ])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["tool"], "pathfence")
        self.assertGreater(len(data["findings"]), 0)
        rules = {f["rule"] for f in data["findings"]}
        self.assertIn("PF03", rules)

    def test_fail_on_none(self):
        code, _, _ = run_main([
            os.path.join(EX, "risky_openai.json"),
            "--fail-on", "none",
            "--disable", "PF12",
        ])
        self.assertEqual(code, 0)

    def test_missing_path(self):
        code, _, err = run_main(["/nonexistent/pathfence-input-xyz.json"])
        self.assertEqual(code, 2)

    def test_no_args(self):
        code, _, _ = run_main([])
        self.assertEqual(code, 2)

    def test_workspace_flag(self):
        code, out, _ = run_main([
            os.path.join(EX, "paths.txt"),
            "--as-paths",
            "--workspace", "/srv/app",
            "--disable", "PF12",
            "--json",
        ])
        self.assertEqual(code, 1)
        data = json.loads(out)
        rules = {f["rule"] for f in data["findings"]}
        self.assertIn("PF07", rules)

    def test_min_severity(self):
        code, out, _ = run_main([
            os.path.join(EX, "generic_paths.jsonl"),
            "--min-severity", "critical",
            "--disable", "PF12",
            "--json",
        ])
        data = json.loads(out)
        for f in data["findings"]:
            self.assertEqual(f["severity"], "critical")

    def test_anthropic_cli(self):
        code, out, _ = run_main([
            os.path.join(EX, "risky_anthropic.json"),
            "--disable", "PF12",
        ])
        self.assertEqual(code, 1)
        self.assertTrue("PF03" in out or "PF04" in out or "PF10" in out)


class TestHelpers(unittest.TestCase):
    def test_norm_path(self):
        self.assertEqual(pf._norm_path(r"C:\Windows\System32"), "C:/Windows/System32")

    def test_strip_file_url(self):
        self.assertEqual(pf._strip_file_url("file:///etc/passwd"), "/etc/passwd")

    def test_looks_like_path(self):
        self.assertTrue(pf._looks_like_path("src/main.py"))
        self.assertTrue(pf._looks_like_path("~/.env"))
        self.assertFalse(pf._looks_like_path("https://example.com/a"))
        self.assertFalse(pf._looks_like_path("hello world"))


if __name__ == "__main__":
    unittest.main()
