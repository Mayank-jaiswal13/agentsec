#!/usr/bin/env python3
"""Tests for modelpin."""
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
import modelpin as mp  # noqa: E402

EX = os.path.join(ROOT, "examples")


def run_main(argv):
    buf = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(err):
        code = mp.main(argv)
    return code, buf.getvalue(), err.getvalue()


class TestHelpers(unittest.TestCase):
    def test_infer_provider_openai(self):
        self.assertEqual(mp.infer_provider("gpt-4o-2024-08-06"), "openai")
        self.assertEqual(mp.infer_provider("o3-mini"), "openai")
        self.assertEqual(mp.infer_provider("openai/gpt-4o"), "openai")

    def test_infer_provider_anthropic(self):
        self.assertEqual(mp.infer_provider("claude-3-5-sonnet-20241022"), "anthropic")

    def test_infer_provider_bedrock(self):
        self.assertEqual(
            mp.infer_provider("bedrock/anthropic.claude-3-5-sonnet-20241022-v1:0"),
            "bedrock",
        )
        self.assertEqual(
            mp.infer_provider("us.anthropic.claude-3-5-sonnet-20241022-v1:0"),
            "bedrock",
        )

    def test_infer_provider_google(self):
        self.assertEqual(mp.infer_provider("gemini-2.0-flash"), "google")

    def test_floating_exact(self):
        self.assertTrue(mp.is_floating_alias("gpt-4o"))
        self.assertTrue(mp.is_floating_alias("claude-3-5-sonnet-latest"))
        self.assertTrue(mp.is_floating_alias("o1"))

    def test_floating_undated_family(self):
        self.assertTrue(mp.is_floating_alias("claude-3-5-sonnet"))
        self.assertTrue(mp.is_floating_alias("gpt-4-turbo"))

    def test_not_floating_dated(self):
        self.assertFalse(mp.is_floating_alias("gpt-4o-2024-08-06"))
        self.assertFalse(mp.is_floating_alias("claude-3-5-sonnet-20241022"))

    def test_deprecated(self):
        self.assertTrue(mp.is_deprecated("gpt-3.5-turbo"))
        self.assertTrue(mp.is_deprecated("claude-instant-1.2"))
        self.assertFalse(mp.is_deprecated("gpt-4o-2024-08-06"))

    def test_capability_tier(self):
        self.assertGreater(mp.capability_tier("gpt-4o-2024-08-06"),
                           mp.capability_tier("gpt-4o-mini"))
        self.assertGreater(mp.capability_tier("claude-3-opus-20240229"),
                           mp.capability_tier("claude-3-haiku-20240307"))

    def test_model_allowed_glob(self):
        self.assertTrue(mp.model_allowed("gpt-4o-2024-08-06", ["gpt-4o-*"]))
        self.assertFalse(mp.model_allowed("claude-3-5-sonnet-20241022", ["gpt-4o-*"]))

    def test_model_allowed_provider_prefix(self):
        self.assertTrue(mp.model_allowed("openai/gpt-4o-2024-08-06", ["gpt-4o-2024-08-06"]))


class TestExtract(unittest.TestCase):
    def test_openai_transcript(self):
        ev = mp.load_events(os.path.join(EX, "clean_openai.json"))
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0].model, "gpt-4o-2024-08-06")
        self.assertEqual(ev[0].provider, "openai")

    def test_anthropic_message(self):
        ev = mp.load_events(os.path.join(EX, "clean_anthropic.json"))
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0].model, "claude-3-5-sonnet-20241022")

    def test_jsonl_switch(self):
        ev = mp.load_events(os.path.join(EX, "risky_switch.jsonl"))
        self.assertEqual(len(ev), 3)
        models = [e.model for e in ev]
        self.assertEqual(models[0], "gpt-4o-2024-08-06")
        self.assertEqual(models[1], "gpt-4o-mini")
        self.assertEqual(models[2], "gpt-3.5-turbo")

    def test_missing_model(self):
        ev = mp.load_events(os.path.join(EX, "risky_missing.json"))
        self.assertEqual(len(ev), 1)
        self.assertTrue(ev[0].missing)

    def test_stdin(self):
        raw = json.dumps({"model": "gpt-4o-2024-08-06", "usage": {"prompt_tokens": 1}})
        old = sys.stdin
        try:
            sys.stdin = io.StringIO(raw)
            ev = mp.load_events("-")
        finally:
            sys.stdin = old
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0].model, "gpt-4o-2024-08-06")


class TestAnalyze(unittest.TestCase):
    def _policy(self, **kw):
        p = mp.default_policy()
        p["allowed"] = ["gpt-4o-2024-08-06", "claude-3-5-sonnet-20241022"]
        p["providers"] = ["openai", "anthropic"]
        p["pinned"] = "gpt-4o-2024-08-06"
        p.update(kw)
        return p

    def test_clean_pinned(self):
        ev = mp.load_events(os.path.join(EX, "clean_openai.json"))
        fs = mp.analyze(ev, self._policy(), disabled=["MD09"])
        self.assertEqual(fs, [])

    def test_alias_md02(self):
        ev = mp.load_events(os.path.join(EX, "risky_aliases.json"))
        fs = mp.analyze(ev, self._policy(pinned="", allowed=[]), disabled=["MD09"])
        rules = {f.rule for f in fs}
        self.assertIn("MD02", rules)

    def test_switch_md03(self):
        ev = mp.load_events(os.path.join(EX, "risky_switch.jsonl"))
        fs = mp.analyze(ev, self._policy(pinned=""), disabled=["MD09"])
        rules = {f.rule for f in fs}
        self.assertIn("MD03", rules)
        self.assertIn("MD02", rules)  # gpt-4o-mini alias
        self.assertIn("MD07", rules)  # gpt-3.5

    def test_provider_drift_md04(self):
        ev = mp.load_events(os.path.join(EX, "risky_provider.json"))
        fs = mp.analyze(ev, self._policy(pinned="", allowed=[]), disabled=["MD09"])
        self.assertIn("MD04", {f.rule for f in fs})

    def test_pin_mismatch_md05_md08(self):
        ev = [mp.ModelEvent("t", "gpt-4o-mini", turn=0)]
        fs = mp.analyze(ev, self._policy(), disabled=["MD09", "MD01", "MD02"])
        rules = {f.rule for f in fs}
        self.assertIn("MD05", rules)
        self.assertIn("MD08", rules)

    def test_missing_md06(self):
        ev = mp.load_events(os.path.join(EX, "risky_missing.json"))
        fs = mp.analyze(ev, self._policy(pinned="", allowed=[]), disabled=["MD09"])
        self.assertIn("MD06", {f.rule for f in fs})

    def test_not_allowed_md01(self):
        ev = [mp.ModelEvent("t", "grok-3", turn=0)]
        fs = mp.analyze(ev, self._policy(pinned="", forbid_aliases=False), disabled=["MD09"])
        self.assertIn("MD01", {f.rule for f in fs})

    def test_inventory_md09(self):
        ev = mp.load_events(os.path.join(EX, "clean_openai.json"))
        fs = mp.analyze(ev, self._policy())
        self.assertIn("MD09", {f.rule for f in fs})

    def test_disable_rule(self):
        ev = mp.load_events(os.path.join(EX, "risky_aliases.json"))
        fs = mp.analyze(ev, self._policy(pinned="", allowed=[]), disabled=["MD02", "MD09", "MD01"])
        self.assertEqual(fs, [])

    def test_allow_switch(self):
        ev = mp.load_events(os.path.join(EX, "risky_switch.jsonl"))
        fs = mp.analyze(
            ev,
            self._policy(pinned="", allowed=[], forbid_switch=False, forbid_aliases=False),
            disabled=["MD09"],
        )
        self.assertNotIn("MD03", {f.rule for f in fs})
        self.assertIn("MD07", {f.rule for f in fs})


class TestCLI(unittest.TestCase):
    def test_list_rules(self):
        code, out, _ = run_main(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertIn("MD01", out)
        self.assertIn("MD09", out)

    def test_clean_exit_0(self):
        code, out, _ = run_main([
            os.path.join(EX, "clean_openai.json"),
            "-p", os.path.join(EX, "policy_strict.json"),
            "--disable", "MD09",
            "--fail-on", "high",
        ])
        self.assertEqual(code, 0)
        self.assertIn("No model-pin findings", out)

    def test_risky_switch_exit_1(self):
        code, out, _ = run_main([
            os.path.join(EX, "risky_switch.jsonl"),
            "-p", os.path.join(EX, "policy_strict.json"),
            "--json",
        ])
        self.assertEqual(code, 1)
        data = json.loads(out)
        rules = {f["rule"] for f in data["findings"]}
        self.assertIn("MD03", rules)

    def test_fail_on_none(self):
        code, _, _ = run_main([
            os.path.join(EX, "risky_aliases.json"),
            "--fail-on", "none",
        ])
        self.assertEqual(code, 0)

    def test_min_severity(self):
        code, out, _ = run_main([
            os.path.join(EX, "clean_openai.json"),
            "-p", os.path.join(EX, "policy_strict.json"),
            "--min-severity", "low",
            "--json",
        ])
        self.assertEqual(code, 0)
        data = json.loads(out)
        # MD09 is info — filtered out
        self.assertEqual(data["findings"], [])

    def test_missing_path_exit_2(self):
        code, _, err = run_main(["/nonexistent/FAKE-EXAMPLE-missing.json"])
        self.assertEqual(code, 2)

    def test_no_args_exit_2(self):
        code, _, _ = run_main([])
        self.assertEqual(code, 2)

    def test_init(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "pol.json")
            code, _, err = run_main(["--init", path])
            self.assertEqual(code, 0)
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertIn("allowed", doc)
            self.assertTrue(doc["forbid_aliases"])

    def test_init_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "pol.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{}")
            code, _, err = run_main(["--init", path])
            self.assertEqual(code, 2)

    def test_cli_allow_flag(self):
        code, out, _ = run_main([
            os.path.join(EX, "clean_openai.json"),
            "--allow", "gpt-4o-2024-08-06",
            "--providers", "openai",
            "--disable", "MD09",
            "--json",
        ])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["findings"], [])

    def test_json_schema_keys(self):
        code, out, _ = run_main([
            os.path.join(EX, "risky_aliases.json"),
            "--json",
            "--fail-on", "none",
        ])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["tool"], "modelpin")
        self.assertIn("findings", data)
        self.assertIn("policy", data)
        f = data["findings"][0]
        for k in ("rule", "severity", "title", "source", "message", "model"):
            self.assertIn(k, f)

    def test_allow_aliases_flag(self):
        # Without allowlist, only MD02 would fire for gpt-4o; suppress it
        code, out, _ = run_main([
            os.path.join(EX, "risky_aliases.json"),
            "--allow-aliases",
            "--disable", "MD09",
            "--json",
        ])
        data = json.loads(out)
        self.assertNotIn("MD02", {f["rule"] for f in data["findings"]})
        self.assertEqual(code, 0)


class TestPolicyLoad(unittest.TestCase):
    def test_load_policy(self):
        p = mp.load_policy(os.path.join(EX, "policy_strict.json"))
        self.assertEqual(p["pinned"], "gpt-4o-2024-08-06")
        self.assertIn("openai", p["providers"])

    def test_normalize_string_forms(self):
        p = mp.normalize_policy({
            "allow": "gpt-4o-2024-08-06",
            "provider": "openai",
            "pin": ["gpt-4o-2024-08-06"],
        })
        self.assertEqual(p["allowed"], ["gpt-4o-2024-08-06"])
        self.assertEqual(p["providers"], ["openai"])
        self.assertEqual(p["pinned"], "gpt-4o-2024-08-06")


if __name__ == "__main__":
    unittest.main()
