#!/usr/bin/env python3
"""Tests for schemafence."""
from __future__ import annotations

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import schemafence as sf  # noqa: E402

EX = os.path.join(ROOT, "examples")


def run_main(argv):
    buf = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(err):
        code = sf.main(argv)
    return code, buf.getvalue(), err.getvalue()


def tool(name, properties, required=None, additional=None, annotations=None, server=""):
    schema = {"type": "object", "properties": properties}
    if required is not None:
        schema["required"] = required
    if additional is not None:
        schema["additionalProperties"] = additional
    return sf.ToolDef(
        source="t",
        name=name,
        schema=schema,
        annotations=annotations or {},
        server=server,
    )


class TestConstraints(unittest.TestCase):
    def test_enum_constrained(self):
        self.assertTrue(sf._prop_constrained({"type": "string", "enum": ["a", "b"]}))

    def test_pattern_constrained(self):
        self.assertTrue(sf._prop_constrained({"type": "string", "pattern": "^x$"}))

    def test_const_constrained(self):
        self.assertTrue(sf._prop_constrained({"const": "fixed"}))

    def test_plain_string_unconstrained(self):
        self.assertFalse(sf._prop_constrained({"type": "string"}))

    def test_oneof_enums(self):
        self.assertTrue(
            sf._prop_constrained(
                {"oneOf": [{"enum": ["a"]}, {"enum": ["b"]}]}
            )
        )


class TestClassify(unittest.TestCase):
    def test_unconstrained_command(self):
        t = tool("run_shell", {"command": {"type": "string"}})
        rules = {f.rule for f in sf.classify_tool(t)}
        self.assertIn("SK01", rules)

    def test_constrained_command_ok(self):
        t = tool(
            "run_shell",
            {"command": {"type": "string", "enum": ["status", "version"]}},
            required=["command"],
        )
        rules = {f.rule for f in sf.classify_tool(t)}
        self.assertNotIn("SK01", rules)

    def test_unconstrained_url(self):
        t = tool("fetch", {"url": {"type": "string"}})
        self.assertIn("SK02", {f.rule for f in sf.classify_tool(t)})

    def test_unconstrained_path(self):
        t = tool("read_file", {"path": {"type": "string"}})
        self.assertIn("SK03", {f.rule for f in sf.classify_tool(t)})

    def test_unconstrained_recipient(self):
        t = tool("send_email", {"to": {"type": "string"}, "body": {"type": "string"}})
        self.assertIn("SK04", {f.rule for f in sf.classify_tool(t)})

    def test_secret_param(self):
        t = tool("call_api", {"api_key": {"type": "string"}, "q": {"type": "string"}})
        self.assertIn("SK06", {f.rule for f in sf.classify_tool(t)})

    def test_additional_properties(self):
        t = tool(
            "run_shell",
            {"command": {"type": "string"}},
            additional=True,
        )
        self.assertIn("SK05", {f.rule for f in sf.classify_tool(t)})

    def test_readonly_with_command(self):
        t = tool(
            "bash",
            {"command": {"type": "string"}},
            annotations={"readOnlyHint": True},
        )
        self.assertIn("SK07", {f.rule for f in sf.classify_tool(t)})

    def test_readonly_write_file(self):
        t = tool(
            "write_file",
            {"path": {"type": "string"}, "content": {"type": "string"}},
            annotations={"readOnlyHint": True},
        )
        rules = {f.rule for f in sf.classify_tool(t)}
        self.assertIn("SK03", rules)
        self.assertIn("SK07", rules)

    def test_destructive_false_on_delete(self):
        t = tool(
            "delete_record",
            {"id": {"type": "string"}},
            annotations={"destructiveHint": False},
        )
        self.assertIn("SK07", {f.rule for f in sf.classify_tool(t)})

    def test_openworld_false_with_url(self):
        t = tool(
            "fetch",
            {"url": {"type": "string"}},
            annotations={"openWorldHint": False},
        )
        self.assertIn("SK07", {f.rule for f in sf.classify_tool(t)})

    def test_consequential_no_required(self):
        t = tool("deploy_app", {"env": {"type": "string"}})
        self.assertIn("SK08", {f.rule for f in sf.classify_tool(t)})

    def test_sql_param(self):
        t = tool("run_sql", {"sql": {"type": "string"}})
        self.assertIn("SK09", {f.rule for f in sf.classify_tool(t)})

    def test_clean_enum_weather(self):
        t = tool(
            "get_weather",
            {"city": {"type": "string", "enum": ["nyc", "sfo"]}},
            required=["city"],
            additional=False,
        )
        self.assertEqual(sf.classify_tool(t), [])

    def test_disable_rule(self):
        t = tool("run_shell", {"command": {"type": "string"}})
        self.assertEqual(sf.classify_tool(t, disabled=["SK01", "SK08"]), [])

    def test_authorization_secret(self):
        t = tool("http_post", {"url": {"type": "string"}, "authorization": {"type": "string"}})
        rules = {f.rule for f in sf.classify_tool(t)}
        self.assertIn("SK02", rules)
        self.assertIn("SK06", rules)

    def test_transfer_funds_recipient_and_sk08(self):
        t = tool("transfer_funds", {"to": {"type": "string"}, "amount": {"type": "number"}})
        rules = {f.rule for f in sf.classify_tool(t)}
        self.assertIn("SK04", rules)
        self.assertIn("SK08", rules)

    def test_code_param(self):
        t = tool("run_code", {"code": {"type": "string"}})
        self.assertIn("SK01", {f.rule for f in sf.classify_tool(t)})

    def test_channel_recipient(self):
        t = tool("send_message", {"channel": {"type": "string"}, "text": {"type": "string"}})
        self.assertIn("SK04", {f.rule for f in sf.classify_tool(t)})


class TestExtraction(unittest.TestCase):
    def test_mcp_jsonrpc(self):
        path = os.path.join(EX, "risky_mcp.json")
        tools = sf.load_tools(path)
        names = {t.name for t in tools}
        self.assertIn("run_shell", names)
        self.assertIn("run_sql", names)
        self.assertGreaterEqual(len(tools), 7)

    def test_openai_clean(self):
        path = os.path.join(EX, "clean_openai.json")
        tools = sf.load_tools(path)
        self.assertEqual(len(tools), 3)
        self.assertEqual({t.name for t in tools}, {"get_weather", "fetch_status", "read_note"})

    def test_anthropic_server(self):
        path = os.path.join(EX, "risky_anthropic.json")
        tools = sf.load_tools(path)
        self.assertTrue(all(t.server == "ops" for t in tools))
        self.assertIn("bash", {t.name for t in tools})

    def test_multi_server(self):
        path = os.path.join(EX, "multi_server.json")
        tools = sf.load_tools(path)
        by = {(t.server, t.name) for t in tools}
        self.assertIn(("fs", "read_file"), by)
        self.assertIn(("mail", "send_message"), by)

    def test_jsonl(self):
        path = os.path.join(EX, "generic_tools.jsonl")
        tools = sf.load_tools(path)
        self.assertEqual({t.name for t in tools}, {"run_code", "lookup_user"})

    def test_normalize_openai_function_wrapper(self):
        raw = {
            "type": "function",
            "function": {
                "name": "x",
                "parameters": {"type": "object", "properties": {}},
            },
        }
        td = sf.normalize_tool(raw, source="t")
        self.assertIsNotNone(td)
        self.assertEqual(td.name, "x")


class TestCLI(unittest.TestCase):
    def test_list_rules(self):
        code, out, _ = run_main(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertIn("SK01", out)
        self.assertIn("SK10", out)

    def test_risky_mcp_fails(self):
        path = os.path.join(EX, "risky_mcp.json")
        code, out, _ = run_main([path, "--disable", "SK10"])
        self.assertEqual(code, 1)
        self.assertIn("SK01", out)
        self.assertIn("SK02", out)
        self.assertIn("SK09", out)

    def test_clean_passes(self):
        path = os.path.join(EX, "clean_openai.json")
        code, out, _ = run_main([path, "--disable", "SK10"])
        self.assertEqual(code, 0)
        self.assertIn("No schema-privilege findings", out)

    def test_json_output(self):
        path = os.path.join(EX, "risky_anthropic.json")
        code, out, _ = run_main([path, "--json", "--disable", "SK10"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["tool"], "schemafence")
        rules = {f["rule"] for f in data["findings"]}
        self.assertIn("SK01", rules)
        self.assertIn("SK04", rules)

    def test_fail_on_none(self):
        path = os.path.join(EX, "risky_mcp.json")
        code, _, _ = run_main([path, "--fail-on", "none", "--disable", "SK10"])
        self.assertEqual(code, 0)

    def test_missing_path(self):
        code, _, err = run_main(["/no/such/schemafence-input.json"])
        self.assertEqual(code, 2)

    def test_no_args(self):
        code, _, _ = run_main([])
        self.assertEqual(code, 2)

    def test_dir_scan(self):
        code, out, _ = run_main([EX, "--disable", "SK10", "--min-severity", "critical"])
        self.assertIn("SK01", out)
        self.assertEqual(code, 1)

    def test_inventory_info_only(self):
        path = os.path.join(EX, "clean_openai.json")
        code, out, _ = run_main([path, "--fail-on", "high"])
        self.assertEqual(code, 0)
        self.assertIn("SK10", out)

    def test_multi_server_mail_sk04(self):
        path = os.path.join(EX, "multi_server.json")
        code, out, _ = run_main([path, "--disable", "SK10"])
        self.assertEqual(code, 1)
        self.assertIn("SK04", out)
        # path is pattern-constrained → no SK03 fail for read_file
        self.assertNotIn("read_file accepts unconstrained path", out)

    def test_generic_jsonl_run_code(self):
        path = os.path.join(EX, "generic_tools.jsonl")
        code, out, _ = run_main([path, "--disable", "SK10"])
        self.assertEqual(code, 1)
        self.assertIn("SK01", out)


class TestHelpers(unittest.TestCase):
    def test_matches_key_set(self):
        self.assertTrue(sf._matches_key_set("command", sf.COMMAND_KEYS))
        self.assertTrue(sf._matches_key_set("webhook_url", sf.URL_KEYS))
        self.assertTrue(sf._matches_key_set("file_path", sf.PATH_KEYS))
        self.assertFalse(sf._matches_key_set("city", sf.URL_KEYS))

    def test_consequential(self):
        self.assertTrue(sf._is_consequential_tool("run_shell"))
        self.assertTrue(sf._is_consequential_tool("transfer_funds"))
        self.assertTrue(sf._is_consequential_tool("deploy_service"))
        self.assertFalse(sf._is_consequential_tool("get_weather"))


if __name__ == "__main__":
    unittest.main()
