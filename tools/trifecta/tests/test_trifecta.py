import io, json, os, subprocess, sys, tempfile, unittest
from contextlib import redirect_stdout
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import trifecta
EX = os.path.join(ROOT, "examples")
CLI = [sys.executable, os.path.join(ROOT, "trifecta.py")]


def mcp(*tools):
    return {"tools": list(tools)}


def tool(name, desc="", props=None, ann=None):
    t = {"name": name, "description": desc,
         "inputSchema": {"type": "object", "properties": props or {}}}
    if ann:
        t["annotations"] = ann
    return t


def tag(name, desc="", props=None, ann=None):
    t = trifecta.Tool("s", name, desc, {"properties": props or {}}, ann or {})
    return trifecta.classify(t).legs()


def write(obj, name="srv.json", d=None):
    d = d or tempfile.mkdtemp()
    p = os.path.join(d, name)
    with open(p, "w") as fh:
        json.dump(obj, fh)
    return p


def run(paths, *extra):
    return trifecta.build(paths, *extra)


def codes(findings):
    return [f["code"] for f in findings]


class TestClassify(unittest.TestCase):
    def test_read_file_private(self):
        self.assertEqual(tag("read_file"), {"private"})

    def test_camel_case_split(self):
        self.assertEqual(tag("readFile"), {"private"})

    def test_send_email_exfil_only(self):
        self.assertEqual(tag("send_email", props={"to": {}, "body": {}}), {"exfil"})

    def test_search_inbox_private_and_untrusted(self):
        self.assertEqual(tag("search_inbox"), {"private", "untrusted"})

    def test_fetch_url_untrusted_and_exfil(self):
        self.assertEqual(tag("fetch", props={"url": {"type": "string"}}), {"untrusted", "exfil"})

    def test_enum_url_not_exfil(self):
        legs = tag("get_status", props={"url": {"type": "string", "enum": ["https://x.example/"]}})
        self.assertNotIn("exfil", legs)

    def test_shell_gets_all_legs(self):
        self.assertEqual(tag("run_shell"), set(trifecta.LEGS))

    def test_command_param_gets_all_legs(self):
        self.assertEqual(tag("tool_x", props={"command": {"type": "string"}}), set(trifecta.LEGS))

    def test_read_verb_suppresses_shell(self):
        self.assertNotIn("action", tag("get_command_history"))

    def test_create_issue_is_exfil(self):
        self.assertIn("exfil", tag("create_issue"))

    def test_list_issues_untrusted_not_exfil(self):
        legs = tag("list_issues")
        self.assertIn("untrusted", legs)
        self.assertNotIn("exfil", legs)

    def test_web_search(self):
        self.assertIn("untrusted", tag("search", "Search the web for pages."))

    def test_delete_is_action(self):
        self.assertEqual(tag("delete_branch"), {"action"})

    def test_extract_text_not_exfil(self):
        self.assertNotIn("exfil", tag("extract_text"))

    def test_destructive_hint(self):
        self.assertIn("action", tag("tidy", ann={"destructiveHint": True}))

    def test_open_world_hint(self):
        self.assertIn("untrusted", tag("lookup_thing", ann={"openWorldHint": True}))

    def test_read_only_hint_drops_verb_exfil(self):
        self.assertNotIn("exfil", tag("post_preview", ann={"readOnlyHint": True}))

    def test_read_only_hint_keeps_url_exfil(self):
        self.assertIn("exfil", tag("preview", props={"url": {}}, ann={"readOnlyHint": True}))

    def test_description_evidence(self):
        self.assertIn("private", tag("lookup", "Returns confidential customer data."))

    def test_unclassified(self):
        self.assertEqual(tag("get_weather", props={"city": {}}), set())


class TestFormats(unittest.TestCase):
    def test_mcp_result_wrapper(self):
        p = write({"jsonrpc": "2.0", "result": mcp(tool("read_file"))})
        tools, _ = run([p])
        self.assertEqual(tools[0].qname, "srv/read_file")

    def test_openai_and_anthropic_shapes(self):
        p = write([{"type": "function", "function": {"name": "send_email", "parameters": {}}},
                   {"name": "read_file", "input_schema": {"properties": {}}}])
        tools, _ = run([p])
        self.assertEqual(sorted(t.name for t in tools), ["read_file", "send_email"])

    def test_servers_map_and_server_key(self):
        p = write({"servers": {"a": mcp(tool("read_file")), "b": [tool("send_email")]}})
        q = write({"server": "named", "tools": [tool("fetch")]}, "other.json")
        tools, _ = run([p, q])
        self.assertEqual({t.server for t in tools}, {"a", "b", "named"})

    def test_bad_shape_is_input_error(self):
        with self.assertRaises(trifecta.InputError):
            run([write({"nope": 1})])

    def test_invalid_json(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.json")
        open(p, "w").write("{not json")
        with self.assertRaises(trifecta.InputError):
            run([p])

    def test_duplicate_tools_deduped(self):
        p = write(mcp(tool("read_file"), tool("read_file")))
        tools, _ = run([p])
        self.assertEqual(len(tools), 1)


class TestAnalysis(unittest.TestCase):
    def test_trifecta_across_servers_and_break(self):
        d = tempfile.mkdtemp()
        write(mcp(tool("read_file"), tool("list_directory")), "fs.json", d)
        write(mcp(tool("fetch", props={"url": {}})), "web.json", d)
        write(mcp(tool("send_email", props={"to": {}})), "mail.json", d)
        _, f = run([d])
        tf01 = [x for x in f if x["code"] == "TF01"][0]
        self.assertTrue(tf01["cross_server"])
        self.assertEqual(tf01["break_leg"], "untrusted")
        self.assertEqual(tf01["break_tools"], ["web/fetch"])
        self.assertEqual(f[0]["code"], "TF01")

    def test_tf04_private_exfil_only(self):
        _, f = run([write(mcp(tool("read_file"), tool("send_email")))])
        self.assertEqual(codes(f), ["TF04"])

    def test_tf05_private_untrusted_only(self):
        _, f = run([write(mcp(tool("read_file"), tool("list_issues")))])
        self.assertEqual(codes(f), ["TF05"])

    def test_tf03_untrusted_plus_action(self):
        _, f = run([write(mcp(tool("list_issues"), tool("delete_branch")))])
        self.assertEqual(codes(f), ["TF03"])

    def test_tf01_suppresses_tf04_tf05(self):
        _, f = run([write(mcp(tool("search_inbox"), tool("send_email")))])
        c = codes(f)
        self.assertIn("TF01", c)
        self.assertNotIn("TF04", c)
        self.assertNotIn("TF05", c)

    def test_overrides_and_ignore(self):
        p = write(mcp(tool("search_inbox"), tool("send_email"), tool("get_weather")))
        d = tempfile.mkdtemp()
        tags = write({"overrides": {"srv/send_email": [], "*weather": ["untrusted"]}}, "t.json", d)
        tools, f = run([p], tags)
        self.assertNotIn("TF01", codes(f))
        self.assertTrue(all(t.overridden for t in tools if t.name != "search_inbox"))
        tools, f = run([p], None, ["send_*"])
        self.assertNotIn("send_email", [t.name for t in tools])

    def test_bad_overrides(self):
        d = tempfile.mkdtemp()
        tags = write({"overrides": {"x": ["root"]}}, "t.json", d)
        with self.assertRaises(trifecta.InputError):
            run([write(mcp(tool("read_file")))], tags)


class TestCLI(unittest.TestCase):
    def cli(self, *args):
        return subprocess.run(CLI + list(args), capture_output=True, text=True)

    def test_example_agent_is_critical(self):
        r = self.cli(os.path.join(EX, "agent"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("TF01", r.stdout)

    def test_example_safe_clean_with_tags(self):
        r = self.cli(os.path.join(EX, "safe"), "--tags", os.path.join(EX, "tags.json"),
                     "--fail-on", "any")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("No risky combinations", r.stdout)

    def test_json_output(self):
        r = self.cli(os.path.join(EX, "agent"), "--json")
        data = json.loads(r.stdout)
        self.assertTrue(data["summary"]["trifecta"])
        self.assertEqual(data["summary"]["tools"], 8)

    def test_fail_on_none_and_min_severity(self):
        self.assertEqual(self.cli(os.path.join(EX, "agent"), "--fail-on", "none").returncode, 0)
        r = self.cli(os.path.join(EX, "agent"), "--min-severity", "critical", "--json")
        self.assertEqual({f["code"] for f in json.loads(r.stdout)["findings"]}, {"TF01"})

    def test_missing_path_exit_2(self):
        self.assertEqual(self.cli("/nonexistent/x.json").returncode, 2)

    def test_stdin(self):
        r = subprocess.run(CLI + ["-", "--json"], input=json.dumps(mcp(tool("read_file"))),
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(json.loads(r.stdout)["tools"][0]["server"], "stdin")

    def test_main_in_process(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = trifecta.main([os.path.join(EX, "agent", "mail.json")])
        self.assertEqual(rc, 1)
        self.assertIn("mail/run_shell", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
