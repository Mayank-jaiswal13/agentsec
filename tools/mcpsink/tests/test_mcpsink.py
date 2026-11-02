import json, os, subprocess, sys, tempfile, textwrap, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import mcpsink as ms
EX = os.path.join(ROOT, "examples")
CLI = [sys.executable, os.path.join(ROOT, "mcpsink.py")]

HDR = "import os, subprocess, sqlite3, pickle, yaml, httpx, requests, shlex, re\n" \
      "from pathlib import Path\nfrom mcp.server.fastmcp import FastMCP, Context\nmcp = FastMCP('t')\n"


def scan(body, **kw):
    f, inv = ms.scan_source("s.py", HDR + textwrap.dedent(body), **kw)
    return f


def rules(body, **kw):
    return sorted({f.rule for f in scan(body, **kw)} - {"MS09"})


def sevs(body, rule):
    return sorted({f.severity for f in scan(body) if f.rule == rule})


def run(*args):
    p = subprocess.run(CLI + list(args), capture_output=True, text=True, cwd=ROOT)
    return p.returncode, p.stdout, p.stderr


class Detection(unittest.TestCase):
    def test_non_handler_function_ignored(self):
        self.assertEqual(rules("def f(cmd):\n    os.system(cmd)\n"), [])

    def test_shell_true_critical(self):
        b = "@mcp.tool()\ndef t(q: str):\n    subprocess.run(f'grep {q} .', shell=True)\n"
        self.assertEqual(sevs(b, "MS01"), ["critical"])

    def test_os_system_and_popen(self):
        self.assertIn("MS01", rules("@mcp.tool()\ndef t(c):\n    os.system('ls ' + c)\n"))
        self.assertIn("MS01", rules("@mcp.tool()\ndef t(c):\n    return os.popen(c).read()\n"))

    def test_shlex_quote_sanitizes(self):
        b = "@mcp.tool()\ndef t(q):\n    subprocess.run('grep ' + shlex.quote(q), shell=True)\n"
        self.assertNotIn("MS01", rules(b))

    def test_constant_command_clean(self):
        self.assertNotIn("MS01", rules("@mcp.tool()\ndef t(q):\n    subprocess.run('uptime', shell=True)\n"))

    def test_tainted_program_high(self):
        b = "@mcp.tool()\ndef t(prog):\n    subprocess.run([prog, '-v'])\n"
        self.assertEqual(sevs(b, "MS01"), ["high"])

    def test_argv_injection_low_and_dashdash(self):
        b = "@mcp.tool()\ndef t(ref):\n    subprocess.run(['git', 'log', ref])\n"
        self.assertEqual(sevs(b, "MS01"), ["low"])
        b2 = "@mcp.tool()\ndef t(ref):\n    subprocess.run(['git', 'log', '--', ref])\n"
        self.assertNotIn("MS01", rules(b2))

    def test_interpreter_dash_c_critical(self):
        b = "@mcp.tool()\ndef t(code):\n    subprocess.run(['python3', '-c', code])\n"
        self.assertEqual(sevs(b, "MS01"), ["critical"])

    def test_propagation_through_assignments(self):
        b = "@mcp.tool()\ndef t(x):\n    a = x.strip()\n    b = 'echo ' + a\n    os.system(b)\n"
        self.assertIn("MS01", rules(b))

    def test_path_traversal_open(self):
        b = "@mcp.tool()\ndef t(name):\n    return open('/data/' + name).read()\n"
        self.assertEqual(sevs(b, "MS02"), ["high"])

    def test_path_method_on_joined_path(self):
        b = "ROOT = Path('/srv')\n@mcp.tool()\ndef t(p):\n    full = ROOT / p\n    return full.read_text()\n"
        self.assertIn("MS02", rules(b))

    def test_path_guard_downgrades_to_info(self):
        b = ("ROOT = Path('/srv')\n@mcp.tool()\ndef t(p):\n    full = (ROOT / p).resolve()\n"
             "    if not full.is_relative_to(ROOT):\n        raise ValueError()\n    return full.read_text()\n")
        self.assertEqual(sevs(b, "MS02"), ["info"])

    def test_guard_helper_sanitizes(self):
        b = ("ROOT = Path('/srv')\ndef safe(p):\n    f = (ROOT / p).resolve()\n    assert f.is_relative_to(ROOT)\n"
             "    return f\n@mcp.tool()\ndef t(p):\n    return safe(p).read_text()\n")
        self.assertNotIn("MS02", rules(b))

    def test_basename_sanitizes_path(self):
        b = "@mcp.tool()\ndef t(n):\n    os.remove(os.path.join('/d', os.path.basename(n)))\n"
        self.assertNotIn("MS02", rules(b))

    def test_str_replace_not_a_path_sink(self):
        b = "@mcp.tool()\ndef t(s: str) -> str:\n    return s.replace('a', 'b')\n"
        self.assertEqual(rules(b), [])

    def test_ssrf_requests_and_client(self):
        self.assertIn("MS03", rules("@mcp.tool()\ndef t(url):\n    return requests.get(url).text\n"))
        b = "@mcp.tool()\nasync def t(u):\n    async with httpx.AsyncClient() as client:\n        return await client.get(u)\n"
        self.assertIn("MS03", rules(b))

    def test_ssrf_host_allowlist_info(self):
        b = ("from urllib.parse import urlparse\nOK = {'a.example'}\n@mcp.tool()\ndef t(url):\n"
             "    if urlparse(url).hostname != 'a.example':\n        raise ValueError()\n    return httpx.get(url)\n")
        self.assertEqual(sevs(b, "MS03"), ["info"])

    def test_dict_get_not_http(self):
        b = "@mcp.tool()\ndef t(k, data: dict):\n    return data.get(k)\n"
        self.assertEqual(rules(b), [])

    def test_sql_fstring_and_raw(self):
        b = "@mcp.tool()\ndef t(c):\n    db = sqlite3.connect('x')\n    db.execute(f\"select * from o where c='{c}'\")\n"
        f = [x for x in scan(b) if x.rule == "MS04"]
        self.assertTrue(f and "placeholders" in f[0].message)
        b2 = "@mcp.tool()\ndef t(sql):\n    sqlite3.connect('x').execute(sql)\n"
        self.assertIn("any query", [x for x in scan(b2) if x.rule == "MS04"][0].message)

    def test_sql_placeholders_clean(self):
        b = "@mcp.tool()\ndef t(c):\n    sqlite3.connect('x').execute('select * from o where c=?', (c,))\n"
        self.assertNotIn("MS04", rules(b))

    def test_eval_and_pickle(self):
        self.assertEqual(sevs("@mcp.tool()\ndef t(e):\n    return eval(e)\n", "MS05"), ["critical"])
        self.assertIn("MS05", rules("@mcp.tool()\ndef t(b):\n    return pickle.loads(b)\n"))

    def test_yaml_safe_loader_clean(self):
        self.assertIn("MS05", rules("@mcp.tool()\ndef t(s):\n    return yaml.load(s)\n"))
        self.assertNotIn("MS05", rules("@mcp.tool()\ndef t(s):\n    return yaml.load(s, Loader=yaml.SafeLoader)\n"))

    def test_env_by_name_and_whole_environ(self):
        self.assertIn("MS06", rules("@mcp.tool()\ndef t(k):\n    return os.getenv(k)\n"))
        self.assertIn("MS06", rules("@mcp.tool()\ndef t(k):\n    return os.environ[k]\n"))
        self.assertIn("MS06", rules("@mcp.tool()\ndef t():\n    return dict(os.environ)\n"))
        self.assertNotIn("MS06", rules("@mcp.tool()\ndef t():\n    return os.environ.get('HOME')\n"))

    def test_allowlist_membership_sanitizes(self):
        b = ("OK = {'A': 'X'}\n@mcp.tool()\ndef t(k):\n    if k not in OK:\n        raise ValueError()\n"
             "    return os.getenv(k)\n")
        self.assertNotIn("MS06", rules(b))

    def test_regex_validation_downgrades(self):
        b = "@mcp.tool()\ndef t(h):\n    if not re.fullmatch(r'[a-z]+', h):\n        return ''\n    os.system('ping ' + h)\n"
        self.assertEqual(sevs(b, "MS01"), ["low"])

    def test_int_cast_sanitizes(self):
        b = "@mcp.tool()\ndef t(n):\n    os.system('sleep %d' % int(n))\n"
        self.assertNotIn("MS01", rules(b))

    def test_context_param_not_tainted(self):
        b = "@mcp.tool()\ndef t(q: str, ctx: Context):\n    os.system(ctx.request_id)\n"
        self.assertNotIn("MS01", rules(b))

    def test_helper_function_followed(self):
        b = "def h(target):\n    os.system('tar czf x ' + target)\n@mcp.tool()\ndef t(d):\n    h(d)\n"
        f = [x for x in scan(b) if x.rule == "MS01"]
        self.assertEqual(f[0].handler, "t")
        self.assertIn("via h", f[0].via)

    def test_helper_with_clean_args_not_flagged(self):
        b = "def h(target):\n    os.system('tar czf x ' + target)\n@mcp.tool()\ndef t(d):\n    h('/srv')\n"
        self.assertNotIn("MS01", rules(b))

    def test_lowlevel_call_tool_arguments(self):
        b = ("from mcp.server import Server\nserver = Server('x')\n@server.call_tool()\n"
             "async def call(name, arguments):\n    return os.popen(arguments['cmd']).read()\n")
        self.assertIn("MS01", rules(b))

    def test_resource_template_param(self):
        b = "@mcp.resource('n://{nid}')\ndef r(nid):\n    return open('/n/' + nid).read()\n"
        self.assertIn("MS02", rules(b))

    def test_extra_decorator(self):
        b = "def register(f):\n    return f\n@register\ndef t(c):\n    os.system(c)\n"
        self.assertEqual(rules(b), [])
        self.assertIn("MS01", rules(b, extra_decorators=["register"]))

    def test_alias_import_resolution(self):
        b = "import subprocess as sp\nfrom os import system as run_it\n@mcp.tool()\ndef t(c):\n    sp.run(c, shell=True)\n    run_it(c)\n"
        self.assertEqual(len([x for x in scan(b) if x.rule == "MS01"]), 2)


class BindAndAnnotations(unittest.TestCase):
    def test_bind_all_interfaces(self):
        f, _ = ms.scan_source("s.py", "from mcp.server.fastmcp import FastMCP\nm = FastMCP('x', host='0.0.0.0')\n")
        self.assertEqual([x.rule for x in f], ["MS07"])
        f, _ = ms.scan_source("s.py", "from mcp.server.fastmcp import FastMCP\nm = FastMCP('x', host='127.0.0.1')\n")
        self.assertEqual(f, [])
        f, _ = ms.scan_source("s.py", "import mcp\nm = mcp.FastMCP('x')\nm.settings.host = '0.0.0.0'\n")
        self.assertEqual([x.rule for x in f], ["MS07"])

    def test_readonly_hint_lie(self):
        b = "@mcp.tool(annotations={'readOnlyHint': True})\ndef t():\n    os.remove('/tmp/x')\n"
        self.assertEqual(sevs(b, "MS08"), ["high"])
        b2 = "@mcp.tool(annotations={'readOnlyHint': True})\ndef t():\n    subprocess.run(['uptime'])\n"
        self.assertEqual(sevs(b2, "MS08"), ["medium"])

    def test_missing_destructive_hint_low_and_declared_ok(self):
        b = "@mcp.tool()\ndef t():\n    Path('/tmp/x').write_text('y')\n"
        self.assertEqual(sevs(b, "MS08"), ["low"])
        b2 = "@mcp.tool(annotations={'destructiveHint': True})\ndef t():\n    Path('/tmp/x').write_text('y')\n"
        self.assertNotIn("MS08", rules(b2))

    def test_tool_annotations_call_form(self):
        b = ("from mcp.types import ToolAnnotations\n@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))\n"
             "def t():\n    open('/tmp/x', 'w').write('y')\n")
        self.assertEqual(sevs(b, "MS08"), ["high"])


class Suppression(unittest.TestCase):
    def test_inline_ignore(self):
        b = "@mcp.tool()\ndef t(c):\n    os.system(c)  # mcpsink: ignore[MS01]\n"
        self.assertNotIn("MS01", rules(b))
        b2 = "@mcp.tool()\ndef t(c):\n    os.system(c)  # mcpsink: ignore[MS02]\n"
        self.assertIn("MS01", rules(b2))

    def test_disable(self):
        b = "@mcp.tool()\ndef t(c):\n    os.system(c)\n"
        self.assertNotIn("MS01", rules(b, disabled={"MS01"}))

    def test_inventory(self):
        _, inv = ms.scan_source("s.py", HDR + "@mcp.tool()\ndef t(a, b: int, ctx: Context):\n    pass\n")
        self.assertEqual(inv[0]["params"], ["a", "b"])


class CommandLine(unittest.TestCase):
    def test_risky_examples(self):
        code, out, _ = run("examples/risky")
        self.assertEqual(code, 1)
        for r in ["MS01", "MS02", "MS03", "MS04", "MS05", "MS06", "MS07", "MS08"]:
            self.assertIn(r, out)
        self.assertIn("13 MCP handler(s)", out)

    def test_clean_examples(self):
        code, out, _ = run("examples/clean", "--fail-on", "any")
        self.assertEqual(code, 0, out)
        self.assertIn("0 finding(s)", out)

    def test_json_and_sarif(self):
        code, out, _ = run("examples/risky", "--json")
        d = json.loads(out)
        self.assertEqual(len(d["files"]), 2)
        self.assertTrue(all("rule" in f for x in d["files"] for f in x["findings"]))
        code, out, _ = run("examples/risky", "--sarif")
        s = json.loads(out)
        self.assertEqual(s["version"], "2.1.0")
        self.assertGreater(len(s["runs"][0]["results"]), 10)

    def test_fail_on_none_and_min_severity(self):
        self.assertEqual(run("examples/risky", "--fail-on", "none")[0], 0)
        code, out, _ = run("examples/risky", "--min-severity", "critical")
        self.assertNotIn("HIGH", out)

    def test_missing_path_and_syntax_error(self):
        self.assertEqual(run("does/not/exist")[0], 2)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.py")
            with open(p, "w") as fh:
                fh.write("import mcp\ndef (:\n")
            code, _, err = run(p)
            self.assertEqual(code, 2)
            self.assertIn("syntax error", err)

    def test_dir_scan_skips_non_mcp_files(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "util.py"), "w") as fh:
                fh.write("import os\ndef tool(f):\n    return f\n@tool\ndef t(c):\n    os.system(c)\n")
            code, out, _ = run(d)
            self.assertEqual(code, 0)
            self.assertIn("0 file(s)", out)

    def test_list_rules(self):
        code, out, _ = run("--list-rules")
        self.assertEqual(code, 0)
        self.assertEqual(out.count("MS0"), 9)


if __name__ == "__main__":
    unittest.main()
