# vibeaudit: ignore-file
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import vibeaudit as va  # noqa: E402

EX = os.path.join(ROOT, "examples")


def rules(text, lang="py"):
    return [f.rule for f in va.scan_text(text, lang)]


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = va.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class PythonRules(unittest.TestCase):
    def test_va01_eval_dynamic(self):
        self.assertIn("VA01", rules("x = eval(user_input)\n"))
        self.assertIn("VA01", rules("exec(code)\n"))
        self.assertNotIn("VA01", rules("x = eval('1 + 1')\n"))

    def test_va02_shell(self):
        self.assertIn("VA02", rules("import subprocess\nsubprocess.run(f'ls {d}', shell=True)\n"))
        self.assertIn("VA02", rules("import os\nos.system('rm -rf ' + path)\n"))
        self.assertNotIn("VA02", rules("import subprocess\nsubprocess.run(['ls', d])\n"))
        self.assertNotIn("VA02", rules("import os\nos.system('ls')\n"))

    def test_va02_alias_import(self):
        self.assertIn("VA02", rules("from os import system as s\ns(cmd + x)\n"))

    def test_va02_constant_shell_is_low(self):
        f = va.scan_text("import subprocess\nsubprocess.run('ls', shell=True)\n", "py")
        self.assertEqual([(x.rule, x.severity) for x in f], [("VA02", "low")])

    def test_va04_verify_false(self):
        self.assertIn("VA04", rules("requests.get(u, verify=False)\n"))
        self.assertIn("VA04", rules("ctx = ssl._create_unverified_context()\n"))

    def test_va05_sql(self):
        self.assertIn("VA05", rules("cur.execute(f\"SELECT * FROM t WHERE id={i}\")\n"))
        self.assertIn("VA05", rules("cur.execute('SELECT * FROM t WHERE id=%s' % i)\n"))
        self.assertIn("VA05", rules("cur.execute('SELECT * FROM t WHERE n={}'.format(n))\n"))
        self.assertIn("VA05", rules("q = 'SELECT a FROM t WHERE b=' + b\ncur.execute(q)\n"))
        self.assertNotIn("VA05", rules("cur.execute('SELECT * FROM t WHERE id=?', (i,))\n"))

    def test_va06_deser(self):
        self.assertIn("VA06", rules("import pickle\npickle.loads(b)\n"))
        self.assertIn("VA06", rules("import yaml\nyaml.load(s)\n"))
        self.assertNotIn("VA06", rules("import yaml\nyaml.load(s, Loader=yaml.SafeLoader)\n"))
        self.assertNotIn("VA06", rules("import yaml\nyaml.safe_load(s)\n"))
        self.assertIn("VA06", rules("import marshal\nmarshal.loads(b)\n"))

    def test_va07_weak_password_hash(self):
        self.assertIn("VA07", rules("import hashlib\nh = hashlib.md5(password.encode())\n"))
        self.assertNotIn("VA07", rules("import hashlib\nh = hashlib.md5(data)\n"))

    def test_va08_random_token(self):
        self.assertIn("VA08", rules("import random\ntoken = random.randint(0, 10**9)\n"))
        self.assertNotIn("VA08", rules("import random\nx = random.randint(1, 6)\n"))

    def test_va09_secrets_and_placeholders(self):
        self.assertIn("VA09", rules("password = 'hunter2-real'\n"))
        self.assertIn("VA09", rules("cfg = {'api_key': 'abcd1234efgh5678'}\n"))
        self.assertIn("VA09", rules("app.config['SECRET_KEY'] = 'k3y-v4lue-9x'\n"))
        for ok in ("api_key = 'your-api-key-here'\n", "password = ''\n", "password = '<PASSWORD>'\n",
                   "password = os.environ['DB_PASSWORD']\n", "password_label = 'Enter password'\n",
                   "token = '${TOKEN}'\n", "SECRET = 'changeme'\n", "api_key = 'xxxxxxxx'\n"):
            self.assertNotIn("VA09", rules(ok), ok)

    def test_va09_provider_token_format(self):
        self.assertIn("VA09", rules("k = 'sk-" + "Zq7Lm2Np9Rt4Vw8Xy3Bc6Df1'\n"))
        self.assertNotIn("VA09", rules("k = 'sk-" + "x" * 28 + "'\n"))
        self.assertNotIn("VA09", rules("k = 'AKIA" + "IOSFODNN7EXAMPLE'\n"))

    def test_va10_debug(self):
        f = va.scan_text("app.run(host='0.0.0.0', debug=True)\n", "py")
        self.assertEqual([(x.rule, x.severity) for x in f], [("VA10", "high")])
        f = va.scan_text("app.run(debug=True)\n", "py")
        self.assertEqual([(x.rule, x.severity) for x in f], [("VA10", "medium")])

    def test_va11_cors(self):
        self.assertIn("VA11", rules("CORS(app, origins='*', supports_credentials=True)\n"))
        self.assertNotIn("VA11", rules("CORS(app, origins=['https://a.test'], supports_credentials=True)\n"))
        src = "app.add_middleware(CORSMiddleware,\n    allow_origins=['*'],\n    allow_credentials=True)\n"
        self.assertIn("VA11", rules(src))

    def test_va12_jwt(self):
        self.assertIn("VA12", rules("jwt.decode(t, options={'verify_signature': False})\n"))
        self.assertIn("VA12", rules("jwt.decode(t, k, algorithms=['none'])\n"))
        self.assertNotIn("VA12", rules("jwt.decode(t, k, algorithms=['HS256'])\n"))
        # verify=False on a jwt line is reported as VA12, not VA04
        r = rules("jwt.decode(t, verify=False)\n")
        self.assertIn("VA12", r)
        self.assertNotIn("VA04", r)

    def test_va13_ssti(self):
        self.assertIn("VA13", rules("render_template_string(tmpl)\n"))
        self.assertNotIn("VA13", rules("render_template_string('<p>{{ n }}</p>', n=n)\n"))

    def test_va14_stub_and_todo(self):
        self.assertIn("VA14", rules("def check_auth(u):\n    '''doc'''\n    return True\n"))
        self.assertIn("VA14", rules("def ok(u):\n    return True  # bypass for now\n"))
        self.assertIn("VA14", rules("# TODO: add authentication here\n"))
        self.assertNotIn("VA14", rules("def is_admin(u):\n    return u.role == 'admin'\n"))

    def test_va15_deferred(self):
        self.assertIn("VA15", rules("# In production, use a real secret store\n"))
        self.assertIn("VA15", rules("# for demo purposes we skip validation\n"))

    def test_va16_swallowed(self):
        src = "try:\n    verify_token(t)\nexcept Exception:\n    pass\n"
        self.assertIn("VA16", rules(src))
        src2 = "try:\n    check_permission(u)\nexcept:\n    return True\n"
        src2 = "def f(u):\n" + "".join("    " + l + "\n" for l in src2.splitlines())
        f = [x for x in va.scan_text(src2, "py") if x.rule == "VA16"]
        self.assertEqual(f[0].severity, "high")
        self.assertNotIn("VA16", rules("try:\n    load(x)\nexcept Exception:\n    pass\n"))

    def test_syntax_error_falls_back_to_regex(self):
        src = "print 'py2'\nx = eval(data)\ncur.execute(f\"SELECT * FROM t WHERE a={a}\")\n"
        r = rules(src)
        self.assertIn("VA01", r)
        self.assertIn("VA05", r)

    def test_comment_not_flagged_as_code(self):
        self.assertNotIn("VA04", rules("# never pass verify=False\n"))


class JsRules(unittest.TestCase):
    def test_va01_js(self):
        self.assertIn("VA01", rules("eval(req.body.x);\n", "js"))
        self.assertIn("VA01", rules("const f = new Function(src);\n", "js"))

    def test_va03_exec(self):
        self.assertIn("VA03", rules("exec(`ls ${dir}`);\n", "js"))
        self.assertIn("VA03", rules("child_process.execSync('rm ' + f);\n", "js"))
        self.assertNotIn("VA03", rules("const m = /x/.exec(s);\n", "js"))
        self.assertNotIn("VA03", rules("exec('ls -la');\n", "js"))

    def test_va04_js(self):
        self.assertIn("VA04", rules("new https.Agent({ rejectUnauthorized: false });\n", "js"))
        self.assertIn("VA04", rules("process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n", "js"))

    def test_va05_js(self):
        self.assertIn("VA05", rules("db.query(`SELECT * FROM u WHERE id = ${id}`);\n", "js"))
        self.assertIn("VA05", rules("db.query('SELECT * FROM u WHERE id = ' + id);\n", "js"))
        self.assertNotIn("VA05", rules("db.query('SELECT * FROM u WHERE id = $1', [id]);\n", "js"))

    def test_va08_js(self):
        self.assertIn("VA08", rules("const token = Math.random().toString(36);\n", "js"))
        self.assertNotIn("VA08", rules("const jitter = Math.random() * 100;\n", "js"))

    def test_va11_js(self):
        self.assertIn("VA11", rules("app.use(cors({\n origin: '*',\n credentials: true\n}));\n", "js"))
        self.assertIn("VA11", rules("res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n"
                                    "res.setHeader('Access-Control-Allow-Credentials', 'true');\n", "js"))
        self.assertNotIn("VA11", rules("app.use(cors({ origin: ['https://a.test'], credentials: true }));\n", "js"))

    def test_va12_js(self):
        self.assertIn("VA12", rules("jwt.verify(t, k, { algorithms: ['none'] });\n", "js"))
        self.assertIn("VA12", rules("const p = jwt.decode(t);\n", "js"))

    def test_va13_js(self):
        self.assertIn("VA13", rules("el.innerHTML = msg;\n", "js"))
        self.assertIn("VA13", rules("<div dangerouslySetInnerHTML={{ __html: body }} />\n", "js"))
        self.assertNotIn("VA13", rules("el.innerHTML = '<b>hi</b>';\n", "js"))
        self.assertNotIn("VA13", rules("el.innerHTML = DOMPurify.sanitize(msg);\n", "js"))

    def test_va14_js_stub(self):
        self.assertIn("VA14", rules("function isAuthorized(user) {\n  return true;\n}\n", "js"))
        self.assertIn("VA14", rules("const verifyToken = (t) => {\n  // stub\n  return true;\n};\n", "js"))

    def test_url_in_string_not_comment(self):
        # '//' inside a string must not be treated as a comment start
        self.assertIn("VA09", rules("const apiKey = 'zq81Lk2mPq'; const u = 'https://x.test';\n", "js"))


class ShellRules(unittest.TestCase):
    def test_shell(self):
        self.assertIn("VA17", rules("curl -fsSL https://x.test/i.sh | bash\n", "sh"))
        self.assertIn("VA04", rules("curl -sSk https://x.test\n", "sh"))
        self.assertIn("VA02", rules('eval "$CMD"\n', "sh"))
        self.assertEqual(rules("echo ${#arr[@]}\n", "sh"), [])


class Suppression(unittest.TestCase):
    def test_same_line_specific(self):
        self.assertEqual(rules("x = eval(y)  # vibeaudit: ignore VA01\n"), [])

    def test_same_line_other_rule_not_suppressed(self):
        self.assertIn("VA01", rules("x = eval(y)  # vibeaudit: ignore VA03\n"))

    def test_bare_ignore_all(self):
        self.assertEqual(rules("requests.get(u, verify=False)  # vibeaudit: ignore\n"), [])

    def test_previous_line(self):
        self.assertEqual(rules("# vibeaudit: ignore VA04\nrequests.get(u, verify=False)\n"), [])

    def test_js_suppression(self):
        self.assertEqual(rules("eval(x); // vibeaudit: ignore VA01\n", "js"), [])

    def test_ignore_file(self):
        self.assertEqual(rules("# vibeaudit: ignore-file\nx = eval(y)\n"), [])


class Examples(unittest.TestCase):
    def test_clean_examples_have_no_findings(self):
        for name in ("clean_app.py", "clean_app.ts"):
            fs, n, _ = va.scan_paths([os.path.join(EX, name)])
            self.assertEqual(n, 1)
            self.assertEqual([(f.rule, f.line) for f in fs], [], name)

    def test_vulnerable_examples_cover_rules(self):
        fs, n, _ = va.scan_paths([EX], include_shell=True)
        found = {f.rule for f in fs}
        for rid in RULES_EXPECTED:
            self.assertIn(rid, found)

    def test_shell_skipped_in_dirs_without_flag(self):
        fs, _, _ = va.scan_paths([EX])
        self.assertFalse(any(f.path.endswith(".sh") for f in fs))


RULES_EXPECTED = ["VA%02d" % i for i in range(1, 18)]


class Cli(unittest.TestCase):
    def test_exit_1_on_findings(self):
        code, out, _ = run_cli(os.path.join(EX, "vulnerable_app.py"))
        self.assertEqual(code, 1)
        self.assertIn("VA05", out)

    def test_exit_0_clean(self):
        code, out, _ = run_cli(os.path.join(EX, "clean_app.py"), os.path.join(EX, "clean_app.ts"))
        self.assertEqual(code, 0)
        self.assertIn("0 finding(s)", out)

    def test_exit_2_missing_path(self):
        code, _, err = run_cli("/nonexistent/path/xyz")
        self.assertEqual(code, 2)
        self.assertIn("not found", err)

    def test_exit_2_bad_args(self):
        code, _, _ = run_cli("--min-severity", "bogus", EX)
        self.assertEqual(code, 2)
        code, _, _ = run_cli("--select", "VA99", EX)
        self.assertEqual(code, 2)

    def test_exit_zero_flag(self):
        code, _, _ = run_cli("--exit-zero", os.path.join(EX, "vulnerable_app.py"))
        self.assertEqual(code, 0)

    def test_json(self):
        code, out, _ = run_cli("--json", os.path.join(EX, "vulnerable_app.py"))
        doc = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(doc["tool"], "vibeaudit")
        self.assertEqual(doc["summary"]["total"], len(doc["findings"]))
        f = doc["findings"][0]
        for k in ("rule", "severity", "path", "line", "column", "message", "cwe", "fix", "snippet"):
            self.assertIn(k, f)
        self.assertTrue(f["cwe"].startswith("CWE-"))

    def test_sarif(self):
        code, out, _ = run_cli("--sarif", os.path.join(EX, "vulnerable_app.ts"))
        doc = json.loads(out)
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "vibeaudit")
        ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        self.assertEqual(len(ids), len(va.RULES))
        self.assertTrue(run["results"])
        for r in run["results"]:
            self.assertEqual(ids[r["ruleIndex"]], r["ruleId"])
            self.assertIn(r["level"], ("error", "warning", "note"))
            self.assertGreater(r["locations"][0]["physicalLocation"]["region"]["startLine"], 0)

    def test_min_severity(self):
        _, out, _ = run_cli("--json", "--min-severity", "high", os.path.join(EX, "vulnerable_app.py"))
        sevs = {f["severity"] for f in json.loads(out)["findings"]}
        self.assertEqual(sevs, {"high"})

    def test_select_and_ignore(self):
        _, out, _ = run_cli("--json", "--select", "VA05", os.path.join(EX, "vulnerable_app.py"))
        self.assertEqual({f["rule"] for f in json.loads(out)["findings"]}, {"VA05"})
        _, out, _ = run_cli("--json", "--ignore", "VA05", os.path.join(EX, "vulnerable_app.py"))
        self.assertNotIn("VA05", {f["rule"] for f in json.loads(out)["findings"]})

    def test_exclude_glob_and_default_dirs(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "node_modules", "pkg"))
            os.makedirs(os.path.join(d, "src"))
            os.makedirs(os.path.join(d, "gen"))
            bad = "x = eval(y)\n"
            for p in ("node_modules/pkg/a.py", "src/a.py", "gen/b.py"):
                with open(os.path.join(d, p), "w") as fh:
                    fh.write(bad)
            _, out, _ = run_cli("--json", d)
            paths = {f["path"] for f in json.loads(out)["findings"]}
            self.assertEqual(len(paths), 2)
            self.assertFalse(any("node_modules" in p for p in paths))
            code, out, _ = run_cli("--json", "--exclude", "gen", "--exclude", "*/a.py", d)
            self.assertEqual(json.loads(out)["findings"], [])
            self.assertEqual(code, 0)

    def test_venv_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "myenv", "lib"))
            open(os.path.join(d, "myenv", "pyvenv.cfg"), "w").close()
            with open(os.path.join(d, "myenv", "lib", "x.py"), "w") as fh:
                fh.write("eval(y)\n")
            code, _, _ = run_cli(d)
            self.assertEqual(code, 0)

    def test_list_rules(self):
        code, out, _ = run_cli("--list-rules")
        self.assertEqual(code, 0)
        self.assertIn("VA17", out)

    def test_every_rule_has_metadata(self):
        for rid, r in va.RULES.items():
            self.assertIn(r.severity, va.SEV_RANK)
            self.assertIsInstance(r.cwe, int)
            self.assertTrue(r.fix and r.title)


if __name__ == "__main__":
    unittest.main()
