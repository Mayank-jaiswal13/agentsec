import io
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import slopcheck as sc  # noqa: E402

EX = os.path.join(ROOT, "examples")
KNOWN = sc.load_known()
NOALLOW = {"pypi": set(), "npm": set()}


def run(argv):
    buf = io.StringIO()
    err = io.StringIO()
    old = sys.stderr
    sys.stderr = err
    try:
        code = sc.main(argv, out=buf)
    finally:
        sys.stderr = old
    return code, buf.getvalue()


def rules_for(name, eco="pypi", kind="declared", spec="==1.0", allow=None):
    d = sc.Dep(name, eco, "f", 1, kind, spec=spec)
    return {f["rule"] for f in sc.name_checks(d, KNOWN, allow or NOALLOW)}


class TmpMixin(object):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        p = os.path.join(self.d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p


class TestHelpers(unittest.TestCase):
    def test_osa_basic(self):
        self.assertEqual(sc.osa_distance("kitten", "sitting"), 3)

    def test_osa_transposition_is_one(self):
        self.assertEqual(sc.osa_distance("reqeusts", "requests"), 1)

    def test_osa_identical(self):
        self.assertEqual(sc.osa_distance("abc", "abc"), 0)

    def test_osa_cap(self):
        self.assertGreater(sc.osa_distance("a", "abcdef", cap=2), 2)

    def test_norm_pypi(self):
        self.assertEqual(sc.norm_pypi("Ruamel_Yaml"), "ruamel-yaml")
        self.assertEqual(sc.norm_pypi("a.b__c"), "a-b-c")

    def test_strip_affixes(self):
        self.assertEqual(sc.strip_affixes("python-openai-helper"), ("openai", ["helper", "python"]))
        self.assertEqual(sc.strip_affixes("requests")[1], [])

    def test_snapshot_size_and_label(self):
        with open(sc.DEFAULT_KNOWN) as f:
            data = json.load(f)
        self.assertIn("NOT the PyPI or npm registry", data["_comment"])
        self.assertGreater(len(data["pypi"]) + len(data["npm"]), 300)

    def test_load_known_bad(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{}")
        try:
            with self.assertRaises(sc.SlopError):
                sc.load_known(f.name)
        finally:
            os.unlink(f.name)


class TestNameChecks(unittest.TestCase):
    def test_known_clean(self):
        self.assertEqual(rules_for("requests"), set())
        self.assertEqual(rules_for("PyYAML"), set())

    def test_typo_swap_high(self):
        self.assertIn("SC02", rules_for("reqeusts"))

    def test_typo_npm(self):
        self.assertIn("SC02", rules_for("expresss", "npm"))

    def test_separator_confusion(self):
        self.assertIn("SC02", rules_for("pythondateutil"))

    def test_npm_case_confusion(self):
        self.assertIn("SC02", rules_for("React", "npm"))

    def test_hallucination_suffix(self):
        self.assertIn("SC03", rules_for("langchain-utils-pro"))

    def test_hallucination_prefix(self):
        self.assertIn("SC03", rules_for("python-openai-helper"))

    def test_hallucination_npm(self):
        self.assertIn("SC03", rules_for("lodash-utils-helper", "npm"))

    def test_ecosystem_confusion_py(self):
        self.assertIn("SC04", rules_for("axios"))

    def test_ecosystem_confusion_npm(self):
        self.assertIn("SC04", rules_for("scikit-learn", "npm"))

    def test_unknown_info(self):
        self.assertEqual(rules_for("zzqxv-totally-unknown"), {"SC01"})

    def test_allowlist_suppresses(self):
        allow = {"pypi": {"reqeusts"}, "npm": set()}
        self.assertEqual(rules_for("reqeusts", allow=allow), set())

    def test_short_names_not_typo_matched(self):
        # 'six' is too short to be a typo target; 'sax' should just be unverified
        self.assertNotIn("SC02", rules_for("sax"))


class TestVersionChecks(unittest.TestCase):
    def v(self, spec, eco="pypi"):
        return {f["rule"] for f in sc.version_checks(sc.Dep("x", eco, "f", 1, "declared", spec=spec))}

    def test_pinned_ok(self):
        self.assertEqual(self.v("==1.2.3"), set())
        self.assertEqual(self.v(">=1,<2"), set())

    def test_unpinned(self):
        self.assertEqual(self.v(""), {"SC05"})

    def test_loose(self):
        self.assertEqual(self.v(">=1.0"), {"SC05"})

    def test_url_dep(self):
        self.assertEqual(self.v("git+https://example.invalid/x.git"), {"SC06"})

    def test_npm_star_latest(self):
        self.assertEqual(self.v("*", "npm"), {"SC05"})
        self.assertEqual(self.v("latest", "npm"), {"SC05"})

    def test_npm_caret_ok(self):
        self.assertEqual(self.v("^1.2.3", "npm"), set())

    def test_npm_git(self):
        self.assertEqual(self.v("github:user/repo", "npm"), {"SC06"})
        self.assertEqual(self.v("user/repo#main", "npm"), {"SC06"})

    def test_imports_skip_version(self):
        self.assertEqual(sc.version_checks(sc.Dep("x", "pypi", "f", 1, "import")), [])


class TestParsers(TmpMixin, unittest.TestCase):
    def test_requirements(self):
        p = self.write("requirements.txt", "# c\n-r other.txt\nFoo[bar]>=1 ; python_version>'3'\n"
                       "-e git+https://e.invalid/r.git#egg=baz\nqux==1  # slopcheck: ignore\n--index-url x\n")
        deps = sc.parse_requirements(p)
        self.assertEqual([d.name for d in deps], ["Foo", "baz", "qux"])
        self.assertEqual(deps[0].spec, ">=1")
        self.assertEqual(deps[0].line, 3)
        self.assertTrue(deps[2].ignored)

    def test_pyproject_pep621_and_poetry(self):
        p = self.write("pyproject.toml", '[project]\nname="x"\ndependencies = ["requests==2.0", "reqeusts"]\n'
                       '[project.optional-dependencies]\ndev = ["pytest"]\n'
                       '[tool.poetry.dependencies]\npython = "^3.10"\nnumpyy = "*"\n'
                       'mylib = { git = "https://e.invalid/m.git" }\n')
        deps = {d.name: d for d in sc.parse_pyproject(p)}
        self.assertIn("reqeusts", deps)
        self.assertTrue(deps["pytest"].dev)
        self.assertNotIn("python", deps)
        self.assertEqual(deps["numpyy"].spec, "*")
        self.assertTrue(deps["mylib"].spec.startswith("git+"))
        self.assertEqual(deps["reqeusts"].line, 3)

    def test_package_json(self):
        p = self.write("package.json", json.dumps({"dependencies": {"a": "1"}, "devDependencies": {"b": "*"}}))
        deps = sc.parse_package_json(p)
        self.assertEqual([(d.name, d.dev) for d in deps], [("a", False), ("b", True)])

    def test_package_json_invalid(self):
        p = self.write("package.json", "{nope")
        with self.assertRaises(sc.SlopError):
            sc.parse_package_json(p)

    def test_python_imports_mapping_and_stdlib(self):
        p = self.write("a.py", "import os, yaml\nfrom sklearn.model_selection import x\nimport cv2\n"
                       "from PIL import Image\nfrom bs4 import BeautifulSoup\nfrom . import y\n"
                       "import fakepkg  # slopcheck: ignore\n")
        deps = sc.parse_python_imports(p)
        names = [d.name for d in deps]
        self.assertEqual(names[:5], ["pyyaml", "scikit-learn", "opencv-python", "pillow", "beautifulsoup4"])
        self.assertNotIn("os", names)
        self.assertTrue(deps[-1].ignored)

    def test_python_syntax_error(self):
        p = self.write("bad.py", "def (:\n")
        with self.assertRaises(sc.SlopError):
            sc.parse_python_imports(p)

    def test_js_imports(self):
        p = self.write("a.ts", 'import x from "lodash/fp";\nimport "./local";\nconst f = require("node:fs");\n'
                       'const p = require("path");\nimport {a} from "@scope/pkg/sub";\nconst m = await import("zod");\n'
                       'export * from "rxjs";\n')
        names = [d.name for d in sc.parse_js_imports(p)]
        self.assertEqual(names, ["lodash", "@scope/pkg", "zod", "rxjs"])

    def test_collect_skips_node_modules(self):
        self.write("node_modules/x/index.js", "require('evil')")
        self.write("src/app.js", "require('lodash')")
        files = sc.collect_files([self.d])
        self.assertEqual([os.path.basename(f) for f in files], ["app.js"])

    def test_local_modules_not_flagged(self):
        self.write("helpers.py", "X = 1\n")
        self.write("main.py", "import helpers\n")
        res = sc.analyze(sc.collect_files([self.d]), KNOWN, NOALLOW)
        self.assertEqual(res["findings"], [])


class TestUsage(TmpMixin, unittest.TestCase):
    def test_undeclared_and_unused(self):
        self.write("requirements.txt", "requests==2.0\nflask==3.0\npytest==8\n")
        self.write("app.py", "import requests\nimport yaml\n")
        res = sc.analyze(sc.collect_files([self.d]), KNOWN, NOALLOW)
        got = {(f["rule"], f["name"]) for f in res["findings"]}
        self.assertIn(("SC07", "pyyaml"), got)
        self.assertIn(("SC08", "flask"), got)
        self.assertNotIn(("SC08", "pytest"), got)
        self.assertNotIn(("SC08", "requests"), got)

    def test_no_usage_without_both(self):
        self.write("app.py", "import requests\n")
        res = sc.analyze(sc.collect_files([self.d]), KNOWN, NOALLOW)
        self.assertEqual(res["findings"], [])

    def test_mapped_dist_counts_as_used(self):
        self.write("requirements.txt", "PyYAML==6.0\nbeautifulsoup4==4\n")
        self.write("app.py", "import yaml\nfrom bs4 import X\n")
        res = sc.analyze(sc.collect_files([self.d]), KNOWN, NOALLOW)
        self.assertEqual(res["findings"], [])


class TestCLI(TmpMixin, unittest.TestCase):
    def test_risky_exit_1(self):
        code, out = run([os.path.join(EX, "risky")])
        self.assertEqual(code, 1)
        self.assertIn("reqeusts", out)
        self.assertIn("SC02", out)

    def test_clean_exit_0(self):
        code, out = run([os.path.join(EX, "clean")])
        self.assertEqual(code, 0)
        self.assertIn("no findings", out)

    def test_inline_ignore_in_example(self):
        code, out = run([os.path.join(EX, "risky"), "--json"])
        names = {f["name"] for f in json.loads(out)["findings"]}
        self.assertNotIn("some-internal-lib", names)

    def test_fail_on_none(self):
        code, _ = run([os.path.join(EX, "risky"), "--fail-on", "none"])
        self.assertEqual(code, 0)

    def test_fail_on_medium_and_any(self):
        p = self.write("requirements.txt", "langchain-utils-pro==1\n")
        self.assertEqual(run([p, "--no-usage"])[0], 0)        # default high
        self.assertEqual(run([p, "--fail-on", "medium"])[0], 1)
        q = self.write("r2/requirements.txt", "zzqxv-unknown==1\n")
        self.assertEqual(run([q, "--fail-on", "medium"])[0], 0)
        self.assertEqual(run([q, "--fail-on", "any"])[0], 1)

    def test_min_severity_filters(self):
        code, out = run([os.path.join(EX, "risky"), "--json", "--min-severity", "high", "--fail-on", "none"])
        sevs = {f["severity"] for f in json.loads(out)["findings"]}
        self.assertEqual(sevs, {"high"})

    def test_allow_file(self):
        p = self.write("requirements.txt", "reqeusts==1\n")
        a = self.write("allow.txt", "# mine\nreqeusts\n")
        code, out = run([p, "--allow", a, "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["findings"], [])

    def test_json_shape(self):
        code, out = run([os.path.join(EX, "risky"), "--json"])
        data = json.loads(out)
        self.assertEqual(data["tool"], "slopcheck")
        self.assertIn("disclaimer", data)
        f = data["findings"][0]
        for k in ("rule", "severity", "name", "ecosystem", "file", "line", "message"):
            self.assertIn(k, f)

    def test_sarif(self):
        code, out = run([os.path.join(EX, "risky"), "--sarif"])
        data = json.loads(out)
        self.assertEqual(data["version"], "2.1.0")
        run0 = data["runs"][0]
        self.assertEqual(run0["tool"]["driver"]["name"], "slopcheck")
        ids = {r["id"] for r in run0["tool"]["driver"]["rules"]}
        self.assertEqual(ids, set(sc.RULES))
        levels = {r["level"] for r in run0["results"]}
        self.assertTrue(levels <= {"error", "warning", "note"})
        self.assertIn("error", levels)

    def test_missing_path_exit_2(self):
        self.assertEqual(run([os.path.join(self.d, "nope.txt")])[0], 2)

    def test_parse_error_exit_2(self):
        p = self.write("package.json", "{bad")
        self.assertEqual(run([p])[0], 2)

    def test_bad_allow_exit_2(self):
        p = self.write("requirements.txt", "requests==1\n")
        self.assertEqual(run([p, "--allow", os.path.join(self.d, "missing")])[0], 2)

    def test_list_rules(self):
        code, out = run(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertIn("SC08", out)

    def test_no_network_imports(self):
        with open(os.path.join(ROOT, "slopcheck.py")) as f:
            src = f.read()
        for mod in ("urllib.request", "http.client", "socket", "requests"):
            self.assertNotIn("import %s" % mod, src)


if __name__ == "__main__":
    unittest.main()
