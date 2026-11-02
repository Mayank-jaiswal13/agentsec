import json, os, subprocess, sys, tempfile, textwrap, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import agentci as ac
EX = os.path.join(ROOT, "examples")
CLI = [sys.executable, os.path.join(ROOT, "agentci.py")]


def scan(yml, extra=()):
    f, ai = ac.scan_workflow("wf.yml", textwrap.dedent(yml), extra)
    return f


def rules(yml, **kw):
    return sorted({f.rule for f in scan(yml, **kw)} - {"AC09"})


def sev(yml, rule):
    return sorted({f.severity for f in scan(yml) if f.rule == rule})


def run(*args):
    p = subprocess.run(CLI + list(args), capture_output=True, text=True, cwd=ROOT)
    return p.returncode, p.stdout, p.stderr


BASE = """
on:
  issue_comment:
    types: [created]
permissions:
  contents: read
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/ai-inference@0123456789abcdef0123456789abcdef01234567
        with:
          prompt: %s
"""


class TestYaml(unittest.TestCase):
    def test_nested_and_lists(self):
        d = ac.parse_yaml("a:\n  b: 1\n  c:\n    - x\n    - y: 2\n      z: 3\nd: [p, 'q, r']\n")
        self.assertEqual(d["a"]["b"], "1")
        self.assertEqual(d["a"]["c"][0], "x")
        self.assertEqual(d["a"]["c"][1], {"y": "2", "z": "3"})
        self.assertEqual(d["d"], ["p", "q, r"])

    def test_block_scalars_and_comments(self):
        d = ac.parse_yaml("k: |\n  line1\n  # not a comment\n\n  line3\nm: >-\n  a\n  b\nn: \"x # y\" # real\n")
        self.assertEqual(d["k"], "line1\n# not a comment\n\nline3")
        self.assertEqual(d["m"], "a b")
        self.assertEqual(d["n"], "x # y")

    def test_seq_same_indent_as_key(self):
        d = ac.parse_yaml("steps:\n- uses: a/b@v1\n- run: echo hi\n")
        self.assertEqual(d["steps"][1]["run"], "echo hi")

    def test_line_numbers(self):
        d = ac.parse_yaml("x: 1\njobs:\n  build:\n    steps:\n      - run: a\n")
        self.assertEqual(d.lines["jobs"], 2)
        self.assertEqual(d["jobs"]["build"]["steps"].lines, [5])

    def test_flow_map(self):
        self.assertEqual(ac.parse_yaml("p: {contents: read, issues: write}")["p"]["issues"], "write")

    def test_bad_indent_raises(self):
        with self.assertRaises(ac.YamlError):
            ac.parse_yaml("a: 1\n   b: 2\n")


class TestTriggers(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(ac.triggers_of({"on": "push"}), {"push"})
        self.assertEqual(ac.triggers_of({"on": ["push", "issues"]}), {"push", "issues"})
        self.assertEqual(ac.triggers_of({"on": {"issues": {}, "schedule": []}}), {"issues", "schedule"})


class TestDetection(unittest.TestCase):
    def test_known_action(self):
        self.assertTrue(ac.is_ai_action("anthropics/claude-code-action@v1"))
        self.assertTrue(ac.is_ai_action("openai/codex-action@abc"))
        self.assertFalse(ac.is_ai_action("actions/checkout@v4"))

    def test_run_commands(self):
        for cmd in ['claude -p "hi"', "npx @google/gemini-cli --yolo -p x", "codex exec 'fix'",
                    "curl https://api.anthropic.com/v1/messages"]:
            self.assertTrue(ac.AI_RUN_RE.search(cmd), cmd)
        self.assertFalse(ac.AI_RUN_RE.search("echo claude is a name"))

    def test_non_ai_workflow_has_no_findings(self):
        f, ai = ac.scan_workflow("x.yml", "on: issues\njobs:\n  a:\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n")
        self.assertFalse(ai)
        self.assertEqual(f, [])

    def test_extra_ai_action(self):
        yml = "on: push\npermissions: {contents: read}\njobs:\n  a:\n    steps:\n      - uses: acme/bot@0123456789abcdef0123456789abcdef01234567\n"
        self.assertEqual(scan(yml), [])
        self.assertIn("AC09", {f.rule for f in scan(yml, extra=["acme/*"])})

    def test_not_a_workflow(self):
        self.assertEqual(ac.scan_workflow("c.yml", "name: x\nversion: 2\n"), ([], False))


class TestAC01(unittest.TestCase):
    def test_issue_body_in_prompt(self):
        f = [x for x in scan(BASE % '"${{ github.event.comment.body }}"') if x.rule == "AC01"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "critical")

    def test_head_ref_and_tojson(self):
        self.assertIn("AC01", rules(BASE % '"${{ github.head_ref }}"'))
        self.assertIn("AC01", rules(BASE % '"${{ toJSON(github.event) }}"'))

    def test_trusted_expression_ok(self):
        self.assertNotIn("AC01", rules(BASE % '"Issue #${{ github.event.issue.number }} in ${{ github.repository }}"'))

    def test_env_indirection_ok(self):
        yml = BASE % '"read $TITLE"' + "        env:\n          TITLE: x\n"
        self.assertNotIn("AC01", rules(yml))

    def test_other_step_run_in_ai_job_high(self):
        yml = BASE % "hi" + "      - run: echo '${{ github.event.issue.title }}' > ctx.txt\n"
        self.assertEqual(sev(yml, "AC01"), ["high"])


class TestAC02(unittest.TestCase):
    def test_ungated(self):
        self.assertIn("AC02", rules(BASE % "hi"))

    def test_author_association_gate(self):
        yml = (BASE % "hi").replace("  j:\n", "  j:\n    if: github.event.comment.author_association == 'OWNER'\n")
        self.assertNotIn("AC02", rules(yml))

    def test_body_contains_is_not_gate(self):
        yml = (BASE % "hi").replace("  j:\n", "  j:\n    if: contains(github.event.comment.body, '/ai')\n")
        self.assertIn("AC02", rules(yml))

    def test_push_trigger_no_ac02(self):
        self.assertNotIn("AC02", rules((BASE % "hi").replace("issue_comment", "push")))

    def test_claude_default_write_check(self):
        yml = (BASE % "hi").replace("actions/ai-inference", "anthropics/claude-code-action")
        self.assertNotIn("AC02", rules(yml))
        self.assertEqual(sev(yml + "          allowed_non_write_users: '*'\n", "AC02"), ["high"])
        self.assertEqual(sev(yml + "          allowed_non_write_users: alice,bob\n", "AC02"), ["medium"])


PRT = """
on: pull_request_target
permissions: {contents: read}
jobs:
  r:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: %s
          persist-credentials: false
      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567
"""


class TestAC03(unittest.TestCase):
    def test_head_sha_checkout(self):
        self.assertEqual(sev(PRT % "${{ github.event.pull_request.head.sha }}", "AC03"), ["critical"])

    def test_base_checkout_ok(self):
        self.assertNotIn("AC03", rules(PRT % "${{ github.event.pull_request.base.sha }}"))

    def test_gh_pr_checkout(self):
        yml = (PRT % "main") + "      - run: gh pr checkout ${{ github.event.pull_request.number }}\n"
        self.assertIn("AC03", rules(yml))

    def test_pull_request_not_privileged(self):
        self.assertNotIn("AC03", rules((PRT % "${{ github.head_ref }}").replace("pull_request_target", "pull_request")))


class TestAC04(unittest.TestCase):
    def test_write_all(self):
        self.assertEqual(sev((BASE % "hi").replace("permissions:\n  contents: read", "permissions: write-all"), "AC04"),
                         ["high"])

    def test_missing_permissions_low(self):
        self.assertEqual(sev((BASE % "hi").replace("permissions:\n  contents: read\n", ""), "AC04"), ["low"])

    def test_contents_write_untrusted_high(self):
        self.assertEqual(sev((BASE % "hi").replace("contents: read", "contents: write"), "AC04"), ["high"])

    def test_id_token(self):
        self.assertIn("high", sev((BASE % "hi").replace("contents: read", "id-token: write"), "AC04"))

    def test_issues_write_ok(self):
        self.assertNotIn("AC04", rules((BASE % "hi").replace("contents: read", "issues: write")))


class TestAC05(unittest.TestCase):
    def test_flags(self):
        for flag in ["--dangerously-skip-permissions", '--allowedTools "Bash(*)"', "--yolo",
                     "--sandbox danger-full-access", "--dangerously-bypass-approvals-and-sandbox"]:
            yml = BASE % "hi" + "          claude_args: %s\n" % flag
            self.assertEqual(sev(yml, "AC05"), ["critical"], flag)

    def test_codex_keys(self):
        self.assertIn("AC05", rules(BASE % "hi" + "          safety-strategy: unsafe\n"))
        self.assertNotIn("AC05", rules(BASE % "hi" + "          safety-strategy: drop-sudo\n"))

    def test_scoped_bash_ok(self):
        self.assertNotIn("AC05", rules(BASE % "hi" + '          allowed_tools: "Read,Bash(git diff:*)"\n'))
        self.assertIn("AC05", rules(BASE % "hi" + '          allowed_tools: "Read,Bash"\n'))

    def test_trusted_trigger_high(self):
        yml = (BASE % "hi").replace("issue_comment", "push") + "          claude_args: --yolo\n"
        self.assertEqual(sev(yml, "AC05"), ["high"])


class TestAC06AC07AC08(unittest.TestCase):
    def test_model_key_ok_other_secret_flagged(self):
        yml = BASE % "hi" + "          api_key: ${{ secrets.OPENAI_API_KEY }}\n        env:\n          T: ${{ secrets.FAKE_EXAMPLE_PAT }}\n"
        f = [x for x in scan(yml) if x.rule == "AC06"]
        self.assertEqual(len(f), 1)
        self.assertIn("FAKE_EXAMPLE_PAT", f[0].message)

    def test_tojson_secrets(self):
        self.assertEqual(sev(BASE % "hi" + "          all: ${{ toJSON(secrets) }}\n", "AC06"), ["critical"])

    def test_pinning(self):
        self.assertNotIn("AC07", rules(BASE % "hi"))
        self.assertEqual(sev((BASE % "hi").replace("@0123456789abcdef0123456789abcdef01234567", "@main"), "AC07"),
                         ["medium"])
        self.assertEqual(sev((BASE % "hi").replace("@0123456789abcdef0123456789abcdef01234567", "@v1"), "AC07"), ["low"])

    def test_checkout_credentials(self):
        yml = (BASE % "hi").replace("    steps:\n", "    steps:\n      - uses: actions/checkout@v4\n")
        self.assertIn("AC08", rules(yml))
        yml2 = (BASE % "hi").replace("    steps:\n", "    steps:\n      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n")
        self.assertNotIn("AC08", rules(yml2))


class TestExamplesAndCLI(unittest.TestCase):
    def test_risky_examples(self):
        code, out, _ = run("examples/risky")
        self.assertEqual(code, 1)
        for r in ["AC01", "AC02", "AC03", "AC04", "AC05", "AC06", "AC07", "AC08"]:
            self.assertIn(r, out)

    def test_clean_examples(self):
        code, out, _ = run("examples/clean", "--fail-on", "any")
        self.assertEqual(code, 0, out)
        self.assertIn("2 with AI agents; 0 finding(s)", out)

    def test_json(self):
        code, out, _ = run("examples/risky", "--json")
        data = json.loads(out)
        self.assertEqual(len(data["files"]), 3)
        self.assertTrue(all(f["ai"] for f in data["files"]))

    def test_sarif(self):
        code, out, _ = run("examples/risky", "--sarif")
        s = json.loads(out)
        self.assertEqual(s["version"], "2.1.0")
        self.assertTrue(s["runs"][0]["results"])

    def test_fail_on_none_and_min_severity(self):
        self.assertEqual(run("examples/risky", "--fail-on", "none")[0], 0)
        code, out, _ = run("examples/risky", "--min-severity", "critical", "--json")
        self.assertTrue(all(f["severity"] == "critical" for x in json.loads(out)["files"] for f in x["findings"]))

    def test_disable(self):
        code, out, _ = run("examples/risky", "--disable", "AC07", "--json")
        self.assertNotIn('"AC07"', out)

    def test_missing_path_and_parse_error(self):
        self.assertEqual(run("does/not/exist")[0], 2)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.yml")
            with open(p, "w") as fh:
                fh.write("on: push\n   jobs: 1\n")
            self.assertEqual(run(p)[0], 2)

    def test_list_rules(self):
        code, out, _ = run("--list-rules")
        self.assertEqual(code, 0)
        self.assertEqual(out.count("\n"), 9)


if __name__ == "__main__":
    unittest.main()
