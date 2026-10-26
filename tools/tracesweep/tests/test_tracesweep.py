"""Unit tests for tracesweep. All secrets below are synthetic/fake."""
import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import tracesweep as ts  # noqa: E402

SCRIPT = os.path.join(ROOT, "tracesweep.py")
EXAMPLES = os.path.join(ROOT, "examples")


def setUpModule():
    """The example transcripts contain secret-shaped FAKE values, so they are not
    committed; regenerate them from examples/make_examples.py before testing."""
    sys.path.insert(0, EXAMPLES)
    import make_examples  # noqa: E402
    make_examples.main()


def b64u(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


FAKE = {
    "TS-AWS-AKID": "AKIA" + "IOSFODNN7EXAMPL3",
    "TS-GITHUB": "ghp" + "_FAKE0tracesweep0test0token0000000001",
    "TS-OPENAI": "sk" + "-proj-FAKEtracesweepTEST1234567890abcdEFGH",
    "TS-ANTHROPIC": "sk" + "-ant-api03-FAKEtracesweepTEST0987654321zyxw",
    "TS-SLACK": "xox" + "b-1234567890-FAKEtracesweep01",
    "TS-STRIPE": "sk" + "_live_FAKEtracesweep0123TEST",
    "TS-GOOGLE-API": "AI" + "zaFAKEtracesweep_TEST-0123456789abcde",
}
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYFAKEKEY123"
JWT = b64u({"alg": "HS256", "typ": "JWT"}) + "." + b64u({"sub": "x1"}) + ".FAKEsigTRACESWEEP0123456789"
PEM = ("-----BEGIN " + "OPENSSH PRIVATE KEY-----\n"
       + base64.b64encode(b"not a real key, tracesweep test material " * 2).decode()
       + "\n-----END " + "OPENSSH PRIVATE KEY-----")


def rules_in(text, **kw):
    return [h["rule"].id for h in ts.scan_text(text, **kw)]


def run_cli(args, stdin=None):
    p = subprocess.run([sys.executable, SCRIPT] + args, input=stdin,
                       capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


class TestDetectors(unittest.TestCase):
    def test_prefix_detectors(self):
        for rid, secret in FAKE.items():
            with self.subTest(rule=rid):
                self.assertIn(rid, rules_in("leaked: %s end" % secret))

    def test_github_pat_and_variants(self):
        for t in ("gho_", "ghs_", "ghu_"):
            self.assertIn("TS-GITHUB", rules_in(t + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"))
        self.assertIn("TS-GITHUB", rules_in("github" + "_pat_11FAKE0000_tracesweepFAKEtoken1234"))

    def test_asia_akid(self):
        self.assertIn("TS-AWS-AKID", rules_in("ASIAFAKE7TRACESWP01"[:4] + "FAKE7TRACESWEEP0"))

    def test_aws_secret_near_keyword(self):
        self.assertIn("TS-AWS-SECRET", rules_in("aws_secret_access_key = %s" % AWS_SECRET))
        self.assertIn("TS-AWS-SECRET", rules_in('"AWS_SECRET": "%s"' % AWS_SECRET))
        self.assertNotIn("TS-AWS-SECRET", rules_in("random %s" % AWS_SECRET))

    def test_anthropic_not_reported_as_openai(self):
        r = rules_in(FAKE["TS-ANTHROPIC"])
        self.assertEqual(r, ["TS-ANTHROPIC"])

    def test_private_key(self):
        self.assertEqual(rules_in("key:\n" + PEM + "\n"), ["TS-PRIVKEY"])
        # header only (truncated tool output) still flagged
        self.assertIn("TS-PRIVKEY", rules_in("-----BEGIN " + "RSA PRIVATE KEY-----\nMIIE"))

    def test_jwt_requires_alg_header(self):
        self.assertIn("TS-JWT", rules_in("Authorization: Bearer " + JWT))
        bogus = b64u({"foo": "bar"}) + "." + b64u({"sub": "x"}) + ".abcdefghijk123"
        self.assertNotIn("TS-JWT", rules_in(bogus))

    def test_url_credentials(self):
        hits = ts.scan_text("postgres://admin:S3cr3tFAKE!@db.test:5432/x")
        self.assertEqual(hits[0]["rule"].id, "TS-URL-CREDS")
        self.assertEqual(hits[0]["secret"], "S3cr3tFAKE!")
        self.assertEqual(rules_in("https://user:password@host.test/"), [])

    def test_generic_assignment(self):
        self.assertIn("TS-GENERIC", rules_in('password = "hunter2-FAKE-pass"'))
        self.assertIn("TS-GENERIC", rules_in("DB_PASSWORD=Tr4ceSweepFAKE"))
        self.assertIn("TS-GENERIC", rules_in("api_key: zq9FAKEvalue77"))
        # not secrets
        self.assertEqual(rules_in('"max_tokens": 100000000'), [])
        self.assertEqual(rules_in("token_count = 12345678"), [])
        self.assertEqual(rules_in("password = os.environ['DB_PASS']"), [])
        self.assertEqual(rules_in("api_key = ${API_KEY}"), [])

    def test_entropy_off_by_default(self):
        s = "q7Zp2Lx9Rk4Vb8Nw3Ty6Hm1Jc5Gd0Fs"
        self.assertEqual(rules_in("blob " + s), [])
        self.assertIn("TS-ENTROPY", rules_in("blob " + s, entropy=True))
        # hex hashes skipped even with entropy on
        self.assertEqual(rules_in("sha " + "a3f5" * 10, entropy=True), [])

    def test_entropy_cli_flag(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.log")
            with open(p, "w") as fh:
                fh.write("blob q7Zp2Lx9Rk4Vb8Nw3Ty6Hm1Jc5Gd0Fs\n")
            self.assertEqual(run_cli([p])[0], 0)
            self.assertEqual(run_cli(["--entropy", p])[0], 1)


class TestPlaceholders(unittest.TestCase):
    def test_placeholders_suppressed(self):
        for text in ("AKIAIOSFODNN7EXAMPLE",
                     "AKIA0000000000000000",
                     "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                     "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                     "api_key = <token>",
                     "api_key = your_api_key",
                     "OPENAI_API_KEY=your_api_key_here",
                     "password = changeme123",
                     "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                     "token = REDACTED_VALUE",
                     "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"):
            with self.subTest(text=text):
                self.assertEqual(rules_in(text), [])

    def test_is_placeholder(self):
        self.assertTrue(ts.is_placeholder("your-token-here"))
        self.assertFalse(ts.is_placeholder(FAKE["TS-OPENAI"]))


class TestAttribution(unittest.TestCase):
    def scan_file(self, name):
        p = os.path.join(EXAMPLES, name)
        with open(p) as fh:
            return ts.scan_source(p, fh.read())

    def find(self, fs, rule, **kw):
        out = [f for f in fs if f["rule"] == rule and all(f[k] == v for k, v in kw.items())]
        self.assertTrue(out, "no %s finding with %r in %r" % (rule, kw, fs))
        return out[0]

    def test_claude_jsonl_tool_output(self):
        fs = self.scan_file("claude_session.jsonl")
        f = self.find(fs, "TS-AWS-AKID")
        self.assertEqual((f["line"], f["record"], f["turn"], f["role"], f["tool"], f["location"]),
                         (3, 3, 3, "tool", "Bash", "tool_output"))

    def test_claude_jsonl_tool_args(self):
        fs = self.scan_file("claude_session.jsonl")
        f = self.find(fs, "TS-GITHUB")
        self.assertEqual((f["role"], f["tool"], f["location"], f["turn"]),
                         ("assistant", "WebFetch", "tool_args", 5))

    def test_claude_placeholders_ignored(self):
        fs = self.scan_file("claude_session.jsonl")
        self.assertFalse([f for f in fs if f["record"] == 6])

    def test_openai_chat_tool_calls(self):
        fs = self.scan_file("openai_chat.json")
        f = self.find(fs, "TS-SLACK")
        self.assertEqual((f["role"], f["tool"], f["location"], f["record"]),
                         ("assistant", "slack_post", "tool_args", 3))
        self.assertIsNotNone(f["line"])
        j = self.find(fs, "TS-JWT")
        self.assertEqual((j["role"], j["tool"], j["location"]), ("tool", "slack_post", "tool_output"))
        k = self.find(fs, "TS-PRIVKEY")
        self.assertEqual((k["role"], k["location"]), ("assistant", "message"))
        self.find(fs, "TS-STRIPE", role="user", location="message")
        self.find(fs, "TS-GOOGLE-API", role="user")
        self.find(fs, "TS-ANTHROPIC", role="assistant", turn=7)

    def test_text_log_roles(self):
        fs = self.scan_file("agent_run.log")
        f = self.find(fs, "TS-URL-CREDS")
        self.assertEqual((f["line"], f["role"], f["tool"], f["location"]), (4, "tool", "bash", "text"))

    def test_codex_style_function_call(self):
        recs = [
            {"type": "function_call", "name": "shell", "call_id": "c1",
             "arguments": json.dumps({"cmd": ["env"]})},
            {"type": "function_call_output", "call_id": "c1",
             "output": "STRIPE_KEY=" + FAKE["TS-STRIPE"]},
        ]
        raw = "\n".join(json.dumps(r) for r in recs)
        fs = ts.scan_source("codex.jsonl", raw)
        f = self.find(fs, "TS-STRIPE")
        self.assertEqual((f["role"], f["tool"], f["location"], f["line"]),
                         ("tool", "shell", "tool_output", 2))

    def test_dict_key_generic(self):
        raw = json.dumps([{"role": "tool", "name": "read_config",
                           "content": [{"api_key": "zq9FAKEvalue77"}]}])
        fs = ts.scan_source("x.json", raw)
        f = self.find(fs, "TS-GENERIC")
        self.assertEqual((f["tool"], f["location"]), ("read_config", "tool_output"))

    def test_explicit_turn_field(self):
        raw = json.dumps({"role": "assistant", "turn": 42, "content": FAKE["TS-SLACK"]})
        fs = ts.scan_source("t.jsonl", raw + "\n")
        self.assertEqual(fs[0]["turn"], 42)


class TestEcho(unittest.TestCase):
    def test_echo_tool_output_then_assistant(self):
        p = os.path.join(EXAMPLES, "claude_session.jsonl")
        with open(p) as fh:
            fs = ts.scan_source(p, fh.read())
        n = ts.mark_echoes(fs)
        self.assertEqual(n, 1)
        echoed = [f for f in fs if f["echoed"]]
        self.assertEqual(sorted(f["location"] for f in echoed), ["message", "tool_output"])
        self.assertTrue(all(f["first_seen"]["location"] == "tool_output" for f in echoed))
        self.assertIn("tool_output(turn 3) -> message(turn 4)", echoed[0]["propagation"])
        self.assertFalse([f for f in fs if f["rule"] == "TS-AWS-AKID" and f["echoed"]])

    def test_echo_without_pattern_context(self):
        # second mention has no 'password=' context; caught via verbatim re-match
        raw = "Tool(bash): DB_PASSWORD=Tr4ceSweepFAKE\nAssistant: I used Tr4ceSweepFAKE\n"
        fs = ts.scan_source("r.log", raw)
        ts.mark_echoes(fs)
        self.assertEqual(len(fs), 2)
        self.assertTrue(all(f["echoed"] for f in fs))
        self.assertEqual(fs[1]["match"], "echo")
        self.assertEqual(fs[1]["role"], "assistant")

    def test_same_turn_not_echo(self):
        raw = json.dumps({"role": "user", "content": FAKE["TS-SLACK"] + " " + FAKE["TS-SLACK"]})
        fs = ts.scan_source("s.jsonl", raw + "\n")
        ts.mark_echoes(fs)
        self.assertFalse(any(f["echoed"] for f in fs))


class TestMasking(unittest.TestCase):
    def test_mask_format(self):
        self.assertEqual(ts.mask("AKIA" + "IOSFODNN7EXAMPL3"), "AKIA...L3")
        self.assertEqual(ts.mask("short12"), "sh***")
        self.assertEqual(ts.mask(PEM, "TS-PRIVKEY"), "[PEM OPENSSH PRIVATE KEY]")

    def test_full_secret_never_in_any_output(self):
        secrets = list(FAKE.values()) + [AWS_SECRET, JWT, "hunter2-FAKE-pass", "Fak3Passw0rd!"]
        for fmt in ([], ["--json"], ["--sarif"]):
            code, out, err = run_cli(fmt + [EXAMPLES])
            with self.subTest(fmt=fmt):
                self.assertEqual(code, 1)
                for s in secrets:
                    self.assertNotIn(s, out + err)
                self.assertNotIn("MIIE", out)
                self.assertNotIn(PEM.splitlines()[1][:30], out)


class TestOutputAndExitCodes(unittest.TestCase):
    def test_json_output(self):
        code, out, _ = run_cli(["--json", os.path.join(EXAMPLES, "claude_session.jsonl")])
        self.assertEqual(code, 1)
        d = json.loads(out)
        self.assertEqual(d["files_scanned"], 1)
        self.assertEqual(d["echoed_secrets"], 1)
        f = d["findings"][0]
        for k in ("file", "line", "record", "turn", "role", "tool", "location",
                  "rule", "severity", "preview", "echoed", "fingerprint"):
            self.assertIn(k, f)
        self.assertFalse(any(k.startswith("_") for k in f))

    def test_sarif_output(self):
        code, out, _ = run_cli(["--sarif", os.path.join(EXAMPLES, "openai_chat.json")])
        self.assertEqual(code, 1)
        d = json.loads(out)
        self.assertEqual(d["version"], "2.1.0")
        self.assertTrue(d["runs"][0]["results"])

    def test_clean_exit_zero(self):
        code, out, _ = run_cli([os.path.join(EXAMPLES, "clean.json")])
        self.assertEqual(code, 0)
        self.assertIn("no findings", out)

    def test_min_severity_threshold(self):
        log = os.path.join(EXAMPLES, "agent_run.log")
        code, out, _ = run_cli(["--json", "--min-severity", "critical", log])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["findings"], [])
        code, out, _ = run_cli(["--json", "--min-severity", "high", log])
        self.assertEqual(code, 1)
        self.assertTrue(all(f["severity"] in ("high", "critical") for f in json.loads(out)["findings"]))

    def test_usage_errors_exit_two(self):
        self.assertEqual(run_cli([])[0], 2)
        self.assertEqual(run_cli(["/nonexistent/path.jsonl"])[0], 2)
        self.assertEqual(run_cli(["--min-severity", "bogus", EXAMPLES])[0], 2)
        self.assertEqual(run_cli(["--json", "--sarif", EXAMPLES])[0], 2)

    def test_stdin(self):
        code, out, _ = run_cli(["--json", "-"], stdin="token: " + FAKE["TS-GITHUB"] + "\n")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["findings"][0]["file"], "<stdin>")

    def test_directory_recursion(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "a", "b"))
            with open(os.path.join(d, "a", "b", "deep.txt"), "w") as fh:
                fh.write("key " + FAKE["TS-STRIPE"])
            with open(os.path.join(d, "ignored.bin"), "w") as fh:
                fh.write("key " + FAKE["TS-STRIPE"])
            code, out, _ = run_cli(["--json", d])
            d2 = json.loads(out)
            self.assertEqual(d2["files_scanned"], 1)
            self.assertEqual(code, 1)

    def test_main_in_process(self):
        buf = io.StringIO()
        rc = ts.main([os.path.join(EXAMPLES, "clean.json")], stdout=buf)
        self.assertEqual(rc, 0)


class TestRedact(unittest.TestCase):
    def test_redact_directory(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "red")
            run_cli(["--redact", out, EXAMPLES])
            with open(os.path.join(out, "openai_chat.json")) as fh:
                chat = fh.read()
            json.loads(chat)  # still valid JSON
            self.assertIn("[REDACTED:TS-PRIVKEY]", chat)
            self.assertNotIn(FAKE["TS-SLACK"], chat)
            code, _, _ = run_cli([out])
            self.assertEqual(code, 0)

    def test_redact_single_file(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "r.jsonl")
            run_cli(["--redact", out, os.path.join(EXAMPLES, "claude_session.jsonl")])
            with open(out) as fh:
                txt = fh.read()
            self.assertIn("[REDACTED:TS-OPENAI]", txt)
            self.assertNotIn(FAKE["TS-OPENAI"], txt)
            self.assertNotIn(AWS_SECRET.replace("/", "\\/"), txt)
            self.assertNotIn(AWS_SECRET, txt)


if __name__ == "__main__":
    unittest.main()
