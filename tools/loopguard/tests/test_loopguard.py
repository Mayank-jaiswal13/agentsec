import json, os, subprocess, sys, tempfile, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import loopguard as lg
EX = os.path.join(ROOT, "examples")
CLI = [sys.executable, os.path.join(ROOT, "loopguard.py")]


def gen(*calls, answer=True):
    """calls: (tool, args, result[, error]) tuples -> generic event list."""
    ev = []
    for c in calls:
        e = {"tool": c[0], "args": c[1]}
        if len(c) > 3 and c[3]:
            e["error"] = c[2]
        else:
            e["result"] = c[2]
        ev.append(e)
    if answer:
        ev.append({"role": "assistant", "content": "done"})
    return ev


def rules(events, **kw):
    calls, ans = lg.parse_events(events)
    return [f.rule for f in lg.analyze(calls, "t", ans, **kw)]


class ParseTests(unittest.TestCase):
    def test_openai(self):
        calls, ans = lg.parse_events(lg.load(os.path.join(EX, "runaway_openai.json")))
        self.assertEqual(len(calls), 15)
        self.assertEqual(calls[1].tool, "send_email")
        self.assertTrue(calls[1].error)
        self.assertEqual(calls[1].args["to"], "team@example.com")
        self.assertFalse(ans)

    def test_anthropic(self):
        calls, ans = lg.parse_events(lg.load(os.path.join(EX, "healthy_anthropic.json")))
        self.assertEqual([c.tool for c in calls], ["get_weather"])
        self.assertEqual(calls[0].result, "52F, cloudy")
        self.assertTrue(ans)

    def test_anthropic_is_error_flag(self):
        ev = [{"role": "assistant", "content": [{"type": "tool_use", "id": "x", "name": "t", "input": {}}]},
              {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "x", "content": "boom", "is_error": True}]}]
        calls, _ = lg.parse_events(ev)
        self.assertTrue(calls[0].error)

    def test_generic_jsonl(self):
        calls, ans = lg.parse_events(lg.load(os.path.join(EX, "truncated_generic.jsonl")))
        self.assertEqual(len(calls), 4)
        self.assertIsNone(calls[-1].result)
        self.assertFalse(ans)

    def test_arg_order_irrelevant(self):
        a = lg.Call(0, "t", {"a": 1, "b": 2}); b = lg.Call(1, "t", '{"b": 2, "a": 1}')
        self.assertEqual(a.key, b.key)

    def test_error_text_heuristic(self):
        c = lg.Call(0, "t", {}); c.set_result("HTTP 503 Service Unavailable")
        self.assertTrue(c.error)
        c.set_result("all good"); self.assertFalse(c.error)

    def test_side_effect_words(self):
        self.assertTrue(lg.is_side_effect("gmail.sendEmail"))
        self.assertTrue(lg.is_side_effect("create_issue"))
        self.assertFalse(lg.is_side_effect("truncate_text"))
        self.assertFalse(lg.is_side_effect("get_weather"))


class RuleTests(unittest.TestCase):
    def test_lg01_identical_repeat(self):
        r = rules(gen(*[("search", {"q": "x"}, "r%d" % i) for i in range(3)]))
        self.assertIn("LG01", r)

    def test_below_threshold_clean(self):
        self.assertEqual(rules(gen(("search", {"q": "x"}, "a"), ("search", {"q": "x"}, "b"))), [])

    def test_repeat_threshold_tunable(self):
        ev = gen(("search", {"q": "x"}, "a"), ("search", {"q": "x"}, "b"))
        self.assertIn("LG01", rules(ev, repeat=2))

    def test_lg08_side_effect_repeat(self):
        r = rules(gen(*[("send_email", {"to": "a@example.com"}, "ok %d" % i) for i in range(3)]))
        self.assertIn("LG08", r)
        self.assertNotIn("LG01", r)

    def test_lg02_cycle(self):
        r = rules(gen(*[c for _ in range(3) for c in (("ls", {"d": "/"}, "x%d" % _), ("cat", {"p": "a"}, "y%d" % _))]))
        self.assertIn("LG02", r)

    def test_lg02_period3(self):
        calls = [c for i in range(3) for c in (("a", {}, "1%d" % i), ("b", {}, "2%d" % i), ("c", {}, "3%d" % i))]
        self.assertEqual(rules(gen(*calls)).count("LG02"), 1)

    def test_no_cycle_when_varied(self):
        calls = [("ls", {"d": str(i)}, "x%d" % i) for i in range(6)]
        self.assertNotIn("LG02", rules(gen(*calls)))

    def test_lg03_error_storm(self):
        calls = [("fetch", {"u": "https://example.com/%d" % i}, "rate limit exceeded", True) for i in range(3)]
        r = rules(gen(*calls))
        self.assertIn("LG03", r)
        self.assertNotIn("LG01", r)

    def test_lg03_interrupted_by_success(self):
        calls = [("fetch", {}, "Error: x", True), ("fetch", {"a": 1}, "fine"), ("fetch", {}, "Error: x", True)]
        self.assertNotIn("LG03", rules(gen(*calls)))

    def test_lg04_stalled_polling(self):
        calls = [("check_status", {"poll": i}, "pending") for i in range(4)]
        r = rules(gen(*calls))
        self.assertIn("LG04", r)
        self.assertNotIn("LG01", r)

    def test_lg04_not_duplicated_with_lg01(self):
        calls = [("check_status", {}, "pending") for _ in range(3)]
        r = rules(gen(*calls))
        self.assertIn("LG01", r)
        self.assertNotIn("LG04", r)

    def test_lg05_budget(self):
        calls = [("t%d" % (i % 7), {"i": i}, "r%d" % i) for i in range(12)]
        self.assertIn("LG05", rules(gen(*calls), max_calls=10))
        self.assertNotIn("LG05", rules(gen(*calls), max_calls=0))

    def test_lg06_dominance(self):
        calls = [("grep", {"i": i}, "r%d" % i) for i in range(18)] + [("ls", {}, "a"), ("cat", {}, "b")]
        self.assertIn("LG06", rules(gen(*calls)))
        self.assertNotIn("LG06", rules(gen(*calls[:15])))

    def test_lg07_no_answer(self):
        self.assertIn("LG07", rules(gen(("a", {}, "x"), answer=False)))
        self.assertNotIn("LG07", rules(gen(("a", {}, "x"))))

    def test_no_calls_no_findings(self):
        self.assertEqual(rules([{"role": "user", "content": "hi"}]), [])

    def test_healthy_example_clean(self):
        f, _ = lg.scan([os.path.join(EX, "healthy_anthropic.json")])
        self.assertEqual(f, [])

    def test_runaway_example_rules(self):
        f, _ = lg.scan([os.path.join(EX, "runaway_openai.json")])
        got = {x.rule for x in f}
        self.assertTrue({"LG02", "LG03", "LG04", "LG07", "LG08"} <= got, got)


class CliTests(unittest.TestCase):
    def run_cli(self, *args, stdin=None):
        return subprocess.run(CLI + list(args), capture_output=True, text=True, input=stdin)

    def test_exit_codes(self):
        self.assertEqual(self.run_cli(os.path.join(EX, "runaway_openai.json")).returncode, 1)
        self.assertEqual(self.run_cli(os.path.join(EX, "healthy_anthropic.json")).returncode, 0)
        self.assertEqual(self.run_cli(os.path.join(EX, "runaway_openai.json"), "--fail-on", "none").returncode, 0)

    def test_fail_on_any(self):
        p = os.path.join(EX, "truncated_generic.jsonl")
        self.assertEqual(self.run_cli(p).returncode, 0)
        self.assertEqual(self.run_cli(p, "--fail-on", "any").returncode, 1)

    def test_json_output(self):
        out = json.loads(self.run_cli(EX, "--json", "--fail-on", "none").stdout)
        self.assertEqual(len(out["runs"]), 3)
        self.assertTrue(all("rule" in f and "severity" in f for f in out["findings"]))

    def test_min_severity(self):
        out = json.loads(self.run_cli(EX, "--json", "--min-severity", "high").stdout)
        self.assertTrue(all(lg.SEV_RANK[f["severity"]] >= lg.SEV_RANK["high"] for f in out["findings"]))

    def test_stdin(self):
        data = json.dumps(gen(*[("x", {}, "same") for _ in range(3)]))
        r = self.run_cli("-", stdin=data)
        self.assertEqual(r.returncode, 1)
        self.assertIn("LG01", r.stdout)

    def test_list_rules(self):
        out = self.run_cli("--list-rules").stdout
        self.assertEqual(sum(1 for l in out.splitlines() if l.startswith("LG")), len(lg.RULES))

    def test_bad_repeat(self):
        self.assertEqual(self.run_cli("--repeat", "1", EX).returncode, 2)


if __name__ == "__main__":
    unittest.main()
