import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import runledger as rl  # noqa: E402

EX = os.path.join(ROOT, "examples")
PRICES = {"gpt-4o": {"input": 2.0, "cache_read": 1.0, "output": 10.0},
          "gpt-4o-mini": {"input": 0.1, "output": 0.4},
          "claude-sonnet-4": {"input": 3.0, "cache_read": 0.3, "cache_write": 3.75, "output": 15.0}}


def run_cli(args, stdin_text=None):
    out, err = io.StringIO(), io.StringIO()
    code = rl.main(args, stdin=io.StringIO(stdin_text or ""), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def turns_from(lines, prices=PRICES):
    warnings = []
    text = "\n".join(json.dumps(x) for x in lines)
    recs = list(rl.parse_text(text, "t.jsonl", warnings))
    return rl.build_turns(recs, prices)


class TestUsageShapes(unittest.TestCase):
    def test_openai_chat_usage(self):
        shape, t = rl.normalize_usage({"prompt_tokens": 1000, "completion_tokens": 50,
                                       "prompt_tokens_details": {"cached_tokens": 400},
                                       "completion_tokens_details": {"reasoning_tokens": 20}})
        self.assertEqual(shape, "openai")
        self.assertEqual(t, {"input": 600, "cache_read": 400, "cache_write": 0, "output": 50, "reasoning": 20})

    def test_openai_cached_clamped_to_prompt(self):
        _, t = rl.normalize_usage({"prompt_tokens": 10, "completion_tokens": 1,
                                   "prompt_tokens_details": {"cached_tokens": 99}})
        self.assertEqual(t["cache_read"], 10)
        self.assertEqual(t["input"], 0)

    def test_openai_null_details(self):
        _, t = rl.normalize_usage({"prompt_tokens": 5, "completion_tokens": 2,
                                   "prompt_tokens_details": None})
        self.assertEqual(t["input"], 5)

    def test_anthropic_usage(self):
        shape, t = rl.normalize_usage({"input_tokens": 100, "output_tokens": 20,
                                       "cache_creation_input_tokens": 300, "cache_read_input_tokens": 700})
        self.assertEqual(shape, "anthropic")
        self.assertEqual(t, {"input": 100, "cache_read": 700, "cache_write": 300, "output": 20, "reasoning": 0})

    def test_openai_responses_api_usage(self):
        shape, t = rl.normalize_usage({"input_tokens": 1000, "output_tokens": 100, "total_tokens": 1100,
                                       "input_tokens_details": {"cached_tokens": 800},
                                       "output_tokens_details": {"reasoning_tokens": 60}})
        self.assertEqual(shape, "openai")
        self.assertEqual(t["input"], 200)
        self.assertEqual(t["cache_read"], 800)
        self.assertEqual(t["reasoning"], 60)

    def test_unknown_usage_returns_none(self):
        self.assertEqual(rl.normalize_usage({"foo": 1}), (None, None))

    def test_generic_nested(self):
        t = rl.generic_usage({"a": {"b": {"tokens_in": 12, "tokens_out": 3}}})
        self.assertEqual(t["input"], 12)
        self.assertEqual(t["output"], 3)

    def test_generic_camelcase(self):
        t = rl.generic_usage({"stats": {"inputTokens": 40, "outputTokens": 9, "cacheReadTokens": 5}})
        self.assertEqual((t["input"], t["output"], t["cache_read"]), (40, 9, 5))

    def test_generic_prompt_style_subtracts_cache(self):
        t = rl.generic_usage({"usageMetadata": {"promptTokenCount": 100, "candidatesTokenCount": 7,
                                                "cachedContentTokenCount": 30}})
        self.assertEqual((t["input"], t["cache_read"], t["output"]), (70, 30, 7))

    def test_generic_none_when_absent(self):
        self.assertIsNone(rl.generic_usage({"message": "hello", "count": 3}))

    def test_find_usage_nested_in_response(self):
        u = rl.find_usage_dict({"response": {"body": {"usage": {"prompt_tokens": 1}}}})
        self.assertEqual(u, {"prompt_tokens": 1})


class TestPricing(unittest.TestCase):
    def test_exact_match(self):
        self.assertEqual(rl.resolve_price("gpt-4o", PRICES)[0], "gpt-4o")

    def test_dated_suffix_match(self):
        self.assertEqual(rl.resolve_price("gpt-4o-2024-08-06", PRICES)[0], "gpt-4o")
        self.assertEqual(rl.resolve_price("claude-sonnet-4-20250514", PRICES)[0], "claude-sonnet-4")

    def test_provider_prefix(self):
        self.assertEqual(rl.resolve_price("openai/gpt-4o-mini", PRICES)[0], "gpt-4o-mini")

    def test_no_fuzzy_guess(self):
        # gpt-4o-mini must NOT fall back to gpt-4o pricing when it is missing
        prices = {"gpt-4o": PRICES["gpt-4o"]}
        self.assertEqual(rl.resolve_price("gpt-4o-mini", prices), (None, None))
        self.assertEqual(rl.resolve_price("gpt-4o-mini-2024-07-18", prices), (None, None))

    def test_longest_prefix_wins(self):
        self.assertEqual(rl.resolve_price("gpt-4o-mini-2024-07-18", PRICES)[0], "gpt-4o-mini")

    def test_turn_cost_math(self):
        t = {"input": 1_000_000, "cache_read": 1_000_000, "cache_write": 0, "output": 100_000, "reasoning": 0}
        self.assertAlmostEqual(rl.turn_cost(t, PRICES["gpt-4o"]), 2.0 + 1.0 + 1.0)

    def test_missing_cache_price_uses_input_rate(self):
        t = {"input": 0, "cache_read": 1_000_000, "cache_write": 1_000_000, "output": 0, "reasoning": 0}
        self.assertAlmostEqual(rl.turn_cost(t, PRICES["gpt-4o-mini"]), 0.2)

    def test_unpriced_cost_is_none(self):
        self.assertIsNone(rl.turn_cost({"input": 1}, None))

    def test_shipped_price_table_loads_and_has_note(self):
        p = rl.load_prices(rl.DEFAULT_PRICES)
        self.assertIn("gpt-4o", p)
        with open(rl.DEFAULT_PRICES) as fh:
            self.assertIn("NOT authoritative", json.load(fh)["_note"])

    def test_bad_price_table(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"models": {"m": {"input": "cheap"}}}, fh)
        try:
            with self.assertRaises(rl.RunledgerError):
                rl.load_prices(fh.name)
        finally:
            os.unlink(fh.name)


class TestAttribution(unittest.TestCase):
    def test_metadata_extraction(self):
        t = turns_from([{"run_id": "r1", "session_id": "s1", "timestamp": "2026-01-01T00:00:00Z",
                         "model": "gpt-4o", "usage": {"prompt_tokens": 10, "completion_tokens": 2}}])[0]
        self.assertEqual((t["run"], t["session"], t["timestamp"], t["model"]),
                         ("r1", "s1", "2026-01-01T00:00:00Z", "gpt-4o"))

    def test_defaults_to_filename(self):
        t = turns_from([{"usage": {"prompt_tokens": 1, "completion_tokens": 1}}])[0]
        self.assertEqual(t["run"], "t.jsonl")
        self.assertEqual(t["session"], "t.jsonl")
        self.assertEqual(t["model"], "(unknown)")
        self.assertIsNone(t["cost"])

    def test_openai_tool_call_made(self):
        t = turns_from([{"model": "gpt-4o", "choices": [{"message": {"tool_calls": [
            {"id": "c1", "function": {"name": "grep"}}]}}], "usage": {"prompt_tokens": 1, "completion_tokens": 1}}])[0]
        self.assertEqual(t["tools"], ["grep"])
        self.assertEqual(t["tool_attribution"], "called")

    def test_history_tool_calls_not_counted_as_made(self):
        rec = {"messages": [{"role": "assistant", "tool_calls": [{"id": "c1", "function": {"name": "old"}}]},
                            {"role": "tool", "tool_call_id": "c1", "content": "x"}],
               "model": "gpt-4o", "usage": {"prompt_tokens": 1, "completion_tokens": 1}}
        t = turns_from([rec])[0]
        self.assertEqual(t["tools"], ["old"])
        self.assertEqual(t["tool_attribution"], "answered")

    def test_anthropic_tool_result_answered(self):
        rec = {"request": {"messages": [
            {"role": "assistant", "content": [{"type": "tool_use", "id": "tu1", "name": "fetch"}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "tu1"}]}]},
            "response": {"model": "claude-sonnet-4", "content": [{"type": "text", "text": "ok"}],
                         "usage": {"input_tokens": 5, "output_tokens": 1}}}
        t = turns_from([rec])[0]
        self.assertEqual(t["tools"], ["fetch"])

    def test_pending_tool_from_previous_turn(self):
        a = {"session_id": "s", "model": "claude-sonnet-4",
             "content": [{"type": "tool_use", "id": "x", "name": "bash"}],
             "usage": {"input_tokens": 5, "output_tokens": 1}}
        b = {"session_id": "s", "model": "claude-sonnet-4", "content": [{"type": "text", "text": "done"}],
             "usage": {"input_tokens": 5, "output_tokens": 1}}
        c = dict(b)
        ts = turns_from([a, b, c])
        self.assertEqual([t["tools"] for t in ts], [["bash"], ["bash"], [rl.NONE_TOOL]])

    def test_explicit_tool_field(self):
        t = turns_from([{"tool": "planner", "tokens_in": 3, "tokens_out": 1}])[0]
        self.assertEqual(t["tools"], ["planner"])
        self.assertEqual(t["shape"], "generic")

    def test_multi_tool_split_evenly(self):
        rec = {"model": "gpt-4o", "choices": [{"message": {"tool_calls": [
            {"function": {"name": "a"}}, {"function": {"name": "b"}}]}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 0}}
        rep = rl.aggregate(turns_from([rec]))
        self.assertEqual(rep["by_tool"]["a"]["input"], 50)
        self.assertEqual(rep["by_tool"]["b"]["turns"], 0.5)


class TestAggregation(unittest.TestCase):
    def test_cache_hit_ratio(self):
        rep = rl.aggregate(turns_from([{"model": "claude-sonnet-4", "usage": {
            "input_tokens": 100, "output_tokens": 1, "cache_read_input_tokens": 300}}]))
        self.assertAlmostEqual(rep["totals"]["cache_hit_ratio"], 0.75)

    def test_unpriced_excluded_from_cost(self):
        rep = rl.aggregate(turns_from([
            {"model": "gpt-4o", "usage": {"prompt_tokens": 1_000_000, "completion_tokens": 0}},
            {"model": "nope-9000", "usage": {"prompt_tokens": 1_000_000, "completion_tokens": 0}}]))
        self.assertAlmostEqual(rep["totals"]["cost"], 2.0)
        self.assertEqual(rep["totals"]["unpriced_turns"], 1)
        self.assertEqual(rep["unpriced_models"], ["nope-9000"])

    def test_top_n_order(self):
        ts = turns_from([{"model": "gpt-4o", "usage": {"prompt_tokens": n, "completion_tokens": 0}}
                         for n in (10, 1000, 100)])
        rep = rl.aggregate(ts, top_n=2)
        self.assertEqual([t["input"] for t in rep["top_turns"]], [1000, 100])

    def test_non_usage_lines_ignored(self):
        self.assertEqual(turns_from([{"event": "note"}, {"model": "gpt-4o"}]), [])


class TestInputParsing(unittest.TestCase):
    def test_json_array_file(self):
        recs = list(rl.parse_text(json.dumps([{"a": 1}, {"b": 2}]), "x.json", []))
        self.assertEqual(len(recs), 2)

    def test_json_wrapper_object(self):
        recs = list(rl.parse_text(json.dumps({"events": [{"a": 1}, {"b": 2}, {"c": 3}]}), "x.json", []))
        self.assertEqual(len(recs), 3)

    def test_bad_jsonl_line_warns(self):
        w = []
        recs = list(rl.parse_text('{"a": 1}\nnot json\n{"b": 2}\n', "x.jsonl", w))
        self.assertEqual(len(recs), 2)
        self.assertEqual(len(w), 1)


class TestCLI(unittest.TestCase):
    def test_examples_table(self):
        code, out, err = run_cli([EX])
        self.assertEqual(code, 0)
        for s in ("By run:", "By model:", "By tool:", "By session:", "Top 5", "unpriced", "get_weather"):
            self.assertIn(s, out)

    def test_examples_json(self):
        code, out, _ = run_cli([EX, "--json"])
        self.assertEqual(code, 0)
        rep = json.loads(out)
        self.assertEqual(rep["totals"]["turns"], 11)
        self.assertIn("mystery-model-x", rep["unpriced_models"])
        self.assertIn("sess-gamma", rep["by_session"])
        self.assertFalse(rep["budget"]["exceeded"])

    def test_csv_turns(self):
        code, out, _ = run_cli([EX, "--csv"])
        self.assertEqual(code, 0)
        lines = out.strip().splitlines()
        self.assertTrue(lines[0].startswith("id,source,line"))
        self.assertEqual(len(lines), 12)

    def test_csv_group_model(self):
        code, out, _ = run_cli([EX, "--csv", "--csv-group", "model"])
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("model,turns"))

    def test_budget_exceeded_exit_1(self):
        code, _, err = run_cli([EX, "--budget", "0.001"])
        self.assertEqual(code, 1)
        self.assertIn("BUDGET EXCEEDED", err)

    def test_budget_ok_exit_0(self):
        code, _, _ = run_cli([EX, "--budget", "100"])
        self.assertEqual(code, 0)

    def test_token_budget(self):
        code, _, err = run_cli([EX, "--budget-tokens", "10"])
        self.assertEqual(code, 1)
        self.assertIn("token budget", err)

    def test_missing_input_exit_2(self):
        code, _, err = run_cli(["/nonexistent/path.jsonl"])
        self.assertEqual(code, 2)
        self.assertIn("error", err)

    def test_bad_prices_exit_2(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{not json")
        try:
            code, _, _ = run_cli([EX, "--prices", fh.name])
            self.assertEqual(code, 2)
        finally:
            os.unlink(fh.name)

    def test_bad_flag_exit_2(self):
        code, _, _ = run_cli(["--no-such-flag"])
        self.assertEqual(code, 2)

    def test_stdin(self):
        line = json.dumps({"model": "gpt-4o", "usage": {"prompt_tokens": 1_000_000, "completion_tokens": 0}})
        code, out, _ = run_cli(["-", "--json"], stdin_text=line + "\n")
        self.assertEqual(code, 0)
        self.assertAlmostEqual(json.loads(out)["totals"]["cost"], 2.5)  # shipped example table

    def test_no_prices_everything_unpriced(self):
        code, out, _ = run_cli([EX, "--json", "--no-prices"])
        rep = json.loads(out)
        self.assertEqual(rep["totals"]["cost"], 0)
        self.assertEqual(rep["totals"]["unpriced_turns"], 11)

    def test_custom_prices_override(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"models": {"mystery-model-x": {"input": 1.0, "output": 1.0}}}, fh)
        try:
            code, out, _ = run_cli([os.path.join(EX, "generic_run.jsonl"), "--json", "--prices", fh.name])
            rep = json.loads(out)
            self.assertAlmostEqual(rep["by_model"]["mystery-model-x"]["cost"], 0.0052)
            self.assertNotIn("mystery-model-x", rep["unpriced_models"])
        finally:
            os.unlink(fh.name)


if __name__ == "__main__":
    unittest.main()
