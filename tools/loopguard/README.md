# loopguard

Offline detector of runaway loops and retry storms in AI agent transcripts.

Agents that get stuck burn tokens, hammer APIs and can repeat real side effects: the same email
sent four times, the same deploy re-run, the same payment retried. loopguard reads saved
transcripts (OpenAI chat `tool_calls`, Anthropic `tool_use`/`tool_result` blocks, or generic
JSON/JSONL `{"tool", "args", "result"|"error"}` events) and flags the patterns. Standard library
only; it never runs an agent or contacts a model.

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| LG01 | high | Identical tool call (same tool, same arguments, key order ignored) repeated back-to-back |
| LG02 | high | Repeating cycle of 2–4 calls (A,B,A,B,A,B) |
| LG03 | high | Error retry storm: same tool failing N times in a row (`is_error`, `error` field, or error-looking text such as `Error:`, `HTTP 503`, `rate limit`, `timed out`) |
| LG04 | medium | Stalled progress: same tool returning the identical result N times in a row, even with changing args (polling that never moves) |
| LG05 | medium | Run exceeds `--max-calls` (default 50) |
| LG06 | low | One tool is ≥70% of calls (runs with ≥20 calls) |
| LG07 | low | Transcript ends on a tool call/result with no final assistant answer |
| LG08 | critical | LG01 on a side-effecting tool (name contains a word like send, post, create, delete, pay, deploy, push, write, run, exec) |

N is `--repeat` (default 3).

## Usage

```
python3 loopguard.py transcript.json [more.jsonl dir/ -]
  --repeat N        repetitions that count as a loop (default 3, min 2)
  --max-calls N     tool-call budget per run, 0 = off (default 50)
  --dominance F     share of calls for LG06 (default 0.7)
  --json            machine-readable output
  --min-severity S  hide findings below S
  --fail-on S       exit 1 if any finding >= S (high default; any, none)
  --list-rules
```

Exit codes: 0 clean (below `--fail-on`), 1 findings, 2 usage error. Use it in CI over eval-run
transcripts, or as a post-run check in an agent harness.

## Example

`python3 loopguard.py examples/runaway_openai.json` (exit code 1):

```
examples/runaway_openai.json: 15 tool calls, 4 errors
[CRITICAL] LG08 examples/runaway_openai.json  send_email called 4 times in a row with identical args {"subject": "Weekly report", "to": "team@example.com"} (calls #2-#5)
[HIGH] LG02 examples/runaway_openai.json  cycle [list_files,read_file] repeated 3 times (calls #6-#11)
[HIGH] LG03 examples/runaway_openai.json  send_email failed 4 times in a row (calls #2-#5); last error: Error: SMTP timeout
[MEDIUM] LG04 examples/runaway_openai.json  check_status returned the identical result 4 times in a row (calls #12-#15)
[LOW] LG07 examples/runaway_openai.json  transcript ends after call #15 (check_status) without a final answer; truncated or runaway?
Note: loopguard is heuristic. Legitimate polling or batch work can look like a loop; tune --repeat/--max-calls.
```

`examples/healthy_anthropic.json` is clean; `examples/truncated_generic.jsonl` shows stalled
search results and a run that stops mid-tool-call.

## Known limits

- Heuristic. Legitimate polling, pagination or batch work can look like a loop; tune `--repeat`
  and `--max-calls`, or use `--fail-on` to gate only on what matters to you.
- Only *consecutive* repeats count; a loop interleaved with unrelated calls (other than the 2–4
  call cycles LG02 finds) is missed. Near-duplicate arguments (a changing timestamp) defeat LG01,
  though LG04 may still catch the stalled result.
- Side-effect detection is by tool-name words only; a tool named `do_it` that sends mail is not
  recognized.
- Error detection on free text is a regex over the first 300 characters of a result and can
  misfire (for example a result that legitimately says "not found").
- It analyzes what was saved. It cannot stop a live loop; pair it with a runtime call cap
  (see toolgate's per-run caps).
