# runledger

Offline, stdlib-only Python CLI for **token and cost accounting of AI agent runs**, computed from
transcripts and usage logs you already have.

> **Honesty note.** runledger counts what your logs report. It cannot see your provider's bill,
> cannot verify billing, and does not know about discounts, batch pricing, tiers, minimums, taxes,
> or price changes. Every dollar figure is an **estimate** from a price table *you* control.
> The shipped `prices.json` is an **EXAMPLE** only - prices change and those numbers are not
> authoritative. Models missing from the table are reported as **unpriced**, never guessed.

## What it does

- Reads JSONL / JSON files, whole directories (`*.jsonl`, `*.json`, `*.ndjson`, recursive), or stdin (`-`).
  JSON files may be a single record, an array, or an object wrapping a list (`records`, `events`, `turns`, ...).
- Auto-detects usage shapes (found under `usage` / `usageMetadata` / `token_usage` at any nesting):
  - **OpenAI Chat Completions**: `prompt_tokens`, `completion_tokens`, `total_tokens`,
    `prompt_tokens_details.cached_tokens`, `completion_tokens_details.reasoning_tokens`
    (cached tokens are *inside* `prompt_tokens`, so they are split out).
  - **OpenAI Responses API**: `input_tokens` + `input_tokens_details` / `total_tokens` (cached inside input).
  - **Anthropic**: `input_tokens`, `output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`
    (cache tokens are *in addition to* `input_tokens`).
  - **Generic fallback**: input/output-ish fields anywhere in the record, snake or camel case
    (`tokens_in`, `inputTokens`, `promptTokenCount`, `candidatesTokenCount`, `cachedInputTokens`, ...).
    Prompt-style names are assumed to include cached tokens (OpenAI/Gemini convention).
- Normalizes every turn to: uncached input, cache read, cache write, output (reasoning is reported
  separately but is already part of output, so it is never double-counted).
- Pulls model, run id (`run_id`/`trace_id`, else file name), session (`session_id`/`conversation_id`/`thread_id`,
  else the run), and timestamp where present.
- **Tool attribution** - a turn's tokens go to, in order of preference:
  1. tool calls the turn **made** (OpenAI `tool_calls`/`function_call`, Anthropic `tool_use` blocks in the
     response - request history is ignored so old calls are not re-counted);
  2. an explicit `tool` / `tool_name` field;
  3. the tool whose result the turn **answered** (last request message is a `tool` role / `tool_result` /
     `function_call_output`, mapped back by id), or else the tool called by the previous turn in the same session;
  4. otherwise `(none)`. Turns calling several tools are split evenly between them.
- Reports per-run, per-model, per-tool and per-session totals, cache hit ratio
  (`cache_read / (input + cache_read + cache_write)`), and the top N most expensive turns.
- `--budget USD` / `--budget-tokens N`: warn on stderr and exit 1 if exceeded (unpriced turns are not
  counted toward the USD budget, and a warning says so).
- Output as an aligned table (default), `--json`, or `--csv` (per turn, or `--csv-group run|model|tool|session`).

## Install

Python 3.8+ and nothing else. No network access, no dependencies.

```bash
cd 003-runledger
python3 runledger.py --help
# optional: chmod +x runledger.py && ln -s "$PWD/runledger.py" ~/bin/runledger
```

## Usage

```bash
python3 runledger.py examples/                          # table report for a directory
python3 runledger.py run.jsonl --json > report.json     # machine-readable
python3 runledger.py logs/ --csv > turns.csv            # one row per turn
python3 runledger.py logs/ --csv --csv-group tool       # one row per tool
cat run.jsonl | python3 runledger.py - --top 10         # stdin
python3 runledger.py logs/ --budget 5.00                # exit 1 if estimate > $5
python3 runledger.py logs/ --prices my_prices.json      # your own price table
python3 runledger.py logs/ --no-prices                  # tokens only
```

Exit codes: `0` ok, `1` budget exceeded, `2` error (missing input, bad price table, bad arguments).

### Price table

USD per **1,000,000** tokens. `cache_read` / `cache_write` are optional; if omitted those tokens are
charged at the `input` rate (an upper-bound assumption - set them explicitly for accuracy).

```json
{"models": {"my-model": {"input": 1.00, "cache_read": 0.10, "cache_write": 1.25, "output": 4.00}}}
```

Model matching is deliberately strict: exact name, then with a `provider/` prefix stripped, then a
table key followed only by a date/version suffix (`gpt-4o-2024-08-06` -> `gpt-4o`,
`claude-sonnet-4-20250514` -> `claude-sonnet-4`). `gpt-4o-mini` will **not** be priced as `gpt-4o`.

## Example output

Real run on the bundled fake logs (`python3 runledger.py examples`):

```
runledger 0.1.0 - token & cost ESTIMATES from logs (not a bill)

Turns: 11   Input: 18,812   Cache read: 23,528   Cache write: 8,000   Output: 3,795 (reasoning 896)
Total tokens: 54,135   Cache hit ratio: 46.7%   Estimated cost: $0.0758*
* 1 turn(s) unpriced (models not in price table: mystery-model-x) - excluded from cost

By run:
run                  turns  input  cache_rd  cache_wr  output   total  cache%      cost
-------------------  -----  -----  --------  --------  ------  ------  ------  --------
anthropic_run.jsonl      4  9,150    16,000     8,000     770  33,920    48.3   $0.0590
run-oa-2                 2  1,924     5,376         0   1,300   8,600    73.6   $0.0108
run-oa-1                 2  1,338     1,152         0      75   2,565    46.3   $0.0055
tr-local-1               3  6,400     1,000         0   1,650   9,050    13.5  $0.0005*

By model:
model                      turns  input  cache_rd  cache_wr  output   total  cache%      cost
-------------------------  -----  -----  --------  --------  ------  ------  ------  --------
claude-sonnet-4-20250514       3  3,950    16,000     8,000     460  28,410    57.2   $0.0536
o3-mini                        2  1,924     5,376         0   1,300   8,600    73.6   $0.0108
gpt-4o                         2  1,338     1,152         0      75   2,565    46.3   $0.0055
claude-3-5-haiku-20241022      1  5,200         0         0     310   5,510     0.0   $0.0054
gpt-4o-mini                    1  1,500     1,000         0     300   2,800    40.0   $0.0005
mystery-model-x                1  4,000         0         0   1,200   5,200     0.0  unpriced
example-local-7b               1    900         0         0     150   1,050     0.0   $0.0000

By tool:
tool         turns  input  cache_rd  cache_wr  output   total  cache%      cost
-----------  -----  -----  --------  --------  ------  ------  ------  --------
bash             1  2,100         0     8,000     120  10,220     0.0   $0.0381
read_file        2  1,850    16,000         0     340  18,190    89.6   $0.0155
search_docs      2  1,924     5,376         0   1,300   8,600    73.6   $0.0108
get_weather      2  1,338     1,152         0      75   2,565    46.3   $0.0055
fetch_url        1  5,200         0         0     310   5,510     0.0   $0.0054
(none)           1  1,500     1,000         0     300   2,800    40.0   $0.0005
coder            1  4,000         0         0   1,200   5,200     0.0  unpriced
planner          1    900         0         0     150   1,050     0.0   $0.0000

By session:
session     turns  input  cache_rd  cache_wr  output   total  cache%      cost
----------  -----  -----  --------  --------  ------  ------  ------  --------
sess-gamma      3  3,950    16,000     8,000     460  28,410    57.2   $0.0536
sess-beta       2  1,924     5,376         0   1,300   8,600    73.6   $0.0108
sess-alpha      2  1,338     1,152         0      75   2,565    46.3   $0.0055
sess-delta      1  5,200         0         0     310   5,510     0.0   $0.0054
tr-local-1      3  6,400     1,000         0   1,650   9,050    13.5  $0.0005*

Top 5 most expensive turns:
turn                                       model         tool  tokens     cost
---------------------  -------------------------  -----------  ------  -------
anthropic_run.jsonl:1   claude-sonnet-4-20250514         bash  10,220  $0.0381
anthropic_run.jsonl:3   claude-sonnet-4-20250514    read_file   9,760  $0.0108
openai_run.jsonl:3                       o3-mini  search_docs   4,300  $0.0066
anthropic_run.jsonl:4  claude-3-5-haiku-20241022    fetch_url   5,510  $0.0054
anthropic_run.jsonl:2   claude-sonnet-4-20250514    read_file   8,430  $0.0046
```

`*` marks totals that exclude unpriced turns. With `--budget 0.05 --top 3` the exit code is 1 and stderr says:

```
runledger: warning: 1 unpriced turn(s) not counted against budget
runledger: BUDGET EXCEEDED: estimated cost $0.0758 exceeds budget $0.0500
Budget: $0.0500 -> EXCEEDED
```

`--csv --csv-group model`:

```
model,turns,input,cache_read,cache_write,output,reasoning,total,cache_hit_ratio,cost,unpriced_turns
claude-sonnet-4-20250514,3,3950,16000,8000,460,0,28410,0.5725,0.05355,0
o3-mini,2,1924,5376,0,1300,896,8600,0.7364,0.010793,0
gpt-4o,2,1338,1152,0,75,0,2565,0.4627,0.005535,0
claude-3-5-haiku-20241022,1,5200,0,0,310,0,5510,0.0,0.0054,0
gpt-4o-mini,1,1500,1000,0,300,0,2800,0.4,0.00048,0
mystery-model-x,1,4000,0,0,1200,0,5200,0.0,0.0,1
example-local-7b,1,900,0,0,150,0,1050,0.0,0.0,0
```

## Limits

- Counts only what the logs contain; turns with no usage data are skipped, and retries/duplicates
  logged twice are counted twice.
- Tool attribution is heuristic and depends on the log including tool calls or results.
- No streaming-chunk reassembly: if each chunk carries cumulative usage, pre-filter to the final chunk.
- Not a billing system. Reconcile against your provider's invoices.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT. See the [LICENSE](../../LICENSE) at the repository root.
