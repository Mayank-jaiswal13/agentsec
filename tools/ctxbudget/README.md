# ctxbudget

Offline **tool-result size / context-window DoS budget checker** for AI agent transcripts.

A single huge tool result — a multi-megabyte dump, a base64 blob, a minified one-liner, or
a flood of large results from one tool — can exhaust the model's context window, hide
payloads from human reviewers, or starve later turns of budget. ctxbudget measures every
tool result in a saved transcript, compares it to absolute and relative budgets, and
reports findings with tool and turn attribution.

Standard library only. It never runs an agent and never contacts the network.

## How it differs from siblings

| Tool | Surface |
|---|---|
| **ctxbudget** | *Size / shape* of tool results vs context budgets (DoS / exhaustion) |
| runledger | Token and dollar cost totals (not size-as-security) |
| loopguard | Identical-call loops and retry storms |
| resultguard | Injection *phrasing* inside tool results |
| outfence | Model *output* before it is rendered to a user |

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| CB01 | high | Single tool result exceeds `--max-bytes` (default 100_000) |
| CB02 | critical | Single tool result exceeds `--critical-bytes` (default 500_000) |
| CB03 | high | One result is ≥ `--share` of all tool-result bytes (default 0.40) |
| CB04 | medium | Large base64 / hex blob inside a result (`--blob-bytes`, default 8192) |
| CB05 | high | Pathological single-line length (`--line-bytes`, default 32768) |
| CB06 | medium | Null bytes / high control-char ratio (binary-looking text) |
| CB07 | high | Same tool emitted ≥ `--flood-count` oversized results |
| CB08 | medium | Total tool-result bytes exceed `--total-bytes` (default 1_000_000) |
| CB09 | low | JSON nesting depth ≥ `--max-depth` (default 32) |
| CB10 | info | Inventory of the largest tool results |

## Usage

```
python3 ctxbudget.py transcript.json [more.jsonl dir/ -]
  --max-bytes N         CB01 per-result budget (default 100000)
  --critical-bytes N    CB02 critical budget (default 500000)
  --share F             CB03 fraction of total (default 0.40)
  --blob-bytes N        CB04 encoded-blob minimum (default 8192)
  --line-bytes N        CB05 max line length (default 32768)
  --flood-count N       CB07 oversized count from one tool (default 5)
  --flood-min-bytes N   CB07 minimum size to count (default 20000)
  --total-bytes N       CB08 run-wide budget (default 1000000)
  --max-depth N         CB09 JSON depth budget (default 32)
  --top N               CB10 inventory size (default 5)
  --disable RULE ...    skip rule ids
  --json                machine-readable output
  --min-severity S      hide findings below S (default info)
  --fail-on S           exit 1 if any finding >= S (default high; any, none)
  --list-rules
```

Exit codes: `0` clean (below `--fail-on`), `1` findings, `2` usage / no readable input.

Accepted shapes: OpenAI chat `role:tool` messages (names resolved via `tool_calls`),
Anthropic `tool_result` content blocks, generic JSON/JSONL
`{tool, result|output|content}` events, directories, stdin (`-`).

## Example

```sh
python3 ctxbudget.py examples/risky_openai.json
```

Flags CB02 on the half-megabyte dump, CB01 on the 120 KB dump, CB04/CB05/CB06/CB07/CB09
on the blob, long line, binary, flood and deep tree, and CB08 when the run total crosses
1 MB (exit 1). `examples/clean_openai.json` stays clean at default budgets (exit 0 aside
from the CB10 info inventory — use `--min-severity low` or `--disable CB10` in CI).
See also `risky_anthropic.json` and `generic_results.jsonl`. All payloads are synthetic
(`FAKE-EXAMPLE-*` / repeated filler bytes); nothing is a real secret.

## Known limits

- Heuristic transcript parsing. A custom logger that stores results under an unusual key
  may be missed; prefer a generic `{tool, result}` JSONL if your harness is exotic.
- Byte counts are UTF-8 length of the *logged* text. They are not tokenizer counts —
  pair with runledger when you need billed tokens.
- Base64/hex detection is regex-based and can miss unusual alphabets or flag dense
  identifiers. Tune `--blob-bytes` or `--disable CB04` if noisy.
- It analyzes what was saved. It cannot cap a live tool result; enforce size limits in
  the tool wrapper or a pre-context-compaction gate in front of the model.
