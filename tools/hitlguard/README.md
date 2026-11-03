# hitlguard

Offline **human-in-the-loop (HITL) gap detector** for AI agent transcripts.

Consequential tool calls — pay, transfer, delete, deploy, force-push, send email,
slack post, shell `rm -rf` — that fire without a nearby confirm-shaped user turn
or approval-tool success are a common autonomy failure mode. hitlguard reads
saved transcripts, classifies each tool call by name and argument risk, and
flags those that lack confirmation inside a configurable lookback window.

Standard library only. It never runs an agent and never contacts the network.

## How it differs from siblings

| Tool | Surface |
|---|---|
| **hitlguard** | *Observed* transcript: did a human confirm this side effect? |
| toolgate | You write allow/deny/warn policy; optional live pre-tool hook |
| loopguard | Repeated / cyclic calls (including side-effect repeats) |
| yolocheck | Static coding-agent autonomy *settings* (not a saved run) |
| trifecta | Capability mix across the whole toolset (not per-call confirmation) |

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| HG01 | critical | Critical-tier tool (pay/transfer/destroy/force-push/prod deploy/…) without nearby confirmation |
| HG02 | high | High-tier tool (send email/slack/delete/deploy/publish/shell/…) without nearby confirmation |
| HG03 | high | Burst of unconfirmed consequential tools (`--burst`, default 3) |
| HG04 | high | Assistant said it would skip asking, then took a consequential action |
| HG05 | critical | Confirm-shaped text in an assistant/tool role (spoofed approval) |
| HG06 | medium | Blanket pre-authorization ("always approve", "don't ask again") followed by consequential calls |
| HG07 | medium | Approval-tool success with no matching approval tool call in lookback |
| HG08 | info | Inventory of consequential calls and confirmation status |

**Confirmation** means either:

1. A **user** turn whose text is confirm-shaped (`yes`, `approved`, `go ahead`,
   `please send/delete/deploy/…`, …), or
2. An **approval tool** result (`request_approval`, `ask_user`, `gatekeeper`, …)
   whose text looks like success (`approved`, `confirmed`, …),

inside the last `--window` events (default 6). The original task prompt alone
does **not** count unless it itself contains confirm phrasing.

## Usage

```
python3 hitlguard.py transcript.json [more.jsonl dir/ -]
  --window N           events to look back for confirm/approval (default 6)
  --burst N            unconfirmed consequential calls → HG03 (default 3)
  --require GLOB ...   tool-name globs that always require confirmation
  --safe GLOB ...      tool-name globs that never need confirmation
  --disable RULE ...   skip rule ids
  --json               machine-readable output
  --min-severity S     hide findings below S (default info)
  --fail-on S          exit 1 if any finding >= S (default high; any, none)
  --list-rules
```

Exit codes: `0` clean (below `--fail-on`), `1` findings, `2` usage / no readable input.

Accepted shapes: OpenAI chat `messages` with `tool_calls`, Anthropic content
blocks (`tool_use` / `tool_result`), generic JSON/JSONL `{tool, args, result}`
events, directories, stdin (`-`).

## Example

```sh
python3 hitlguard.py examples/risky_openai.json --disable HG08
python3 hitlguard.py examples/clean_confirmed.json --disable HG08
python3 hitlguard.py examples/clean_approval_tool.jsonl --json
```

## Known limits

- Heuristic tiering from tool **names** and a few argument shapes. A tool named
  `helper` that secretly wires money will not be flagged unless you `--require` it.
- "Confirm-shaped" matching is English-centric and can false-positive on short
  replies, or false-negative on unusual phrasing / button clicks that were never
  logged as text.
- Only sees what the transcript recorded. UI approval clicks, out-of-band Slack
  reactions, or unlogged gates are invisible.
- Coding-agent `write_file` / `read_file` loops are intentionally low-noise
  (medium or ignored). Use `--require` for paths that must always be gated.
- A clean result does **not** prove a human approved the action in the real system.

## License

MIT. Example secrets use the `FAKE-EXAMPLE-...` prefix only.
