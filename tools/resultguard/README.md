# resultguard

Offline scanner for **indirect prompt injection in AI agent tool results**.

When an agent reads a page, file, ticket or API response, that content is fed back to the
model as a tool result. Attackers plant instructions there ("ignore prior rules", "call
`send_email`", "quietly hit this webhook"). resultguard extracts those results from saved
transcripts and flags hijack / exfil bait patterns with tool and turn attribution.

Standard library only. It never runs an agent or contacts a model.

## How it differs from siblings

| Tool | Surface |
|---|---|
| **resultguard** | Content *returned by tools* to the model (next-turn hijack) |
| ragsieve | Documents *before* RAG ingestion |
| toolpoison | Tool *descriptions* / manifests |
| outfence | Model *output* before it is rendered to a user |
| canarytrap | Live canary-payload resistance test |

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| TR01 | high | AI-directed override / jailbreak phrasing (`ignore previous instructions`, `you are now in DAN mode`, …) |
| TR02 | high | Fake role delimiters / system tokens (`<\|im_start\|>`, `<system>`, `[INST]`, `</tool_result>`, …) |
| TR03 | critical | Hidden Unicode smuggling (zero-width, bidi, Unicode TAG block) |
| TR04 | high | Tool-chaining / action bait (`call the send_email tool`, `run bash`, `exfiltrate`, …) |
| TR05 | high | Exfil / callback URL bait (webhook.site, requestbin, interact.sh, `evil-callback.*`, “send secrets to https://…”) |
| TR06 | medium | Base64/hex blob that decodes to instruction-like text |
| TR07 | high | Credential harvest (`paste your API key`, `cat ~/.ssh/…`, dump `.env`) |
| TR08 | medium | Conceal-from-user phrasing (`do not tell the user`, `silently perform`) |
| TR09 | medium | Markdown/HTML auto-loading image or resource URL in a result |

## Usage

```
python3 resultguard.py transcript.json [more.jsonl dir/ -]
  --as-result         treat each file body as one tool result (skip transcript parse)
  --tool-name NAME    name used with --as-result / plain files (default: file)
  --tools NAME ...    only scan results from these tools
  --disable RULE ...  skip rule ids (e.g. TR09)
  --json              machine-readable output
  --min-severity S    hide findings below S (default info)
  --fail-on S         exit 1 if any finding >= S (default high; any, none)
  --list-rules
```

Exit codes: `0` clean (below `--fail-on`), `1` findings, `2` usage / no readable input.

Accepted shapes: OpenAI chat (`role=tool` + `tool_calls`), Anthropic `tool_use` /
`tool_result` content blocks, generic JSON/JSONL `{"tool","result"|"output"}` events,
plain `.txt`/`.md`/`.html` (treated as one synthetic result).

## Example

```sh
python3 resultguard.py examples/poisoned_openai.json
```

Flags TR01/TR04/TR05/TR07/TR08/TR09 on `fetch_ticket` and TR01/TR02/TR06/TR09 on
`browse_page` (exit 1). `examples/clean_openai.json` is clean (exit 0).
`examples/poisoned_anthropic.json` shows hidden Unicode (TR03).
`examples/generic_results.jsonl` and `examples/standalone_result.txt` cover generic and
`--as-result` paths. All secrets and callback IDs in examples are `FAKE-EXAMPLE-*`.

## Known limits

- Heuristic. Benign docs that discuss jailbreaks, or HTML with ordinary `<img src=https://…>`,
  can match (especially TR09). Use `--disable` / `--tools` / `--fail-on`.
- Only *tool results* are scanned. User messages, assistant prose and tool *arguments* are
  ignored by design.
- Encoded-blob detection (TR06) only flags UTF-8 payloads that look instruction-like; short or
  binary blobs are skipped.
- Callback-host matching is a fixed list plus a few `evil-*` / `exfil*` patterns — novel
  domains need TR05's phrasing arm or a custom allow/deny later.
- It analyzes what was saved. It cannot block a live tool result; pair it with a runtime
  filter in front of the model context.
