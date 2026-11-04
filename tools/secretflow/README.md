# secretflow

Offline **data-flow secret-propagation** detector for AI agent transcripts.

[tracesweep](../tracesweep/) asks whether a secret *appeared* in a run. **secretflow**
asks the next question: once a secret showed up in a tool result (or earlier
message), was that *same value* later passed into another tool's arguments —
especially an outbound HTTP/webhook/email tool or a shell? That reuse pattern is
the classic agent exfiltration hop (`read .env` → `http_post` webhook).

Standard library only. It never connects to a network.

## How it differs from siblings

| Tool | Surface |
|---|---|
| **secretflow** | Same secret *value* flowing from a source event into later tool args |
| tracesweep | Secret *presence* / credential shapes anywhere in a transcript |
| fetchfence | Risky *URL destinations* an agent fetched |
| shellfence | Dangerous *shell command* shapes |
| pathfence | Sensitive *file paths* touched |
| resultguard | Prompt-injection phrasing inside tool *results* |

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| FL01 | critical | Secret from a tool result propagated into an outbound/exfil tool's arguments |
| FL02 | critical | Secret from a tool result propagated into a shell/command tool's arguments |
| FL03 | high | Secret from a tool result reused in a later tool call's arguments |
| FL04 | critical | Auth/session token (Bearer, JWT, Cookie, Authorization) reused in later tool args |
| FL05 | high | Secret echoed by the assistant, then passed into a subsequent tool call |
| FL06 | high | Multi-hop: same secret value appears in arguments of two or more distinct tools |
| FL07 | high | Labeled secret value (`api_key=` / `password=` / `token=` / env `*_KEY=`) reused later |
| FL08 | medium | User-supplied secret forwarded into an outbound/exfil tool |
| FL09 | medium | Secret from a tool result written to a file/log/memory sink tool |
| FL10 | info | Inventory of tainted secret sources and observed sinks |

Matches are **masked** in reports (e.g. `FAKE…2e`).

## Usage

```
python3 secretflow.py transcript.json [more.jsonl dir/ -]
  --disable RULE ...  skip rule ids (e.g. FL10)
  --json              machine-readable output
  --min-severity S    hide findings below S (default info)
  --fail-on S         exit 1 if any finding >= S (default high; any, none)
  --list-rules
```

Exit codes: `0` clean (below `--fail-on`), `1` findings, `2` usage / no readable
input. FL10 inventory alone does not fail the default `--fail-on high` gate.

Accepted shapes: OpenAI / Anthropic / generic JSON or JSONL transcripts
(messages, tool_calls, tool_use / tool_result), directories, stdin (`-`).

## Example

```sh
python3 secretflow.py examples/risky_openai.json --disable FL10
```

Flags the staging `API_KEY` flowing into `http_post` (FL01), the session token
into `bash` (FL02/FL04), assistant echo then tool use (FL05), labeled env reuse
(FL07), stripe key into `write_file` (FL09), and multi-tool hops (FL06). Exit 1.

```sh
python3 secretflow.py examples/risky_anthropic.json --disable FL10
python3 secretflow.py examples/risky_user_forward.jsonl --disable FL10 --fail-on medium
python3 secretflow.py examples/multi_hop.jsonl --disable FL10
python3 secretflow.py examples/clean_openai.json --disable FL10
```

`examples/clean_openai.json` is clean under `--fail-on high` (exit 0).

## Known limits

- Value-equality taint only (exact substring). Transformed secrets (base64 of a
  key, truncated, hashed, or concatenated differently) are invisible.
- Secret shapes are heuristic (FAKE-EXAMPLE-*, labeled assignments, JWT, Bearer,
  common provider prefixes, `*_KEY=` env lines). Novel formats are missed;
  long benign tokens can false-positive — review masked snippets.
- Only sees what was logged. A clean secretflow result does not mean no secrets
  were present — run **tracesweep** for presence, and treat this as a
  propagation / exfil-hop review aid, not a security boundary.
- Outbound / shell / write-sink classification is by tool-name tokens; renamed
  wrappers may be under-counted (they still hit FL03 on any later reuse).
