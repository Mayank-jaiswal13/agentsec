# memfence

Offline **persistent agent-memory / store poisoning** scanner.

Agent memory stores (mem0 exports, LangGraph checkpoints, custom fact JSONL,
Assistants-style memory files, plain-text dumps) are re-injected into later
sessions. A single poisoned entry can override instructions, plant exfil bait,
smuggle hidden Unicode, or demand "always remember / from now on" persistence.
memfence reviews *saved memory dumps* and reports findings with per-entry
attribution.

Standard library only. It never connects to a network and never writes to the
store.

## How it differs from siblings

| Tool | Surface |
|---|---|
| **memfence** | Persistent *memory / store dumps* that re-inject across sessions |
| ragsieve | Pre-ingestion *RAG corpora* (docs before chunking) |
| resultguard | *Tool results* inside one run transcript |
| rulesguard | Agent *instruction files* (AGENTS.md, SKILL.md, …) |
| outfence | Model *output* before it is rendered |
| canarytrap | Live canary payloads against a running agent |

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| MF01 | high | Override / jailbreak phrasing planted in memory |
| MF02 | high | Fake role / system / developer tokens |
| MF03 | critical | Hidden Unicode (zero-width, bidi, TAG) — escalates when decoded text is instruction-like |
| MF04 | high | Exfil / callback URL bait (`webhook`, `oast`, `${API_KEY}` in URL, …) |
| MF05 | high | Credential / secret harvest instructions |
| MF06 | high | Tool-chaining / consequential-action bait (shell, deploy, pay, transfer) |
| MF07 | high | Conceal-from-user / silently instructions |
| MF08 | medium | Base64/hex blob that decodes to instruction-like text |
| MF09 | critical | Cross-session persistence bait (`always remember`, `from now on you must`, `update your system prompt`, `every future session`) |
| MF10 | info | Inventory of memory entries scanned (disable in CI with `--disable MF10`) |

## Usage

```
python3 memfence.py memory.json [more.jsonl dir/ -]
  --as-text           treat inputs as plain-text dumps (paragraph = entry)
  --disable RULE ...  skip rule ids (e.g. MF10 MF08)
  --json              machine-readable output
  --min-severity S    hide findings below S (default info)
  --fail-on S         exit 1 if any finding >= S (default high; any, none)
  --list-rules
```

Exit codes: `0` clean (below `--fail-on`), `1` findings, `2` usage / no readable
input. MF10 inventory alone does not fail the default `--fail-on high` gate.

Accepted shapes: mem0-style `{memories:[…]}`, `{facts|entries|documents|results:[…]}`,
LangGraph `{channel_values:{messages:[…]}}` / top-level `messages`, flat string
maps, JSONL of memory objects, directories, stdin (`-`), and `--as-text` paragraph
dumps (`.txt` / `.md` / `.memory`).

## Example

```sh
python3 memfence.py examples/poisoned_mem0.json --disable MF10
```

Flags MF09/MF01 on the persistence entry, MF04/MF05 on the webhook exfil entry,
MF06 on the shell-tool bait, MF07 on conceal-from-user, MF02/MF01 on the fake
role token, MF05 on credential harvest (exit 1).

`examples/clean_memory.json` is clean under `--fail-on high` (exit 0). See also
`poisoned_unicode.json` (MF03 TAG/bidi/ZW), `poisoned_encoded.json` (MF08),
`poisoned_facts.jsonl`, `poisoned_langgraph.json`, and
`poisoned_plaintext.txt --as-text`.

## Known limits

- Heuristic phrase and URL matching. Novel wording or indirect paraphrases can
  evade detection; benign ops notes that say "always remember the runbook URL"
  can false-positive MF09/MF04 — review snippets.
- Only sees what was exported. Live vector DBs, encrypted stores, and embeddings
  without the source text are invisible.
- Encoded-blob decoding is best-effort (base64/hex); other encodings are missed.
- A clean memfence result does not mean the memory backend or write-path is safe.
