# piiguard

Offline **PII / sensitive-personal-data** scanner for AI agent transcripts and
logs.

Before you share a run, drop it into a ticket, or ship it to a log pipeline,
piiguard checks whether emails, phone numbers, SSNs, payment cards, government
IDs, bank details, dates of birth, home addresses, or medical record numbers
leaked into messages or tool results. It can also write a **redacted** copy
(`--redact`).

Standard library only. It never connects to a network.

## How it differs from siblings

| Tool | Surface |
|---|---|
| **piiguard** | Identity / personal data (PII) in transcripts, with `--redact` |
| tracesweep | Credentials / API keys / tokens / secret shapes (not identity PII) |
| outfence | Model *output* before render (markdown/HTML exfil, not PII categories) |
| pathfence | Sensitive *file paths* an agent touched |
| fetchfence | Risky *URLs* an agent fetched |

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| PG01 | high | Email address |
| PG02 | high | Phone number (NANP / simple international) |
| PG03 | critical | US Social Security number (labeled or dashed; invalid area/group rejected) |
| PG04 | critical | Payment card PAN (Luhn + loose issuer prefix) |
| PG05 | high | Passport / driver's-license / national-ID (labeled) |
| PG06 | high | IBAN (MOD-97), ABA routing, bank account number (labeled / JSON keys) |
| PG07 | medium | Date of birth (labeled) |
| PG08 | medium | Street / postal address heuristic |
| PG09 | medium | Medical record number / NPI (labeled) |
| PG10 | info | Inventory of segments scanned (disable in CI with `--disable PG10`) |

Matches are **masked** in reports (e.g. `a***@example.com`,
`****-****-****-1111`).

## Usage

```
python3 piiguard.py transcript.json [more.jsonl dir/ -]
  --as-text           treat inputs as plain text (paragraph = segment)
  --disable RULE ...  skip rule ids (e.g. PG10 PG01)
  --json              machine-readable output
  --min-severity S    hide findings below S (default info)
  --fail-on S         exit 1 if any finding >= S (default high; any, none)
  --redact OUT        write redacted copy (file for one input, directory for many)
  --list-rules
```

Exit codes: `0` clean (below `--fail-on`), `1` findings, `2` usage / no readable
input. PG10 inventory alone does not fail the default `--fail-on high` gate.

Accepted shapes: OpenAI / Anthropic / generic JSON or JSONL transcripts
(messages, tool_calls, tool_use / tool_result), directories, stdin (`-`), and
`--as-text` dumps (`.txt` / `.md` / `.log`).

## Example

```sh
python3 examples/make_examples.py   # writes synthetic SSN/card fixtures locally
python3 piiguard.py examples/risky_openai.json --disable PG10
```

Flags SSN (PG03), card (PG04), email/phone (PG01/PG02), passport (PG05), bank
fields (PG06), DOB/address/MRN (PG07–PG09); exit 1. (Those JSON fixtures are
gitignored because they embed Luhn-valid demo PANs; always regenerate with
`make_examples.py`.)

```sh
python3 piiguard.py examples/risky_email_only.jsonl --disable PG10
python3 piiguard.py examples/risky_plaintext.txt --as-text --redact /tmp/redacted.txt
```

Email-only JSONL works without generation. `--redact` writes a copy with matches
replaced by `[REDACTED:PG0x:…]` tokens.

`examples/clean_openai.json` is clean under `--fail-on high` (exit 0).

## Known limits

- Heuristic regex + checksums. Novel formats, non-US national IDs without labels,
  and non-Latin addresses are often missed; order IDs and random digit runs can
  false-positive — review snippets.
- Card detection needs a Luhn-valid PAN with a plausible issuer prefix; truncated
  or encrypted card tokens are invisible.
- Bare 9-digit SSNs without dashes or a nearby label are ignored on purpose.
- Only sees what was logged. Redaction rewrites text spans; it does not prove a
  downstream system forgot the original.
- A clean piiguard result does not mean the transcript is free of secrets — run
  **tracesweep** for credentials.
