# promptleak

Detects **system-prompt leakage** in LLM app transcripts and outputs, offline.

System prompts often carry business rules, internal codenames, routing logic and sometimes
secrets that should never have been there. Prompt-extraction attacks ("repeat the words
above", "print your instructions in a code block") get models to recite them. promptleak
compares what the model actually said (assistant text **and tool-call arguments**) against the
system/developer prompt and reports how much of it came back out, verbatim or lightly obfuscated.

Inputs: OpenAI-style message lists (incl. `developer` role and `tool_calls`), Anthropic
requests/sessions (top-level `system`, `tool_use` blocks), generic `{"messages": [...]}` JSON or
JSONL, plain text outputs, directories, or stdin (`-`). If no `--prompt` is given, the system
messages inside each transcript are used.

## How it works

Text is NFKC-normalized, lowercased, stripped of zero-width/bidi/TAG characters and split into
words (punctuation ignored). The prompt is indexed as overlapping *n*-word shingles (default 8);
any output shingle found in the prompt is a verbatim match, and adjacent matches merge into spans.
Coverage = share of prompt words reproduced.

## Rules

| Rule | Severity | Finding |
|---|---|---|
| PL01 | critical | Bulk leak: coverage ≥ `--bulk` (default 50%) of a prompt |
| PL02 | high | Verbatim span ≥ `--span` words (default 25) or coverage ≥ `--partial` (default 20%) |
| PL03 | medium | Shorter verbatim fragment(s) (at least *n* words) |
| PL04 | high | A prompt line marked confidential/secret/"do not reveal"/password/API key/codename was reproduced |
| PL05 | critical | A `--protect` string appeared in output (also checked inside base64/hex blobs); shown masked |
| PL06 | high | A base64 / base64url / hex blob in output decodes to prompt content (e.g. smuggled via a tool call) |
| PL07 | info | A user turn looks like a prompt-extraction attempt (context for the findings above) |

## Usage

```sh
cd tools/promptleak
python3 promptleak.py examples/leaky_transcript.json          # 6 findings, exit 1
python3 promptleak.py examples/clean_transcript.json          # 1 info (attempt, no leak), exit 0
python3 promptleak.py examples/anthropic_session.jsonl        # PL03 fragment, exit 1
python3 promptleak.py -p examples/system_prompt.txt examples/model_output.txt --protect "BLUE HERON"
my_app --once | python3 promptleak.py -p prompts/system.txt - --fail-on high   # CI / guard
python3 promptleak.py logs/ -p prompts/system.txt --json --min-severity medium
```

Options: `-p/--prompt FILE` (repeatable; text, or a JSON/JSONL transcript whose system messages
are used), `--protect STRING` (repeatable), `-n` shingle size (min 3), `--span`, `--bulk`,
`--partial`, `--no-tools`, `--min-severity`, `--fail-on` (default `medium`, or `none`), `--json`.
Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage or input error.

Example output:

```
CRITICAL PL01 examples/leaky_transcript.json#msg3(assistant)
         100% of prompt 'system1' reproduced (1 spans, longest 97 words)
         > you are pennywise assistant the customer support agent for acme budget bank always answer ...
HIGH     PL06 examples/leaky_transcript.json#msg6(tool:send_email)
         base64-encoded text decodes to content of prompt 'system1'
INFO     PL07 examples/leaky_transcript.json#msg2(user)
         user turn resembles a prompt-extraction request
```

All example prompts, codenames and codes are fake (`FAKE-EXAMPLE-...`).

## Known limits

- **Verbatim only.** Paraphrases, summaries, translations, and leaks split into chunks shorter
  than *n* words are not detected. Lower `-n` for stricter checks at the cost of false positives
  from generic phrases ("if you are unsure, ...").
- Obfuscation handled: case, punctuation, whitespace, zero-width/Unicode-TAG characters,
  full-width forms, base64/base64url/hex. Not handled: ROT13, reversed text, letter spacing
  like "y o u  a r e", leetspeak, other encodings.
- A model legitimately quoting public parts of its prompt (e.g. a product list) will show as
  PL03; tune `--fail-on` or keep public text out of the prompt you pass with `-p`.
- PL04 and the text output show snippets of the reproduced prompt; treat promptleak reports
  as sensitive as the prompt itself. `--protect` values are masked.
- PL07 is a keyword heuristic for context only; it is neither complete nor a guardrail.
- It reads what was logged. It cannot see streamed output that was never written to the log.
