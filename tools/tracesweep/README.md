# tracesweep

**tracesweep** scans AI agent transcripts and logs for secrets that leaked into the conversation. That covers API keys printed by a tool, tokens passed as tool-call arguments, and credentials the model repeated back. It attributes each finding to the place it surfaced: file, line or record, turn, role, tool name, and location kind. It also flags secrets that **propagated** across turns. For example, a key can first appear in a `cat .env` tool output and then show up again in the assistant's reply.

> **Honesty notice.** tracesweep is **pattern-based**. It **can miss secrets**: custom token formats, secrets split across messages, or encoded/obfuscated values. It **can also produce false positives**. It does **not** verify whether a key is live or valid, and it never contacts any service. A clean result does not prove that a transcript is free of secrets. Treat findings as leads to triage, and rotate any real credential that you find.

## Install

You only need Python 3.8+ (standard library only, no dependencies, no network access).

```sh
python3 tracesweep.py --help
# optional: cp tracesweep.py ~/bin/tracesweep && chmod +x ~/bin/tracesweep
```

## Inputs

| Format | Detection | Attribution |
|---|---|---|
| JSONL (one event per line). Covers Claude Code / Codex-style session logs and generic `{role, content, tool_name/name, tool_calls}` objects | most non-empty lines parse as JSON | line number = record; non-JSON lines are scanned as `text` |
| JSON array of messages (OpenAI chat format, including `tool_calls[].function.arguments` and `role: "tool"`), or an object with `messages`/`items`/`events` | whole file parses as JSON | record = array index (1-based); line = best-effort position in the file |
| Plain-text logs | everything else | line-numbered; `User:` / `Assistant:` / `Tool(bash):` prefixes set role/tool/turn |

Paths can be files, directories (searched recursively for `*.jsonl *.json *.log *.txt`; dot-directories are skipped), or `-` for stdin.

The JSON walk is generic. Role comes from `role`, `message.role`, `author.role`, or `type` (`user`/`assistant`/...). The tool name comes from `tool_use.name`, `function.name`, `tool_name`, or `name` on `role=tool`. Results are linked to their calls through `tool_use_id` / `call_id` / `tool_call_id`. Location is reported as `tool_args` (`input`, `arguments`, `tool_calls`), `tool_output` (`tool_result`, `function_call_output`, `role=tool`, `output`/`stdout`/`stderr`), `message`, or `text`. The turn is an explicit `turn`/`turn_index` field if present. Otherwise it is the ordinal of role-bearing records.

## Detectors

| Rule | Severity | Matches |
|---|---|---|
| TS-PRIVKEY | critical | PEM `-----BEGIN ... PRIVATE KEY-----` blocks (also a header alone, as in truncated output) |
| TS-AWS-AKID | high | AWS access key IDs `AKIA…`/`ASIA…` |
| TS-AWS-SECRET | critical | 40-char secret near `aws…secret… =`/`:` |
| TS-GITHUB | high | `ghp_ gho_ ghs_ ghu_ ghr_ github_pat_` |
| TS-ANTHROPIC | critical | `sk-ant-…` |
| TS-OPENAI | critical | `sk-…`, `sk-proj-…` (excluding `sk-ant-`) |
| TS-SLACK | high | `xoxb- xoxa- xoxp- xoxr- xoxs-` |
| TS-STRIPE | critical | `sk_live_…`, `rk_live_…` |
| TS-GOOGLE-API | high | `AIza…` (39 chars) |
| TS-JWT | medium | `eyJ….….…` where the header base64url-decodes to JSON containing `alg` |
| TS-URL-CREDS | high | `scheme://user:pass@host` (the password is the secret) |
| TS-GENERIC | medium | `password/secret/token/api_key/... = value` assignments, including JSON keys like `{"api_key": "..."}` |
| TS-ENTROPY | low | high-Shannon-entropy tokens (≥24 chars). **Off by default**; enable with `--entropy` (`--entropy-threshold`, default 4.0) |

**False-positive controls.** Obvious placeholders are skipped: values containing `EXAMPLE`, `xxxx`, `<token>`, `your_api_key`, `changeme`, `${VAR}`, `REDACTED`, `...`, or low-diversity bodies such as `AKIA0000000000000000`, plus literal `password`/`secret`. Generic rules also ignore `max_tokens`, `token_count`, numeric values, booleans, and `os.environ[...]` / `process.env` references. Pure-hex strings (hashes, UUIDs) never trigger the entropy rule. When rules overlap, the more specific rule wins.

**Echo detection.** Within one transcript, any secret seen in more than one turn is marked `echoed`. The finding then carries `occurrences`, `first_seen`, and a `propagation` path such as `tool_output(turn 3) -> message(turn 4)`. Once a secret has been found, tracesweep also looks for **verbatim re-appearances** in places that lack the original pattern context (for example, "I used password X"). Those findings have `"match": "echo"`.

**Masking.** Previews show the first 4 and last 2 characters (`AKIA...L3`). Secrets under 12 characters show only the first 2 (`sh***`), and PEM blocks show only their type (`[PEM RSA PRIVATE KEY]`). The full secret is never printed. JSON/SARIF include a 12-hex-character SHA-256 `fingerprint`, so you can correlate the same secret across files.

## Usage

```sh
python3 tracesweep.py session.jsonl                    # table
python3 tracesweep.py ~/agent-logs/                    # recursive
cat run.log | python3 tracesweep.py -                  # stdin
python3 tracesweep.py --json --min-severity high logs/ # machine-readable, high+ only
python3 tracesweep.py --sarif logs/ > tracesweep.sarif # SARIF 2.1.0 for code-scanning UIs
python3 tracesweep.py --entropy logs/                  # add noisy entropy fallback
python3 tracesweep.py --redact clean/ logs/            # write redacted copies
python3 tracesweep.py --list-rules
```

`--redact OUT` writes a copy of each input with every detected secret replaced by `[REDACTED:<rule>]`. That includes JSON-escaped and double-escaped forms, so JSON files remain valid JSON. OUT is a file for a single input and a directory (mirroring relative paths) otherwise. Redaction covers all findings, regardless of `--min-severity`. It is only as good as detection, so review the output before sharing it.

**Exit codes:** `0` means no findings at or above `--min-severity`. `1` means at least one finding. `2` means a usage error (bad flag, missing path, no inputs).

## Example output

The examples in `examples/` contain **synthetic, fake** keys that only match the token shapes. They are **not committed** (so secret scanners don't flag shape-valid fakes); generate them with `python3 examples/make_examples.py` before running the commands below. The test suite generates them automatically.

```
$ python3 tracesweep.py examples
SEV       RULE           FILE:LINE                        REC  TURN  ROLE       TOOL        WHERE        PREVIEW                ECHO
--------  -------------  -------------------------------  ---  ----  ---------  ----------  -----------  ---------------------  ----
MEDIUM    TS-GENERIC     examples/agent_run.log:3         3    3     tool       bash        text         hunt...ss              x2
HIGH      TS-URL-CREDS   examples/agent_run.log:4         4    4     tool       bash        text         Fak3...d!
MEDIUM    TS-GENERIC     examples/agent_run.log:5         5    5     assistant  -           text         hunt...ss              x2
HIGH      TS-AWS-AKID    examples/claude_session.jsonl:3  3    3     tool       Bash        tool_output  AKIA...L3
CRITICAL  TS-AWS-SECRET  examples/claude_session.jsonl:3  3    3     tool       Bash        tool_output  wJal...23
CRITICAL  TS-OPENAI      examples/claude_session.jsonl:3  3    3     tool       Bash        tool_output  sk-p...GH              x2
HIGH      TS-URL-CREDS   examples/claude_session.jsonl:3  3    3     tool       Bash        tool_output  Fak3...d!
CRITICAL  TS-OPENAI      examples/claude_session.jsonl:4  4    4     assistant  -           message      sk-p...GH              x2
HIGH      TS-GITHUB      examples/claude_session.jsonl:5  5    5     assistant  WebFetch    tool_args    ghp_...01
HIGH      TS-SLACK       examples/openai_chat.json:19     3    3     assistant  slack_post  tool_args    xoxb...01
MEDIUM    TS-JWT         examples/openai_chat.json:27     4    4     tool       slack_post  tool_output  eyJh...89
CRITICAL  TS-PRIVKEY     examples/openai_chat.json:31     5    5     assistant  -           message      [PEM RSA PRIVATE KEY]
CRITICAL  TS-STRIPE      examples/openai_chat.json:35     6    6     user       -           message      sk_l...ST
HIGH      TS-GOOGLE-API  examples/openai_chat.json:35     6    6     user       -           message      AIza...de
CRITICAL  TS-ANTHROPIC   examples/openai_chat.json:39     7    7     assistant  -           message      sk-a...xw

15 finding(s) (6 critical, 6 high, 3 medium) in 4 file(s); 2 secret(s) echoed across turns.
Propagation:
  examples/agent_run.log TS-GENERIC hunt...ss: text(turn 3) -> text(turn 5)
  examples/claude_session.jsonl TS-OPENAI sk-p...GH: tool_output(turn 3) -> message(turn 4)
Note: pattern-based; may miss secrets or flag false positives; keys are not verified as live.
```

Line 6 of `claude_session.jsonl` mentions `AKIAIOSFODNN7EXAMPLE` and `your_api_key`, and `clean.json` contains `OPENAI_API_KEY=your_api_key_here` and `max_tokens: 4096`. Both are correctly ignored.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The tests cover every detector, placeholder suppression, attribution fields (Claude Code JSONL, OpenAI chat JSON, Codex-style `function_call`/`function_call_output`, text logs), echo detection, masking (the full secret never appears in table/JSON/SARIF output), JSON/SARIF output, `--min-severity`, stdin, directory recursion, redaction, and exit codes.

## Limitations

- Regex/heuristic only, with no live-key verification and no provider API calls.
- Secrets split across chunks or messages, or base64/URL-encoded inside other data, are usually missed.
- Turn numbering is best-effort and depends on the log format. Echo detection is per file.
- Line numbers for pretty-printed JSON arrays are located by searching the raw text, so they are best-effort.
- Very large files are read fully into memory.

## License

MIT. See the [LICENSE](../../LICENSE) at the repository root.
