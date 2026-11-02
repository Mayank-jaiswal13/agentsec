# trifecta

Offline **"lethal trifecta"** analyzer for an AI agent's toolset.

An agent can be made to leak data by prompt injection when one session can do all three of these:
**(P)** read private data, **(U)** take in untrusted content, and **(E)** send data out. A good
example is a filesystem MCP server, a `fetch` tool and a `send_email` tool loaded in the same
client. No single server looks dangerous, but together they give an attacker a complete path: a
web page tells the agent to read `~/.ssh` and mail it out.

`trifecta` reads the tool definitions an agent is given and tags each tool with the legs it
provides, plus **(A)** for consequential actions such as shell, delete, pay or deploy. It then
reports the risky combinations across the **whole** toolset, including combinations that span
several servers. For each one it names the smallest group of tools you would need to remove or
put behind human approval to break it.

Standard library only (Python 3.10+). It never connects to a server.

## Input

Pass one or more JSON files or directories. Directories are searched recursively for `*.json`,
and `-` reads stdin. Each file counts as one server, named after the file unless the file has a
`"server"` key. The tool can read these shapes:

- MCP `tools/list` output: `{"result": {"tools": [...]}}` or `{"tools": [...]}`, using
  `inputSchema` and `annotations` (`readOnlyHint`, `destructiveHint`, `openWorldHint`)
- OpenAI function tools: `[{"type": "function", "function": {...}}]`
- Anthropic tools: `[{"name", "description", "input_schema"}]`
- several servers in one file: `{"servers": {"github": {"tools": [...]}, "mail": [...]}}`

To capture MCP definitions, save each server's `tools/list` response (for example from the MCP
Inspector) into one folder and point `trifecta` at that folder.

## Usage

```sh
python3 trifecta.py examples/agent                     # exit 1: lethal trifecta found
python3 trifecta.py examples/safe --tags examples/tags.json --fail-on any   # exit 0
python3 trifecta.py tools/ --json
python3 trifecta.py tools/ --ignore 'github/get_me' --min-severity medium
```

| Option | Meaning |
|---|---|
| `--tags FILE` | Overrides: `{"overrides": {"server/tool or tool glob": ["private", "untrusted", "exfil", "action"]}}`. The list replaces the inferred tags, and `[]` means "this tool has no risky capability". |
| `--ignore GLOB` | Skip matching tools. Can be repeated. |
| `--json` | Machine-readable output with per-tool evidence. |
| `--min-severity` | Hide findings below this severity. |
| `--fail-on` | `critical`, `high` (default), `medium`, `low`, `any` or `none`. |

Exit codes: `0` means nothing at or above `--fail-on`, `1` means findings at or above it, and
`2` means a usage or input error.

## Rules

| Code | Severity | Meaning |
|---|---|---|
| TF01 | critical | Private + untrusted + exfil tools are all available. The finding lists each leg, notes when the legs span servers, and suggests the smallest leg to remove or gate. |
| TF02 | high | A single tool both takes in untrusted content and can send data out, for example `fetch(url)`, since data can leave in the query string. |
| TF03 | high | Untrusted content and consequential-action tools together (injection-to-action). |
| TF04 | medium | Private + exfil with no untrusted source yet. Adding one more tool completes the trifecta. |
| TF05 | medium | Private + untrusted with no exfil tool yet. Indirect channels may still exist. |
| TF06 | info | The tool could not be classified. Review it and tag it with `--tags`. |

TF04 and TF05 are not reported when TF01 fires, because TF01 already covers them.

## Example

```
$ python3 trifecta.py examples/agent
  -UE- fetch/fetch                U: fetches caller-chosen URL 'url'; E: arbitrary URL parameter 'url' ...
  P--- filesystem/read_file       P: name reads file
  PU-- mail/search_inbox          P: name reads inbox; U: name ingests inbox
  --E- mail/send_email            E: name verb send
  PUEA mail/run_shell             P: general command/code execution (name: run/shell); ...
[CRITICAL] TF01 Lethal trifecta: private data + untrusted content + exfiltration channel
    4 private / 3 untrusted / 3 exfil tools are available to the same agent across servers
    fetch, filesystem, mail. Break it by removing or human-gating the untrusted leg: ...
```

## How tagging works (and its limits)

Tags come from heuristics, and every tag records its evidence:

- tool-name tokens (snake_case and camelCase are split), as verb and noun pairs: `read`/`list`/`search` with
  `file`/`inbox`/`db` gives private, `send`/`post`/`upload` gives exfil, and `create` with
  `issue`/`comment` gives exfil
- schema parameters: an unrestricted `url`/`uri`/`link` (no `enum` or `const`) adds exfil and
  untrusted, a `to`/`recipient`/`cc`/`bcc` parameter adds exfil, and a `command`/`code`/`script`
  parameter adds all four legs
- description phrases (for example "the internet", "confidential", "sends an email") and MCP
  annotations. With `readOnlyHint: true`, exfil inferred from verbs is dropped, but exfil
  through URL or recipient parameters is kept.

Known limits:

- **It is not a proof.** Names and descriptions can lie: a malicious server can describe an
  exfil tool as harmless, and pairing trifecta with `toolpoison` helps here. Benign tools can also be
  over-tagged.
- It only sees the tools you give it. Indirect exfiltration channels are out of scope. These
  include rendered markdown images (see `outfence`), files written to synced folders, and
  links the user clicks.
- "Private" and "untrusted" depend on context. A GitHub `get_file_contents` tool counts as
  private for a private repo but untrusted for a public one. Use `--tags` to say which.
- It works on one toolset at a time. If your client turns tools on per conversation, run it
  once for each profile.
- English-centric keyword lists, best-effort as of 2026.

The legs follow Simon Willison's "lethal trifecta" framing of prompt-injection data theft.
All example tool definitions are fake.
