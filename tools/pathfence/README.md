# pathfence

Offline **sensitive-path / path-traversal auditor** for file paths an AI agent actually
touched via tools.

When an agent can `read_file`, `write_file`, `apply_patch`, `Bash`, or use an MCP
filesystem server, a prompt injection or confused tool choice can steer it at `.env`
files, SSH keys, cloud credential stores, browser password DBs, `/etc/shadow`,
`docker.sock`, or paths outside the intended workspace. pathfence extracts those paths
from saved transcripts (or a plain path list), classifies each one, and reports
findings with tool and turn attribution.

Standard library only. It never runs an agent and never contacts the network.

## How it differs from siblings

| Tool | Surface |
|---|---|
| **pathfence** | File paths the agent *requested* via read/write/shell/fs tools |
| fetchfence | URL destinations the agent fetched (SSRF / OOB) |
| toolgate | Policy-as-code you write over any tool args (generic allow/deny) |
| yolocheck | Coding-agent *settings* (static permission/autonomy config) |
| tracesweep | Secret *values* that already appeared in transcript content |

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| PF01 | critical | Secret / credential files (`.env`, `*.pem`, `secrets.json`, tokens, netrc, …) |
| PF02 | critical | SSH / GPG private key paths (`~/.ssh/id_*`, `~/.gnupg/`, …) |
| PF03 | critical | Cloud credential paths (`.aws/credentials`, `.kube/config`, gcloud ADC, `.azure/`, …) |
| PF04 | high | Browser cookie / password / autofill database paths |
| PF05 | critical | OS identity paths (`/etc/shadow`, `/etc/passwd`, host SSH keys, …) |
| PF06 | high | Path traversal segments (`../`, `..\\`) |
| PF07 | high | Absolute / home path outside `--workspace` roots (opt-in) |
| PF08 | medium | Broad home-directory or dotfile reads (`~/`, `$HOME`, `~/.something`) |
| PF09 | high | Write/shell targeting a path already flagged as sensitive |
| PF10 | high | Container / hypervisor escape paths (`docker.sock`, `/proc/self`, `/sys`, …) |
| PF11 | high | Windows sensitive system paths (`…\config\SAM`, `Unattend.xml`, `ntds.dit`, …) |
| PF12 | info | Inventory of every observed path (disable in CI with `--disable PF12`) |

## Usage

```
python3 pathfence.py transcript.json [more.jsonl dir/ paths.txt -]
  --as-paths            treat inputs as plain path lists
  --allow-path GLOB     allowlist path (repeatable); still flags traversal + OS identity
  --workspace ROOT      expected workspace root (repeatable); enables PF07
  --disable RULE ...    skip rule ids (e.g. PF08 PF12)
  --json                machine-readable output
  --min-severity S      hide findings below S (default info)
  --fail-on S           exit 1 if any finding >= S (default high; any, none)
  --list-rules
```

Exit codes: `0` clean (below `--fail-on`), `1` findings, `2` usage / no readable input.
PF12 inventory alone does not fail the default `--fail-on high` gate.

Accepted shapes: OpenAI chat `tool_calls`, Anthropic `tool_use` blocks, generic
JSON/JSONL `{tool, args|arguments|path}` events, plain `.txt` path lists, directories,
stdin (`-`).

File-like tools are detected by name tokens (`read`, `write`, `edit`, `Bash`,
`apply_patch`, `list_dir`, …). Shell tools also have path-looking tokens mined from
the `command` / `cmd` string. Any tool whose arguments contain an obvious
`path` / `file` / `file_path` key is also considered.

## Example

```sh
python3 pathfence.py examples/risky_openai.json --disable PF12
```

Flags PF03 on `.aws/credentials`, PF01+PF06 on `../../.env`, PF02 on `~/.ssh/id_rsa`
(via Bash), and PF05+PF09 on the write to `/etc/shadow` (exit 1).
`examples/clean_openai.json` is clean (exit 0). See also `risky_anthropic.json`,
`generic_paths.jsonl` and `paths.txt`. All example secrets are `FAKE-EXAMPLE-*`.

## Known limits

- Heuristic tool-name and argument-key detection. A custom tool named `get_content`
  that takes `target` may be missed unless the value looks like a path; use
  `--as-paths` on an extracted list if needed.
- Shell-command path mining is regex-based and will miss obfuscated constructions
  (`$(echo /etc)/shadow`, base64-decoded paths, variables expanded at runtime).
- `--workspace` compares the *written* path string, not the resolved real path after
  symlinks or `..` normalization beyond the PF06 flag.
- It analyzes what was saved. It cannot block a live read; pair it with an OS
  sandbox, MCP fs root allowlist, or toolgate policy in front of the agent.
