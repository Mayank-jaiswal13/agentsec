# shellfence

Offline **dangerous-shell-command auditor** for commands an AI agent actually ran
(or attempted) via Bash / shell / terminal tools.

When an agent can `Bash`, `run_command`, `shell`, or PowerShell, a prompt injection
or confused tool choice can steer it into `curl | bash`, `rm -rf /`, reverse shells,
`chmod 777`, force-pushes, publishes, firewall flushes, env exfil, or crontab
persistence. shellfence extracts those commands from saved transcripts (or a plain
command list), classifies each one, and reports findings with tool and turn
attribution.

Standard library only. It never executes a command and never contacts the network.

## How it differs from siblings

| Tool | Surface |
|---|---|
| **shellfence** | Shell *command strings* the agent requested via Bash/shell tools |
| pathfence | File *paths* inside read/write/shell/fs tool args |
| fetchfence | URL destinations the agent fetched (SSRF / OOB) |
| toolgate | Policy-as-code you write over any tool args (generic allow/deny) |
| yolocheck | Coding-agent *settings* (static permission/autonomy config) |
| hitlguard | Missing human approval before consequential tools |

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| SF01 | critical | Pipe-to-shell / remote script execution (`curl\|sh`, `wget\|bash`, `irm\|iex`) |
| SF02 | critical | Destructive wipe / disk destroy (`rm -rf /`, `mkfs`, `dd of=/dev/…`) |
| SF03 | high | Privilege escalation (`sudo`, `su -`, `doas`, `pkexec`, `runas`) |
| SF04 | critical | Reverse shell / remote listener (`nc -e`, `bash -i >& /dev/tcp`, `ncat`) |
| SF05 | critical | Eval of encoded or remote content (`base64\|bash`, `eval $(curl)`, …) |
| SF06 | high | Permission weakening (`chmod 777`, `chmod -R a+rwx`, `icacls Everyone:F`) |
| SF07 | high | Dangerous git mutation (`push --force`, `reset --hard`, `clean -fdx`) |
| SF08 | high | Publish / release / registry push (`npm publish`, `twine upload`, `docker push`) |
| SF09 | high | Firewall / network defense change (`iptables -F`, `ufw disable`, `nft flush`) |
| SF10 | medium | Environment / secret dump piped outbound (`printenv\|curl`, …) |
| SF11 | medium | Persistence install (`crontab`, systemd unit drop, LaunchAgent) |
| SF12 | info | Inventory of every observed shell command (disable in CI with `--disable SF12`) |

## Usage

```
python3 shellfence.py transcript.json [more.jsonl dir/ commands.txt -]
  --as-commands         treat inputs as plain command lists (one per line)
  --allow-command GLOB  fnmatch allowlist for the full command (repeatable)
  --disable RULE ...    skip rule ids (e.g. SF03 SF12)
  --json                machine-readable output
  --min-severity S      hide findings below S (default info)
  --fail-on S           exit 1 if any finding >= S (default high; any, none)
  --list-rules
```

Exit codes: `0` clean (below `--fail-on`), `1` findings, `2` usage / no readable input.
SF12 inventory alone does not fail the default `--fail-on high` gate.

Accepted shapes: OpenAI chat `tool_calls`, Anthropic `tool_use` blocks, generic
JSON/JSONL `{tool, args|arguments|command|cmd}` events, plain `.txt` command lists,
directories, stdin (`-`).

Shell-like tools are detected by name tokens (`Bash`, `shell`, `run_command`,
`execute_command`, `run_terminal`, `powershell`, `pwsh`, …). Command text is taken
from `command` / `cmd` / `script` / `argv` (and similar) argument keys.

## Example

```sh
python3 shellfence.py examples/risky_openai.json --disable SF12
```

Flags SF01 on `curl … | bash`, SF02+SF03 on `sudo rm -rf /`, SF04 on the
`/dev/tcp` reverse shell, SF05 on `base64 -d | bash`, SF06–SF08 on
`chmod 777` / force-push / `npm publish`, SF09–SF11 on firewall flush, env exfil
and crontab (exit 1). `examples/clean_openai.json` is clean (exit 0). See also
`risky_anthropic.json`, `generic_commands.jsonl` and `commands.txt`. All example
secrets/payloads are `FAKE-EXAMPLE-*` or reserved documentation IPs.

## Known limits

- Heuristic tool-name detection. A custom tool named `run_task` that takes
  `payload` may be missed unless you extract commands and pass `--as-commands`.
- Regex detectors will miss obfuscation (`$'rm\x20-rf\x20/'`, variables expanded
  at runtime, multi-stage decode that never appears as one string in the log).
- It analyzes what was saved. It cannot block a live shell; pair it with an OS
  sandbox, command allowlist, or toolgate policy in front of the agent.
- Benign admin workflows (intentional `sudo`, intentional `docker push`) will
  match — use `--allow-command` or `--disable` for known-good patterns in CI.
