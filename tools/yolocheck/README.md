# yolocheck

Offline, stdlib-only Python 3 CLI that audits **coding-agent permission / autonomy settings files**
for risky over-permissioning: wildcard shell allows, interpreters and network tools on auto-approve,
bypass / YOLO modes, disabled sandboxes, hooks that run `curl | sh` or ship your env to a server,
filesystem scopes that include `/` or your home directory, and more. Each file gets a grade A–F.

Supported (best-effort) inputs:

| Harness | Files auto-discovered in directories | What is evaluated |
|---|---|---|
| Claude Code | `.claude/settings.json`, `.claude/settings.local.json` (pass `~/.claude/settings.json` explicitly) | `permissions.allow/deny/defaultMode/additionalDirectories`, `hooks`, `statusLine`, `apiKeyHelper` & other helpers, `enableAllProjectMcpServers` |
| OpenAI Codex CLI | `.codex/config.toml`, `config.toml` | `sandbox_mode`, `approval_policy`, `[sandbox_workspace_write] network_access / writable_roots`, `[profiles.*]`, `[projects.*] trust_level`, `notify` |
| Gemini CLI | `.gemini/settings.json` | yolo / approval mode keys, `autoAccept`, `tools.allowed`, `mcpServers.*.trust`, hooks |
| VS Code (Copilot agent) | `.vscode/settings.json` | `chat.tools.autoApprove`, `chat.tools.global.autoApprove`, `chat.tools.terminal.autoApprove` (and older terminal allow-list keys), `chat.tools.urls.autoApprove`, `chat.tools.edits.autoApprove` |
| Cursor (CLI-style permissions) | `.cursor/cli.json`, `.cursor/cli-config.json` | `permissions.allow/deny` with `Shell(...)`/`Read(...)`/`Write(...)`, plus recognizable allowlist / yolo / auto-run keys |

Files passed explicitly are recognized by content shape even with other names. JSONC (`//` and `/* */`
comments, trailing commas) is accepted.

## Honest limits — read this

- **Schemas are best-effort as of 2026 and may drift.** These harnesses change their settings keys often.
  yolocheck only reports what is literally in the file. When it meets an approval-related key, value,
  tool name or file shape it does not know, it reports **YC17 "unrecognized" (info)** instead of guessing.
- It does **not** know your harness's built-in defaults, managed/enterprise policy files, CLI flags you
  pass at launch, environment variables, or how multiple settings files merge at runtime. A clean file
  can still run in a risky mode if you launch with e.g. `--dangerously-skip-permissions`.
- Command analysis is prefix/token based. It cannot prove that an "allowed" narrow command (say, a
  package script) is not itself able to run arbitrary code. `npm run test:*` is only as safe as your
  `package.json`.
- Hook analysis is regex based (download-to-shell, env/secret + network, world-writable paths). It does
  not read the scripts the hooks call.
- YC07 (missing secret denies) only fires when reads are explicitly broad (broad Read allow, unrestricted
  shell, bypass/auto-run). Some harnesses allow reads inside the project by default; yolocheck does not
  assume that.
- Cursor IDE stores most of its allowlist outside of plain JSON files; only recognizable JSON shapes are checked.
- Grades are a coarse heuristic (100 minus 30/high, 10/medium, 3/low; any high caps at C), not a certification.
- No network access, no telemetry, no dependencies. Nothing leaves your machine.

## Install

Python 3.8+ (3.11+ for full TOML via `tomllib`; older versions use a minimal built-in TOML reader).

```bash
python3 yolocheck.py --help
chmod +x yolocheck.py && cp yolocheck.py ~/.local/bin/yolocheck   # optional
```

## Usage

```bash
yolocheck .                                   # discover settings files under the current repo
yolocheck ~/.claude/settings.json ~/.codex/config.toml
yolocheck . --min-severity medium             # hide low/info
yolocheck . --json > yolocheck.json
yolocheck . --sarif > yolocheck.sarif         # SARIF 2.1.0 for code-scanning UIs
yolocheck . --fail-on medium                  # CI gate
yolocheck . --disable YC17,YC05
yolocheck --list-rules
```

Exit codes: **0** no shown finding at/above `--fail-on` (default `high`; choices `high|medium|low|any|none`),
**1** such a finding exists, **2** errors (missing path, parse error, no settings files found in a directory).
`--fail-on` is evaluated on the findings left after `--min-severity`.

## Rules

| ID | Default severity | Title |
|---|---|---|
| YC01 | high | Unrestricted shell auto-approved |
| YC02 | high | Arbitrary-code interpreter auto-approved |
| YC03 | medium | Network tool auto-approved |
| YC04 | high | Privilege escalation auto-approved |
| YC05 | medium | Destructive or publishing command auto-approved |
| YC06 | medium | Unrestricted web fetch auto-approved |
| YC07 | medium | Secrets not protected while reads are broad |
| YC08 | high | Permission prompts bypassed |
| YC09 | high | Codex sandbox disabled (danger-full-access) |
| YC10 | high | Approvals disabled (approval_policy = never) |
| YC11 | medium | Sandbox network access enabled |
| YC12 | high | Global auto-approve / YOLO mode |
| YC13 | high | Hook/helper downloads-and-executes or exfiltrates |
| YC14 | medium | Hook/helper uses world-writable path |
| YC15 | high | Filesystem scope includes root or home |
| YC16 | medium | All project MCP servers auto-enabled |
| YC17 | info | Unrecognized key or shape |

Some rules emit a different severity per case (e.g. YC08 `acceptEdits` = low, YC10 `never` + read-only = low,
YC15 home directory = medium, YC12 Gemini `autoAccept` = low). `--list-rules` prints rationale and fix hints.

## Example output

`examples/risky/` is a **FAKE**, deliberately over-permissioned set (all 17 rules fire, exit 1);
`examples/clean/` is a tight set (0 findings, grade A, exit 0).

```text
$ python3 yolocheck.py examples/risky/.gemini/settings.json
yolocheck 0.1.0 - 1 file(s) scanned

examples/risky/.gemini/settings.json  [gemini]  grade F (score 17; 2 high, 2 medium, 1 low, 0 info)
  SEV     RULE  LINE  LOCATION                                 MESSAGE
  high    YC01  6     tools.allowed[0]                         Unrestricted shell auto-approved: run_shell_command
                      fix: Remove the wildcard; allow only specific, read-mostly commands (e.g. Bash(npm run test:*), Bash(git status)) and keep everything else on 'ask'.
  high    YC12  3     general.defaultApprovalMode              general.defaultApprovalMode = yolo (all tool calls auto-approved)
                      fix: Turn global auto-approve off; approve individual low-risk tools instead.
  medium  YC03  6     tools.allowed[1]                         Network tool auto-approved: run_shell_command(curl)
                      fix: Move network tools to 'ask' or deny; use a domain-restricted fetch tool (e.g. WebFetch(domain:docs.example.com)) instead.
  medium  YC12  9     mcpServers.random-server.trust           MCP server 'random-server' is trusted (its tool calls skip confirmation)
                      fix: Turn global auto-approve off; approve individual low-risk tools instead.
  low     YC12  5     tools.autoAccept                         tools.autoAccept is true (auto-accepts tool calls Gemini deems safe)
                      fix: Turn global auto-approve off; approve individual low-risk tools instead.

Total: 2 high, 2 medium, 1 low, 0 info
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT. See the [LICENSE](../../LICENSE) at the repository root.
