# mcpposture

An offline, standard-library-only Python 3 CLI that audits **MCP (Model Context
Protocol) client configuration files** for least-privilege and supply-chain
risk: plaintext secrets, unpinned `npx`/`uvx` packages, privileged Docker
launches, over-broad filesystem roots, shell-capable servers, plaintext or
credential-bearing remote URLs, and more. It prints masked findings, a
per-server risk summary and an overall A–F grade.

> **Honesty note.** mcpposture is a **static config review only**. It never
> launches servers, resolves packages or touches the network. It **cannot see
> what a server actually does at runtime** (a perfectly pinned package can
> still be malicious), it **cannot verify token scopes or whether a key is
> live**, and every rule is a heuristic with false positives and false
> negatives (e.g. MP07 "shell-capable" is name-based). A grade of **A means
> "no smells found by these rules"**, not "safe".

## What it does

- Reads Claude Desktop `claude_desktop_config.json`, Cursor `.cursor/mcp.json`,
  VS Code `.vscode/mcp.json` (top-level `servers` + `inputs`) and
  `settings.json` (`"mcp": {"servers": ...}`), Windsurf/Cline/Gemini-style
  files, and generic `{"mcpServers": {...}}`.
- Understands stdio servers (`command`/`args`/`env`/`cwd`) and remote servers
  (`url`/`serverUrl`/`httpUrl`, `headers`, `type: sse|http|streamable-http`).
- Tolerates JSONC (`//` and `/* */` comments, trailing commas).
- Directory mode walks the tree (skipping `node_modules`, `.git`, venvs…) and
  picks up `claude_desktop_config.json`, `mcp.json`, `.mcp.json`,
  `mcp_config.json`, `mcp_settings.json`, `cline_mcp_settings.json`,
  `settings.json`, and any `*mcp*.json`. Files without MCP servers are skipped.
- Recognises launchers `npx`, `bunx`, `pnpx`, `pnpm dlx`, `yarn dlx`,
  `npm exec`, `bun x`, `uvx`, `uv tool run`, `pipx run`, `docker run`,
  `podman run` and checks the package / image for exact pins.
- Secret values are **always masked** (`ghp_****(40 chars)`). `${VAR}`,
  `${env:VAR}`, `${input:id}`, `$VAR`, `%VAR%`, `<your-token>`, `xxxx` etc.
  are treated as placeholders and not flagged.

## Install

No dependencies. Python 3.8+.

```bash
cp mcpposture.py ~/bin/mcpposture && chmod +x ~/bin/mcpposture
# or just: python3 mcpposture.py <paths>
```

## Usage

```bash
python3 mcpposture.py ~/Library/Application\ Support/Claude/claude_desktop_config.json
python3 mcpposture.py .                      # discover configs under the project
python3 mcpposture.py .cursor/mcp.json --json
python3 mcpposture.py . --sarif > mcpposture.sarif
python3 mcpposture.py . --min-severity high  # only high/critical (and exit on them)
python3 mcpposture.py . --select MP01,MP02,MP09   # only secret rules
python3 mcpposture.py . --ignore MP07 --exit-zero
python3 mcpposture.py --list-rules
```

| Option | Meaning |
|---|---|
| `--json` / `--sarif` | machine output (SARIF 2.1.0, with rule metadata + line numbers) |
| `--min-severity {info,low,medium,high,critical}` | report threshold **and** exit-code threshold (default `low`; `info` shows duplicate notices) |
| `--select IDS` / `--ignore IDS` | comma-separated rule ids |
| `--exit-zero` | exit 0 even with findings (parse/usage errors still exit 2) |
| `--no-color` | no ANSI colours (also honours `NO_COLOR`) |

**Exit codes:** `0` no findings at/above threshold · `1` findings · `2` usage
error, missing path, or unparsable config.

**Scoring:** each finding adds critical 40 / high 20 / medium 8 / low 3 / info 0
to its server. Grade: A = 0, B < 10, C < 25, D < 50, F ≥ 50. The overall grade
is the worst server's score plus any VS Code `inputs` findings.

## Example output

`examples/vscode-project` (exit code 1):

```text
mcpposture 0.1.0 - static MCP config posture review (offline; heuristics, not runtime analysis)

== examples/vscode-project/.vscode/mcp.json
   MEDIUM   MP03 L13   [perplexity] package 'server-perplexity-ask' launched via npx with no exact version
            evidence: server-perplexity-ask
            fix: Pin an exact version (pkg@1.2.3, pkg==1.2.3, image@sha256:...) and review upgrades deliberately.
   LOW      MP16 L5    [input:perplexity-key] input 'perplexity-key' looks secret but lacks "password": true
            evidence: perplexity-key
            fix: Add "password": true to the input definition.
   LOW      MP04 L13   [perplexity] npx -y auto-installs without confirmation
            evidence: npx -y
            fix: Pin the version; preferably install once to a vetted location and run the local binary.

Per-server summary:
  SERVER      TRANSPORT  LAUNCHER  PACKAGE                PINNED  SECRETS  FINDINGS  SCORE  GRADE
  ----------  ---------  --------  ---------------------  ------  -------  --------  -----  -----
  github      http       remote    -                      -       0        0         0      A    
  perplexity  stdio      npx       server-perplexity-ask  NO      0        2         11     C    
  local-dev   sse        remote    -                      -       0        0         0      A    

Overall grade: C (score 14 = worst server + input findings) | servers: 3 | files: 1 | critical: 0, high: 0, medium: 1, low: 2, info: 0
```

`examples/risky_claude_desktop_config.json` triggers MP01–MP15 (34 findings,
grade F; all secrets in it are fake). Excerpt with `--select MP01,MP05,MP06,MP08`:

```text
== examples/risky_claude_desktop_config.json
   CRITICAL MP05 L27   [docker-tools] container runs --privileged (full host device & capability access)
            evidence: --privileged
   CRITICAL MP05 L27   [docker-tools] container adds Linux capability SYS_ADMIN
            evidence: --cap-add SYS_ADMIN
   CRITICAL MP05 L27   [docker-tools] Docker socket mounted into container (equivalent to root on host)
            evidence: -v /var/run/docker.sock:/var/run/docker.sock
   CRITICAL MP05 L27   [docker-tools] host root filesystem mounted into container: /:/host
            evidence: -v /:/host
   HIGH     MP01 L4    [github] inline secret in env GITHUB_PERSONAL_ACCESS_TOKEN (GitHub classic PAT)
            evidence: GITHUB_PERSONAL_ACCESS_TOKEN=ghp_****(40 chars)
   HIGH     MP06 L11   [filesystem] filesystem server granted filesystem root: /
            evidence: /
   HIGH     MP06 L11   [filesystem] filesystem server granted entire home directory: ~
            evidence: ~
   HIGH     MP01 L15   [aws-everything] inline secret in env AWS_ACCESS_KEY_ID (AWS access key id)
            evidence: AWS_ACCESS_KEY_ID=AKIA****(20 chars)
   HIGH     MP01 L15   [aws-everything] inline secret in env AWS_SECRET_ACCESS_KEY (secret-named key 'AWS_SECRET_ACCESS_KEY')
            evidence: AWS_SECRET_ACCESS_KEY=fake****(40 chars)
   HIGH     MP01 L15   [aws-everything] inline secret in env STRIPE_API_KEY (secret-named key 'STRIPE_API_KEY')
...
```

`examples/clean_mcp.json` (pinned versions, digest-pinned image, `${VAR}`
references, narrow filesystem root, https remote) → no findings, grade A,
exit 0. Scanning the whole `examples/` dir at `--min-severity info` also shows
MP17/MP18 duplicate notices.

## Rules

| ID | Severity | Name | What it flags | Fix hint |
|---|---|---|---|---|
| MP01 | high | inline-secret | Secret value is stored in plaintext in the config file (env, header, or arg); config files get synced, shared, committed and read by other tools. | Reference it instead: ${VAR}/${env:VAR}, VS Code ${input:id} with password:true, or an OS keychain/secret manager. |
| MP02 | high | inline-bearer-token | Authorization header carries a literal Bearer/Basic credential. | Use ${input:...}/${env:...} substitution or the client's OAuth flow instead of a pasted token. |
| MP03 | medium | unpinned-package | Package/image is fetched at launch without an exact version (or @latest); a compromised or hijacked release runs with your privileges on next start. | Pin an exact version (pkg@1.2.3, pkg==1.2.3, image@sha256:...) and review upgrades deliberately. |
| MP04 | low | auto-install-no-prompt | `npx -y`/`--yes` installs whatever resolves without confirmation. | Pin the version; preferably install once to a vetted location and run the local binary. |
| MP05 | high | docker-privileged | Container launched with privileges that weaken isolation (privileged, host network/pid/ipc, added caps, host root or docker.sock mounts, unconfined seccomp/apparmor). | Drop the flag; mount only the specific directories needed, read-only where possible; never mount docker.sock. |
| MP06 | high | broad-filesystem-root | Filesystem-type server is granted an over-broad root (/, ~, $HOME, a whole user profile, drive root, /etc ...), exposing SSH keys, browser profiles, cloud creds. | Grant only the project directories the agent needs. |
| MP07 | medium | shell-capable-server | Server is launched through a shell or looks like a shell/terminal/exec MCP server (heuristic, by name). Such servers give the model arbitrary command execution. | Prefer narrowly-scoped servers; require per-call confirmation; run in a sandbox/container with no secrets. |
| MP08 | high | plaintext-remote | Remote MCP server reached over plain http:// / ws:// to a non-localhost host; traffic and tokens can be read or modified in transit. | Use https:// (wss://). |
| MP09 | high | credential-in-url | Remote URL embeds credentials in userinfo or a secret-looking query parameter; URLs leak into logs, history and proxies. | Move the credential to a header populated from ${input:...}/${env:...} or use OAuth. |
| MP10 | high | untrusted-exec-path | Command or script runs from a world-writable/temp/download location that other users or processes can replace. | Install the binary/script to a user-owned, non-writable-by-others location. |
| MP11 | critical | pipe-to-shell | Launch arguments download and execute remote code (curl\|sh, wget\|bash, iex(iwr ...)) on every start. | Download, verify (checksum/signature), and pin a local copy. |
| MP12 | medium | broad-scope-credential | Credential type cannot be narrowly scoped or is long-lived (GitHub classic PAT ghp_, AWS long-term AKIA key, live payment key). Actual scopes cannot be verified offline. | Use fine-grained/short-lived credentials (github_pat_ fine-grained, AWS SSO/STS role, restricted keys). |
| MP13 | low | secret-concentration | Many secret-bearing variables are handed to a single server, enlarging blast radius if it is compromised. | Split responsibilities; give each server only the credential it needs. |
| MP14 | high | tls-verification-disabled | Environment disables TLS certificate verification (NODE_TLS_REJECT_UNAUTHORIZED=0, PYTHONHTTPSVERIFY=0, ...). | Remove the override; add a proper CA bundle if needed (NODE_EXTRA_CA_CERTS / SSL_CERT_FILE). |
| MP15 | medium | code-injection-env | Environment sets loader/interpreter injection variables (LD_PRELOAD, DYLD_INSERT_LIBRARIES, NODE_OPTIONS --require, PYTHONSTARTUP...). | Remove unless strictly required and the referenced code is trusted. |
| MP16 | low | unmasked-secret-input | VS Code `inputs` entry looks like a secret but is not declared with "password": true, so it is echoed when typed. | Add "password": true to the input definition. |
| MP17 | info | duplicate-server-name | Same server name defined in multiple files; which one wins depends on the client and precedence can surprise you. | Rename or remove one definition. |
| MP18 | info | duplicate-package | Same package/image launched by more than one server entry (possibly with different versions/credentials). | Consolidate into a single entry. |

Some MP05 sub-checks are raised to **critical** (`--privileged`, `docker.sock`
mounts, host `/` mounts, `--cap-add ALL/SYS_ADMIN/...`); `--device` is medium.

## Limitations

- **Static config review only.** No server is started and no package is
  downloaded; what a server *does* (tools it exposes, files it reads, network
  calls it makes) is invisible. Pair with runtime controls, sandboxing and
  tool-description review (see `toolpoison` in this kit).
- **Token scopes cannot be verified offline.** MP12 only reasons about token
  *type* by prefix (classic `ghp_` PATs can't be repo-scoped; `AKIA` keys are
  long-lived and might be root/IAM-user keys). A fine-grained token may still be
  over-privileged; a flagged one may be tightly scoped.
- **Heuristics have false positives and negatives.** Secret detection relies on
  key names and known token shapes; custom secret formats or oddly named keys
  are missed, and long non-secret values under secret-like names may be
  flagged. MP07 matches names like `shell`, `terminal`, `exec`, `ssh`,
  `desktop-commander`. MP06 only inspects positional args of filesystem-looking
  servers.
- Pinning to an exact version reduces surprise upgrades but does not prove the
  pinned release is benign; lockfiles/digests and provenance checks are out of
  scope.
- Client-specific precedence (global vs. project configs, env inheritance,
  `envFile`, keychain integrations) is not modelled.
- Line numbers point at the server's name key, not the exact offending value.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT. See the [LICENSE](../../LICENSE) at the repository root.
