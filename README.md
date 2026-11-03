# agentsec

**agentsec** is a kit of 26 small, offline security tools for people building and running AI
agents: MCP servers and clients, coding agents, RAG pipelines and tool-calling apps.

Each tool is a single Python file that uses **only the standard library**. There is nothing to
`pip install`, no network calls, and no telemetry. Each tool has its own README, examples
built from fake data, and a unittest suite.

> **Status: experimental.** These tools were AI-built (see [How this was built](#how-this-was-built)).
> They are heuristic scanners meant to help a human reviewer. A clean result does not mean
> something is safe.

## The tools

| Tool | What it does | Try it |
|---|---|---|
| [toolpoison](tools/toolpoison/) | Scans MCP tool manifests and descriptions for tool poisoning: hidden instructions, invisible Unicode, exfiltration hints and cross-tool shadowing. It also diffs snapshots to catch "rug pulls" | `python3 toolpoison.py examples/poisoned.json` |
| [tracesweep](tools/tracesweep/) | Finds secrets that leaked into agent transcripts and logs, attributes each to its turn, role and tool, and flags secrets echoed across turns. Output can be masked, JSON, SARIF or redacted | `python3 examples/make_examples.py && python3 tracesweep.py examples` |
| [runledger](tools/runledger/) | Offline token and cost accounting for agent runs (OpenAI, Anthropic and generic usage logs), broken down per run, model, tool and session, with budget gates | `python3 runledger.py examples/ --budget 0.05` |
| [vibeaudit](tools/vibeaudit/) | Heuristic security-smell scanner for AI-written Python and JS/TS (eval, shell injection, TLS off, SQL string building, hardcoded secrets, unverified JWTs and more; 17 rules) | `python3 vibeaudit.py examples --shell` |
| [canarytrap](tools/canarytrap/) | Prompt-injection and exfiltration test harness: feeds canary-tagged payloads to your agent command and checks for canary echo, exfil URLs, forbidden actions and secret leaks | `python3 canarytrap.py run -- python3 examples/naive_agent.py` |
| [mcpposture](tools/mcpposture/) | Least-privilege and supply-chain auditor for MCP client configs (Claude Desktop, Cursor, VS Code, generic), with an A–F grade per server | `python3 mcpposture.py examples/risky_claude_desktop_config.json` |
| [rundiff](tools/rundiff/) | Behavioral diff of two agent runs: added, removed and reordered tool calls, argument diffs, result divergence, and new-surface risk notes (new hosts, paths, shell programs) | `python3 rundiff.py examples/baseline.jsonl examples/candidate.jsonl` |
| [scopefit](tools/scopefit/) | Least-privilege checker for GitHub tokens used by agents. It compares granted scopes or permissions with the REST calls the agent actually made | `python3 scopefit.py -g examples/classic_overprivileged_scopes.json -c examples/agent_transcript.jsonl` |
| [toolgate](tools/toolgate/) | Policy-as-code for agent tool calls. It can audit a transcript or act as a pre-tool-use hook that returns allow, warn or deny | `python3 toolgate.py audit examples/risky_transcript.json -p examples/strict_policy.json` |
| [slopcheck](tools/slopcheck/) | Flags hallucinated and slopsquatting-prone package names in AI-generated dependencies and imports (PyPI and npm), using a bundled snapshot of known package names | `python3 slopcheck.py examples/risky` |
| [ragsieve](tools/ragsieve/) | Scans documents for indirect prompt injection and exfiltration before they are ingested into a RAG knowledge base (hidden text, Unicode smuggling, exfil URLs, fake role tokens) | `python3 ragsieve.py examples/poisoned` |
| [yolocheck](tools/yolocheck/) | Grades coding-agent permission and autonomy settings (Claude Code, Codex CLI, Gemini CLI, VS Code Copilot, Cursor CLI) from A to F | `python3 yolocheck.py examples/risky` |
| [rulesguard](tools/rulesguard/) | Finds "rules file backdoors" in agent instruction files (AGENTS.md, CLAUDE.md, .cursorrules, .mdc rules, copilot-instructions and more) | `python3 rulesguard.py examples/risky` |
| [outfence](tools/outfence/) | Scans and sanitizes LLM *output* before it is rendered: zero-click exfiltration via markdown images and HTML/CSS, data- or secret-carrying links, dangerous URL schemes, terminal escapes (OSC 52 clipboard, OSC 8 links), invisible Unicode and `curl \| sh` suggestions | `python3 outfence.py examples` |
| [aibom](tools/aibom/) | AI bill of materials for a repo: LLM/agent SDKs, model IDs, weight files, AI endpoints, MCP servers, agent files and key env-var names, with governance notes (pickle weights, unpinned deps, floating model aliases) and a baseline diff to catch shadow AI in CI. Outputs text, JSON or CycloneDX 1.6 | `python3 aibom.py examples/sample_app --baseline examples/baseline.json` |
| [trifecta](tools/trifecta/) | Finds the "lethal trifecta" across an agent's whole toolset: private-data, untrusted-content and exfiltration tools (plus shell, delete and pay actions) available to the same agent, even when they are spread across MCP servers. It names the smallest group of tools to remove or gate. Reads MCP `tools/list`, OpenAI and Anthropic tool definitions | `python3 trifecta.py examples/agent` |
| [pickleprobe](tools/pickleprobe/) | Checks pickle-based model files (PyTorch `.pt`/`.pth`/`.ckpt`, `.pkl`, joblib, NumPy `.npy`/`.npz`, Keras `.keras`) for code-execution risk *without loading them*: dangerous imports like `os.system` or `exec`, unknown classes, pickles disguised as `.safetensors`, object arrays, Keras Lambda layers and path-traversal archive members | `python3 examples/make_examples.py && python3 pickleprobe.py examples/risky` |
| [promptleak](tools/promptleak/) | Detects system-prompt leakage in transcripts and model outputs: bulk or verbatim reproduction of the system/developer prompt, leaked confidential lines, protected strings, and prompt text smuggled out base64/hex-encoded in tool-call arguments. It also notes user turns that look like extraction attempts | `python3 promptleak.py examples/leaky_transcript.json` |
| [agentci](tools/agentci/) | Audits GitHub Actions workflows that run AI agents (Claude Code, Codex, Gemini CLI, `actions/ai-inference`, custom CLI/API steps) for prompt injection in CI: untrusted issue/PR/comment text in prompts, outsider triggers without an actor gate, `pull_request_target` checkouts of PR code, broad token scopes, unlocked shells and sandboxes, exposed secrets and unpinned actions | `python3 agentci.py examples/risky` |
| [mcpsink](tools/mcpsink/) | Taint scanner for Python MCP server *code*: follows tool, resource and `call_tool` arguments (which the model, or whoever injected it, controls) into shell commands, file paths, outbound URLs, SQL, `eval`/`pickle` and `os.environ`. It also flags servers bound to `0.0.0.0` and `readOnlyHint`/`destructiveHint` annotations that contradict the code | `python3 mcpsink.py examples/risky` |
| [agentcard](tools/agentcard/) | Audits A2A (Agent2Agent) Agent Cards (`agent-card.json`) with an A–F grade: agents anyone can call, anonymous `{}` requirements, plaintext or private/metadata-IP endpoints, inline keys, weak auth (query API keys, Basic, implicit/password OAuth), off-domain interfaces, unsigned cards, risky skills, and prompt injection hidden in skill descriptions that orchestrator LLMs read | `python3 agentcard.py examples/risky` |
| [loopguard](tools/loopguard/) | Finds runaway loops in agent transcripts: identical tool calls repeated back-to-back (critical when the tool sends, posts, deletes, pays or deploys), A-B-A-B cycles, error retry storms, polling that never makes progress, call-budget blowups and runs that end mid-tool-call. Reads OpenAI, Anthropic and generic JSON/JSONL | `python3 loopguard.py examples/runaway_openai.json` |
| [toolpin](tools/toolpin/) | Pins MCP tool definitions in a hashed lockfile and catches "rug pulls" later: description changes (escalated for injection phrasing, URLs, exfil words or hidden Unicode), new url/command/recipient parameters, dropped enums and loosened types, readOnly/destructive annotation flips, renames, new servers and cross-server tool shadowing. CI gate with `--fail-on` | `python3 toolpin.py check examples/drifted.json -l examples/toolpin.lock.json` |
| [resultguard](tools/resultguard/) | Scans *tool results* (the content tools return to the model) for indirect prompt injection: override/jailbreak phrasing, fake role tokens, hidden Unicode, tool-chaining bait, exfil/callback URLs, encoded instruction blobs, credential harvest and conceal-from-user instructions. OpenAI, Anthropic and generic transcripts, or standalone result files | `python3 resultguard.py examples/poisoned_openai.json` |
| [fetchfence](tools/fetchfence/) | Audits URLs an agent actually fetched (WebFetch, browse, http_get, …) for SSRF and destination risk: cloud metadata and link-local IPs, loopback, private networks, `file://` and other dangerous schemes, URL userinfo credentials, known callback/OOB hosts, cleartext http, IP literals, punycode, shorteners, secret query params and admin ports on non-public hosts | `python3 fetchfence.py examples/risky_openai.json` |
| [ctxbudget](tools/ctxbudget/) | Checks tool-result *size* against context-window budgets: absolute and critical byte caps, share-of-run, large base64/hex blobs, pathological line lengths, binary-looking content, result floods from one tool, run-wide totals and deep JSON nesting. Complements runledger (cost) and loopguard (loops) | `python3 ctxbudget.py examples/risky_openai.json` |

Run the "Try it" commands from inside the tool's folder (`cd tools/<name>`). Every tool
supports `--help` and `--json`. Eleven tools also emit SARIF (`--sarif`), and most have a `--fail-on` /
`--min-severity` switch for CI. Exit codes are consistent across the kit: `0` means clean,
`1` means findings at or above the threshold, and `2` means a usage or input error.

## Install and run

Requirements: **Python 3.10 or newer**. No third-party packages are needed.

```sh
git clone https://github.com/<owner>/agentsec.git
cd agentsec/tools/mcpposture
python3 mcpposture.py --help
python3 mcpposture.py ~/.cursor/mcp.json --json
```

Each tool is self-contained. You can copy a single `.py` file (plus any JSON data file next to it,
such as `scopefit_mapping.json`, `slopcheck_known.json` or `prices.json`) onto your `PATH`.

### Run the tests

```sh
python3 run_tests.py            # all 26 suites (or: make test)
python3 run_tests.py toolgate   # one tool
```

`run_tests.py` runs each suite in its own process. It fails if any suite fails **or runs zero
tests**. CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs the same script on
Python 3.10, 3.11, 3.12 and 3.13 on `ubuntu-latest` for every push and pull request.

## How this was built

- **AI-built.** The tools, tests and documentation were written by an AI coding agent working
  through a series of build sessions, one tool at a time. A human chose the direction and
  reviewed the result before release. Treat the code as you would any new, lightly reviewed
  open-source project: read it before relying on it.
- **What it was tested against.** Each tool ships with a unittest suite (1193 tests in total)
  and with example inputs built from **synthetic, fake data**: fake keys, fake transcripts,
  fake configs and fake documents. The tests check rule behavior, output formats and CLI exit
  codes against those fixtures. The tools have **not** been benchmarked against real-world
  corpora, real attack datasets, or the live schemas of every agent or MCP client they parse.
- **Known limits.**
  - *Observed versus inferred.* Tools that read transcripts (tracesweep, runledger, rundiff,
    scopefit, toolgate, promptleak) only see what was logged. They cannot see runtime side effects, real
    token scopes or unlogged calls. Some results are inferences: for example, scopefit maps
    endpoints to permissions using a best-effort subset of the GitHub docs, and slopcheck
    compares names with a bundled snapshot rather than the live registry. The tool READMEs say
    which outputs are observed and which are inferred, and unknown cases are reported as
    unmapped rather than guessed.
  - *Heuristics produce false positives and false negatives.* Most detectors are regex, AST or
    pattern based. Determined attackers can evade them, and benign text sometimes matches
    them. Use them as review aids and CI tripwires, not as a security boundary.
  - *Formats drift.* Config and transcript formats for agent tools change often. Parsers are
    best-effort as of 2026, and unrecognized shapes are reported (as `info`) rather than
    silently passed.
  - canarytrap is a smoke test. An agent "resisting" its payloads is not proof that the agent is
    robust to prompt injection.

## Repository layout

```
agentsec/
├── tools/<name>/        one folder per tool: <name>.py, README.md, tests/, examples/
├── run_tests.py         runs every suite, enforces the zero-test rule
├── Makefile             `make test`
├── .github/workflows/   CI (Python 3.10–3.13)
├── SECURITY.md  CONTRIBUTING.md  LICENSE
```

## License

MIT, see [LICENSE](LICENSE). All example secrets in this repository are fake.
