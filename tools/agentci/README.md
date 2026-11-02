# agentci

Audits **GitHub Actions workflows that run AI agents** for prompt injection and excess privilege, offline.

Agent actions (Claude Code, Codex, Gemini CLI, `actions/ai-inference`, home-grown `claude -p` / `curl
api.openai.com` steps) are increasingly wired to `issues`, `issue_comment` and `pull_request_target`.
That means any GitHub user can write text that lands in an LLM prompt, and that LLM often holds a
write-scoped `GITHUB_TOKEN`, cloud secrets and a shell. This is the "prompt injection in CI" class
(sometimes called *PromptPwnd*). agentci finds the AI steps in your workflows and reports how
untrusted text reaches them, who can trigger them, and what they can do once hijacked.

Standard library only (it has its own small YAML-subset parser). No network.

## Rules

| Rule | Default severity | Finding |
|---|---|---|
| AC01 | critical (high outside the agent step) | Untrusted event text (`issue.title/body`, `comment.body`, `pull_request.title/body/head.ref`, `github.head_ref`, commit messages, `toJSON(github.event)`, ...) interpolated with `${{ }}` into the agent step, or into a `run`/`env`/prompt-like input of another step in the AI job |
| AC02 | medium (high for `*`) | Outsider trigger (`issues`, `issue_comment`, `pull_request_target`, `discussion*`, `workflow_run`, review events) with no `author_association` / actor / label gate in the job or step `if:`. `anthropics/claude-code-action` checks write access itself, so it is only flagged when `allowed_non_write_users` / `allowed_bots` is set |
| AC03 | critical (high for `gh pr checkout`) | `pull_request_target` / `workflow_run` job that checks out the PR head (or fetches `pull/N`), so the agent reads attacker-controlled `CLAUDE.md`, `AGENTS.md`, scripts and configs with secrets in scope |
| AC04 | low / medium / high | AI job token scope: no `permissions:` block (low), `write-all` (high), write to contents/actions/packages/pages/... (high with outsider triggers), `id-token: write` (high) |
| AC05 | critical with outsider triggers, else high | Agent shell/sandbox unlocked: `Bash(*)` or bare `Bash` in allowed tools, `--dangerously-skip-permissions`, `--dangerously-bypass-approvals-and-sandbox`, `danger-full-access`, Codex `safety-strategy: unsafe`, Gemini `--yolo`, `bypassPermissions`, approvals `never` |
| AC06 | medium / high / critical | Secrets reachable by the agent that are not model API keys (workflow, job or step `env`/`with`), and `toJSON(secrets)` (critical) |
| AC07 | low (medium for `@main`/no ref) | AI action not pinned to a full 40-character commit SHA |
| AC08 | low | `actions/checkout` in the AI job without `persist-credentials: false` (token left in `.git/config`) |
| AC09 | info | Inventory: which step is an AI agent and how it was recognised |

## Usage

```sh
cd tools/agentci
python3 agentci.py examples/risky              # 3 workflows, 26 findings, exit 1
python3 agentci.py examples/clean --fail-on any # 2 AI workflows, 0 findings, exit 0
python3 agentci.py                              # defaults to ./.github/workflows
python3 agentci.py .github/workflows --sarif > agentci.sarif
python3 agentci.py . --ai-action 'acme/review-bot*' --json --min-severity medium
```

Options: `--ai-action GLOB` (treat extra `owner/action` as an AI step, repeatable), `--disable RULE`,
`--min-severity` (default `low`; use `info` to see AC09 inventory), `--fail-on`
(`critical|high|medium|low|any|none`, default `high`), `--json`, `--sarif`, `--list-rules`.
Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage, missing path or YAML parse error.

Example output:

```
CRITICAL AC03 examples/risky/pr-review-target.yml:14 job=review step=actions/checkout@v4
         pull_request_target + checkout of '${{ github.event.pull_request.head.sha }}': the agent reads (and may run) attacker-controlled files ...
CRITICAL AC01 examples/risky/pr-review-target.yml:17 job=review step=Review
         ${{ github.event.pull_request.title }} in the agent step field 'with.prompt'; pass it via env and treat as data, ...
CRITICAL AC05 examples/risky/pr-review-target.yml:17 job=review step=Review
         --dangerously-skip-permissions; combined with untrusted trigger(s) this is remote code execution by prompt
HIGH     AC02 examples/risky/pr-review-target.yml:17 job=review step=Review
         allowed_non_write_users/allowed_bots is '*': any GitHub user can drive the agent via pull_request_target
```

## Fixing what it finds

- Never put `${{ github.event.* }}` text in a prompt. Let the agent fetch the issue with a read-only
  tool, or pass it through `env:` and tell the model it is untrusted data.
- Gate outsider triggers on `author_association` (OWNER/MEMBER/COLLABORATOR) or a maintainer-applied label.
- Give the AI job `permissions: contents: read` plus only the one write scope it needs; no `id-token`.
- Allow specific tools (`Bash(gh issue view:*)`), never `Bash(*)` or skip-permissions flags.
- Only the model key in the agent's environment. Pin actions to a SHA. `persist-credentials: false`.

## Known limits

- **Heuristic and static.** It reads YAML, not runtime behaviour. It does not know what an agent will do
  with the text it is given, and a clean report does not mean the workflow is safe.
- **AI step detection** uses a list of known action names and globs plus a regex for common CLIs and API
  hosts. Unusual wrappers, composite/reusable workflows (`uses: ./...` or `workflow_call`) and Docker
  actions are not followed; add them with `--ai-action`.
- **Indirect injection is not traced.** An agent that fetches an issue or PR body itself is still exposed
  to its content; agentci only flags the trigger/gate/permission side of that (AC02, AC04, AC05).
  Data flowing through step outputs (`steps.x.outputs.y`) into prompts is not followed.
- **Gate detection** is a regex over `if:` (author_association, actor, sender, label, ...). It cannot tell
  whether a condition is actually correct.
- **YAML subset.** Anchors/aliases, tags and complex keys are not supported; unusual files fail with a parse
  error (exit 2) instead of being guessed at. Action input names change between versions; checks use the
  names documented as of 2026.
- `claude-code-action`'s built-in write-access check is assumed to be on; other actions are assumed to have none.
