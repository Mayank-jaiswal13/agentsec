# scopefit

**Offline least-privilege checker for GitHub tokens used by AI agents.**

You give scopefit two things:

1. **What the token was granted.** You type or paste this yourself. Two formats work: a fine-grained PAT / GitHub App permission map, or a classic OAuth scope list.
2. **What the agent actually called.** Either an agent transcript (JSON/JSONL) or a plain list of endpoints.

scopefit works out which permissions the observed GitHub REST calls need, using a bundled endpoint→permission mapping. It then reports:

- **OVER-GRANTED**: a permission was granted but never needed, or `write` was granted where `read` is enough. For classic tokens it also flags a scope as "broader than needed", e.g. `repo` when `repo:status` would do.
- **MISSING**: a call needed a permission the token doesn't have.
- **UNMAPPED** endpoints: calls scopefit doesn't know about. These are listed as unknown. scopefit never guesses their permissions.
- **HIGH-RISK grants**: `administration`, `secrets`, `workflows`/`actions` write, webhooks, `delete_repo`, `admin:org`, `workflow`, `repo`, and similar. Each one says whether the observed calls actually used it.
- **A suggested minimal grant**. For classic input, it also shows the fine-grained alternative, which is the better choice.

It is a single file of stdlib-only Python with no dependencies, and it makes **no network calls**.

## Important limitations (read these)

- **scopefit cannot see your real token's scopes.** It never calls GitHub. The grant is whatever *you* supply. If that file is wrong, the results are wrong. (A classic token's scopes show up in the `X-OAuth-Scopes` response header. Fine-grained permissions appear in the token settings page.)
- **Observed usage covers only the runs you give it.** Future runs, other prompts, or error paths may need more permissions. Treat the suggestion as a starting point and re-check after changes.
- **GraphQL is not covered.** GraphQL calls (`gh api graphql`, `POST /graphql`) are counted and reported but not analyzed.
- **The mapping is a subset.** `scopefit_mapping.json` covers 77 common endpoints: contents, issues, pulls, comments, labels, Actions runs/workflows/dispatches, releases, branches/protection, commits, statuses/checks, repo metadata, user, orgs/members, gists, hooks, secrets, deployments, search, and rate_limit. It is a **best-effort** reading of the GitHub REST docs and **may be out of date or wrong**. Anything else is reported as UNMAPPED. Some endpoints depend on context (for example, writing to `.github/workflows/` also needs `workflows`; commenting on a PR may need `pull_requests`). Those cases are noted in the mapping rather than modeled.
- Classic tokens: by default scopefit assumes **private** repos (`repo`). Pass `--public-repos` if the agent only touches public repos; then `public_repo` is used, or no scope at all for reads.
- Extraction is heuristic. It reads tool-call **arguments** only, never tool results: `method`+`url`/`path`/`endpoint` fields, plus `curl` and `gh api` commands inside shell strings. Named MCP tools such as `create_issue` are not mapped to endpoints.

## Install

Requires Python 3.8+. You don't need to install anything:

```bash
python3 scopefit.py --help
```

Keep `scopefit_mapping.json` next to `scopefit.py`, or pass `--mapping FILE`.

## Usage

```bash
# classic token vs. an agent transcript
python3 scopefit.py --grants examples/classic_overprivileged_scopes.json --calls examples/agent_transcript.jsonl

# fine-grained grant vs. an endpoint list, JSON output, fail only on missing permissions
python3 scopefit.py -g examples/fine_grained_tight.json -c examples/endpoints.txt --json --fail-on missing
```

| Option | Meaning |
|---|---|
| `-g/--grants FILE` | Granted permissions (see formats below) |
| `-c/--calls FILE` | Transcript (JSON/JSONL) or endpoints text; repeatable |
| `--grant-type auto\|fine\|classic` | Force the grant format |
| `--calls-format auto\|transcript\|endpoints` | Force the calls format (auto: a leading `{`/`[` means transcript) |
| `--public-repos` | Use the classic scopes for public repos |
| `--mapping FILE` | Use an alternate mapping JSON |
| `--json` | Machine-readable output |
| `--fail-on over\|missing\|any\|none` | Policy (default `any`) |

**Exit codes:** `0` = OK, `1` = policy failed, `2` = error (bad file, bad arguments).

### Grant formats

```json
{"contents": "write", "issues": "read", "pull_requests": "read"}
```
```json
["repo", "workflow", "read:org"]
```
YAML-ish files work too: `Issues: read and write` lines (names as shown in the GitHub UI are normalized), `- repo` lists, `scopes: repo, gist`, or `{"permissions": {...}}` / `{"scopes": [...]}` wrappers. Classic scope implication is applied: `repo` ⇒ `repo:status`, `repo_deployment`, `public_repo`, `repo:invite`, `security_events`; `admin:org` ⇒ `write:org` ⇒ `read:org`; `user` ⇒ `read:user`, `user:email`, `user:follow`; and so on. For fine-grained tokens, `metadata:read` is treated as implicit.

### Call formats

- **Transcripts:** OpenAI chat `tool_calls` (JSON-string arguments), the legacy `function_call`, Responses-style `function_call` items, Anthropic `tool_use` blocks, and generic `{"tool": ..., "args": ...}` events.
- **Endpoint lists:** one `METHOD path` per line. `#` starts a comment.

Full URLs, `api.github.com`, GHES `/api/v3`, query strings, `:owner` placeholders, and concrete owners/repos/numbers are all normalized to templates.

## Example output

The over-privileged classic token in `examples/` checked against a fake triage-agent transcript (exit code 1):

```text
scopefit 0.1.0 - grant type: classic OAuth scopes
Observed calls: 8 (mapped 6, unmapped 1, graphql 1)

ENDPOINTS USED (deduplicated):
  METHOD  ENDPOINT                                              FINE-GRAINED                       CLASSIC  N
  ------  ----------------------------------------------------  ---------------------------------  -------  -
  GET     /repos/{owner}/{repo}/issues                          issues:read, metadata:read         repo     1
  POST    /repos/{owner}/{repo}/issues/{issue_number}/labels    issues:write, metadata:read        repo     1
  GET     /repos/{owner}/{repo}/pulls/{pull_number}             metadata:read, pull_requests:read  repo     1
  GET     /repos/{owner}/{repo}/commits/{ref}/status            metadata:read, statuses:read       repo     1
  POST    /repos/{owner}/{repo}/issues/{issue_number}/comments  issues:write, metadata:read        repo     1
  GET     /repos/{owner}/{repo}/contents/{path+}                contents:read, metadata:read       repo     1

OVER-GRANTED:
  SCOPE            WHY
  ---------------  ------------------------------
  admin:org        never needed by observed calls
  admin:repo_hook  never needed by observed calls
  delete_repo      never needed by observed calls
  gist             never needed by observed calls
  user             never needed by observed calls
  workflow         never needed by observed calls

MISSING (needed but not granted):
  (none)

HIGH-RISK GRANTS:
  GRANT            USED  RISK
  ---------------  ----  ----------------------------------------------------------------------
  admin:org        NO    full control of organizations, teams and memberships
  admin:repo_hook  NO    can create/delete repo webhooks (exfiltration channel)
  delete_repo      NO    can permanently delete repositories
  repo             yes   full read/write to ALL private repositories the user can access
  user             NO    can modify the user profile
  workflow         NO    can modify GitHub Actions workflows (CI code execution, secret access)

UNMAPPED ENDPOINTS (unknown to scopefit; permissions NOT guessed - check GitHub docs):
  METHOD  ENDPOINT                             N
  ------  -----------------------------------  -
  GET     /repos/{owner}/{repo}/traffic/views  1
  note: 1 GraphQL call(s) seen; GraphQL is NOT analyzed.

SUGGESTED MINIMAL GRANT (observed usage only):
  ["repo"]
  (fine-grained alternative, preferred: {"contents": "read", "issues": "write", "metadata": "read", "pull_requests": "read", "statuses": "read"})
  WARNING: unmapped/GraphQL calls may need more than this suggestion.

Summary: 6 over-granted, 0 missing, 6 high-risk, 1 unmapped.
Mapping is a best-effort SUBSET from GitHub docs and may be out of date; future runs may need more.
Policy --fail-on any: FAIL
```

The same transcript checked against `examples/fine_grained_tight.json`: 0 over-granted, 0 missing, exit 0.

## Tests

```bash
python3 -m unittest -v
```

## License

MIT. See the [LICENSE](../../LICENSE) at the repository root. All example data is fake.
