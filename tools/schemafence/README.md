# schemafence

Offline **tool-schema privilege auditor** for AI agent / MCP / OpenAI / Anthropic
tool definitions.

Before an agent can call tools, someone decided which parameters the model may
fill in. Unconstrained `command`, `url`, `path`, `to`, `api_key`, or `sql`
fields turn a single prompt injection into shell, SSRF, path traversal, email
exfil, credential harvest, or SQLi. schemafence reviews those *input schemas*
(not live calls) and reports privilege risks with tool and parameter
attribution.

Standard library only. It never connects to a network and never invokes a tool.

## How it differs from siblings

| Tool | Surface |
|---|---|
| **schemafence** | Static *inputSchema / parameters* privilege review |
| toolpoison | Poisoning / injection phrasing in tool *descriptions* |
| trifecta | Capability *combinations* (P/U/E/A) across the whole toolset |
| toolpin | Schema *drift* vs a hashed lockfile |
| toolgate | Runtime policy over *observed* tool-call arguments |
| mcpposture | MCP *client config* launch posture |

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| SK01 | critical | Unconstrained `command` / `shell` / `code` / `script` / `argv` parameter |
| SK02 | high | Unconstrained `url` / `uri` / `endpoint` / `webhook` parameter |
| SK03 | high | Unconstrained `path` / `filepath` / `directory` parameter |
| SK04 | high | Unconstrained `to` / `recipient` / `email` / `channel` / `phone` parameter |
| SK05 | medium | `additionalProperties: true` on a sensitive or consequential tool |
| SK06 | high | Model-supplied secret/credential parameter (`api_key`, `token`, `password`, …) |
| SK07 | high | Annotation contradiction (`readOnlyHint` / `destructiveHint` / `openWorldHint` vs params or name) |
| SK08 | medium | Consequential tool (shell / pay / delete / deploy) with no `required` params |
| SK09 | high | Unconstrained `sql` / `query` parameter on a data tool |
| SK10 | info | Inventory of tools and sensitive parameter names (disable in CI with `--disable SK10`) |

A parameter counts as **constrained** when its schema has a non-empty `enum`,
`const`, `pattern`, or an `oneOf`/`anyOf` of enums/consts. Plain
`type: string` (or untyped) is unconstrained.

## Usage

```
python3 schemafence.py tools.json [more.jsonl dir/ -]
  --disable RULE ...    skip rule ids (e.g. SK10 SK05)
  --json                machine-readable output
  --min-severity S      hide findings below S (default info)
  --fail-on S           exit 1 if any finding >= S (default high; any, none)
  --list-rules
```

Exit codes: `0` clean (below `--fail-on`), `1` findings, `2` usage / no readable
input. SK10 inventory alone does not fail the default `--fail-on high` gate.

Accepted shapes: MCP `tools/list` JSON-RPC `result.tools`, `{server, tools:[…]}`,
multi-server maps (`{ "fs": {tools:[…]}, "mail": […] }`), OpenAI
`{type:"function", function:{…}}` arrays, Anthropic `input_schema` tools,
JSONL of the above, directories, stdin (`-`).

## Example

```sh
python3 schemafence.py examples/risky_mcp.json --disable SK10
```

Flags SK01/SK03/SK05/SK07 on `run_shell`, SK02/SK06/SK07 on `fetch_url`, SK03/SK07
on `write_file`, SK04 on `send_email`, SK07/SK08 on `delete_record` /
`deploy_service`, SK09 on `run_sql` (exit 1). `examples/clean_openai.json` is
clean under `--fail-on high` (exit 0): cities/URLs/note ids are enum- or
pattern-constrained. See also `risky_anthropic.json`, `multi_server.json` and
`generic_tools.jsonl`.

## Known limits

- Heuristic parameter-name matching. A custom field named `target` that holds a
  shell string may be missed; rename detection is name-based, not semantic.
- Constraints are only what appears in the schema. Runtime allowlists enforced
  only in server code are invisible here — pair with mcpsink / toolgate.
- `additionalProperties` omitted (common) is not flagged; only explicit `true`.
- Annotation defaults differ across MCP clients; contradictions are best-effort.
- A clean schemafence result does not mean the tool implementation is safe.
