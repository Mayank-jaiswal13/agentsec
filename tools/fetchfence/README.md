# fetchfence

Offline **SSRF / destination-risk auditor** for URLs an AI agent actually requested.

When an agent can `WebFetch`, browse, `http_get` or otherwise retrieve a URL, a prompt
injection or confused tool choice can steer it at cloud-metadata endpoints, private
networks, callback/OOB hosts, credentialed URLs or `file://` paths. fetchfence extracts
those destinations from saved transcripts (or a plain URL list), classifies each
scheme/host/port/query, and reports findings with tool and turn attribution.

Standard library only. It never runs an agent and never contacts the network.

## How it differs from siblings

| Tool | Surface |
|---|---|
| **fetchfence** | Destinations the agent *requested* via fetch/browse/http tools |
| toolgate | Policy-as-code you write over any tool args (generic allow/deny) |
| mcpposture | MCP *client config* (launchers, roots, env) — not observed calls |
| outfence | Model *output* before it is rendered to a user |
| scopefit | GitHub token scopes vs observed REST calls |

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| FF01 | critical | Cloud metadata / link-local destinations (`169.254.169.254`, `metadata.google.internal`, …) |
| FF02 | high | Loopback / `localhost` / `::1` |
| FF03 | high | Private RFC1918, ULA or other non-public IPs |
| FF04 | critical | Dangerous schemes (`file`, `gopher`, `dict`, `ftp`, `jar`, `data`, …) |
| FF05 | high | Credentials in URL userinfo (`https://user:pass@…`) |
| FF06 | high | Known OOB / callback hosts (`webhook.site`, `interact.sh`, `ngrok`, …) |
| FF07 | medium | Cleartext `http://` fetches |
| FF08 | medium | Raw IP-literal hosts (bypass name-based allowlists) |
| FF09 | medium | Punycode / IDN hosts (`xn--…`) |
| FF10 | low | URL shortener hosts (`bit.ly`, `t.co`, …) |
| FF11 | medium | Secret-looking query parameters (`api_key=`, `token=`, …) |
| FF12 | medium | Admin / data-store ports (6379, 9200, 27017, 2375, …) on non-public hosts |
| FF13 | high | Internal / corporate hostname suffixes (`.internal`, `.corp`, `.lan`, `.cluster.local`, …) |

## Usage

```
python3 fetchfence.py transcript.json [more.jsonl dir/ urls.txt -]
  --as-urls           treat inputs as plain URL lists
  --allow-host GLOB   allowlist host (repeatable); still flags userinfo + dangerous schemes
  --disable RULE ...  skip rule ids (e.g. FF07 FF10)
  --json              machine-readable output
  --min-severity S    hide findings below S (default info)
  --fail-on S         exit 1 if any finding >= S (default high; any, none)
  --list-rules
```

Exit codes: `0` clean (below `--fail-on`), `1` findings, `2` usage / no readable input.

Accepted shapes: OpenAI chat `tool_calls`, Anthropic `tool_use` blocks, generic
JSON/JSONL `{tool, args|arguments|url}` events, plain `.txt` URL lists, directories,
stdin (`-`).

Fetch-like tools are detected by name tokens (`fetch`, `browse`, `WebFetch`, `http_get`,
`open_url`, …). Any tool whose arguments contain an obvious `url`/`uri`/`href` key is
also considered.

## Example

```sh
python3 fetchfence.py examples/risky_openai.json
```

Flags FF01/FF07/FF08 on the metadata IP, FF06 on `webhook.site`, FF03/FF05/FF08/FF12 on
the private Redis URL, and FF11 on the `api_key` query (exit 1).
`examples/clean_openai.json` is clean (exit 0). See also `risky_anthropic.json`,
`generic_fetches.jsonl` and `urls.txt`. All secrets and callback IDs in examples are
`FAKE-EXAMPLE-*`.

## Known limits

- Heuristic tool-name and argument-key detection. A custom tool named `get_content` that
  takes `target` may be missed unless the value looks like a URL; rename detection via
  `--as-urls` on an extracted list if needed.
- Host allowlists are name-based. An allowlisted name that resolves (at runtime) to a
  private IP is invisible offline — fetchfence only sees the written URL.
- Callback-host and shortener lists are fixed snapshots; novel domains need FF05/FF11
  phrasing or a deny list you enforce elsewhere.
- It analyzes what was saved. It cannot block a live fetch; pair it with an egress proxy
  or toolgate policy in front of the agent.
