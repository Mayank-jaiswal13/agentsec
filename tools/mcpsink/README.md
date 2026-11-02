# mcpsink

Offline **taint scanner for Python MCP server code**. It finds where a tool's arguments end up.

An MCP tool's arguments are chosen by the model, and the model can be steered by anything it has read:
a web page, an issue, a poisoned document. So every `@mcp.tool()` parameter is attacker-controlled input.
mcpsink finds the tool, resource and `call_tool` handlers in a FastMCP or official-SDK server, treats their
parameters as tainted, follows them through assignments and same-file helper functions, and reports when
they reach a dangerous sink: a shell, a file path, an outbound URL, SQL, `eval`/`pickle`, or `os.environ`.
It also flags HTTP transports bound to `0.0.0.0` and tool annotations (`readOnlyHint`, `destructiveHint`)
that contradict what the code does.

Other agentsec tools look at what the server *says* (toolpoison: descriptions; trifecta: capability mix;
mcpposture: client configs). mcpsink reads the server's *implementation*.

Standard library only (`ast`). Nothing is imported or executed. No network.

## Rules

| Rule | Default severity | Finding |
|---|---|---|
| MS01 | critical (shell) / high (program) / low (argv) | Tool argument reaches `os.system`, `os.popen`, `subprocess.*(shell=True)`, `create_subprocess_shell` (critical); chooses the program, or is passed as code to `sh/python/node -c` (high / critical); sits in an argv list without a preceding `--` (low: option injection such as `git --upload-pack`) |
| MS02 | high | Tool argument used as a path for `open`, `os.remove`, `shutil.*`, `os.listdir`, `Path(...).read_text/write_text/unlink/...` without a containment check. With `resolve()`/`realpath` + `is_relative_to`/`commonpath`/`startswith` in the handler it drops to info |
| MS03 | high | Tool argument used as the URL/host for `requests`, `httpx`, `aiohttp`, `urllib.request`, `http.client`, `socket` or a `client`/`session` object (SSRF to `169.254.169.254`/localhost, exfiltration via URL). A `urlparse(...).hostname` check drops it to info |
| MS04 | high | Tool argument in the SQL text of `.execute()`/`executemany`/`executescript`/`text()`/`read_sql`: f-string/`%`/`+`/`.format` built queries, or a tool that runs caller-supplied SQL |
| MS05 | critical | Tool argument reaches `eval`, `exec`, `compile`, `__import__`/`importlib.import_module`, `pickle`/`dill`/`marshal` loads, `yaml.load` without `SafeLoader`, `torch.load`, `jinja2.Template`, `runpy` |
| MS06 | high | `os.getenv(arg)` / `os.environ[arg]` with a tool-chosen name, or a tool that returns the whole `os.environ` |
| MS07 | medium | Server bound to all interfaces: `host="0.0.0.0"` / `"::"` in `FastMCP(...)`, `run(...)`, `uvicorn.run(...)`, or `*.host = "0.0.0.0"` |
| MS08 | high / medium / low | `readOnlyHint=True` on a tool that writes/deletes files (high) or runs processes (medium); `destructiveHint=False` on a tool that writes/deletes (medium); writes, deletes or runs processes with no annotation at all (low) |
| MS09 | info | Inventory of handlers and the parameters treated as tainted |

Sanitizers it understands: `int()`/`float()`/`bool()`/`len()`, `shlex.quote` (commands), `os.path.basename`,
`secure_filename` and `Path(x).name` (paths), `urllib.parse.quote` (URLs), membership in an allowlist
(`if x not in ALLOWED:`), same-file helpers that contain a path or host check, and `re.fullmatch` (downgrades
the finding to low: the pattern still needs a human look). Parameters named `self`/`ctx`/`context` or
annotated `Context` are not tainted.

## Usage

```sh
cd tools/mcpsink
python3 mcpsink.py examples/risky                 # 2 servers, 13 handlers, 21 findings, exit 1
python3 mcpsink.py examples/clean --fail-on any   # 9 handlers, 0 findings, exit 0
python3 mcpsink.py src/ --min-severity info       # include guarded sinks and the handler inventory
python3 mcpsink.py server.py --sarif > mcpsink.sarif
python3 mcpsink.py . --decorator 'register_tool' --json
```

Options: `--decorator GLOB` (extra decorator that marks a tool handler, repeatable), `--disable RULE`,
`--min-severity` (default `low`), `--fail-on` (`critical|high|medium|low|any|none`, default `high`),
`--json`, `--sarif`, `--list-rules`. Suppress one line with `# mcpsink: ignore[MS02]` (or `# mcpsink: ignore`).
In a directory scan, only `.py` files that mention `mcp`/`FastMCP`/`call_tool` are analysed; files named
explicitly are always analysed. Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage error,
missing path or a Python syntax error.

Example output (from `examples/risky`):

```
CRITICAL MS01 examples/risky/files_server.py:33 handler=grep
         tool argument in a shell command via subprocess.run (shell=True): shell metacharacters run arbitrary commands; pass an argv list, no shell
CRITICAL MS05 examples/risky/files_server.py:66 handler=calc
         tool argument reaches eval: arbitrary code execution on the MCP host
CRITICAL MS01 examples/risky/files_server.py:87 handler=backup via _archive
         tool argument in a shell command via subprocess.run (shell=True): ...
HIGH     MS02 examples/risky/files_server.py:19 handler=read_file
         tool argument used as a path for .read_text() (read): '../' or absolute paths reach files outside the intended root (~/.ssh, .env); ...
MEDIUM   MS08 examples/risky/files_server.py:30 handler=grep
         tool declares readOnlyHint=True but performs process execution (subprocess.run): clients may auto-approve it as read-only; ...
```

`examples/clean/safe_server.py` has the same kinds of tools written defensively (resolved paths checked
with `is_relative_to`, a host allowlist, placeholders, an env-name map, `--` before a validated git ref).

## Known limits

- **Python only.** TypeScript/JavaScript MCP servers are not analysed.
- **Intraprocedural plus same-file helpers.** Taint is followed through assignments, loops, `with`,
  comprehensions and calls to functions or methods defined in the same file (up to 3 levels). A helper's return
  value counts as tainted when any argument was. Taint is not followed across modules, through class
  attributes or globals, or through framework magic (a Pydantic model parameter is one tainted value).
- **Flow-insensitive.** A variable is tainted if *any* assignment to it is tainted, and guards are detected
  per function by pattern, not proven to dominate the sink. An `is_relative_to` check anywhere in the
  handler downgrades every path finding in it. That is why guarded findings are `info`, not silent.
- **Sinks and sanitizers are lists.** Unusual libraries (custom HTTP wrappers, ORMs, `sh`, `plumbum`) are not
  recognised; a custom sanitizer the tool doesn't know about produces a false positive (use the inline ignore).
- **Annotation checks** only see literal `annotations={...}` / `ToolAnnotations(...)` values on the decorator.
- A clean report means "no known pattern matched", not "safe". Use it as a review aid and CI tripwire.
