#!/usr/bin/env python3
"""schemafence: offline tool-schema privilege auditor for AI agent / MCP tool defs.

Reviews OpenAI function tools, Anthropic tools, and MCP tools/list (or multi-server
maps) *input schemas* for unconstrained high-privilege parameters: free-form
command/code, URL, path, recipient, secret, and SQL fields; additionalProperties
opened; annotation contradictions; consequential tools with no required args.

Complements toolpoison (description poisoning text), trifecta (capability mix across
the whole toolset), toolpin (schema drift vs a lockfile), and toolgate (runtime
policy over observed calls). Stdlib only; never connects to a network.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

VERSION = "0.1.0"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "SK01": ("critical", "Unconstrained command/shell/code/script parameter"),
    "SK02": ("high", "Unconstrained URL/URI/endpoint/webhook parameter (SSRF surface)"),
    "SK03": ("high", "Unconstrained path/filepath/directory parameter (traversal surface)"),
    "SK04": ("high", "Unconstrained recipient/to/email/channel/phone parameter (send/exfil)"),
    "SK05": ("medium", "additionalProperties opened on a sensitive tool schema"),
    "SK06": ("high", "Model-supplied secret/credential parameter (api_key/token/password)"),
    "SK07": ("high", "Annotation contradiction (readOnly/destructive/openWorld vs params)"),
    "SK08": ("medium", "Consequential tool (shell/pay/delete/deploy) with no required params"),
    "SK09": ("high", "Unconstrained SQL/query parameter on a data tool"),
    "SK10": ("info", "Inventory of tools and sensitive parameter names observed"),
}

COMMAND_KEYS = {
    "command", "cmd", "script", "code", "shell", "shell_command", "bash",
    "powershell", "argv", "program", "executable", "interpreter",
}
URL_KEYS = {
    "url", "uri", "href", "link", "endpoint", "webhook", "webhook_url",
    "callback", "callback_url", "target_url", "base_url", "host", "hostname",
}
PATH_KEYS = {
    "path", "filepath", "file_path", "filename", "file_name", "directory",
    "dir", "folder", "target_path", "dest", "destination", "src_path",
    "output_path", "input_path", "workdir", "cwd",
}
RECIPIENT_KEYS = {
    "to", "recipient", "recipients", "cc", "bcc", "email", "email_to",
    "to_address", "phone", "phone_number", "channel", "chat_id", "user_id",
    "webhook", "destination",
}
SECRET_KEYS = {
    "api_key", "apikey", "api_token", "access_token", "auth_token", "token",
    "password", "passwd", "secret", "secret_key", "private_key", "authorization",
    "bearer", "credentials", "credential", "client_secret", "refresh_token",
}
SQL_KEYS = {
    "sql", "query", "statement", "raw_sql", "sql_query", "cypher", "sparql",
}

SHELL_NAME_TOKENS = {
    "shell", "bash", "exec", "execute", "terminal", "command", "cmd",
    "powershell", "pwsh", "eval", "interpreter", "repl",
}
CONSEQUENTIAL_NAME_TOKENS = SHELL_NAME_TOKENS | {
    "delete", "remove", "rm", "drop", "pay", "payment", "transfer", "withdraw",
    "deploy", "publish", "destroy", "wipe", "kill", "terminate", "refund",
    "purchase", "buy", "force_push", "reset",
}
WRITE_PARAM_HINTS = COMMAND_KEYS | {
    "content", "body", "data", "payload", "text", "value", "bytes",
}
DESTRUCTIVE_PARAM_HINTS = {
    "path", "filepath", "file_path", "id", "name", "resource", "key", "target",
} | COMMAND_KEYS

PLACEHOLDER_RE = re.compile(
    r"(?i)^(null|none|n/?a|todo|tbd|example|placeholder|"
    r"\$\{?[A-Z0-9_]+\}?|<[^>]+>|your[-_].*|xxx+)$"
)


class Finding:
    __slots__ = ("rule", "severity", "source", "message", "tool", "param", "server")

    def __init__(self, rule, source, message, tool="", param="", server=""):
        self.rule = rule
        self.severity = RULES[rule][0]
        self.source = source
        self.message = message
        self.tool = tool
        self.param = param
        self.server = server

    def to_dict(self):
        d = {
            "rule": self.rule,
            "severity": self.severity,
            "title": RULES[self.rule][1],
            "source": self.source,
            "message": self.message,
            "tool": self.tool,
            "param": self.param,
        }
        if self.server:
            d["server"] = self.server
        return d


class ToolDef:
    __slots__ = ("source", "server", "name", "description", "schema", "annotations")

    def __init__(self, source, name, schema=None, description="", annotations=None, server=""):
        self.source = source
        self.server = server or ""
        self.name = name
        self.description = description or ""
        self.schema = schema if isinstance(schema, dict) else {}
        self.annotations = annotations if isinstance(annotations, dict) else {}


def _tokens(name: str):
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name or "")
    return [t for t in re.split(r"[^a-zA-Z0-9]+", s.lower()) if t]


def _key_tokens(key: str):
    return set(_tokens(key))


def _norm_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (key or "").lower())


def normalize_tool(raw, source="", server=""):
    """Return ToolDef or None for MCP/OpenAI/Anthropic shapes."""
    if not isinstance(raw, dict):
        return None
    if raw.get("type") == "function" and isinstance(raw.get("function"), dict):
        raw = raw["function"]
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    schema = raw.get("inputSchema") or raw.get("input_schema") or raw.get("parameters") or {}
    if not isinstance(schema, dict):
        schema = {}
    ann = raw.get("annotations") if isinstance(raw.get("annotations"), dict) else {}
    desc = raw.get("description") or raw.get("title") or ""
    return ToolDef(
        source=source,
        name=name.strip(),
        schema=schema,
        description=desc if isinstance(desc, str) else "",
        annotations=ann,
        server=server,
    )


def _unwrap_tools_payload(doc):
    """Yield (server, tool_dict) from common wrappers."""
    if isinstance(doc, list):
        for item in doc:
            if isinstance(item, dict):
                yield "", item
        return

    if not isinstance(doc, dict):
        return

    # JSON-RPC tools/list
    result = doc.get("result")
    if isinstance(result, dict) and isinstance(result.get("tools"), list):
        for t in result["tools"]:
            if isinstance(t, dict):
                yield "", t
        return

    # {server, tools:[...]}
    if isinstance(doc.get("tools"), list):
        server = doc.get("server") or doc.get("name") or ""
        if not isinstance(server, str):
            server = ""
        for t in doc["tools"]:
            if isinstance(t, dict):
                yield server, t
        return

    # multi-server map: { "fs": {tools:[...]}, "mail": [...] }
    looks_multi = False
    for k, v in doc.items():
        if k in ("jsonrpc", "id", "method", "error"):
            continue
        if isinstance(v, dict) and isinstance(v.get("tools"), list):
            looks_multi = True
            for t in v["tools"]:
                if isinstance(t, dict):
                    yield k, t
        elif isinstance(v, list) and v and all(isinstance(x, dict) and x.get("name") for x in v[:3]):
            looks_multi = True
            for t in v:
                if isinstance(t, dict):
                    yield k, t
    if looks_multi:
        return

    # bare single tool
    if doc.get("name") and (
        "inputSchema" in doc or "input_schema" in doc or "parameters" in doc or doc.get("type") == "function"
    ):
        yield "", doc


def extract_tools_from_obj(doc, source: str):
    tools = []
    for server, raw in _unwrap_tools_payload(doc):
        td = normalize_tool(raw, source=source, server=server)
        if td:
            tools.append(td)
    return tools


def load_tools(path: str):
    if path == "-":
        raw = sys.stdin.read()
        source = "<stdin>"
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
        source = path

    # JSONL of tools / wrappers
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    if len(lines) > 1:
        parsed = []
        jsonl_ok = True
        for ln in lines:
            try:
                parsed.append(json.loads(ln))
            except ValueError:
                jsonl_ok = False
                break
        if jsonl_ok and parsed and all(isinstance(x, (dict, list)) for x in parsed):
            tools = []
            for obj in parsed:
                tools.extend(extract_tools_from_obj(obj, source))
            if tools:
                return tools

    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise ValueError("%s: not valid JSON (%s)" % (source, e))

    return extract_tools_from_obj(doc, source)


def _schema_properties(schema: dict):
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties")
    return props if isinstance(props, dict) else {}


def _schema_required(schema: dict):
    req = schema.get("required") if isinstance(schema, dict) else None
    if isinstance(req, list):
        return {str(x) for x in req if isinstance(x, str)}
    return set()


def _prop_constrained(prop: dict) -> bool:
    """True if the property has a meaningful allow-constraint."""
    if not isinstance(prop, dict):
        return False
    if "enum" in prop and isinstance(prop["enum"], list) and len(prop["enum"]) > 0:
        return True
    if "const" in prop:
        return True
    if isinstance(prop.get("pattern"), str) and prop["pattern"].strip():
        return True
    # oneOf/anyOf of consts/enums
    for key in ("oneOf", "anyOf"):
        alts = prop.get(key)
        if isinstance(alts, list) and alts and all(
            isinstance(a, dict) and ("enum" in a or "const" in a) for a in alts
        ):
            return True
    # $ref to a constrained def is unknown offline — treat as unconstrained
    return False


def _prop_type(prop: dict):
    if not isinstance(prop, dict):
        return None
    t = prop.get("type")
    if isinstance(t, list):
        return t
    return t


def _is_stringish(prop: dict) -> bool:
    t = _prop_type(prop)
    if t == "string":
        return True
    if isinstance(t, list) and "string" in t:
        return True
    if t is None and not any(k in prop for k in ("properties", "items", "type")):
        # untyped — treat as string-capable
        return True
    return False


def _matches_key_set(name: str, keys: set) -> bool:
    n = (name or "").lower()
    if n in keys:
        return True
    nk = _norm_key(name)
    for k in keys:
        if _norm_key(k) == nk:
            return True
    # token overlap for multiword keys like "target_url"
    toks = _key_tokens(name)
    for k in keys:
        kt = _key_tokens(k)
        if kt and kt <= toks:
            return True
    return False


def _tool_name_tokens(name: str) -> set:
    return set(_tokens(name))


def _is_consequential_tool(name: str) -> bool:
    toks = _tool_name_tokens(name)
    if toks & CONSEQUENTIAL_NAME_TOKENS:
        return True
    lower = (name or "").lower()
    return any(
        x in lower
        for x in (
            "run_command", "execute_command", "run_shell", "run_terminal",
            "force_push", "rm_rf", "send_payment",
        )
    )


def _is_shell_tool(name: str) -> bool:
    toks = _tool_name_tokens(name)
    if toks & SHELL_NAME_TOKENS:
        return True
    lower = (name or "").lower()
    return any(x in lower for x in ("run_command", "execute_command", "run_shell", "run_terminal"))


def _is_data_query_tool(name: str) -> bool:
    toks = _tool_name_tokens(name)
    return bool(toks & {"sql", "query", "db", "database", "postgres", "mysql", "mongo", "sqlite"})


def _sensitive_props(schema: dict):
    """Return list of (name, prop, category) for sensitive-looking properties."""
    out = []
    for name, prop in _schema_properties(schema).items():
        if not isinstance(prop, dict):
            prop = {}
        if _matches_key_set(name, COMMAND_KEYS):
            out.append((name, prop, "command"))
        elif _matches_key_set(name, URL_KEYS):
            out.append((name, prop, "url"))
        elif _matches_key_set(name, PATH_KEYS):
            out.append((name, prop, "path"))
        elif _matches_key_set(name, RECIPIENT_KEYS):
            out.append((name, prop, "recipient"))
        elif _matches_key_set(name, SECRET_KEYS):
            out.append((name, prop, "secret"))
        elif _matches_key_set(name, SQL_KEYS):
            out.append((name, prop, "sql"))
    return out


def classify_tool(tool: ToolDef, disabled=None):
    disabled = set(disabled or [])
    findings = []
    schema = tool.schema or {}
    props = _schema_properties(schema)
    required = _schema_required(schema)
    ann = tool.annotations or {}
    label = tool.name
    if tool.server:
        label = "%s/%s" % (tool.server, tool.name)

    def add(rule, message, param=""):
        if rule in disabled:
            return
        findings.append(
            Finding(
                rule,
                tool.source,
                message,
                tool=tool.name,
                param=param,
                server=tool.server,
            )
        )

    sensitive = _sensitive_props(schema)

    for name, prop, cat in sensitive:
        constrained = _prop_constrained(prop)
        stringish = _is_stringish(prop) or _prop_type(prop) in ("array", None) or isinstance(
            _prop_type(prop), list
        )
        # arrays of strings still matter
        if cat == "command" and not constrained and (stringish or _prop_type(prop) == "array"):
            add(
                "SK01",
                "Tool %s accepts unconstrained %s parameter %r (command/code execution surface)"
                % (label, cat, name),
                param=name,
            )
        elif cat == "url" and not constrained and stringish:
            add(
                "SK02",
                "Tool %s accepts unconstrained URL parameter %r (SSRF / open-world fetch)"
                % (label, name),
                param=name,
            )
        elif cat == "path" and not constrained and stringish:
            add(
                "SK03",
                "Tool %s accepts unconstrained path parameter %r (traversal / sensitive-file surface)"
                % (label, name),
                param=name,
            )
        elif cat == "recipient" and not constrained and stringish:
            add(
                "SK04",
                "Tool %s accepts unconstrained recipient parameter %r (send/exfil surface)"
                % (label, name),
                param=name,
            )
        elif cat == "secret" and not constrained and stringish:
            add(
                "SK06",
                "Tool %s accepts model-supplied secret/credential parameter %r"
                % (label, name),
                param=name,
            )
        elif cat == "sql" and not constrained and stringish:
            add(
                "SK09",
                "Tool %s accepts unconstrained SQL/query parameter %r"
                % (label, name),
                param=name,
            )

    # Also flag SQL-like params by tool name even if key is generic "query"
    if _is_data_query_tool(tool.name):
        for name, prop in props.items():
            if not isinstance(prop, dict):
                continue
            if name.lower() in SQL_KEYS or name.lower() in ("q", "statement"):
                if not _prop_constrained(prop) and _is_stringish(prop):
                    if not any(f.rule == "SK09" and f.param == name for f in findings):
                        add(
                            "SK09",
                            "Data tool %s accepts unconstrained query parameter %r"
                            % (label, name),
                            param=name,
                        )

    # SK05 additionalProperties
    if schema.get("additionalProperties") is True and sensitive:
        add(
            "SK05",
            "Tool %s sets additionalProperties=true with sensitive params %s"
            % (label, ",".join(n for n, _, _ in sensitive)),
        )
    elif schema.get("additionalProperties") is True and _is_consequential_tool(tool.name):
        add(
            "SK05",
            "Consequential tool %s sets additionalProperties=true"
            % label,
        )

    # SK07 annotations
    read_only = ann.get("readOnlyHint")
    destructive = ann.get("destructiveHint")
    open_world = ann.get("openWorldHint")
    sens_cats = {c for _, _, c in sensitive}
    sens_names = {n.lower() for n, _, _ in sensitive}

    if read_only is True:
        if "command" in sens_cats:
            add(
                "SK07",
                "Tool %s has readOnlyHint=true but accepts command/code parameter"
                % label,
                param="readOnlyHint",
            )
        write_params = [
            n for n in props
            if n.lower() in {"content", "body", "data", "payload", "text", "value"}
            or _matches_key_set(n, WRITE_PARAM_HINTS - COMMAND_KEYS)
        ]
        # write_file style: path + content
        if any(n.lower() in {"content", "body", "data", "payload"} for n in props) and (
            "path" in sens_cats or any(_matches_key_set(n, PATH_KEYS) for n in props)
        ):
            add(
                "SK07",
                "Tool %s has readOnlyHint=true but looks like a write (path + content/body)"
                % label,
                param="readOnlyHint",
            )
        name_toks = _tool_name_tokens(tool.name)
        if name_toks & {"write", "update", "delete", "remove", "create", "put", "post", "send"}:
            add(
                "SK07",
                "Tool %s has readOnlyHint=true but name implies mutation"
                % label,
                param="readOnlyHint",
            )

    if destructive is False:
        name_toks = _tool_name_tokens(tool.name)
        if name_toks & {"delete", "remove", "rm", "drop", "destroy", "wipe", "truncate"}:
            add(
                "SK07",
                "Tool %s has destructiveHint=false but name implies destruction"
                % label,
                param="destructiveHint",
            )
        if "command" in sens_cats:
            add(
                "SK07",
                "Tool %s has destructiveHint=false but accepts command/code parameter"
                % label,
                param="destructiveHint",
            )

    if open_world is False and "url" in sens_cats:
        add(
            "SK07",
            "Tool %s has openWorldHint=false but accepts unconstrained-looking URL parameter"
            % label,
            param="openWorldHint",
        )

    # SK08 consequential with no required
    if _is_consequential_tool(tool.name):
        if props and not required:
            add(
                "SK08",
                "Consequential tool %s declares parameters but none are required"
                % label,
            )
        elif not props and not required:
            add(
                "SK08",
                "Consequential tool %s has empty/unspecified parameter schema"
                % label,
            )

    return findings


def collect_paths(args_paths):
    paths = []
    for p in args_paths:
        if p == "-":
            paths.append(p)
            continue
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [
                    d
                    for d in dirs
                    if d not in (".git", "node_modules", "__pycache__", ".venv", "venv")
                ]
                for fn in sorted(files):
                    if fn.endswith((".json", ".jsonl")):
                        paths.append(os.path.join(root, fn))
        else:
            paths.append(p)
    return paths


def format_table(findings, tool_count):
    lines = []
    lines.append(
        "schemafence %s — %d tool(s), %d finding(s)"
        % (VERSION, tool_count, len(findings))
    )
    if not findings:
        lines.append("No schema-privilege findings.")
        return "\n".join(lines)
    lines.append("")
    lines.append("%-6s %-8s %-28s %s" % ("RULE", "SEV", "TOOL", "MESSAGE"))
    lines.append("-" * 100)
    for f in findings:
        tool = f.tool or "-"
        if f.server:
            tool = "%s/%s" % (f.server, f.tool)
        lines.append(
            "%-6s %-8s %-28s %s"
            % (f.rule, f.severity, tool[:28], f.message[:70])
        )
        if f.param:
            lines.append("       param: %s" % f.param)
        if f.source:
            lines.append("       at:    %s" % f.source)
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="schemafence",
        description="Offline tool-schema privilege auditor for AI agent / MCP tool definitions.",
    )
    ap.add_argument(
        "paths",
        nargs="*",
        help="tool schema JSON/JSONL files or directories (or - for stdin)",
    )
    ap.add_argument("--disable", nargs="+", default=[], metavar="RULE", help="skip rule ids")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--min-severity", default="info", choices=SEVERITIES)
    ap.add_argument(
        "--fail-on",
        default="high",
        choices=SEVERITIES + ["any", "none"],
        help="exit 1 if any finding >= this severity (default high)",
    )
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version="schemafence " + VERSION)
    ns = ap.parse_args(argv)

    if ns.list_rules:
        for rid, (sev, title) in RULES.items():
            print("%s  %-8s  %s" % (rid, sev, title))
        return 0

    if not ns.paths:
        ap.print_help()
        return 2

    file_paths = collect_paths(ns.paths)
    if not file_paths:
        sys.stderr.write("schemafence: no readable inputs\n")
        return 2

    all_tools = []
    errors = 0
    for path in file_paths:
        try:
            all_tools.extend(load_tools(path))
        except (OSError, ValueError) as e:
            sys.stderr.write("schemafence: %s\n" % e)
            errors += 1

    if errors and not all_tools:
        return 2

    disabled = set(ns.disable or [])
    findings = []
    for tool in all_tools:
        findings.extend(classify_tool(tool, disabled=disabled))

    # SK10 inventory
    if "SK10" not in disabled:
        for tool in all_tools:
            sens = _sensitive_props(tool.schema or {})
            names = sorted({n for n, _, _ in sens})
            label = tool.name
            if tool.server:
                label = "%s/%s" % (tool.server, tool.name)
            msg = "Tool %s" % label
            if names:
                msg += " sensitive params: %s" % ",".join(names)
            else:
                msg += " (no sensitive-looking params)"
            findings.append(
                Finding(
                    "SK10",
                    tool.source,
                    msg,
                    tool=tool.name,
                    param=",".join(names),
                    server=tool.server,
                )
            )

    min_rank = SEV_RANK[ns.min_severity]
    shown = [f for f in findings if SEV_RANK[f.severity] >= min_rank]
    shown.sort(
        key=lambda f: (-SEV_RANK[f.severity], f.rule, f.server or "", f.tool or "", f.param or "")
    )

    if ns.json:
        print(
            json.dumps(
                {
                    "tool": "schemafence",
                    "version": VERSION,
                    "tools": [
                        {
                            "name": t.name,
                            "server": t.server,
                            "source": t.source,
                            "params": list(_schema_properties(t.schema).keys()),
                        }
                        for t in all_tools
                    ],
                    "findings": [f.to_dict() for f in shown],
                },
                indent=2,
            )
        )
    else:
        print(format_table(shown, len(all_tools)))

    actionable = [f for f in shown if f.rule != "SK10"]
    if ns.fail_on == "none":
        return 0
    if ns.fail_on == "any":
        return 1 if actionable else 0
    threshold = SEV_RANK[ns.fail_on]
    pool = shown if ns.fail_on == "info" else actionable
    if any(SEV_RANK[f.severity] >= threshold for f in pool):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
