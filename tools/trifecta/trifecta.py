#!/usr/bin/env python3
"""trifecta - offline "lethal trifecta" analyzer for an AI agent's toolset.

An agent is exposed to prompt-injection data theft when the SAME agent session can
  (P) read private data, (U) ingest untrusted content, and (E) send data out.
trifecta reads the tool definitions an agent is given (MCP tools/list results,
OpenAI function tools, Anthropic tools), tags each tool heuristically with the
legs it provides (plus A = consequential action: shell, delete, pay, deploy),
and reports risky combinations across the whole toolset, with the smallest set
of tools to remove to break each combination.

Standard library only. Never connects to anything.
Exit codes: 0 = nothing at/above --fail-on, 1 = findings at/above it, 2 = usage/input error.
"""
import argparse
import fnmatch
import json
import os
import re
import sys

__version__ = "0.1.0"

LEGS = ("private", "untrusted", "exfil", "action")
SHORT = {"private": "P", "untrusted": "U", "exfil": "E", "action": "A"}
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

READ_VERBS = {"read", "get", "list", "search", "query", "fetch", "open", "view", "find",
              "lookup", "retrieve", "load", "show", "cat", "export", "download", "browse",
              "scrape", "crawl", "inspect", "describe", "history", "summarize", "extract"}
SEND_VERBS = {"send", "post", "publish", "upload", "share", "forward", "reply", "notify",
              "tweet", "push", "submit", "invite", "broadcast", "sms", "mms",
              "transmit", "exfiltrate"}
CREATE_VERBS = {"create", "add", "new", "make", "write", "update", "edit", "file"}
EXTERNAL_WRITE_NOUNS = {"issue", "issues", "comment", "comments", "pr", "gist", "post",
                        "posts", "message", "messages", "tweet", "page", "event", "ticket",
                        "invite", "email", "review", "discussion", "release", "webhook",
                        "status", "reply", "thread", "pull", "request"}
ACTION_TOKENS = {"delete", "remove", "rm", "drop", "truncate", "kill", "terminate", "transfer",
                 "pay", "payment", "purchase", "buy", "deploy", "overwrite", "move", "rename",
                 "merge", "revoke", "destroy", "wipe", "write", "chmod", "install", "refund",
                 "withdraw", "trade", "sell", "approve", "reset", "format", "shutdown"}
SHELL_TOKENS = {"shell", "bash", "exec", "execute", "terminal", "command", "cmd", "powershell",
                "sh", "eval", "interpreter", "repl"}
CODE_RUN = {("run", "code"), ("run", "python"), ("run", "script"), ("run", "command"),
            ("execute", "code"), ("code", "interpreter")}
PRIVATE_NOUNS = {"file", "files", "dir", "directory", "folder", "fs", "filesystem", "email",
                 "emails", "mail", "inbox", "gmail", "outlook", "calendar", "events", "contact",
                 "contacts", "drive", "doc", "docs", "document", "documents", "sheet", "sheets",
                 "spreadsheet", "db", "database", "sql", "table", "tables", "record", "records",
                 "secret", "secrets", "credential", "credentials", "vault", "password",
                 "passwords", "keychain", "env", "token", "tokens", "memory", "memories", "note",
                 "notes", "customer", "customers", "user", "users", "profile", "account",
                 "accounts", "crm", "invoice", "invoices", "transaction", "transactions", "bank",
                 "balance", "clipboard", "screenshot", "screen", "photo", "photos", "location",
                 "health", "message", "messages", "chat", "dm", "slack", "channel", "repo",
                 "repository", "source", "employee", "employees", "payroll", "patient"}
UNTRUSTED_NOUNS = {"web", "url", "urls", "uri", "page", "pages", "webpage", "website", "site",
                   "http", "html", "browser", "rss", "feed", "news", "tweet", "tweets",
                   "social", "reddit", "google", "bing", "internet", "email", "emails", "mail",
                   "inbox", "gmail", "message", "messages", "chat", "slack", "discord", "issue",
                   "issues", "comment", "comments", "pr", "review", "reviews", "ticket",
                   "tickets", "pdf", "attachment", "attachments", "youtube", "transcript",
                   "forum", "mentions", "notifications", "feedback", "submissions"}
UNTRUSTED_VERBS = {"browse", "scrape", "crawl", "download"}
URL_PROPS = {"url", "uri", "link", "href", "endpoint", "webhook_url", "callback_url",
             "target_url", "image_url", "src"}
RECIPIENT_PROPS = {"to", "recipient", "recipients", "cc", "bcc", "webhook", "phone_number",
                   "to_address", "email_to"}
COMMAND_PROPS = {"command", "cmd", "script", "code", "shell_command"}

DESC_RX = {
    "private": re.compile(r"\b(private|personal|confidential|internal|sensitive|credentials?|"
                          r"secrets?|api keys?|passwords?|local files?|file ?system|"
                          r"database|customer data|medical|financial records?)\b", re.I),
    "untrusted": re.compile(r"\b(web ?pages?|websites?|the internet|search the web|web search|"
                            r"any url|arbitrary url|incoming (mail|messages?|e-?mails?)|"
                            r"third[- ]party content|user[- ]submitted|untrusted|public "
                            r"(posts?|comments?|issues?))\b", re.I),
    "exfil": re.compile(r"\b(sends? (an? )?(e-?mail|message|sms|request|data)|posts? to|"
                        r"uploads? (to|files?)|publish(es)? |webhook|http (post|put|request)|"
                        r"outbound|to any (url|host|recipient))", re.I),
    "action": re.compile(r"\b(executes? (shell|commands?|code|scripts?)|permanently delet|"
                         r"irreversibl|transfers? (funds|money)|places? (an )?orders?|deploy)",
                         re.I),
}

RULES = {
    "TF01": ("critical", "Lethal trifecta: private data + untrusted content + exfiltration channel"),
    "TF02": ("high", "Single tool both ingests untrusted content and can send data out"),
    "TF03": ("high", "Untrusted content + consequential action (injection-to-action)"),
    "TF04": ("medium", "Private data + exfiltration, one untrusted source away from the trifecta"),
    "TF05": ("medium", "Private data + untrusted content, one exfiltration channel away"),
    "TF06": ("info", "Tool could not be classified; tag it with --tags"),
}


class InputError(Exception):
    pass


# ---------------------------------------------------------------- parsing

def tokens(name):
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name or "")
    return [t for t in re.split(r"[^a-zA-Z0-9]+", s.lower()) if t]


def normalize_tool(raw):
    """Return (name, description, schema, annotations) or None for MCP/OpenAI/Anthropic shapes."""
    if not isinstance(raw, dict):
        return None
    if raw.get("type") == "function" and isinstance(raw.get("function"), dict):
        raw = raw["function"]
    name = raw.get("name")
    if not isinstance(name, str) or not name:
        return None
    schema = raw.get("inputSchema") or raw.get("input_schema") or raw.get("parameters") or {}
    ann = raw.get("annotations") if isinstance(raw.get("annotations"), dict) else {}
    desc = raw.get("description") if isinstance(raw.get("description"), str) else ""
    return name, desc, schema if isinstance(schema, dict) else {}, ann


def _tool_list(obj):
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        if isinstance(obj.get("tools"), list):
            return obj["tools"]
        res = obj.get("result")
        if isinstance(res, dict) and isinstance(res.get("tools"), list):
            return res["tools"]
    return None


def load_doc(obj, default_server):
    """Return list of (server, rawtool). Raises InputError on unknown shapes."""
    out = []
    if isinstance(obj, dict) and isinstance(obj.get("servers"), dict):
        for srv, val in obj["servers"].items():
            lst = _tool_list(val)
            if lst is None:
                raise InputError("server %r: no tool list found" % srv)
            out.extend((srv, t) for t in lst)
        return out
    lst = _tool_list(obj)
    if lst is None:
        raise InputError("no tool list found (expected a list, {tools: [...]}, "
                         "{result: {tools: [...]}} or {servers: {...}})")
    server = default_server
    if isinstance(obj, dict) and isinstance(obj.get("server"), str):
        server = obj["server"]
    return [(server, t) for t in lst]


def load_paths(paths):
    entries = []
    files = []
    for p in paths:
        if p == "-":
            files.append(("-", "stdin"))
        elif os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                for n in sorted(names):
                    if n.endswith(".json"):
                        files.append((os.path.join(root, n), os.path.splitext(n)[0]))
        elif os.path.isfile(p):
            files.append((p, os.path.splitext(os.path.basename(p))[0]))
        else:
            raise InputError("no such file or directory: %s" % p)
    if not files:
        raise InputError("no .json tool definition files found")
    for path, server in files:
        try:
            if path == "-":
                text = sys.stdin.read()
            else:
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
            obj = json.loads(text)
        except (OSError, ValueError) as e:
            raise InputError("%s: %s" % (path, e))
        entries.extend(load_doc(obj, server))
    return entries


# ---------------------------------------------------------------- classification

def _props(schema):
    props = schema.get("properties") if isinstance(schema, dict) else None
    return props if isinstance(props, dict) else {}


def _restricted(prop):
    return isinstance(prop, dict) and ("enum" in prop or "const" in prop)


class Tool:
    def __init__(self, server, name, desc, schema, ann):
        self.server, self.name, self.desc, self.schema, self.ann = server, name, desc, schema, ann
        self.tags = {}          # leg -> [evidence]
        self.overridden = False

    @property
    def qname(self):
        return "%s/%s" % (self.server, self.name)

    def add(self, leg, why):
        ev = self.tags.setdefault(leg, [])
        if why not in ev:
            ev.append(why)

    def legs(self):
        return {leg for leg in LEGS if leg in self.tags}

    def code(self):
        return "".join(SHORT[leg] if leg in self.tags else "-" for leg in LEGS)


def classify(tool):
    toks = tokens(tool.name)
    tset = set(toks)
    verbs_read = tset & READ_VERBS
    verbs_send = tset & SEND_VERBS
    verbs_create = tset & CREATE_VERBS
    props = _props(tool.schema)
    pnames = {k.lower(): v for k, v in props.items()}
    no_write_verb = not (verbs_send or verbs_create or (tset & ACTION_TOKENS))
    readish = bool(verbs_read) or no_write_verb

    # shell / code execution: can do everything
    shell = not verbs_read and bool((tset & SHELL_TOKENS) or
                                    any(a in tset and b in tset for a, b in CODE_RUN))
    cmd_props = [k for k in pnames if k in COMMAND_PROPS and not _restricted(pnames[k])]
    if shell or cmd_props:
        why = "general command/code execution (%s)" % (
            "name: " + "/".join(sorted(tset & (SHELL_TOKENS | {"run", "code"})))
            if shell else "param: " + ", ".join(sorted(cmd_props)))
        for leg in LEGS:
            tool.add(leg, why)

    if readish:
        hit = sorted(tset & PRIVATE_NOUNS)
        if hit:
            tool.add("private", "name reads %s" % "/".join(hit))
        hit = sorted(tset & UNTRUSTED_NOUNS)
        if hit:
            tool.add("untrusted", "name ingests %s" % "/".join(hit))
    if tset & UNTRUSTED_VERBS:
        tool.add("untrusted", "name verb %s" % "/".join(sorted(tset & UNTRUSTED_VERBS)))
    if "search" in tset and tset & {"web", "internet", "google", "bing", "news"}:
        tool.add("untrusted", "web search")

    if verbs_send:
        tool.add("exfil", "name verb %s" % "/".join(sorted(verbs_send)))
    if verbs_create and tset & EXTERNAL_WRITE_NOUNS:
        tool.add("exfil", "creates externally visible %s" %
                 "/".join(sorted(tset & EXTERNAL_WRITE_NOUNS)))

    for k, v in pnames.items():
        if k in URL_PROPS and not _restricted(v):
            tool.add("exfil", "arbitrary URL parameter '%s' (data can leave in the URL)" % k)
            if readish:
                tool.add("untrusted", "fetches caller-chosen URL '%s'" % k)
        elif k in RECIPIENT_PROPS and not _restricted(v):
            tool.add("exfil", "recipient parameter '%s'" % k)

    act = sorted(tset & ACTION_TOKENS)
    if act and not verbs_read:
        tool.add("action", "name verb %s" % "/".join(act))

    for leg, rx in DESC_RX.items():
        m = rx.search(tool.desc)
        if m:
            tool.add(leg, "description: '%s'" % m.group(0).strip())

    ann = tool.ann
    if ann.get("openWorldHint") is True and "untrusted" not in tool.tags and readish:
        tool.add("untrusted", "annotation openWorldHint=true")
    if ann.get("destructiveHint") is True:
        tool.add("action", "annotation destructiveHint=true")
    if ann.get("readOnlyHint") is True and "exfil" in tool.tags and not shell:
        # read-only tools cannot send by verb; URL/recipient params still leak
        keep = [e for e in tool.tags["exfil"] if "parameter" in e]
        if keep:
            tool.tags["exfil"] = keep
        else:
            del tool.tags["exfil"]
    return tool


def load_overrides(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        raise InputError("--tags %s: %s" % (path, e))
    ov = data.get("overrides", data) if isinstance(data, dict) else None
    if not isinstance(ov, dict):
        raise InputError("--tags: expected {\"overrides\": {\"glob\": [legs]}}")
    for k, v in ov.items():
        if not isinstance(v, list) or any(x not in LEGS for x in v):
            raise InputError("--tags: %r must be a list drawn from %s" % (k, ", ".join(LEGS)))
    return ov


def apply_overrides(tool, overrides):
    for pat, legs in overrides.items():
        if fnmatch.fnmatchcase(tool.qname, pat) or fnmatch.fnmatchcase(tool.name, pat):
            tool.tags = {leg: ["override '%s'" % pat] for leg in legs}
            tool.overridden = True
            return


# ---------------------------------------------------------------- analysis

def _leg(tools, leg):
    return [t for t in tools if leg in t.tags]


def _servers(lst):
    return sorted({t.server for t in lst})


def _names(lst):
    return [t.qname for t in lst]


def analyze(tools):
    findings = []

    def add(code, message, tools_involved, **extra):
        sev, title = RULES[code]
        f = {"code": code, "severity": sev, "title": title, "message": message,
             "tools": tools_involved}
        f.update(extra)
        findings.append(f)

    P, U, E, A = (_leg(tools, leg) for leg in LEGS)
    if P and U and E:
        legs = {"private": P, "untrusted": U, "exfil": E}
        smallest = min(legs, key=lambda k: (len(legs[k]), LEGS.index(k)))
        servers = sorted(set(_servers(P)) | set(_servers(U)) | set(_servers(E)))
        add("TF01", "%d private / %d untrusted / %d exfil tools are available to the same agent%s. "
            "Break it by removing or human-gating the %s leg: %s" % (
                len(P), len(U), len(E),
                " across servers %s" % ", ".join(servers) if len(servers) > 1 else "",
                smallest, ", ".join(_names(legs[smallest]))),
            sorted(set(_names(P + U + E))),
            legs={k: _names(v) for k, v in legs.items()}, break_leg=smallest,
            break_tools=_names(legs[smallest]), cross_server=len(servers) > 1)
    else:
        if P and E:
            add("TF04", "private: %s; exfil: %s. Adding any tool that reads untrusted content "
                "(web, email, issues) completes the trifecta" % (
                    ", ".join(_names(P)), ", ".join(_names(E))), _names(P + E))
        if P and U:
            add("TF05", "private: %s; untrusted: %s. Injected content can read private data; "
                "check for indirect channels (rendered links/images, written files)" % (
                    ", ".join(_names(P)), ", ".join(_names(U))), _names(P + U))
    for t in tools:
        if "untrusted" in t.tags and "exfil" in t.tags:
            add("TF02", "%s [%s]: untrusted: %s; exfil: %s" % (
                t.qname, t.code(), "; ".join(t.tags["untrusted"]), "; ".join(t.tags["exfil"])),
                [t.qname])
    if U and A:
        add("TF03", "untrusted: %s; action: %s. Require human approval for the action tools" % (
            ", ".join(_names(U)), ", ".join(_names(A))), sorted(set(_names(U + A))),
            break_tools=_names(A))
    for t in tools:
        if not t.tags and not t.overridden:
            add("TF06", "%s: no capability matched; review and tag it" % t.qname, [t.qname])
    findings.sort(key=lambda f: (-SEV_RANK[f["severity"]], f["code"]))
    return findings


def build(paths, tags_path=None, ignore=()):
    overrides = load_overrides(tags_path) if tags_path else {}
    tools, seen = [], set()
    for server, raw in load_paths(paths):
        n = normalize_tool(raw)
        if not n:
            continue
        t = Tool(server, *n)
        if t.qname in seen or any(fnmatch.fnmatchcase(t.qname, g) or
                                  fnmatch.fnmatchcase(t.name, g) for g in ignore):
            continue
        seen.add(t.qname)
        classify(t)
        apply_overrides(t, overrides)
        tools.append(t)
    if not tools:
        raise InputError("no tool definitions found in input")
    return tools, analyze(tools)


# ---------------------------------------------------------------- output

def report_json(tools, findings):
    return {
        "tool": "trifecta", "version": __version__,
        "summary": {"tools": len(tools),
                    "legs": {leg: len(_leg(tools, leg)) for leg in LEGS},
                    "trifecta": any(f["code"] == "TF01" for f in findings),
                    "findings": len(findings)},
        "tools": [{"server": t.server, "name": t.name, "legs": sorted(t.legs(), key=LEGS.index),
                   "evidence": t.tags, "overridden": t.overridden} for t in tools],
        "findings": findings,
    }


def report_text(tools, findings):
    lines = ["trifecta %s: %d tools (P=private U=untrusted E=exfil A=action)" % (
        __version__, len(tools)), ""]
    w = max(len(t.qname) for t in tools)
    for t in tools:
        ev = "; ".join("%s: %s" % (SHORT[leg], t.tags[leg][0]) for leg in LEGS if leg in t.tags)
        lines.append("  %-4s %-*s  %s" % (t.code(), w, t.qname,
                                          ev or ("(override: none)" if t.overridden else "(unclassified)")))
    lines.append("")
    if not findings:
        lines.append("No risky combinations found.")
    for f in findings:
        lines.append("[%s] %s %s" % (f["severity"].upper(), f["code"], f["title"]))
        lines.append("    " + f["message"])
    lines.append("")
    lines.append("Heuristic tags from names, schemas and descriptions; verify and fix with --tags.")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="trifecta", description=__doc__.split("\n")[1])
    ap.add_argument("paths", nargs="+", help="tool definition JSON files or directories ('-' = stdin)")
    ap.add_argument("--tags", help="JSON overrides {\"overrides\": {\"server/tool glob\": [legs]}}")
    ap.add_argument("--ignore", action="append", default=[], help="skip tools matching glob")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="info")
    ap.add_argument("--fail-on", choices=SEVERITIES[1:] + ("any", "none"), default="high",
                    help="exit 1 if a finding is at/above this severity (default high)")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    try:
        tools, findings = build(a.paths, a.tags, a.ignore)
    except InputError as e:
        sys.stderr.write("trifecta: error: %s\n" % e)
        return 2
    findings = [f for f in findings if SEV_RANK[f["severity"]] >= SEV_RANK[a.min_severity]]
    print(json.dumps(report_json(tools, findings), indent=2) if a.json
          else report_text(tools, findings))
    if a.fail_on == "none":
        return 0
    floor = 0 if a.fail_on == "any" else SEV_RANK[a.fail_on]
    return 1 if any(SEV_RANK[f["severity"]] >= floor for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
