#!/usr/bin/env python3
"""toolgate - offline policy-as-code checker for AI agent tool calls.

A JSON policy declares which tools may be called, what arguments are acceptable
(path globs, host allow/deny lists, shell-command denies, arbitrary regexes) and
per-run call caps.  toolgate can:

  * audit   a whole transcript (OpenAI chat tool_calls, Anthropic tool_use,
            generic {tool,args} JSONL events) and report every violation;
  * check   one tool call (JSON on stdin or as an argument) and print an
            allow / warn / deny decision - usable as a pre-tool-use hook;
  * explain the rules of a policy in plain language;
  * init    write an example starter policy.

Only tool-call *arguments* are inspected; tool results are never read.
This is string/heuristic matching, not a sandbox.  Stdlib only.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shlex
import sys
from urllib.parse import urlparse

__version__ = "0.1.0"

FORMATS = ("auto", "openai", "anthropic", "generic")
SEVERITIES = ("deny", "warn")
KINDS = ("path", "host", "command", "regex")
FAIL_ON = ("deny", "warn", "none")


class ToolgateError(Exception):
    """Input/usage/policy problem -> exit 2."""


# --------------------------------------------------------------------------
# Heuristics: argument key names and extraction regexes
# --------------------------------------------------------------------------

PATH_KEYS = {"path", "paths", "file", "files", "file_path", "filepath", "filename",
             "file_name", "dir", "dirs", "directory", "cwd", "workdir", "working_dir",
             "target", "target_path", "source", "src", "dest", "destination", "dst",
             "output", "output_path", "input_path", "root", "folder", "notebook_path"}
HOST_KEYS = {"url", "urls", "uri", "endpoint", "host", "hostname", "domain", "base_url",
             "href", "link", "server", "website", "address"}
CMD_KEYS = {"command", "cmd", "commands", "script", "shell", "bash", "command_line",
            "commandline", "cmdline", "sh", "exec"}
SHELL_TOOL_RE = re.compile(r"(shell|bash|exec|terminal|command|run_cmd|^sh$|powershell|cmd)", re.I)

URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s'\"<>`|;)]+")
# bare host:port or user@host for ssh/scp/nc style usage inside commands
PATH_RE = re.compile(r"(?:(?<=^)|(?<=[\s'\"=@<>(:,]))((?:~|\.{1,2})?/[^\s'\"<>|;&)`,]*|~|\.env(?:\.[\w-]+)?)")
SHELL_WRAPPERS = {"sudo", "env", "nohup", "time", "exec", "command", "xargs", "nice",
                  "doas", "stdbuf", "timeout", "builtin"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "busybox"}
SEPARATORS = ("|", "||", "&&", ";", "&", "|&")

BUILTIN_COMMAND_PATTERNS = [
    ("pipe-to-shell", r"\b(curl|wget|fetch|iwr|invoke-webrequest)\b[^\n]*\|\s*(sudo\s+)?(-?\w+=\S+\s+)*(ba|z|da|k|fi|a)?sh\b",
     "downloads content and pipes it straight into a shell"),
    ("shell-of-download", r"\b(ba|z|da|k)?sh\s+(-c\s+)?[\"']?\$\(\s*(curl|wget)\b",
     "executes a downloaded script via command substitution"),
    ("rm-rf-root", r"\brm\s+(-[a-zA-Z]*\s+)*(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*|-r\s+-f|-f\s+-r|--recursive\s+--force|--force\s+--recursive)\s+(--no-preserve-root\s+)?[\"']?(/|/\*|~/?|\$HOME/?|\*)[\"']?(\s|$|;|&|\|)",
     "recursive force-delete of /, ~ or *"),
    ("no-preserve-root", r"--no-preserve-root", "rm with --no-preserve-root"),
    ("base64-to-network", r"\bbase64\b[^\n]*\|\s*[^\n]*\b(curl|wget|nc|ncat|netcat|socat|telnet|openssl\s+s_client)\b",
     "base64-encodes data and pipes it to a network tool (exfiltration pattern)"),
    ("dev-tcp", r"/dev/(tcp|udp)/", "bash /dev/tcp network redirection (reverse shell pattern)"),
    ("nc-exec", r"\b(nc|ncat|netcat)\b[^\n|;]*\s-(e|c)\s", "netcat with -e/-c (reverse/bind shell)"),
    ("disk-wipe", r"\b(mkfs(\.\w+)?\s+/dev/|dd\s+[^\n]*of=/dev/(sd|nvme|hd|disk|xvd))", "formats or overwrites a block device"),
    ("fork-bomb", r":\(\)\s*\{\s*:\|:&\s*\};:", "fork bomb"),
    ("chmod-777-root", r"\bchmod\s+(-R\s+)?777\s+/(\s|$)", "chmod 777 on /"),
]


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def _as_list(v):
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return list(v)
    return [v]


def strings_in(obj, key=None):
    """Yield (key, string) for every string leaf in obj (key = nearest dict key)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from strings_in(v, k)
    elif isinstance(obj, list):
        for v in obj:
            yield from strings_in(v, key)
    elif isinstance(obj, str):
        yield key, obj


def _key_matches(key, keys):
    if key is None:
        return False
    k = str(key).lower()
    return any(fnmatch.fnmatchcase(k, p.lower()) for p in keys)


def parse_args_value(raw):
    if raw is None:
        return {}
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return {}
        try:
            v = json.loads(s)
        except ValueError:
            return {"_raw": raw}
        return v if isinstance(v, dict) else {"_value": v}
    if isinstance(raw, dict):
        return raw
    return {"_value": raw}


# --------------------------------------------------------------------------
# Transcript loading (adapted from rundiff #7)
# --------------------------------------------------------------------------

def parse_records(text, source="<input>"):
    text = text.strip()
    if not text:
        raise ToolgateError("%s: empty transcript" % source)
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if data is not None:
        if isinstance(data, list):
            recs = data
        elif isinstance(data, dict):
            for key in ("messages", "events", "transcript", "items"):
                if isinstance(data.get(key), list):
                    recs = list(data[key])
                    break
            else:
                recs = [data]
        else:
            raise ToolgateError("%s: unsupported JSON top-level type" % source)
    else:
        recs = []
        for n, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                recs.append(json.loads(line))
            except ValueError as exc:
                raise ToolgateError("%s:%d: invalid JSON line: %s" % (source, n, exc))
    out = []
    for r in recs:
        if not isinstance(r, dict):
            continue
        if isinstance(r.get("message"), dict) and "role" not in r and "type" not in r:
            r = r["message"]
        out.append(r)
    if not out:
        raise ToolgateError("%s: no JSON object records found" % source)
    return out


def load_records(path):
    try:
        if path == "-":
            text = sys.stdin.read()
        else:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
    except OSError as exc:
        raise ToolgateError("cannot read %s: %s" % (path, exc))
    return parse_records(text, source=path)


def detect_format(records):
    generic = anthropic = openai = 0
    for r in records:
        t = r.get("type")
        if t in ("tool_call", "tool_use", "tool_result") and "role" not in r:
            generic += 1
        if "tool" in r and ("args" in r or "arguments" in r or "input" in r) and "role" not in r:
            generic += 1
        c = r.get("content")
        if isinstance(c, list):
            for b in c:
                if isinstance(b, dict) and b.get("type") in ("tool_use", "tool_result"):
                    anthropic += 1
        if r.get("tool_calls") or r.get("role") == "tool" or r.get("function_call"):
            openai += 1
    if generic and generic >= max(anthropic, openai):
        return "generic"
    if anthropic and anthropic >= openai:
        return "anthropic"
    if openai:
        return "openai"
    return "generic"


class Call:
    def __init__(self, turn, tool, args, call_id=None):
        self.turn = turn
        self.tool = str(tool or "<unknown>")
        self.raw_args = args
        self.args = parse_args_value(args)
        self.call_id = call_id

    def to_dict(self):
        return {"turn": self.turn, "tool": self.tool, "id": self.call_id, "args": self.args}


def extract_calls(records, fmt="auto"):
    """Return ordered Calls from transcript records. Never reads tool results."""
    if fmt == "auto":
        fmt = detect_format(records)
    calls = []
    for i, r in enumerate(records):
        role = r.get("role")
        if not role:
            t = r.get("type")
            if t in ("tool_call", "tool_use", "function_call") or (
                    t is None and "tool" in r and any(k in r for k in ("args", "arguments", "input"))):
                tool = r.get("tool") or r.get("name") or r.get("tool_name")
                args = r.get("args", r.get("arguments", r.get("input", r.get("tool_input"))))
                calls.append(Call(i, tool, args, r.get("id") or r.get("call_id")))
                continue
        if role == "assistant" or (role is None and isinstance(r.get("content"), list)):
            content = r.get("content")
            if isinstance(content, list):
                for b in content:
                    if isinstance(b, dict) and b.get("type") == "tool_use":
                        calls.append(Call(i, b.get("name"), b.get("input"), b.get("id")))
            for tc in r.get("tool_calls") or []:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get("function") or {}
                calls.append(Call(i, fn.get("name") or tc.get("name"),
                                  fn.get("arguments", tc.get("arguments")), tc.get("id")))
            fc = r.get("function_call")
            if isinstance(fc, dict):
                calls.append(Call(i, fc.get("name"), fc.get("arguments")))
    return fmt, calls


def parse_single_call(obj):
    """Accept many single-call shapes; return a Call."""
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except ValueError as exc:
            raise ToolgateError("call is not valid JSON: %s" % exc)
    if not isinstance(obj, dict):
        raise ToolgateError("call must be a JSON object")
    # Claude Code style hook payload
    if "tool_name" in obj:
        return Call(0, obj["tool_name"], obj.get("tool_input", obj.get("arguments", obj.get("args"))))
    if isinstance(obj.get("function"), dict):  # OpenAI tool_call
        fn = obj["function"]
        return Call(0, fn.get("name"), fn.get("arguments"), obj.get("id"))
    if obj.get("type") == "tool_use":
        return Call(0, obj.get("name"), obj.get("input"), obj.get("id"))
    if isinstance(obj.get("tool_calls"), list) or isinstance(obj.get("content"), list):
        _, calls = extract_calls([obj])
        if calls:
            return calls[0]
    tool = obj.get("tool") or obj.get("name")
    if tool is None:
        raise ToolgateError("cannot find tool name (expected tool/name/tool_name/function.name)")
    return Call(0, tool, obj.get("args", obj.get("arguments", obj.get("input", obj.get("parameters")))),
                obj.get("id"))


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------

class Rule:
    def __init__(self, d, idx):
        if not isinstance(d, dict):
            raise ToolgateError("rules[%d] must be an object" % idx)
        self.id = str(d.get("id") or "rule-%d" % (idx + 1))
        self.kind = d.get("kind")
        if self.kind not in KINDS:
            raise ToolgateError("rule %s: kind must be one of %s" % (self.id, ", ".join(KINDS)))
        self.severity = d.get("severity", "deny")
        if self.severity not in SEVERITIES:
            raise ToolgateError("rule %s: severity must be deny or warn" % self.id)
        self.tools = _as_list(d.get("tools", ["*"]))
        self.except_tools = _as_list(d.get("except_tools"))
        self.keys = [str(k) for k in _as_list(d.get("keys"))]
        self.description = d.get("description", "")
        self.allow = [str(x) for x in _as_list(d.get("allow"))]
        self.deny = [str(x) for x in _as_list(d.get("deny"))]
        self.deny_programs = [str(x) for x in _as_list(d.get("deny_programs"))]
        self.allow_programs = [str(x) for x in _as_list(d.get("allow_programs"))]
        self.builtin = bool(d.get("builtin_patterns", self.kind == "command"))
        self.scan_all_strings = bool(d.get("scan_all_strings", True))
        self.deny_patterns = []
        for p in _as_list(d.get("deny_patterns")):
            try:
                self.deny_patterns.append((p, re.compile(p, re.I)))
            except re.error as exc:
                raise ToolgateError("rule %s: bad regex %r: %s" % (self.id, p, exc))
        if self.kind == "regex" and not self.deny_patterns:
            raise ToolgateError("rule %s: regex rules need deny_patterns" % self.id)
        if self.kind in ("path", "host") and not (self.allow or self.deny):
            raise ToolgateError("rule %s: %s rules need allow and/or deny" % (self.id, self.kind))
        if self.kind == "command" and not (self.deny_programs or self.deny_patterns
                                           or self.allow_programs or self.builtin):
            raise ToolgateError("rule %s: command rule has nothing to check" % self.id)

    def applies_to(self, tool):
        if any(fnmatch.fnmatchcase(tool, p) for p in self.except_tools):
            return False
        return any(fnmatch.fnmatchcase(tool, p) for p in self.tools)


class Policy:
    def __init__(self, d, source="<policy>"):
        if not isinstance(d, dict):
            raise ToolgateError("%s: policy must be a JSON object" % source)
        self.source = source
        self.name = d.get("name", os.path.basename(source))
        self.default = d.get("default", "allow")
        if self.default not in ("allow", "deny", "warn"):
            raise ToolgateError("%s: default must be allow, deny or warn" % source)
        tools = d.get("tools") or {}
        if not isinstance(tools, dict):
            raise ToolgateError("%s: 'tools' must be an object" % source)
        self.tools_allow = [str(x) for x in _as_list(tools.get("allow"))]
        self.tools_deny = [str(x) for x in _as_list(tools.get("deny"))]
        self.tools_warn = [str(x) for x in _as_list(tools.get("warn"))]
        self.rules = [Rule(r, i) for i, r in enumerate(_as_list(d.get("rules")))]
        ids = [r.id for r in self.rules]
        dup = {x for x in ids if ids.count(x) > 1}
        if dup:
            raise ToolgateError("%s: duplicate rule ids: %s" % (source, ", ".join(sorted(dup))))
        caps = d.get("caps") or {}
        if not isinstance(caps, dict):
            raise ToolgateError("%s: 'caps' must be an object" % source)
        self.cap_total = caps.get("total")
        self.cap_per_tool = caps.get("per_tool") or {}
        self.cap_severity = caps.get("severity", "deny")
        if self.cap_severity not in SEVERITIES:
            raise ToolgateError("%s: caps.severity must be deny or warn" % source)
        for k, v in list(self.cap_per_tool.items()) + [("total", self.cap_total)]:
            if v is not None and (not isinstance(v, int) or isinstance(v, bool) or v < 0):
                raise ToolgateError("%s: cap %r must be a non-negative integer" % (source, k))
        known = {"name", "description", "version", "default", "tools", "rules", "caps", "$schema", "_comment"}
        self.unknown_keys = sorted(set(d) - known)


def load_policy(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise ToolgateError("cannot read policy %s: %s" % (path, exc))
    except ValueError as exc:
        raise ToolgateError("policy %s is not valid JSON: %s" % (path, exc))
    return Policy(data, path)


# --------------------------------------------------------------------------
# Matching primitives
# --------------------------------------------------------------------------

HOME_PREFIXES = ("~/", "/home/*/", "/Users/*/", "/root/", "$HOME/", "${HOME}/", "C:\\Users\\*\\")


def normalize_path(p):
    p = p.strip().strip("'\"")
    if p.startswith("@"):
        p = p[1:]
    if p.startswith("file://"):
        p = p[7:]
    p = p.replace("\\", "/") if re.match(r"^[A-Za-z]:\\", p) is None else p
    for h in ("$HOME", "${HOME}"):
        if p == h or p.startswith(h + "/"):
            p = "~" + p[len(h):]
    if not p:
        return p
    keep_slash = p.endswith("/") and len(p) > 1
    n = os.path.normpath(p) if not re.match(r"^[A-Za-z]:\\", p) else p
    if p.startswith("./") and not n.startswith(".."):
        n = "./" + n if n != "." else "."
    return n + ("/" if keep_slash and not n.endswith("/") else "")


def _pattern_variants(pat):
    """Expand a policy path glob into fnmatch variants (home aliases, **/ prefix)."""
    pat = pat.strip()
    out = {pat}
    if pat.startswith("~/") or pat == "~":
        rest = pat[2:] if pat.startswith("~/") else ""
        for pre in HOME_PREFIXES:
            out.add(pre + rest)
    for v in list(out):
        if v.startswith("**/"):
            out.add(v[3:])
        if v.endswith("/**"):
            out.add(v[:-3])
    return out


def path_matches(path, pat):
    n = normalize_path(path)
    if not n:
        return False
    candidates = {n, n.rstrip("/")}
    if n.startswith("./"):
        candidates.add(n[2:])
    for v in _pattern_variants(pat):
        if v.startswith("./"):
            # relative-only pattern: path must be relative and must not escape
            if n.startswith(("/", "~", "..")) or re.match(r"^[A-Za-z]:", n):
                continue
            rel = n[2:] if n.startswith("./") else n
            if fnmatch.fnmatchcase(rel, v[2:]) or (v[2:] in ("**", "*")):
                return True
            continue
        for c in candidates:
            if fnmatch.fnmatchcase(c, v):
                return True
        # basename-only patterns like ".env" or "*.pem"
        if "/" not in v and fnmatch.fnmatchcase(os.path.basename(n.rstrip("/")), v):
            return True
    return False


def host_matches(host, pat):
    host = host.lower().rstrip(".")
    pat = pat.lower().strip()
    if fnmatch.fnmatchcase(host, pat):
        return True
    if pat.startswith("*.") and host == pat[2:]:
        return True
    return False


def host_of(s):
    s = s.strip()
    if "://" in s:
        try:
            return (urlparse(s).hostname or "").lower() or None
        except ValueError:
            return None
    m = re.match(r"^(?:[\w.\-]+@)?([A-Za-z0-9.\-]+\.[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3}|localhost)(?::\d+)?(?:/.*)?$", s)
    return m.group(1).lower() if m else None


def tokenize(cmd):
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        return list(lex)
    except ValueError:
        return cmd.split()


def command_programs(cmd):
    """Best-effort list of program basenames invoked by a shell command string."""
    progs = []
    toks = tokenize(cmd)
    expect = True
    skip_next = False
    in_wrapper, wrapper = False, None
    for t in toks:
        if t in SEPARATORS or (t and set(t) <= set("|&;")):
            expect = True
            continue
        if t in ("(", ")", "{", "}", "$(", "`"):
            expect = True
            continue
        if not expect:
            if t.startswith("$(") or t.startswith("`"):
                inner = t.lstrip("$(`")
                if inner:
                    progs.append(os.path.basename(inner))
            continue
        if skip_next:
            skip_next = False
            continue
        if re.match(r"^\w+=", t):
            continue
        if in_wrapper and t.startswith("-"):
            if t in ("-u", "-g", "-C", "-k", "-n") and wrapper in ("sudo", "doas", "timeout", "nice"):
                skip_next = t != "-k"
            continue
        if t in SHELL_WRAPPERS:
            progs.append(t)
            in_wrapper, wrapper = True, t
            if t == "timeout":
                skip_next = True
            continue
        in_wrapper = False
        progs.append(os.path.basename(t.lstrip("$(`")))
        expect = False
    # also catch sh -c "inner"
    for i, t in enumerate(toks):
        if os.path.basename(t) in SHELLS and i + 2 < len(toks) and toks[i + 1] == "-c":
            progs.extend(command_programs(toks[i + 2]))
    return [p for p in progs if p]


# --------------------------------------------------------------------------
# Argument extraction
# --------------------------------------------------------------------------

def command_strings(call, rule_keys=()):
    keys = rule_keys or CMD_KEYS
    cmds = []
    for key, s in strings_in(call.args):
        if _key_matches(key, keys):
            cmds.append(s)
    if not cmds and not rule_keys and SHELL_TOOL_RE.search(call.tool):
        for key, s in strings_in(call.args):
            cmds.append(s)
            break
    return cmds


def path_values(call, rule_keys=(), scan_all=True):
    """Return list of (value, source) where source is 'key' or 'scan'."""
    keys = rule_keys or PATH_KEYS
    out = []
    seen = set()
    cmd_set = set(command_strings(call))
    for key, s in strings_in(call.args):
        if _key_matches(key, keys) and s.strip() and "\n" not in s and not URL_RE.match(s.strip()):
            if s not in seen:
                seen.add(s)
                out.append((s, "key"))
            continue
        if not scan_all:
            continue
        if s in cmd_set:
            for tok in tokenize(s):
                tok = tok.lstrip("<>").lstrip("0123456789").lstrip(">") if re.match(r"^\d*[<>]", tok) else tok
                tok = tok.split("=", 1)[1] if re.match(r"^-{1,2}[\w-]+=", tok) else tok
                if URL_RE.match(tok):
                    continue
                t2 = tok.lstrip("@")
                if t2.startswith(("/", "~", "./", "../", "$HOME")) or re.search(r"(^|/)\.env(\.|$)", t2):
                    if tok not in seen:
                        seen.add(tok)
                        out.append((tok, "scan"))
        else:
            clean = URL_RE.sub(" ", s)
            for m in PATH_RE.findall(clean):
                m = m.rstrip(".,:")
                if len(m) > 1 and m not in seen:
                    seen.add(m)
                    out.append((m, "scan"))
    return out


def host_values(call, rule_keys=()):
    keys = rule_keys or HOST_KEYS
    hosts = []
    seen = set()

    def add(h, src):
        if h and h not in seen:
            seen.add(h)
            hosts.append((h, src))

    cmd_set = set(command_strings(call))
    for key, s in strings_in(call.args):
        for u in URL_RE.findall(s):
            try:
                h = urlparse(u).hostname
            except ValueError:
                h = None
            add(h.lower() if h else None, "url")
        if _key_matches(key, keys) and "://" not in s:
            add(host_of(s), "key")
        if s in cmd_set:
            toks = tokenize(s)
            progs_net = {"ssh", "scp", "sftp", "nc", "ncat", "netcat", "telnet", "rsync", "ping",
                         "curl", "wget", "socat", "ftp", "dig", "nslookup", "host"}
            active = False
            for t in toks:
                b = os.path.basename(t)
                if b in progs_net:
                    active = True
                    continue
                if t in SEPARATORS:
                    active = False
                    continue
                if active and not t.startswith("-") and "://" not in t:
                    hh = host_of(t.split(":", 1)[0] if "@" in t or re.match(r"^[\w.\-]+:\S*$", t) else t)
                    if hh and not re.search(r"\.(txt|json|sh|py|tar|gz|zip|log|pem|key|md)$", hh):
                        add(hh, "cmd")
    return hosts


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------

def _v(rule_id, severity, reason, call, detail=None):
    d = {"turn": call.turn, "tool": call.tool, "rule_id": rule_id, "severity": severity, "reason": reason}
    if call.call_id:
        d["call_id"] = call.call_id
    if detail is not None:
        d["detail"] = detail
    return d


def check_tool_name(policy, call):
    t = call.tool
    out = []
    for p in policy.tools_deny:
        if fnmatch.fnmatchcase(t, p):
            out.append(_v("TG-TOOL-DENY", "deny", "tool '%s' matches denied pattern '%s'" % (t, p), call))
            return out
    for p in policy.tools_warn:
        if fnmatch.fnmatchcase(t, p):
            out.append(_v("TG-TOOL-WARN", "warn", "tool '%s' matches warn pattern '%s'" % (t, p), call))
            return out
    if any(fnmatch.fnmatchcase(t, p) for p in policy.tools_allow):
        return out
    if policy.default == "deny":
        out.append(_v("TG-TOOL-DEFAULT", "deny", "tool '%s' is not in the allow list (default: deny)" % t, call))
    elif policy.default == "warn":
        out.append(_v("TG-TOOL-DEFAULT", "warn", "tool '%s' is not in the allow list (default: warn)" % t, call))
    return out


def check_rule(rule, call):
    out = []
    if not rule.applies_to(call.tool):
        return out
    sev = rule.severity
    if rule.kind == "path":
        for val, src in path_values(call, rule.keys, rule.scan_all_strings):
            hit = next((p for p in rule.deny if path_matches(val, p)), None)
            if hit:
                out.append(_v(rule.id, sev, "path '%s' matches denied glob '%s'" % (val, hit), call, val))
                continue
            # allowlists only apply to values found under path-like keys
            if rule.allow and src == "key" and not any(path_matches(val, p) for p in rule.allow):
                out.append(_v(rule.id, sev, "path '%s' is outside allowed globs %s" % (val, rule.allow), call, val))
    elif rule.kind == "host":
        for h, _src in host_values(call, rule.keys):
            hit = next((p for p in rule.deny if host_matches(h, p)), None)
            if hit:
                out.append(_v(rule.id, sev, "host '%s' matches denied pattern '%s'" % (h, hit), call, h))
                continue
            if rule.allow and not any(host_matches(h, p) for p in rule.allow):
                out.append(_v(rule.id, sev, "host '%s' is not in the host allowlist" % h, call, h))
    elif rule.kind == "command":
        for cmd in command_strings(call, rule.keys):
            progs = command_programs(cmd)
            for p in progs:
                hit = next((d for d in rule.deny_programs if fnmatch.fnmatchcase(p, d)), None)
                if hit:
                    out.append(_v(rule.id, sev, "command runs denied program '%s'" % p, call, cmd))
                elif rule.allow_programs and not any(fnmatch.fnmatchcase(p, a) for a in rule.allow_programs):
                    out.append(_v(rule.id, sev, "command runs program '%s' not in allow_programs" % p, call, cmd))
            for pat, rx in rule.deny_patterns:
                if rx.search(cmd):
                    out.append(_v(rule.id, sev, "command matches denied pattern /%s/" % pat, call, cmd))
            if rule.builtin:
                for name, rx, why in BUILTIN_RX:
                    if rx.search(cmd):
                        out.append(_v(rule.id, sev, "builtin:%s - %s" % (name, why), call, cmd))
    elif rule.kind == "regex":
        for key, s in strings_in(call.args):
            if rule.keys and not _key_matches(key, rule.keys):
                continue
            for pat, rx in rule.deny_patterns:
                if rx.search(s):
                    out.append(_v(rule.id, sev, "argument '%s' matches denied pattern /%s/" % (key, pat), call,
                                  s if len(s) <= 200 else s[:197] + "..."))
    return out


BUILTIN_RX = [(n, re.compile(p, re.I), why) for n, p, why in BUILTIN_COMMAND_PATTERNS]


def _cap_for(policy, tool):
    best = None
    for pat, n in policy.cap_per_tool.items():
        if fnmatch.fnmatchcase(tool, pat):
            # most specific (longest non-wildcard) pattern wins
            score = len(pat.replace("*", "").replace("?", ""))
            if best is None or score > best[0]:
                best = (score, pat, n)
    return best


class Counter:
    def __init__(self, total=0, per_tool=None):
        self.total = total
        self.per_tool = dict(per_tool or {})


def check_caps(policy, call, counter):
    """Increment counters for this call and return cap violations."""
    out = []
    counter.total += 1
    best = _cap_for(policy, call.tool)
    key = best[1] if best else call.tool
    counter.per_tool[key] = counter.per_tool.get(key, 0) + 1
    if policy.cap_total is not None and counter.total > policy.cap_total:
        out.append(_v("TG-CAP-TOTAL", policy.cap_severity,
                      "call #%d exceeds total cap of %d calls per run" % (counter.total, policy.cap_total), call))
    if best is not None and counter.per_tool[key] > best[2]:
        out.append(_v("TG-CAP-TOOL", policy.cap_severity,
                      "call #%d to '%s' exceeds cap of %d (pattern '%s')"
                      % (counter.per_tool[key], call.tool, best[2], key), call))
    return out


def evaluate_call(policy, call, counter=None):
    vs = check_tool_name(policy, call)
    for r in policy.rules:
        vs.extend(check_rule(r, call))
    if counter is not None:
        vs.extend(check_caps(policy, call, counter))
    # de-duplicate identical (rule, reason)
    seen, uniq = set(), []
    for v in vs:
        k = (v["rule_id"], v["reason"])
        if k not in seen:
            seen.add(k)
            uniq.append(v)
    return uniq


def decision_of(violations):
    sevs = {v["severity"] for v in violations}
    if "deny" in sevs:
        return "deny"
    if "warn" in sevs:
        return "warn"
    return "allow"


def audit(policy, records, fmt="auto"):
    fmt, calls = extract_calls(records, fmt)
    counter = Counter()
    violations = []
    per_call = []
    for idx, c in enumerate(calls):
        vs = evaluate_call(policy, c, counter)
        for v in vs:
            v["call_index"] = idx
        violations.extend(vs)
        per_call.append({"call_index": idx, "turn": c.turn, "tool": c.tool, "decision": decision_of(vs)})
    summary = {
        "calls": len(calls),
        "violations": len(violations),
        "deny": sum(1 for v in violations if v["severity"] == "deny"),
        "warn": sum(1 for v in violations if v["severity"] == "warn"),
        "denied_calls": sum(1 for p in per_call if p["decision"] == "deny"),
        "warned_calls": sum(1 for p in per_call if p["decision"] == "warn"),
    }
    return {"tool": "toolgate", "version": __version__, "policy": policy.name, "format": fmt,
            "summary": summary, "calls": per_call, "violations": violations}


def gate(report, fail_on):
    s = report["summary"]
    if fail_on == "none":
        return 0
    if fail_on == "deny":
        return 1 if s["deny"] else 0
    return 1 if (s["deny"] or s["warn"]) else 0


# --------------------------------------------------------------------------
# explain / init
# --------------------------------------------------------------------------

def explain(policy):
    L = ["Policy: %s  (%s)" % (policy.name, policy.source),
         "Default action for unlisted tools: %s" % policy.default]
    if policy.tools_allow:
        L.append("  TG-TOOL-ALLOW   allowed tools: %s" % ", ".join(policy.tools_allow))
    if policy.tools_deny:
        L.append("  TG-TOOL-DENY    [deny] denied tools: %s" % ", ".join(policy.tools_deny))
    if policy.tools_warn:
        L.append("  TG-TOOL-WARN    [warn] warn on tools: %s" % ", ".join(policy.tools_warn))
    L.append("  TG-TOOL-DEFAULT [%s] tools matching none of the above" % policy.default)
    if policy.cap_total is not None:
        L.append("  TG-CAP-TOTAL    [%s] at most %d tool calls per run" % (policy.cap_severity, policy.cap_total))
    for pat, n in policy.cap_per_tool.items():
        L.append("  TG-CAP-TOOL     [%s] at most %d calls to tools matching '%s'" % (policy.cap_severity, n, pat))
    L.append("")
    L.append("Argument rules:")
    if not policy.rules:
        L.append("  (none)")
    for r in policy.rules:
        scope = ", ".join(r.tools) + ((" except " + ", ".join(r.except_tools)) if r.except_tools else "")
        L.append("  %-16s [%s] %s rule on tools: %s" % (r.id, r.severity, r.kind, scope))
        if r.description:
            L.append("      %s" % r.description)
        keys = r.keys or sorted({"path": PATH_KEYS, "host": HOST_KEYS, "command": CMD_KEYS}.get(r.kind, []))
        if r.kind != "regex" or r.keys:
            L.append("      arg keys: %s%s" % (", ".join(keys) if keys else "(all string args)",
                                              "" if r.keys else "  (heuristic default)"))
        if r.allow:
            L.append("      allow: %s" % ", ".join(r.allow))
        if r.deny:
            L.append("      deny:  %s" % ", ".join(r.deny))
        if r.deny_programs:
            L.append("      denied programs: %s" % ", ".join(r.deny_programs))
        if r.allow_programs:
            L.append("      allowed programs only: %s" % ", ".join(r.allow_programs))
        for p, _ in r.deny_patterns:
            L.append("      denied pattern: /%s/" % p)
        if r.kind == "command" and r.builtin:
            L.append("      builtin patterns: %s" % ", ".join(n for n, _, _ in BUILTIN_COMMAND_PATTERNS))
    if policy.unknown_keys:
        L.append("")
        L.append("Note: unknown top-level keys ignored: %s" % ", ".join(policy.unknown_keys))
    return "\n".join(L) + "\n"


STARTER_POLICY = {
    "name": "starter",
    "description": "Example toolgate policy - edit before use. Globs use fnmatch: '*' also matches '/'.",
    "default": "deny",
    "tools": {
        "allow": ["read_file", "list_dir", "search*", "write_file", "web_fetch", "run_shell"],
        "deny": ["delete_*", "*_admin", "send_email", "transfer_*"],
        "warn": ["write_file"]
    },
    "rules": [
        {"id": "no-secret-paths", "kind": "path", "severity": "deny",
         "description": "Never touch credentials or system config, wherever the path appears.",
         "deny": ["~/.ssh/**", "~/.aws/**", "~/.gnupg/**", "~/.config/gh/**", "~/.netrc", "~/.docker/config.json",
                  "**/.env", "**/.env.*", "*.pem", "id_rsa*", "id_ed25519*", "/etc/**", "/proc/**", "/root/**"]},
        {"id": "workspace-only", "kind": "path", "severity": "deny",
         "tools": ["read_file", "write_file", "list_dir"],
         "description": "File tools may only use paths under the project or /tmp.",
         "allow": ["./**", "/srv/app/**", "/tmp/**"]},
        {"id": "egress-allowlist", "kind": "host", "severity": "deny",
         "description": "Network access only to known hosts.",
         "allow": ["api.github.com", "*.githubusercontent.com", "pypi.org", "files.pythonhosted.org",
                   "registry.npmjs.org", "docs.python.org"],
         "deny": ["169.254.169.254", "metadata.google.internal", "*.ngrok.io", "*.ngrok-free.app",
                  "pastebin.com", "transfer.sh", "webhook.site"]},
        {"id": "dangerous-shell", "kind": "command", "severity": "deny",
         "description": "Block destructive / exfiltration-shaped shell commands.",
         "deny_programs": ["nc", "ncat", "netcat", "socat", "telnet", "mkfs*", "shred", "sudo", "su", "chown"],
         "deny_patterns": [r"\bgit\s+push\s+.*--force", r"\bhistory\s+-c\b", r"\bcrontab\s+-r\b"],
         "builtin_patterns": True},
        {"id": "shell-network-warn", "kind": "command", "severity": "warn",
         "description": "Flag (but allow) shell commands that use the network.",
         "deny_programs": ["curl", "wget", "ssh", "scp", "rsync"], "builtin_patterns": False},
        {"id": "no-inline-secrets", "kind": "regex", "severity": "deny",
         "description": "Arguments must not carry credential-looking strings.",
         "deny_patterns": [r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"\bAKIA[0-9A-Z]{16}\b",
                           r"\bgh[pousr]_[A-Za-z0-9]{30,}\b", r"\bsk-[A-Za-z0-9_\-]{20,}"]}
    ],
    "caps": {"total": 100, "per_tool": {"run_shell": 25, "web_fetch": 20, "*": 50}, "severity": "deny"}
}


# --------------------------------------------------------------------------
# Rendering / CLI
# --------------------------------------------------------------------------

def _short(s, n=90):
    s = str(s).replace("\n", "\\n")
    return s if len(s) <= n else s[: n - 3] + "..."


def render_audit_text(rep):
    s = rep["summary"]
    L = ["toolgate audit  policy=%s  format=%s" % (rep["policy"], rep["format"]),
         "calls: %d   violations: %d (deny %d, warn %d)   denied calls: %d   warned calls: %d"
         % (s["calls"], s["violations"], s["deny"], s["warn"], s["denied_calls"], s["warned_calls"]), ""]
    if not rep["violations"]:
        L.append("No violations.")
    for v in rep["violations"]:
        L.append("[%s] turn %d  call #%d  %s  %s" % (v["severity"].upper(), v["turn"], v["call_index"],
                                                   v["tool"], v["rule_id"]))
        L.append("    %s" % _short(v["reason"], 160))
        if "detail" in v and v["detail"] not in v["reason"]:
            L.append("    arg: %s" % _short(v["detail"]))
    L.append("")
    L.append("RESULT: %s" % ("DENY" if s["deny"] else "WARN" if s["warn"] else "PASS"))
    return "\n".join(L) + "\n"


def render_check_text(res):
    L = ["%s  %s" % (res["decision"].upper(), res["tool"])]
    for v in res["violations"]:
        L.append("  [%s] %s: %s" % (v["severity"], v["rule_id"], _short(v["reason"], 160)))
    return "\n".join(L) + "\n"


def load_state(path):
    if not path or not os.path.exists(path):
        return Counter()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            d = json.load(fh)
        return Counter(int(d.get("total", 0)), d.get("per_tool") or {})
    except (OSError, ValueError, TypeError) as exc:
        raise ToolgateError("cannot read state file %s: %s" % (path, exc))


def save_state(path, counter):
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"total": counter.total, "per_tool": counter.per_tool}, fh, indent=2)
    except OSError as exc:
        raise ToolgateError("cannot write state file %s: %s" % (path, exc))


def build_parser():
    p = argparse.ArgumentParser(prog="toolgate",
                                description="Offline policy-as-code checker for AI agent tool calls.")
    p.add_argument("--version", action="version", version="toolgate " + __version__)
    sub = p.add_subparsers(dest="cmd")

    a = sub.add_parser("audit", help="audit a transcript against a policy")
    a.add_argument("transcript", help="transcript file (JSON/JSONL) or - for stdin")
    a.add_argument("-p", "--policy", required=True, help="policy JSON file")
    a.add_argument("--format", choices=FORMATS, default="auto")
    a.add_argument("--json", action="store_true", help="emit JSON report")
    a.add_argument("--fail-on", choices=FAIL_ON, default="deny",
                   help="exit 1 on deny violations (default), on any warn/deny, or never")

    c = sub.add_parser("check", help="decide allow/warn/deny for a single tool call")
    c.add_argument("call", nargs="?", default="-",
                   help="call as JSON string, @file, or - for stdin (default)")
    c.add_argument("-p", "--policy", required=True, help="policy JSON file")
    c.add_argument("--json", action="store_true", help="emit JSON decision")
    c.add_argument("--state", help="JSON counter file so call caps apply across hook invocations")
    c.add_argument("--deny-exit", type=int, default=1, help="exit code for deny (default 1; e.g. 2 for some hook APIs)")
    c.add_argument("--warn-exit", type=int, default=0, help="exit code for warn (default 0)")
    c.add_argument("--quiet", action="store_true", help="print nothing on allow")

    e = sub.add_parser("explain", aliases=["list-rules"], help="list policy rules in plain language")
    e.add_argument("-p", "--policy", required=True)
    e.add_argument("--json", action="store_true")

    i = sub.add_parser("init", help="write an example starter policy")
    i.add_argument("output", nargs="?", default="toolgate.policy.json", help="file to write, or - for stdout")
    i.add_argument("--force", action="store_true", help="overwrite existing file")
    return p


def _read_call_arg(s):
    if s == "-":
        return sys.stdin.read()
    if s.startswith("@"):
        try:
            with open(s[1:], "r", encoding="utf-8") as fh:
                return fh.read()
        except OSError as exc:
            raise ToolgateError("cannot read %s: %s" % (s[1:], exc))
    return s


def main(argv=None, stdout=None):
    stdout = stdout or sys.stdout
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "--list-rules":
        argv[0] = "explain"
    parser = build_parser()
    try:
        ns = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2
    if not ns.cmd:
        parser.print_help(sys.stderr)
        return 2
    try:
        if ns.cmd == "init":
            text = json.dumps(STARTER_POLICY, indent=2) + "\n"
            if ns.output == "-":
                stdout.write(text)
                return 0
            if os.path.exists(ns.output) and not ns.force:
                raise ToolgateError("%s exists (use --force to overwrite)" % ns.output)
            with open(ns.output, "w", encoding="utf-8") as fh:
                fh.write(text)
            stdout.write("wrote starter policy to %s\n" % ns.output)
            return 0
        policy = load_policy(ns.policy)
        if policy.unknown_keys:
            sys.stderr.write("toolgate: warning: unknown policy keys ignored: %s\n" % ", ".join(policy.unknown_keys))
        if ns.cmd in ("explain", "list-rules"):
            if ns.json:
                stdout.write(json.dumps({
                    "policy": policy.name, "default": policy.default,
                    "tools": {"allow": policy.tools_allow, "deny": policy.tools_deny, "warn": policy.tools_warn},
                    "caps": {"total": policy.cap_total, "per_tool": policy.cap_per_tool,
                             "severity": policy.cap_severity},
                    "rules": [{"id": r.id, "kind": r.kind, "severity": r.severity, "tools": r.tools,
                               "keys": r.keys, "allow": r.allow, "deny": r.deny,
                               "deny_programs": r.deny_programs, "deny_patterns": [p for p, _ in r.deny_patterns],
                               "builtin_patterns": r.builtin if r.kind == "command" else None}
                              for r in policy.rules]}, indent=2) + "\n")
            else:
                stdout.write(explain(policy))
            return 0
        if ns.cmd == "audit":
            rep = audit(policy, load_records(ns.transcript), ns.format)
            code = gate(rep, ns.fail_on)
            if ns.json:
                rep["exit_code"] = code
                stdout.write(json.dumps(rep, indent=2, default=str) + "\n")
            else:
                stdout.write(render_audit_text(rep))
            return code
        if ns.cmd == "check":
            call = parse_single_call(_read_call_arg(ns.call))
            counter = load_state(ns.state) if ns.state else None
            vs = evaluate_call(policy, call, counter)
            if ns.state:
                save_state(ns.state, counter)
            dec = decision_of(vs)
            res = {"decision": dec, "tool": call.tool, "violations": vs}
            if ns.json:
                stdout.write(json.dumps(res, indent=2) + "\n")
            elif not (ns.quiet and dec == "allow"):
                stdout.write(render_check_text(res))
            return ns.deny_exit if dec == "deny" else ns.warn_exit if dec == "warn" else 0
    except ToolgateError as exc:
        sys.stderr.write("toolgate: error: %s\n" % exc)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
