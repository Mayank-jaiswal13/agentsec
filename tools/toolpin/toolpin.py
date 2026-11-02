#!/usr/bin/env python3
"""toolpin: pin an MCP server's tool definitions and detect drift ("rug pulls") against the pin.

A tool you approved yesterday can quietly change today: a new sentence in its description that
tells the model to forward data, a new `url` parameter, a dropped enum, readOnlyHint flipped to
false, or a new tool on another server that shadows a trusted one. toolpin writes a lockfile with
per-tool SHA-256 hashes of the canonicalized definition (name, title, description, inputSchema,
annotations) and later compares a fresh snapshot against it, explaining every change by risk.

Inputs: MCP tools/list results (raw or JSON-RPC wrapped), OpenAI or Anthropic tool-definition
arrays, and multi-server {server: tools} maps. Standard library only; never contacts a server.
"""
import argparse
import datetime
import difflib
import hashlib
import json
import os
import re
import sys
import unicodedata

VERSION = "0.1.0"
LOCK_FORMAT = 1
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
DEFAULT_SERVER = "default"

RULES = {
    "PN01": ("medium", "Tool description changed (high if the added text has injection phrasing, URLs or exfil words; critical if it adds hidden Unicode)"),
    "PN02": ("low", "New input parameter (medium if required; high if url/command/path/recipient-like)"),
    "PN03": ("medium", "Input constraint removed or widened (enum/const/pattern/max*/format dropped, enum values added)"),
    "PN04": ("medium", "Input type loosened (types added or removed, additionalProperties no longer false)"),
    "PN05": ("low", "Other input schema change (param removed, required changed, param description changed; high if suspicious)"),
    "PN06": ("high", "Annotation weakened (readOnlyHint true->false, destructiveHint false->true; openWorld medium; other low)"),
    "PN07": ("low", "New tool added (medium if suspicious text or near-duplicate name on same server; high if it shadows a tool on another server)"),
    "PN08": ("info", "Tool removed"),
    "PN09": ("low", "Tool renamed (identical definition under a new name)"),
    "PN10": ("low", "Server added (not in the lockfile)"),
    "PN11": ("info", "Server removed"),
    "PN12": ("low", "Tool title changed (high if suspicious)"),
    "PN13": ("high", "Lockfile entry does not match its own hash (lockfile edited or corrupted)"),
}

# ---------------------------------------------------------------- loading / normalizing

class InputError(Exception):
    pass


def load_json(path):
    try:
        if path == "-":
            return json.load(sys.stdin)
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as e:
        raise InputError("%s: %s" % (path, e))


def _tool_list(obj):
    """Return a list of tool dicts if obj looks like a single server's tools, else None."""
    if isinstance(obj, dict):
        if isinstance(obj.get("result"), dict) and "tools" in obj["result"]:
            obj = obj["result"]
        if isinstance(obj.get("tools"), list):
            return obj["tools"]
        return None
    if isinstance(obj, list) and all(isinstance(t, dict) for t in obj):
        return obj
    return None


def canon_tool(t):
    """Normalize MCP / OpenAI / Anthropic tool definitions to one shape."""
    if t.get("type") == "function" and isinstance(t.get("function"), dict):
        t = t["function"]
    name = t.get("name")
    if not isinstance(name, str) or not name:
        raise InputError("tool without a name: %s" % json.dumps(t)[:80])
    schema = t.get("inputSchema", t.get("input_schema", t.get("parameters")))
    out = {"name": name,
           "description": t.get("description") or "",
           "inputSchema": schema if isinstance(schema, dict) else {},
           "annotations": t.get("annotations") if isinstance(t.get("annotations"), dict) else {}}
    title = t.get("title") or (out["annotations"].get("title") if out["annotations"] else None)
    if title:
        out["title"] = title
    return out


def normalize(obj, server=None):
    """Return {server: {tool_name: canon_tool}} from any supported snapshot shape."""
    if isinstance(obj, dict) and isinstance(obj.get("servers"), dict):
        obj = obj["servers"]
        tools = None
    else:
        tools = _tool_list(obj)
    if tools is not None:
        servers = {server or DEFAULT_SERVER: tools}
    elif isinstance(obj, dict) and obj and all(_tool_list(v) is not None for v in obj.values()):
        servers = {k: _tool_list(v) for k, v in obj.items()}
    else:
        raise InputError("unrecognized snapshot: expected tools/list result, tool array or {server: tools} map")
    out = {}
    for srv, lst in servers.items():
        d = {}
        for t in lst:
            c = canon_tool(t)
            if c["name"] in d:
                raise InputError("duplicate tool %r on server %r" % (c["name"], srv))
            d[c["name"]] = c
        out[srv] = d
    return out


def cjson(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(x):
    return hashlib.sha256(cjson(x).encode("utf-8")).hexdigest()


def body(t):
    return {k: v for k, v in t.items() if k != "name"}


def hashes(t):
    return {"sha256": sha(t), "body_sha256": sha(body(t)),
            "description_sha256": sha(t["description"]), "schema_sha256": sha(t["inputSchema"]),
            "annotations_sha256": sha(t["annotations"])}

# ---------------------------------------------------------------- lockfile

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def make_lock(servers, source=""):
    lock = {"toolpin": LOCK_FORMAT, "created": now_iso(), "source": source, "servers": {}}
    for srv in sorted(servers):
        lock["servers"][srv] = {"tools": {}}
        for name in sorted(servers[srv]):
            t = servers[srv][name]
            lock["servers"][srv]["tools"][name] = {"hashes": hashes(t), "definition": t}
    return lock


def is_lock(obj):
    return isinstance(obj, dict) and "toolpin" in obj and isinstance(obj.get("servers"), dict)


def read_lock(obj):
    """Return ({server: {name: tool}}, integrity findings)."""
    if not is_lock(obj):
        raise InputError("not a toolpin lockfile")
    servers, issues = {}, []
    for srv, sd in obj["servers"].items():
        servers[srv] = {}
        for name, entry in (sd.get("tools") or {}).items():
            t = entry.get("definition") or {}
            servers[srv][name] = t
            want = (entry.get("hashes") or {}).get("sha256")
            if t.get("name") != name or want != sha(t):
                issues.append(Finding("PN13", "high", srv, name,
                                      "lockfile entry hash mismatch: the pinned definition was edited after pinning"))
    return servers, issues

# ---------------------------------------------------------------- heuristics

HIDDEN_RE = re.compile("[\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff"
                       "\ufe00-\ufe0f\U000e0000-\U000e007f\U000e0100-\U000e01ef]")
INJECTION_RE = re.compile(
    r"ignore (?:all |any )?(?:previous|prior|above|earlier|other) (?:instructions|rules|prompts)"
    r"|disregard (?:all |any |the )?(?:previous|prior|above|system)"
    r"|(?:do not|don't|never) (?:tell|inform|mention|reveal|show|notify)\b[^.]{0,30}\buser"
    r"|without (?:telling|asking|informing|notifying)\b"
    r"|before (?:using|calling|running|invoking) (?:this|any|the) tool"
    r"|<\s*/?\s*(?:important|system|instructions?|secret)\s*>"
    r"|\b(?:you must|you should always|always (?:call|send|include|forward|use)|instead of (?:calling|using))\b"
    r"|\b(?:secretly|silently|covertly)\b|system prompt|\boverride\b", re.I)
URL_RE = re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>)]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|xyz|ru|top|site|app|dev)\b", re.I)
EXFIL_RE = re.compile(
    r"\b(?:exfiltrat\w*|forward(?:ed|ing)? (?:it|them|all|the|to)|upload(?:ed|ing)? (?:it|them|all|the|to)"
    r"|send (?:it|them|all|the|a copy|copies|to)|bcc|cc:|webhook|post (?:it |them )?to)\b"
    r"|~/\.ssh|id_rsa|\.env\b|\b(?:api[ _-]?keys?|access tokens?|passwords?|credentials?|private keys?|secrets?)\b"
    r"|mcp\.json|\.aws/credentials", re.I)


def hidden_desc(text):
    chars = HIDDEN_RE.findall(text)
    if not chars:
        return ""
    tag = "".join(chr(ord(c) - 0xE0000) for c in chars if 0xE0020 <= ord(c) <= 0xE007E)
    kinds = sorted({unicodedata.name(c, "U+%04X" % ord(c)) for c in chars})[:3]
    s = "%d hidden char(s) (%s)" % (len(chars), ", ".join(kinds))
    if tag:
        s += ", TAG text decodes to %r" % tag[:80]
    return s


def suspicious(text):
    """Return (severity_or_None, [reasons]) for text that a model will read."""
    reasons, sev = [], None
    h = hidden_desc(text)
    if h:
        reasons.append(h)
        sev = "critical"
    for label, rx in (("injection phrasing", INJECTION_RE), ("URL/domain", URL_RE), ("exfil wording", EXFIL_RE)):
        m = rx.search(text)
        if m:
            reasons.append("%s %r" % (label, m.group(0)[:60]))
            sev = sev or "high"
    return sev, reasons


def added_text(old, new):
    """Text present in new but not in old, at word granularity."""
    a, b = re.findall(r"\S+", old or ""), re.findall(r"\S+", new or "")
    out = []
    for op, _, _, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if op in ("insert", "replace"):
            out.append(" ".join(b[j1:j2]))
    # hidden chars may sit inside an otherwise unchanged word; keep them visible
    text = " ... ".join(out)
    extra = "".join(c for c in (new or "") if HIDDEN_RE.match(c) and c not in (old or "") and c not in text)
    return text + extra


def sentences(text):
    return [s for s in re.split(r"(?<=[.!?])\s+|\n", text or "") if s.strip()]


def short_diff(old, new, limit=12):
    lines = list(difflib.unified_diff(sentences(old), sentences(new), "pinned", "current", n=1, lineterm=""))
    out = []
    for ln in lines[2:]:
        ln = re.sub("(?:%s)+" % HIDDEN_RE.pattern, lambda m: "<%d hidden char(s)>" % len(m.group(0)), ln)
        out.append(ln if len(ln) <= 160 else ln[:157] + "...")
    if len(out) > limit:
        out = out[:limit] + ["... (%d more diff lines)" % (len(out) - limit)]
    return out


SENSITIVE_PARAM_WORDS = {
    "url", "uri", "urls", "link", "endpoint", "webhook", "callback", "host", "hostname", "domain", "server",
    "command", "cmd", "script", "shell", "exec", "code", "eval", "path", "file", "filename", "filepath",
    "dir", "directory", "folder", "recipient", "recipients", "to", "cc", "bcc", "email", "address",
    "phone", "destination", "dest", "forward", "upload", "sink", "redirect"}


def words(name):
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name or "")
    return [w.lower() for w in re.split(r"[^A-Za-z0-9]+", name) if w]


def sensitive_param(name):
    return bool(set(words(name)) & SENSITIVE_PARAM_WORDS)


def norm_name(name):
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def edit_distance(a, b):
    """Damerau-Levenshtein (optimal string alignment)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def similar_name(a, b):
    """'same' if names normalize equal, 'near' if within one edit (names >= 5 chars), else ''."""
    na, nb = norm_name(a), norm_name(b)
    if not na or not nb:
        return ""
    if na == nb:
        return "same"
    if min(len(na), len(nb)) >= 5 and edit_distance(na, nb) <= 1:
        return "near"
    return ""

# ---------------------------------------------------------------- findings

class Finding:
    def __init__(self, rule, severity, server, tool, message, details=None, diff=None):
        self.rule, self.severity, self.server, self.tool = rule, severity, server, tool
        self.message, self.details, self.diff = message, details or [], diff or []

    @property
    def where(self):
        return "%s/%s" % (self.server, self.tool) if self.tool else self.server

    def to_dict(self):
        return {"rule": self.rule, "severity": self.severity, "server": self.server, "tool": self.tool,
                "message": self.message, "details": self.details, "diff": self.diff}


def max_sev(*sevs):
    return max((s for s in sevs if s), key=lambda s: SEV_RANK[s])


def type_set(s):
    t = s.get("type") if isinstance(s, dict) else None
    if t is None:
        return None
    return set(t) if isinstance(t, list) else {t}


CONSTRAINT_KEYS = ("enum", "const", "pattern", "maxLength", "maximum", "exclusiveMaximum", "minimum",
                   "exclusiveMinimum", "minLength", "format", "maxItems", "maxProperties")


def diff_schema(old, new, path, out):
    """Append (rule, severity, message, details) tuples describing changes between two schemas."""
    if not isinstance(old, dict) or not isinstance(new, dict):
        return
    label = path or "(root)"
    for k in CONSTRAINT_KEYS:
        if k in old and k not in new:
            sev = "high" if sensitive_param(path.split(".")[-1]) and k in ("enum", "const", "pattern") else "medium"
            out.append(("PN03", sev, "constraint %s removed from %s (was %s)" % (k, label, cjson(old[k])[:80]), []))
    if isinstance(old.get("enum"), list) and isinstance(new.get("enum"), list):
        added = [v for v in new["enum"] if v not in old["enum"]]
        if added:
            out.append(("PN03", "medium", "enum of %s widened with %s" % (label, cjson(added)[:80]), []))
    ot, nt = type_set(old), type_set(new)
    if ot is not None and ot != nt:
        if nt is None:
            out.append(("PN04", "medium", "type of %s removed (was %s; now accepts anything)" % (label, "/".join(sorted(ot))), []))
        elif not nt <= ot:
            out.append(("PN04", "medium", "type of %s loosened %s -> %s" % (label, "/".join(sorted(ot)), "/".join(sorted(nt))), []))
        else:
            out.append(("PN05", "low", "type of %s narrowed %s -> %s" % (label, "/".join(sorted(ot)), "/".join(sorted(nt))), []))
    if old.get("additionalProperties") is False and new.get("additionalProperties") is not False and (
            "properties" in old or "properties" in new):
        out.append(("PN04", "medium", "additionalProperties of %s is no longer false (extra arguments now accepted)" % label, []))
    od, nd = old.get("description") or "", new.get("description") or ""
    if path and od != nd:
        sev, why = suspicious(added_text(od, nd))
        out.append(("PN05", sev or "low", "description of parameter %s changed" % path, why))
    op, np_ = old.get("properties") or {}, new.get("properties") or {}
    oreq, nreq = set(old.get("required") or []), set(new.get("required") or [])
    if isinstance(op, dict) and isinstance(np_, dict):
        for p in np_:
            if p not in op:
                full = (path + "." if path else "") + p
                sev = "high" if sensitive_param(p) else ("medium" if p in nreq else "low")
                why = ["url/command/path/recipient-like name"] if sensitive_param(p) else []
                if p in nreq:
                    why.append("required")
                s2, w2 = suspicious(added_text("", (np_[p] or {}).get("description") or "")) if isinstance(np_[p], dict) else (None, [])
                out.append(("PN02", max_sev(sev, s2), "new parameter %s (%s)" % (full, cjson(np_[p])[:80]), why + w2))
        for p in op:
            full = (path + "." if path else "") + p
            if p not in np_:
                out.append(("PN05", "low", "parameter %s removed" % full, []))
            else:
                diff_schema(op[p], np_[p], full, out)
        for p in sorted(oreq - nreq):
            if p in np_:
                out.append(("PN05", "low", "parameter %s is no longer required" % ((path + "." if path else "") + p), []))
        for p in sorted(nreq - oreq):
            if p in op:
                out.append(("PN05", "low", "parameter %s is now required" % ((path + "." if path else "") + p), []))
    if isinstance(old.get("items"), dict) or isinstance(new.get("items"), dict):
        diff_schema(old.get("items") or {}, new.get("items") or {}, (path or "") + "[]", out)


ANNOTATION_DEFAULTS = {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}


def diff_annotations(old, new):
    out = []
    oe = dict(ANNOTATION_DEFAULTS, **{k: v for k, v in old.items() if k in ANNOTATION_DEFAULTS})
    ne = dict(ANNOTATION_DEFAULTS, **{k: v for k, v in new.items() if k in ANNOTATION_DEFAULTS})
    def show(d, k):
        return "%s%s" % (cjson(d[k]), "" if k in (old if d is oe else new) else " (default)")
    if oe["readOnlyHint"] is True and ne["readOnlyHint"] is not True:
        out.append(("high", "readOnlyHint %s -> %s: tool no longer claims to be read-only" % (show(oe, "readOnlyHint"), show(ne, "readOnlyHint"))))
    if oe["destructiveHint"] is False and ne["destructiveHint"] is not False:
        out.append(("high", "destructiveHint %s -> %s: tool may now destroy data" % (show(oe, "destructiveHint"), show(ne, "destructiveHint"))))
    if oe["openWorldHint"] is False and ne["openWorldHint"] is not False:
        out.append(("medium", "openWorldHint %s -> %s: tool now reaches external systems" % (show(oe, "openWorldHint"), show(ne, "openWorldHint"))))
    if oe["idempotentHint"] is True and ne["idempotentHint"] is not True:
        out.append(("low", "idempotentHint %s -> %s" % (show(oe, "idempotentHint"), show(ne, "idempotentHint"))))
    if not out and old != new:
        keys = sorted(k for k in set(old) | set(new) if old.get(k) != new.get(k))
        out.append(("low", "annotations changed: %s" % ", ".join(keys)))
    return out


def compare(pinned, current):
    """Compare {server: {name: tool}} maps; return findings."""
    f = []
    all_pinned = [(s, n) for s in pinned for n in pinned[s]]
    for srv in sorted(set(pinned) | set(current)):
        if srv not in current:
            f.append(Finding("PN11", "info", srv, None, "server removed (%d pinned tools)" % len(pinned[srv])))
            continue
        cur = current[srv]
        if srv not in pinned:
            f.append(Finding("PN10", "low", srv, None, "server not in lockfile (%d tools): review and pin it" % len(cur),
                             details=sorted(cur)[:20]))
            for name in sorted(cur):
                f.extend(new_tool_findings(srv, cur[name], pinned, current, only_shadow=True))
            continue
        old = pinned[srv]
        removed = [n for n in old if n not in cur]
        added = [n for n in cur if n not in old]
        # rename: identical body under another name on the same server
        by_body = {}
        for n in removed:
            by_body.setdefault(sha(body(old[n])), []).append(n)
        renamed = set()
        for n in sorted(added):
            cand = by_body.get(sha(body(cur[n])))
            if cand:
                o = cand.pop(0)
                renamed.add(o)
                renamed.add(n)
                f.append(Finding("PN09", "low", srv, n, "tool %r renamed to %r (definition unchanged)" % (o, n)))
                f.extend(new_tool_findings(srv, cur[n], pinned, current, only_shadow=True, exclude=o))
        for n in sorted(removed):
            if n not in renamed:
                f.append(Finding("PN08", "info", srv, n, "tool removed"))
        for n in sorted(added):
            if n not in renamed:
                f.extend(new_tool_findings(srv, cur[n], pinned, current))
        for n in sorted(set(old) & set(cur)):
            f.extend(changed_tool_findings(srv, old[n], cur[n]))
    f.sort(key=lambda x: (x.server, x.tool or "", -SEV_RANK[x.severity], x.rule))
    return f


def new_tool_findings(srv, tool, pinned, current, only_shadow=False, exclude=None):
    name = tool["name"]
    sev, why = "low", []
    for s2 in sorted(set(pinned) | set(current)):
        names = set(pinned.get(s2, {})) | set(current.get(s2, {}))
        for other in sorted(names):
            if (s2 == srv and other == name) or other == exclude:
                continue
            kind = similar_name(name, other)
            if not kind:
                continue
            if s2 != srv and other in pinned.get(s2, {}):
                sev = "high"
                why.append("%s %s/%s (possible cross-server shadowing)" %
                           ("shadows" if kind == "same" else "near-duplicate of", s2, other))
            elif s2 == srv and kind == "near" and other in pinned.get(s2, {}):
                sev = max_sev(sev, "medium")
                why.append("near-duplicate of pinned %s/%s (typo-squat?)" % (s2, other))
    if only_shadow and sev != "high":
        return []
    s2, w2 = suspicious(tool["description"] + " " + (tool.get("title") or ""))
    if s2:
        sev = max_sev(sev, "medium" if s2 == "high" else s2)
        why += ["description: " + w for w in w2]
    return [Finding("PN07", sev, srv, name, "new tool not in lockfile", details=why,
                    diff=["+ " + l for l in sentences(tool["description"])[:4]])]


def changed_tool_findings(srv, old, new):
    if sha(old) == sha(new):
        return []
    f, name = [], new["name"]
    if old["description"] != new["description"]:
        sev, why = suspicious(added_text(old["description"], new["description"]))
        f.append(Finding("PN01", max_sev("medium", sev), srv, name, "description changed", details=why,
                         diff=short_diff(old["description"], new["description"])))
    if (old.get("title") or "") != (new.get("title") or ""):
        sev, why = suspicious(added_text(old.get("title") or "", new.get("title") or ""))
        f.append(Finding("PN12", sev or "low", srv, name, "title %r -> %r" % (old.get("title"), new.get("title")), details=why))
    if sha(old["inputSchema"]) != sha(new["inputSchema"]):
        items = []
        diff_schema(old["inputSchema"], new["inputSchema"], "", items)
        if not items:
            items.append(("PN05", "low", "input schema changed (non-semantic keys)", []))
        for rule, sev, msg, why in items:
            f.append(Finding(rule, sev, srv, name, msg, details=why))
    oa = {k: v for k, v in old["annotations"].items() if k != "title"}
    na = {k: v for k, v in new["annotations"].items() if k != "title"}
    if oa != na:
        for sev, msg in diff_annotations(oa, na):
            f.append(Finding("PN06", sev, srv, name, msg))
    return f

# ---------------------------------------------------------------- CLI

def load_current(path, server):
    obj = load_json(path)
    if is_lock(obj):
        servers, _ = read_lock(obj)
        return servers
    return normalize(obj, server)


def cmd_pin(a):
    servers = normalize(load_json(a.snapshot), a.server)
    lock = make_lock(servers, source=os.path.basename(a.snapshot) if a.snapshot != "-" else "stdin")
    text = json.dumps(lock, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if a.output == "-":
        sys.stdout.write(text)
    else:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        n = sum(len(v) for v in servers.values())
        print("pinned %d tool(s) on %d server(s) -> %s" % (n, len(servers), a.output), file=sys.stderr)
    return 0


def cmd_show(a):
    obj = load_json(a.file)
    if is_lock(obj):
        servers, issues = read_lock(obj)
        meta = {"created": obj.get("created"), "source": obj.get("source")}
    else:
        servers, issues, meta = normalize(obj, a.server), [], {"created": None, "source": "snapshot (not pinned)"}
    rows = []
    for srv in sorted(servers):
        for n in sorted(servers[srv]):
            t = servers[srv][n]
            props = (t.get("inputSchema") or {}).get("properties") or {}
            rows.append({"server": srv, "tool": n, "sha256": sha(t), "params": sorted(props),
                         "annotations": {k: v for k, v in (t.get("annotations") or {}).items() if k != "title"}})
    if a.json:
        print(json.dumps({"version": VERSION, "meta": meta, "tools": rows,
                          "integrity": [i.to_dict() for i in issues]}, indent=2))
    else:
        print("%s (created %s): %d server(s), %d tool(s)" % (a.file, meta["created"] or "-", len(servers), len(rows)))
        for r in rows:
            print("  %-40s %s  params=%s" % (r["server"] + "/" + r["tool"], r["sha256"][:12], ",".join(r["params"]) or "-"))
        for i in issues:
            print("[%s] %s %s  %s" % (i.severity.upper(), i.rule, i.where, i.message))
    return 1 if issues else 0


def cmd_check(a):
    lock_obj = load_json(a.lockfile)
    pinned, issues = read_lock(lock_obj)
    current = load_current(a.snapshot, a.server)
    findings = issues + compare(pinned, current)
    shown = [f for f in findings if SEV_RANK[f.severity] >= SEV_RANK[a.min_severity]]
    summary = {"pinned_servers": len(pinned), "pinned_tools": sum(len(v) for v in pinned.values()),
               "current_servers": len(current), "current_tools": sum(len(v) for v in current.values()),
               "findings": len(findings),
               "by_severity": {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}}
    if a.json:
        print(json.dumps({"version": VERSION, "lockfile": a.lockfile, "snapshot": a.snapshot,
                          "summary": summary, "findings": [f.to_dict() for f in shown]}, indent=2, ensure_ascii=False))
    else:
        print("toolpin check: %s (%d tools) vs %s (%d tools): %d change finding(s)" % (
            a.lockfile, summary["pinned_tools"], a.snapshot, summary["current_tools"], len(findings)))
        for f in shown:
            print("[%s] %s %s  %s" % (f.severity.upper(), f.rule, f.where, f.message))
            for d in f.details:
                print("    - " + d)
            for d in f.diff:
                print("      " + d)
        if not findings:
            print("No drift: every tool matches its pin.")
        print("Note: toolpin reports change, not intent. Review each change, then re-pin with `toolpin.py pin`.")
    if a.fail_on == "none":
        return 0
    thr = 0 if a.fail_on == "any" else SEV_RANK[a.fail_on]
    return 1 if any(SEV_RANK[f.severity] >= thr for f in findings) else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="toolpin", description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", action="version", version="toolpin " + VERSION)
    ap.add_argument("--list-rules", action="store_true", help="list rules and exit")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("pin", help="write a lockfile from a snapshot")
    p.add_argument("snapshot", help="tools/list JSON, tool array or {server: tools} map ('-' = stdin)")
    p.add_argument("-o", "--output", default="toolpin.lock.json", help="lockfile path ('-' = stdout)")
    p.add_argument("--server", help="server name for single-server snapshots (default 'default')")
    c = sub.add_parser("check", help="compare a snapshot against a lockfile")
    c.add_argument("snapshot")
    c.add_argument("-l", "--lockfile", default="toolpin.lock.json")
    c.add_argument("--server", help="server name for single-server snapshots (default 'default')")
    c.add_argument("--json", action="store_true")
    c.add_argument("--min-severity", choices=SEVERITIES, default="info")
    c.add_argument("--fail-on", choices=SEVERITIES[1:] + ["any", "none"], default="high")
    s = sub.add_parser("show", help="list pinned tools and verify lockfile integrity")
    s.add_argument("file", nargs="?", default="toolpin.lock.json")
    s.add_argument("--server")
    s.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.list_rules:
        for r, (sev, t) in sorted(RULES.items()):
            print("%s  %-8s %s" % (r, sev, t))
        return 0
    if not a.cmd:
        ap.print_help()
        return 2
    try:
        return {"pin": cmd_pin, "check": cmd_check, "show": cmd_show}[a.cmd](a)
    except InputError as e:
        print("toolpin: error: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
