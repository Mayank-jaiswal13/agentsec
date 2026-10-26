#!/usr/bin/env python3
"""toolpoison - static, offline scanner for MCP tool manifests.

Flags tool-poisoning / prompt-injection patterns in MCP tool names,
descriptions and inputSchemas using HEURISTIC PATTERN MATCHING.

It cannot prove a server is safe. It never executes or contacts a server,
cannot see runtime behaviour, and cannot see descriptions that change after
approval ("rug pulls") unless you diff snapshots with --diff.

Standard library only. MIT licensed.
"""
import argparse
import hashlib
import json
import re
import sys
import unicodedata

__version__ = "0.1.0"

DISCLAIMER = ("Note: toolpoison is heuristic pattern matching. A clean result does not "
              "prove a server is safe; it cannot see runtime behaviour or descriptions "
              "that change after approval (rug pulls) unless you diff snapshots (--diff).")

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "TP01": ("hidden-instruction", "high",
             "Instruction-override / concealment phrasing aimed at the model"),
    "TP02": ("invisible-unicode", "high",
             "Invisible, zero-width, bidi-control or Unicode tag characters"),
    "TP03": ("sensitive-path", "high",
             "Reference to sensitive files/paths (SSH keys, .env, cloud creds, MCP config)"),
    "TP04": ("exfiltration-hint", "high",
             "Instructions to send/encode/embed data (URLs, base64, put contents in a parameter)"),
    "TP05": ("smuggling-parameter", "medium",
             "Parameter name that invites data smuggling (sidenote, notes, context...); "
             "high if its description asks for file/secret contents"),
    "TP06": ("cross-tool-shadowing", "high",
             "Description tries to alter how another tool behaves"),
    "TP07": ("excessive-length", "low",
             "Unusually long description (room to hide instructions)"),
    "TP08": ("confusable-name", "medium",
             "Tool/parameter name mixes scripts or uses non-ASCII confusable letters"),
    "TP09": ("duplicate-name", "medium",
             "Same tool name defined more than once (across or within files)"),
    "TP10": ("hidden-markup", "medium",
             "HTML comments, hidden HTML/markdown, or pseudo-system tags"),
}

# ---------------------------------------------------------------- patterns
I = re.IGNORECASE
TP01_PATTERNS = [
    r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|prompts?|rules|directions)",
    r"disregard\s+(all\s+|any\s+)?(previous|prior|above|earlier|your)\s+(instructions|rules|guidelines)",
    r"forget\s+(all\s+)?(previous|prior|your)\s+instructions",
    r"(do\s*n[o']?t|never)\s+(tell|inform|mention|reveal|notify|alert|show)\s+(this\s+to\s+)?(the\s+)?user",
    r"without\s+(telling|informing|notifying|alerting)\s+(the\s+)?user",
    r"(the\s+)?user\s+(must|should)\s+(not|never)\s+(know|be\s+told|see|find\s+out)",
    r"(keep|this\s+is)\s+(this\s+)?(secret|hidden|confidential)\s+from\s+(the\s+)?user",
    r"before\s+(using|calling|invoking|running)\s+this\s+tool,?\s+(you\s+must\s+|first\s+|always\s+)?(read|open|cat|load|fetch|access|call)",
    r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin|override)\s*>",
    r"\b(you\s+are\s+now|new\s+instructions\s*:|system\s+prompt\s*:|act\s+as\s+(an?\s+)?(admin|root|developer))",
    r"(otherwise|or\s+else)\s+the\s+tool\s+will\s+(not\s+work|fail|crash)",
    r"this\s+is\s+(very\s+)?(important|critical|mandatory)\s*[,:-]?\s*(you\s+must|always|do\s+not)",
]
TP03_PATTERNS = [
    r"~?/?\.ssh\b[/\w.-]*", r"\bid_(rsa|dsa|ecdsa|ed25519)(\.pub)?\b", r"\bauthorized_keys\b",
    r"(^|[\s/'\"`(])\.env(\.[\w-]+)?\b", r"~?/?\.aws/(credentials|config)\b", r"\baws_secret_access_key\b",
    r"\bmcp\.json\b", r"claude_desktop_config\.json", r"~?/?\.cursor/[\w./-]*",
    r"~?/?\.kube/config\b", r"~?/?\.docker/config\.json\b", r"~?/?\.npmrc\b", r"~?/?\.pypirc\b",
    r"~?/?\.netrc\b", r"~?/?\.git-credentials\b", r"~?/?\.config/gcloud\b",
    r"/etc/(passwd|shadow|sudoers)\b", r"~?/?\.gnupg\b", r"\.bash_history\b", r"\.zsh_history\b",
    r"\bwallet\.dat\b", r"\b(private[_ -]?key|seed\s+phrase|mnemonic\s+phrase)\b",
    r"%(USERPROFILE|APPDATA)%", r"Login\s+Data\b", r"\bkeychain\b",
]
_DATA = r"(the\s+)?(contents?|data|file|files|keys?|secrets?|credentials?|tokens?|passwords?|conversation|chat\s+history|history|messages?|results?|output|response|it|them|this)"
TP04_PATTERNS = [
    r"(send|post|upload|forward|transmit|exfiltrate|leak|submit|report|beacon)\w*\s+(all\s+|any\s+)?" + _DATA + r"[^.\n]{0,80}?\s+to\s+(https?://|ftp://|\S+@\S+|(the\s+)?(remote|external|following)\s+(server|url|endpoint|address))",
    r"(curl|wget|fetch|http\s+(post|get)|requests\.(post|get))\s+[^\n]{0,40}https?://",
    r"base64[\s-]*(encode|encoded|encoding)", r"(encode|encoded)\s+[^.\n]{0,40}\bbase64",
    r"(pass|put|include|insert|embed|append|place|add|provide)\w*\s+(the\s+)?(full\s+|entire\s+|raw\s+)?(contents?|text|data|value)\s+(of\s+[^.\n]{1,60}?\s+)?(in|into|as|inside|within)\s+(the\s+|this\s+|a\s+)?['\"`]?\w+['\"`]?\s+(parameter|param|argument|field)",
    r"(as|in|into)\s+(the\s+)?['\"`]?\w+['\"`]?\s+(parameter|argument|field)[^.\n]{0,60}(contents?\s+of|file\s+contents|secrets?|credentials?|keys?)",
    r"\bwebhook\.site\b|\brequestbin\b|\bngrok\.io\b|\bpipedream\.net\b|\binteract\.sh\b|\bburpcollaborator\b",
    r"(bcc|cc)\s*[:]?\s*[\w.+-]+@[\w-]+\.[\w.]+",
]
TP06_PATTERNS = [
    r"(when|whenever|if|every\s+time|each\s+time)\s+(the\s+|any\s+)?[`'\"]?[\w.-]+[`'\"]?\s+(tool|function|command)\s+(is\s+)?(used|called|invoked|run|executed)",
    r"(when|whenever|if)\s+(you\s+)?(use|call|invoke|run)\s+(the\s+|any\s+)?(other\s+)?[`'\"]?[\w.-]+[`'\"]?\s+(tool|function)",
    r"(instead\s+of|rather\s+than)\s+(using\s+|calling\s+)?(the\s+)?[`'\"]?[\w.-]+[`'\"]?\s+tool",
    r"(all|any|every|other)\s+(other\s+)?(tools?|tool\s+calls?)\s+(must|should|need\s+to|are\s+required\s+to)",
    r"(always|must)\s+(also\s+)?(bcc|cc|redirect|reroute|change\s+the\s+recipient|send\s+a\s+copy)",
    r"(override|overrides|modify|modifies|change|changes|alter|alters|replace|replaces|hijack)\s+(the\s+)?(behaviou?r|parameters?|arguments?|recipient)\s+of\s+(the\s+)?(other\s+|another\s+|any\s+)?[\w.-]*\s*tools?",
]
TP10_PATTERNS = [
    r"<!--[\s\S]*?(-->|$)",
    r"<\s*(div|span|p|details)[^>]*(display\s*:\s*none|visibility\s*:\s*hidden|hidden\b)[^>]*>",
    r"<\s*details[^>]*>",
    r"\[//\]\s*:\s*#",  # markdown comment [//]: # (...)
    r"\[[^\]]*\]\(\s*#\s*['\"][^)]*\)",  # [](# "hidden title")
    r"<\s*(script|style|iframe)\b",
    r"\n\s*\n\s*\n\s*\n\s*\n",  # long run of blank lines pushing text out of view
    r"[ \t]{40,}\S",  # long horizontal padding hiding trailing text
]
SMUGGLE_NAMES = {"sidenote", "side_note", "note", "notes", "context", "extra", "extra_info",
                 "additional_context", "additional_info", "metadata", "meta", "debug", "feedback",
                 "comment", "comments", "remarks", "hidden", "internal", "reasoning", "thoughts",
                 "scratchpad", "memo", "aux", "payload", "data_blob"}
SMUGGLE_DESC = re.compile(
    r"(contents?\s+of|content\s+from|read\s+(the\s+)?(file|contents?)|file\s+contents|"
    r"(ssh|api|private|secret|access)\s*keys?|credentials?|passwords?|tokens?|secrets?|"
    r"conversation|chat\s+history|previous\s+messages|system\s+prompt|environment\s+variables|\.env)", I)

C01 = [re.compile(p, I) for p in TP01_PATTERNS]
C03 = [re.compile(p, I) for p in TP03_PATTERNS]
C04 = [re.compile(p, I) for p in TP04_PATTERNS]
C06 = [re.compile(p, I) for p in TP06_PATTERNS]
C10 = [re.compile(p, I) for p in TP10_PATTERNS]


def invisible_kind(ch):
    cp = ord(ch)
    if 0xE0000 <= cp <= 0xE007F:
        return "unicode-tag"
    if cp in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F, 0x061C):
        return "bidi-control"
    if cp in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x2061, 0x2062, 0x2063, 0x2064, 0x00AD, 0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0):
        return "zero-width/invisible"
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        return "variation-selector"
    if 0xE000 <= cp <= 0xF8FF or 0xF0000 <= cp <= 0x10FFFF:
        return "private-use"
    cat = unicodedata.category(ch)
    if cat == "Cf":
        return "format-control"
    if cat == "Cc" and ch not in "\n\r\t":
        return "control-char"
    return None


def visible(s):
    """Render a string with invisible characters escaped."""
    out = []
    for ch in s:
        if invisible_kind(ch) or (unicodedata.category(ch) == "Cc"):
            out.append("\\n" if ch == "\n" else "\\t" if ch == "\t" else "\\r" if ch == "\r" else "<U+%04X>" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def snippet(text, start, end, pad=40, maxlen=160):
    a, b = max(0, start - pad), min(len(text), end + pad)
    s = visible(text[a:b])
    if len(s) > maxlen:
        s = s[:maxlen] + "..."
    return ("..." if a > 0 else "") + s + ("..." if b < len(text) else "")


def script_of(ch):
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "UNKNOWN"
    if not ch.isalpha():
        return None
    for scr in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC", "CHEROKEE",
                "FULLWIDTH LATIN", "MATHEMATICAL", "CJK", "HIRAGANA", "KATAKANA", "HANGUL", "THAI", "DEVANAGARI"):
        if name.startswith(scr) or (" " + scr + " ") in name:
            return scr
    return name.split(" ")[0]


# ---------------------------------------------------------------- loading
class ParseError(Exception):
    pass


def extract_tools(doc, source):
    if isinstance(doc, list):
        tools = doc
    elif isinstance(doc, dict):
        if isinstance(doc.get("result"), dict) and "tools" in doc["result"]:
            tools = doc["result"]["tools"]
            base = "$.result.tools"
            return _validate(tools, source), base
        if "tools" in doc:
            tools = doc["tools"]
            return _validate(tools, source), "$.tools"
        if "name" in doc and ("description" in doc or "inputSchema" in doc):
            return _validate([doc], source), "$"
        raise ParseError("%s: no tools found (expected {\"tools\":[...]}, a list, or {\"result\":{\"tools\":[...]}})" % source)
    else:
        raise ParseError("%s: unsupported JSON top-level type %s" % (source, type(doc).__name__))
    return _validate(tools, source), "$"


def _validate(tools, source):
    if not isinstance(tools, list):
        raise ParseError("%s: 'tools' is not a list" % source)
    for i, t in enumerate(tools):
        if not isinstance(t, dict):
            raise ParseError("%s: tool #%d is not an object" % (source, i))
    return tools


def load(path, stdin=None):
    try:
        if path == "-":
            raw = (stdin or sys.stdin).read()
            source = "<stdin>"
        else:
            with open(path, "r", encoding="utf-8") as f:
                raw = f.read()
            source = path
    except (OSError, UnicodeDecodeError) as e:
        raise ParseError("%s: cannot read: %s" % (path, e))
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ParseError("%s: invalid JSON: %s" % (source, e))
    tools, base = extract_tools(doc, source)
    return source, tools, base


# ---------------------------------------------------------------- scanning
def iter_strings(obj, path, in_props=False):
    """Yield (path, kind, text). kind: 'key' for property names, else the JSON key."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = "%s.%s" % (path, k) if re.match(r"^[A-Za-z_][\w]*$", str(k)) else "%s[%s]" % (path, json.dumps(k))
            if in_props:
                yield p, "property-name", str(k)
            else:
                yield p, "key", str(k)
            if isinstance(v, str):
                yield p, str(k), v
            else:
                yield from iter_strings(v, p, in_props=(k == "properties" and isinstance(v, dict)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            p = "%s[%d]" % (path, i)
            if isinstance(v, str):
                yield p, "item", v
            else:
                yield from iter_strings(v, p)


def scan_tools(source, tools, base, max_desc_len=1000):
    findings = []
    seen = set()

    def add(rule, path, evidence, severity=None, message=None, tool=None):
        key = (rule, path, evidence)
        if key in seen:
            return
        seen.add(key)
        name, sev, desc = RULES[rule]
        findings.append({"rule": rule, "name": name, "severity": severity or sev,
                         "message": message or desc, "file": source, "tool": tool,
                         "path": path, "evidence": evidence})

    for i, tool in enumerate(tools):
        tpath = "%s[%d]" % (base, i)
        tname = tool.get("name") if isinstance(tool.get("name"), str) else None
        for path, kind, text in iter_strings(tool, tpath):
            # TP02 invisible unicode (all strings incl. keys)
            kinds = {}
            for idx, ch in enumerate(text):
                k = invisible_kind(ch)
                if k:
                    kinds.setdefault(k, []).append(idx)
            for k, idxs in kinds.items():
                sev = "critical" if k in ("unicode-tag", "bidi-control") else "high"
                ev = snippet(text, idxs[0], idxs[0] + 1)
                extra = ""
                if k == "unicode-tag":
                    hidden = "".join(chr(ord(text[j]) - 0xE0000) for j in idxs if 0x20 <= ord(text[j]) - 0xE0000 < 0x7F)
                    if hidden:
                        extra = " (decoded tag text: %r)" % hidden[:120]
                add("TP02", path, ev, sev, "%d %s character(s)%s" % (len(idxs), k, extra), tname)
            if kind == "key":
                continue
            # TP08 confusable names (tool name + property names)
            if kind in ("property-name",) or (kind == "name" and path == tpath + ".name"):
                letters = [c for c in text if c.isalpha()]
                scripts = {script_of(c) for c in letters} - {None}
                nonascii = [c for c in letters if ord(c) > 127]
                if len(scripts) > 1:
                    add("TP08", path, visible(text), "high",
                        "Name mixes scripts: %s" % ", ".join(sorted(scripts)), tname)
                elif nonascii:
                    add("TP08", path, visible(text), None,
                        "Name contains non-ASCII letters: %s" % ", ".join("U+%04X" % ord(c) for c in nonascii[:5]), tname)
            if kind == "property-name":
                low = text.lower()
                if low in SMUGGLE_NAMES:
                    # look up this property's description
                    pdesc = _prop_desc(tool, path, tpath)
                    if pdesc and SMUGGLE_DESC.search(pdesc):
                        m = SMUGGLE_DESC.search(pdesc)
                        add("TP05", path, "%s: %s" % (text, snippet(pdesc, m.start(), m.end())), "high",
                            "Parameter %r invites smuggling and its description asks for sensitive content" % text, tname)
                    else:
                        add("TP05", path, text, "low" if not pdesc else None,
                            "Parameter name %r is a common data-smuggling channel; review its use" % text, tname)
                continue
            # textual rules
            for rule, pats in (("TP01", C01), ("TP03", C03), ("TP04", C04), ("TP06", C06), ("TP10", C10)):
                spans = []
                for rx in pats:
                    for m in rx.finditer(text):
                        if not any(m.start() < e and s < m.end() for s, e in spans):
                            spans.append((m.start(), m.end()))
                if not spans:
                    continue
                spans.sort()
                matched = [visible(text[a:b]).strip() for a, b in spans]
                sev = None
                if rule == "TP04" and all("base64" in x.lower() for x in matched):
                    sev = "medium"  # base64 alone is often benign (e.g. image uploads)
                shown = "; ".join(repr(x[:60]) for x in matched[:5]) + (" ..." if len(matched) > 5 else "")
                add(rule, path, snippet(text, spans[0][0], spans[0][1]), sev,
                    "%s - %d match(es): %s" % (RULES[rule][2], len(matched), shown), tname)
            if kind == "description" and len(text) > max_desc_len:
                add("TP07", path, "%d chars (limit %d)" % (len(text), max_desc_len), tool=tname,
                    message="Description is %d characters (limit %d)" % (len(text), max_desc_len))
    return findings


def _prop_desc(tool, path, tpath):
    """Resolve the description for a property-name path like $.tools[0].inputSchema.properties.notes"""
    rel = path[len(tpath):]
    node = tool
    for tok in re.findall(r'\.([A-Za-z_]\w*)|\[("(?:[^"\\]|\\.)*"|\d+)\]', rel):
        key = tok[0] if tok[0] else (json.loads(tok[1]) if tok[1].startswith('"') else int(tok[1]))
        try:
            node = node[key]
        except (KeyError, IndexError, TypeError):
            return None
    if isinstance(node, dict):
        d = node.get("description")
        return d if isinstance(d, str) else None
    return None


def scan_files(paths, max_desc_len=1000, stdin=None):
    findings, loaded = [], []
    for p in paths:
        source, tools, base = load(p, stdin)
        loaded.append((source, tools, base))
        findings.extend(scan_tools(source, tools, base, max_desc_len))
    # TP09 duplicates across/within files
    where = {}
    for source, tools, base in loaded:
        for i, t in enumerate(tools):
            n = t.get("name")
            if isinstance(n, str):
                where.setdefault(unicodedata.normalize("NFKC", n).casefold(), []).append((source, i, n, base))
    for key, locs in where.items():
        if len(locs) > 1:
            desc = ", ".join("%s#%d" % (s, i) for s, i, _, _ in locs)
            for s, i, n, base in locs:
                findings.append({"rule": "TP09", "name": RULES["TP09"][0], "severity": RULES["TP09"][1],
                                 "message": "Tool name %r defined %d times (%s); a later definition may shadow another" % (n, len(locs), desc),
                                 "file": s, "tool": n, "path": "%s[%d].name" % (base, i),
                                 "evidence": visible(n)})
    total_tools = sum(len(t) for _, t, _ in loaded)
    return findings, total_tools


# ---------------------------------------------------------------- diff
def _canon(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def diff_snapshots(old_path, new_path, stdin=None):
    _, old, _ = load(old_path, stdin)
    _, new, _ = load(new_path, stdin)

    def index(tools):
        d = {}
        for t in tools:
            d[t.get("name") if isinstance(t.get("name"), str) else _canon(t)] = t
        return d
    o, n = index(old), index(new)
    changes = []
    for name in sorted(set(o) | set(n)):
        if name not in n:
            changes.append({"tool": name, "change": "removed", "fields": []})
        elif name not in o:
            changes.append({"tool": name, "change": "added", "fields": []})
        else:
            fields = sorted(k for k in set(o[name]) | set(n[name]) if _canon(o[name].get(k)) != _canon(n[name].get(k)))
            if fields:
                changes.append({"tool": name, "change": "modified", "fields": fields,
                                "old_sha256": hashlib.sha256(_canon(o[name]).encode()).hexdigest()[:16],
                                "new_sha256": hashlib.sha256(_canon(n[name]).encode()).hexdigest()[:16]})
    return changes


# ---------------------------------------------------------------- output
def format_text(findings, total_tools, nfiles, min_sev):
    lines = []
    shown = [f for f in findings if SEV_RANK[f["severity"]] >= SEV_RANK[min_sev]]
    shown.sort(key=lambda f: (-SEV_RANK[f["severity"]], f["file"], f["path"], f["rule"]))
    for f in shown:
        lines.append("[%s] %s %s  %s" % (f["severity"].upper(), f["rule"], f["name"], f["file"]))
        lines.append("    tool:     %s" % (visible(f["tool"]) if f["tool"] else "-"))
        lines.append("    path:     %s" % f["path"])
        lines.append("    message:  %s" % f["message"])
        lines.append("    evidence: %s" % f["evidence"])
    counts = {}
    for f in shown:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = ", ".join("%d %s" % (counts[s], s) for s in reversed(SEVERITIES) if s in counts) or "no findings"
    if lines:
        lines.append("")
    lines.append("Scanned %d tool(s) in %d file(s): %s (min severity: %s)." % (total_tools, nfiles, summary, min_sev))
    lines.append(DISCLAIMER)
    return "\n".join(lines)


def main(argv=None, stdin=None, stdout=None, stderr=None):
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    ap = argparse.ArgumentParser(prog="toolpoison",
                                 description="Static, offline heuristic scanner for MCP tool manifests (tool poisoning / prompt injection).",
                                 epilog=DISCLAIMER)
    ap.add_argument("files", nargs="*", help="JSON files ('-' for stdin)")
    ap.add_argument("--json", action="store_true", help="machine-readable JSON output")
    ap.add_argument("--min-severity", default="low", choices=SEVERITIES,
                    help="report/fail only on findings at or above this severity (default: low)")
    ap.add_argument("--max-desc-len", type=int, default=1000, help="TP07 threshold (default 1000 chars)")
    ap.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"),
                    help="compare two snapshots and report added/removed/modified tools (rug-pull detection); "
                         "also scans NEW")
    ap.add_argument("--list-rules", action="store_true", help="print rule table and exit")
    ap.add_argument("--version", action="version", version="toolpoison " + __version__)
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return 0 if e.code == 0 else 2

    if args.list_rules:
        for rid, (name, sev, desc) in RULES.items():
            print("%s  %-22s %-8s %s" % (rid, name, sev, desc), file=stdout)
        return 0
    if not args.files and not args.diff:
        print("toolpoison: error: no input files (use '-' for stdin)", file=stderr)
        return 2
    if args.files and args.diff:
        print("toolpoison: error: use either FILES or --diff OLD NEW, not both", file=stderr)
        return 2

    try:
        changes = None
        if args.diff:
            changes = diff_snapshots(args.diff[0], args.diff[1], stdin)
            findings, total = scan_files([args.diff[1]], args.max_desc_len, stdin)
            nfiles = 1
        else:
            if args.files.count("-") > 1:
                print("toolpoison: error: stdin ('-') given more than once", file=stderr)
                return 2
            findings, total = scan_files(args.files, args.max_desc_len, stdin)
            nfiles = len(args.files)
    except ParseError as e:
        print("toolpoison: error: %s" % e, file=stderr)
        return 2

    shown = [f for f in findings if SEV_RANK[f["severity"]] >= SEV_RANK[args.min_severity]]
    if args.json:
        out = {"tool": "toolpoison", "version": __version__, "disclaimer": DISCLAIMER,
               "min_severity": args.min_severity, "tools_scanned": total, "files_scanned": nfiles,
               "findings": shown}
        if changes is not None:
            out["changes"] = changes
        print(json.dumps(out, indent=2, ensure_ascii=True), file=stdout)
    else:
        if changes is not None:
            if changes:
                print("Snapshot diff (possible rug pull - review every change):", file=stdout)
                for c in changes:
                    extra = (" fields: " + ", ".join(c["fields"])) if c["fields"] else ""
                    print("  %-8s %s%s" % (c["change"].upper(), visible(c["tool"]), extra), file=stdout)
            else:
                print("Snapshot diff: no tool changes.", file=stdout)
            print("", file=stdout)
        print(format_text(findings, total, nfiles, args.min_severity), file=stdout)
    failed = bool(shown) or bool(changes)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
