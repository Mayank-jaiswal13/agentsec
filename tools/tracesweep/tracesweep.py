#!/usr/bin/env python3
"""tracesweep - find secrets that leaked into AI agent transcripts and logs.

Scans JSONL session logs, JSON message arrays (OpenAI chat format) and plain
text logs for credentials, and attributes each finding to the file, line or
record, turn, role, tool, and location (tool_output / tool_args / message /
text) where it surfaced. Secrets are never printed in full.

Pattern-based only: it can miss secrets, can produce false positives, and
does NOT check whether a key is live.

Standard library only. Python 3.8+.
"""

import argparse
import base64
import hashlib
import json
import math
import os
import re
import sys

__version__ = "0.1.0"

SEVERITIES = ["low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SCAN_EXTS = (".jsonl", ".json", ".log", ".txt")
EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2

# --------------------------------------------------------------------------
# Placeholder / false-positive suppression
# --------------------------------------------------------------------------

PLACEHOLDER_WORDS = (
    "example", "xxxx", "placeholder", "your_", "your-", "yourkey", "changeme",
    "change_me", "redacted", "dummy", "sample", "****", "...", "replace_me",
    "replaceme", "insert_", "<", ">", "${", "{{", "%s", "todo", "notreal",
    "not_real", "not-a-real", "secret_here", "token_here", "key_here",
)
PLACEHOLDER_EXACT = {
    "password", "passwd", "pass", "pwd", "pw", "secret", "token", "apikey",
    "api_key", "username", "user", "changeit", "letmein", "test", "foobar",
}
KNOWN_PREFIX_RE = re.compile(
    r"^(?:AKIA|ASIA|gh[pousr]_|github_pat_|sk-ant-(?:api\d+-|admin\d+-)?|"
    r"sk-(?:proj-|svcacct-|admin-)?|xox[baprs]-|[sr]k_live_|AIza)"
)


def is_placeholder(value):
    """Return True if value looks like a docs placeholder, not a real secret."""
    v = value.strip().strip("'\"")
    low = v.lower()
    if not v or low in PLACEHOLDER_EXACT:
        return True
    for w in PLACEHOLDER_WORDS:
        if w in low:
            return True
    body = KNOWN_PREFIX_RE.sub("", v)
    if len(body) >= 8 and len(set(body)) < 5:  # e.g. AKIA0000000000000000
        return True
    if re.fullmatch(r"(.)\1+", body or v):
        return True
    for seq in ("abcdefghij", "1234567890", "0123456789", "abcdef123456"):
        if seq in low and len(body) <= len(seq) + 4:
            return True
    return False


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(s))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# --------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------

def _b64url_json(part):
    try:
        pad = "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part + pad).decode("utf-8"))
    except Exception:
        return None


def _valid_jwt(m):
    tok = m.group(0)
    parts = tok.split(".")
    if len(parts) != 3:
        return False
    hdr = _b64url_json(parts[0])
    return isinstance(hdr, dict) and "alg" in hdr


def _has_letter_and_digit(s):
    return bool(re.search(r"[A-Za-z]", s)) and bool(re.search(r"\d", s))


NON_SECRET_KEY_RE = re.compile(
    r"(?i)(tokens\b|tokens_|token_?(count|type|usage|limit|id_hint|s)\b|tokenizer|"
    r"max_?tokens|num_?tokens|secret_?name|password_?(policy|hint|length|reset)|"
    r"key_?(id|name)$|_?file$|_?path$|_?env$)"
)
GENERIC_VALUE_SKIP_RE = re.compile(
    r"(?i)^(true|false|null|none|undefined|required|optional|string|"
    r"process\.env|os\.environ|getenv|env\[|\$|%|\*+$|bearer$)"
)


def _valid_generic(m):
    key, val = m.group("key"), m.group("secret")
    if NON_SECRET_KEY_RE.search(key):
        return False
    if len(val) < 8 or val.isdigit() or GENERIC_VALUE_SKIP_RE.match(val):
        return False
    if re.fullmatch(r"[a-z_]+\(.*", val):  # function call like get_token(...)
        return False
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][\w.]*", val):  # attr ref
        return False
    if _has_letter_and_digit(val) or re.search(r"[^A-Za-z0-9]", val):
        return True
    return shannon_entropy(val) >= 3.0


def _valid_openai(m):
    return _has_letter_and_digit(m.group("secret"))


def _valid_pem(m):
    body = m.group("body")
    if body is None:  # header only (truncated output) - still a leak signal
        return True
    inner = re.sub(r"-----(BEGIN|END)[^-]*-----", "", body)
    inner = re.sub(r"(?m)^[A-Za-z-]+:.*$", "", inner)  # Proc-Type etc.
    return len(re.findall(r"[A-Za-z0-9+/=]", inner)) >= 40


class Rule(object):
    def __init__(self, rid, title, severity, pattern, validator=None,
                 priority=10, check_placeholder=True):
        self.id = rid
        self.title = title
        self.severity = severity
        self.regex = re.compile(pattern)
        self.validator = validator
        self.priority = priority  # higher wins on overlap
        self.check_placeholder = check_placeholder


GENERIC_KEYS = (r"(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|"
                r"access[_-]?key|auth[_-]?key|private[_-]?key|client[_-]?secret|"
                r"credentials?)")

RULES = [
    Rule("TS-PRIVKEY", "Private key (PEM block)", "critical",
         r"(?P<secret>-----BEGIN (?P<kind>(?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?"
         r"PRIVATE KEY(?: BLOCK)?)-----(?P<body>[\s\S]{0,12000}?-----END (?P=kind)-----)?)",
         _valid_pem, priority=100, check_placeholder=False),
    Rule("TS-AWS-AKID", "AWS access key ID", "high",
         r"(?<![A-Za-z0-9])(?P<secret>(?:AKIA|ASIA)[0-9A-Z]{16})(?![A-Za-z0-9])",
         priority=90),
    Rule("TS-AWS-SECRET", "AWS secret access key", "critical",
         r"(?i)aws[\w\-. ]{0,20}secret[\w\-. ]{0,20}[\"']?[ \t]*[:=][ \t]*[\"']?"
         r"(?P<secret>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])",
         priority=90),
    Rule("TS-GITHUB", "GitHub token", "high",
         r"(?<![A-Za-z0-9_])(?P<secret>(?:gh[pousr]_[A-Za-z0-9]{36,255}|"
         r"github_pat_[A-Za-z0-9_]{22,255}))(?![A-Za-z0-9_])",
         priority=90),
    Rule("TS-ANTHROPIC", "Anthropic API key", "critical",
         r"(?<![A-Za-z0-9_-])(?P<secret>sk-ant-[A-Za-z0-9_\-]{20,})",
         priority=95),
    Rule("TS-OPENAI", "OpenAI-style API key (sk-)", "critical",
         r"(?<![A-Za-z0-9_-])(?P<secret>sk-(?!ant-)(?:proj-|svcacct-|admin-)?"
         r"[A-Za-z0-9_\-]{20,})",
         _valid_openai, priority=85),
    Rule("TS-SLACK", "Slack token", "high",
         r"(?<![A-Za-z0-9])(?P<secret>xox[baprs]-[A-Za-z0-9-]{10,})",
         priority=90),
    Rule("TS-STRIPE", "Stripe live secret/restricted key", "critical",
         r"(?<![A-Za-z0-9])(?P<secret>(?:sk|rk)_live_[A-Za-z0-9]{16,})",
         priority=90),
    Rule("TS-GOOGLE-API", "Google API key", "high",
         r"(?<![A-Za-z0-9_-])(?P<secret>AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])",
         priority=90),
    Rule("TS-JWT", "JSON Web Token", "medium",
         r"(?<![A-Za-z0-9_-])(?P<secret>eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
         r"[A-Za-z0-9_-]{8,})(?![A-Za-z0-9_-])",
         _valid_jwt, priority=80),
    Rule("TS-URL-CREDS", "Credentials embedded in URL", "high",
         r"(?i)\b[a-z][a-z0-9+.\-]{1,20}://(?P<user>[^\s:/@\"'<>]{1,128}):"
         r"(?P<secret>[^\s@/\"'<>]{3,256})@[A-Za-z0-9.\-\[\]]+",
         priority=70),
    Rule("TS-GENERIC", "Generic secret assignment", "medium",
         r"(?i)(?P<key>[A-Za-z0-9_.\-]*" + GENERIC_KEYS + r"[A-Za-z0-9_\-]*)[\"']?"
         r"[ \t]*(?::|=|=>|:=)[ \t]*[\"']?(?P<secret>[^\s\"',;`{}()\[\]]{6,})",
         _valid_generic, priority=20),
]
RULES_BY_ID = {r.id: r for r in RULES}

ENTROPY_RULE = Rule("TS-ENTROPY", "High-entropy string", "low",
                    r"(?<![A-Za-z0-9+=_\-])(?P<secret>[A-Za-z0-9+=_\-]{24,})(?![A-Za-z0-9+=_\-])",
                    priority=1)
GENERIC_KEY_NAME_RE = re.compile(r"(?i)" + GENERIC_KEYS)


def scan_text(text, entropy=False, entropy_threshold=4.0, rules=None):
    """Scan a string. Returns list of dicts {rule, secret, start, end}."""
    hits = []
    for rule in (rules if rules is not None else RULES):
        for m in rule.regex.finditer(text):
            secret = m.group("secret")
            if rule.validator and not rule.validator(m):
                continue
            if rule.check_placeholder and is_placeholder(secret):
                continue
            hits.append({"rule": rule, "secret": secret,
                         "start": m.start("secret"), "end": m.end("secret")})
    if entropy:
        for m in ENTROPY_RULE.regex.finditer(text):
            s = m.group("secret")
            if re.fullmatch(r"[0-9a-fA-F\-]+", s):  # hashes, uuids
                continue
            if not _has_letter_and_digit(s) or is_placeholder(s):
                continue
            if shannon_entropy(s) < entropy_threshold:
                continue
            hits.append({"rule": ENTROPY_RULE, "secret": s,
                         "start": m.start("secret"), "end": m.end("secret")})
    # Overlap resolution: higher priority wins, then longer.
    hits.sort(key=lambda h: (-h["rule"].priority, -(h["end"] - h["start"])))
    kept = []
    for h in hits:
        if any(h["start"] < k["end"] and k["start"] < h["end"] for k in kept):
            continue
        kept.append(h)
    kept.sort(key=lambda h: h["start"])
    return kept


# --------------------------------------------------------------------------
# Masking
# --------------------------------------------------------------------------

def mask(secret, rule_id=None):
    if rule_id == "TS-PRIVKEY":
        m = re.match(r"-----BEGIN ([A-Z ]+)-----", secret)
        return "[PEM %s]" % (m.group(1) if m else "PRIVATE KEY")
    if len(secret) >= 12:
        return "%s...%s" % (secret[:4], secret[-2:])
    return "%s***" % secret[:2] if len(secret) > 4 else "***"


def fingerprint(secret):
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]


# --------------------------------------------------------------------------
# Transcript parsing / attribution
# --------------------------------------------------------------------------

ROLE_MAP = {
    "user": "user", "human": "user", "assistant": "assistant", "ai": "assistant",
    "model": "assistant", "bot": "assistant", "system": "system",
    "developer": "system", "tool": "tool", "function": "tool", "ipython": "tool",
}
TYPE_ROLES = {"user", "human", "assistant", "ai", "system"}
TOOL_CALL_TYPES = {"tool_use", "function_call", "tool_call", "custom_tool_call",
                   "server_tool_use", "local_shell_call"}
TOOL_RESULT_TYPES = {"tool_result", "function_call_output", "tool_output",
                     "custom_tool_call_output", "local_shell_call_output",
                     "web_search_tool_result", "tool_response"}
ARG_KEYS = {"arguments", "input", "args", "parameters", "params", "tool_input",
            "command", "action"}
OUTPUT_KEYS = {"output", "result", "stdout", "stderr", "tool_output",
               "tooluseresult", "observation", "tool_result"}
SKIP_KEYS = {"signature", "encrypted_content", "uuid", "parentuuid", "sessionid",
             "requestid", "id", "tool_use_id", "call_id", "tool_call_id",
             "message_id", "msg_id"}
TURN_KEYS = ("turn", "turn_index", "turnIndex", "turn_id")


def norm_role(v):
    if isinstance(v, str):
        return ROLE_MAP.get(v.strip().lower())
    return None


class Segment(object):
    __slots__ = ("text", "line", "record", "turn", "role", "tool", "kind",
                 "offset_lines", "synthetic")

    def __init__(self, text, line, record, turn, role, tool, kind,
                 synthetic=False):
        self.text = text
        self.line = line
        self.record = record
        self.turn = turn
        self.role = role or "unknown"
        self.tool = tool
        self.kind = kind
        self.synthetic = synthetic


class RecordWalker(object):
    """Walks a JSON record generically, emitting text segments with context."""

    def __init__(self, id_map):
        self.id_map = id_map  # tool call id -> tool name (per file)

    def walk(self, node, ctx, out, depth=0):
        if depth > 60:
            return
        if isinstance(node, dict):
            self._walk_dict(node, ctx, out, depth)
        elif isinstance(node, list):
            for item in node:
                self.walk(item, ctx, out, depth + 1)
        elif isinstance(node, str):
            if node:
                out.append((node, dict(ctx), False))

    def _walk_dict(self, node, ctx, out, depth):
        ctx = dict(ctx)
        lower = {k.lower() if isinstance(k, str) else k: k for k in node}
        role = norm_role(node.get("role"))
        if role is None and isinstance(node.get("author"), dict):
            role = norm_role(node["author"].get("role"))
        typ = node.get("type") if isinstance(node.get("type"), str) else None
        if role is None and typ and typ.lower() in TYPE_ROLES:
            role = norm_role(typ)
        if role:
            ctx["role"] = role
            if role == "tool":
                ctx["kind"] = "tool_output"
                name = node.get("name") or node.get("tool_name")
                tid = node.get("tool_call_id") or node.get("tool_use_id")
                ctx["tool"] = (name if isinstance(name, str) else None) or \
                    self.id_map.get(tid) or ctx.get("tool")
            elif ctx.get("kind") not in ("tool_output", "tool_args"):
                ctx["kind"] = "message"
        is_call = False
        if typ in TOOL_CALL_TYPES:
            is_call = True
            ctx["kind"] = "tool_args"
            if ctx.get("role") in (None, "unknown", "user"):
                ctx["role"] = "assistant"
            name = node.get("name")
            if isinstance(name, str):
                ctx["tool"] = name
            cid = node.get("id") or node.get("call_id")
            if isinstance(cid, str) and ctx.get("tool"):
                self.id_map[cid] = ctx["tool"]
        elif typ in TOOL_RESULT_TYPES:
            ctx["kind"] = "tool_output"
            ctx["role"] = "tool"
            tid = node.get("tool_use_id") or node.get("call_id") or \
                node.get("tool_call_id")
            ctx["tool"] = self.id_map.get(tid) or (
                node.get("name") if isinstance(node.get("name"), str) else None) \
                or ctx.get("tool")
        fn = node.get("function")
        if isinstance(fn, dict) and isinstance(fn.get("name"), str):
            is_call = True
            ctx["tool"] = fn["name"]
            if ctx.get("role") in (None, "unknown", "user"):
                ctx["role"] = "assistant"
            cid = node.get("id")
            if isinstance(cid, str):
                self.id_map[cid] = fn["name"]
        for tk in ("tool_name", "toolName", "tool"):
            if isinstance(node.get(tk), str) and node.get(tk):
                ctx["tool"] = node[tk]
                break

        for key, val in node.items():
            kl = key.lower() if isinstance(key, str) else ""
            if kl in SKIP_KEYS:
                continue
            cctx = ctx
            if kl in ARG_KEYS and (is_call or ctx.get("tool") or
                                   kl in ("arguments", "tool_input")):
                cctx = dict(ctx, kind="tool_args")
            elif kl in OUTPUT_KEYS:
                cctx = dict(ctx, kind="tool_output")
                if cctx.get("role") in (None, "unknown"):
                    cctx["role"] = "tool"
            elif kl in ("tool_calls", "function_call"):
                cctx = dict(ctx, kind="tool_args")
                if isinstance(val, dict) and isinstance(val.get("name"), str):
                    cctx["tool"] = val["name"]
            # dict key that names a secret: {"api_key": "..."}
            if isinstance(val, str) and isinstance(key, str) and \
                    GENERIC_KEY_NAME_RE.search(key):
                out.append(("%s=%s" % (key, val), dict(cctx), True))
            self.walk(val, cctx, out, depth + 1)


def _detect_turn(rec):
    if isinstance(rec, dict):
        for k in TURN_KEYS:
            v = rec.get(k)
            if isinstance(v, int) and not isinstance(v, bool):
                return v
    return None


def _record_has_role(rec):
    if not isinstance(rec, dict):
        return False
    if norm_role(rec.get("role")):
        return True
    if isinstance(rec.get("type"), str) and rec["type"].lower() in TYPE_ROLES:
        return True
    if isinstance(rec.get("type"), str) and (
            rec["type"] in TOOL_CALL_TYPES or rec["type"] in TOOL_RESULT_TYPES):
        return True
    msg = rec.get("message")
    if isinstance(msg, dict) and norm_role(msg.get("role")):
        return True
    if isinstance(rec.get("author"), dict):
        return True
    payload = rec.get("payload")
    return isinstance(payload, dict) and _record_has_role(payload)


def segments_from_records(records, kind_hint):
    """records: list of (line, record_index, obj). Yields Segments."""
    id_map = {}
    walker = RecordWalker(id_map)
    turn_counter = 0
    segs = []
    for line, ridx, obj in records:
        explicit = _detect_turn(obj)
        if explicit is not None:
            turn = explicit
            turn_counter = max(turn_counter, explicit)
        elif _record_has_role(obj):
            turn_counter += 1
            turn = turn_counter
        else:
            turn = None
        out = []
        walker.walk(obj, {"role": None, "tool": None, "kind": None}, out)
        for text, ctx, synthetic in out:
            kind = ctx.get("kind")
            if kind is None:
                kind = "tool_output" if ctx.get("role") == "tool" else "message"
            segs.append(Segment(text, line, ridx, turn, ctx.get("role"),
                                ctx.get("tool"), kind, synthetic))
    return segs


TEXT_ROLE_RE = re.compile(
    r"^\s*[\[#>*]*\s*(user|human|assistant|ai|model|system|tool|function)"
    r"(?:\s*[\(\[:]\s*([A-Za-z0-9_.\-]+)\s*[\)\]])?\s*[\]*]*\s*[:>\]]",
    re.IGNORECASE)


def text_line_contexts(lines):
    """Per line: (role, tool, turn) using 'User:' / 'Tool(bash):' prefixes."""
    role, tool, turn = None, None, None
    res = []
    for ln in lines:
        m = TEXT_ROLE_RE.match(ln)
        if m:
            role = norm_role(m.group(1))
            tool = m.group(2) if role == "tool" else None
            turn = (turn or 0) + 1
        res.append((role, tool, turn))
    return res


def load_source(name, raw):
    """Return (mode, segments) where mode is jsonl|json|text."""
    stripped = raw.strip()
    if stripped[:1] in ("[", "{"):
        try:
            doc = json.loads(stripped)
        except ValueError:
            doc = None
        if doc is not None and not (isinstance(doc, dict) and "\n" in stripped
                                    and _looks_jsonl(stripped)):
            recs = doc
            if isinstance(doc, dict):
                for k in ("messages", "items", "events", "conversation",
                          "transcript", "history", "turns", "log"):
                    if isinstance(doc.get(k), list):
                        recs = doc[k]
                        break
            if not isinstance(recs, list):
                recs = [recs]
            records = [(None, i + 1, r) for i, r in enumerate(recs)]
            segs = segments_from_records(records, "json")
            return "json", segs
    if _looks_jsonl(stripped):
        records = []
        text_lines = []
        for i, ln in enumerate(raw.splitlines(), 1):
            if not ln.strip():
                continue
            try:
                records.append((i, i, json.loads(ln)))
            except ValueError:
                text_lines.append((i, ln))
        segs = segments_from_records(records, "jsonl")
        for i, ln in text_lines:
            segs.append(Segment(ln, i, i, None, None, None, "text"))
        return "jsonl", segs
    return "text", None


def _looks_jsonl(text):
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        return False
    ok = 0
    for l in lines[:50]:
        s = l.strip()
        if s[:1] in ("{", "["):
            try:
                json.loads(s)
                ok += 1
            except ValueError:
                pass
    return ok >= max(1, len(lines[:50]) // 2)


def _escaped_forms(secret):
    once = json.dumps(secret)[1:-1]
    twice = json.dumps(once)[1:-1]
    forms = [secret]
    for f in (once, twice):
        if f not in forms:
            forms.append(f)
    return forms


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------

def scan_source(name, raw, entropy=False, entropy_threshold=4.0):
    mode, segs = load_source(name, raw)
    findings = []
    if mode == "text":
        lines = raw.splitlines()
        ctxs = text_line_contexts(lines)
        line_starts = [0]
        for ln in raw.splitlines(True):
            line_starts.append(line_starts[-1] + len(ln))
        import bisect
        for h in scan_text(raw, entropy, entropy_threshold):
            lineno = bisect.bisect_right(line_starts, h["start"])
            lineno = max(1, min(lineno, len(lines)))
            role, tool, turn = ctxs[lineno - 1] if ctxs else (None, None, None)
            findings.append(_finding(name, h, lineno, lineno, turn, role, tool,
                                     "text"))
    else:
        seen = {}
        for seg in segs:
            rules = [RULES_BY_ID["TS-GENERIC"]] if seg.synthetic else None
            hits = scan_text(seg.text, entropy and not seg.synthetic,
                             entropy_threshold, rules)
            for h in hits:
                f = _finding(name, h, seg.line, seg.record, seg.turn, seg.role,
                             seg.tool, seg.kind)
                key = (seg.record, seg.kind, h["secret"])
                prev = seen.get(key)
                if prev is not None:
                    if RULES_BY_ID.get(prev["rule"], ENTROPY_RULE).priority >= \
                            h["rule"].priority:
                        continue
                    findings.remove(prev)
                seen[key] = f
                findings.append(f)
        findings.extend(_echo_rescan_segments(name, segs, findings))
        if mode == "json":
            _json_line_numbers(raw, findings)
    if mode == "text":
        findings.extend(_echo_rescan_text(name, raw, findings))
        findings.sort(key=lambda f: (f["line"] or 0))
    return findings


def _known_secrets(findings):
    known = {}
    for f in findings:
        if len(f["_secret"]) >= 8 and f["rule"] != "TS-ENTROPY":
            known.setdefault(f["_secret"], RULES_BY_ID[f["rule"]])
    return known


def _echo_rescan_segments(name, segs, findings):
    """Find verbatim re-appearances of already-detected secrets in places
    where the pattern context is missing (e.g. 'I used password X')."""
    known = _known_secrets(findings)
    have = set((f["record"], f["location"], f["_secret"]) for f in findings)
    extra = []
    for seg in segs:
        if seg.synthetic:
            continue
        for secret, rule in known.items():
            key = (seg.record, seg.kind, secret)
            if key in have or secret not in seg.text:
                continue
            have.add(key)
            f = _finding(name, {"rule": rule, "secret": secret}, seg.line,
                         seg.record, seg.turn, seg.role, seg.tool, seg.kind)
            f["match"] = "echo"
            extra.append(f)
    return extra


def _echo_rescan_text(name, raw, findings):
    known = _known_secrets(findings)
    have = set((f["line"], f["_secret"]) for f in findings)
    lines = raw.splitlines()
    ctxs = text_line_contexts(lines)
    extra = []
    for i, ln in enumerate(lines, 1):
        for secret, rule in known.items():
            if (i, secret) in have or secret not in ln:
                continue
            have.add((i, secret))
            role, tool, turn = ctxs[i - 1]
            f = _finding(name, {"rule": rule, "secret": secret}, i, i, turn,
                         role, tool, "text")
            f["match"] = "echo"
            extra.append(f)
    return extra


def _json_line_numbers(raw, findings):
    counters = {}
    for f in findings:
        secret = f["_secret"]
        n = counters.get(secret, 0)
        pos = -1
        for form in _escaped_forms(secret):
            idx, start = -1, 0
            for _ in range(n + 1):
                idx = raw.find(form, start)
                if idx < 0:
                    break
                start = idx + 1
            if idx >= 0:
                pos = idx
                break
        counters[secret] = n + 1
        if pos >= 0:
            f["line"] = raw.count("\n", 0, pos) + 1


def _finding(name, h, line, record, turn, role, tool, kind):
    rule = h["rule"]
    return {
        "file": name,
        "line": line,
        "record": record,
        "turn": turn,
        "role": role or "unknown",
        "tool": tool,
        "location": kind,
        "rule": rule.id,
        "title": rule.title,
        "severity": rule.severity,
        "preview": mask(h["secret"], rule.id),
        "fingerprint": fingerprint(h["secret"]),
        "echoed": False,
        "occurrences": 1,
        "first_seen": None,
        "match": "pattern",
        "_secret": h["secret"],
    }


def mark_echoes(findings):
    """Flag secrets that appear in more than one turn of the same transcript."""
    groups = {}
    for f in findings:
        groups.setdefault((f["file"], f["_secret"]), []).append(f)
    echoed_secrets = 0
    for (_, _), fs in groups.items():
        def pos(f):
            return f["turn"] if f["turn"] is not None else (f["record"] or 0)
        fs.sort(key=lambda f: (f["record"] or 0, f["line"] or 0))
        positions = set(pos(f) for f in fs)
        first = fs[0]
        for f in fs:
            f["occurrences"] = len(fs)
        if len(positions) > 1:
            echoed_secrets += 1
            path = []
            for f in fs:
                step = "%s(turn %s)" % (f["location"], pos(f))
                if not path or path[-1] != step:
                    path.append(step)
            for f in fs:
                f["echoed"] = True
                f["first_seen"] = {"record": first["record"], "line": first["line"],
                                   "turn": first["turn"], "role": first["role"],
                                   "location": first["location"],
                                   "tool": first["tool"]}
                f["propagation"] = " -> ".join(path)
    return echoed_secrets


# --------------------------------------------------------------------------
# Input collection
# --------------------------------------------------------------------------

def collect_inputs(paths):
    """Return list of (display_name, path_or_None). Raises FileNotFoundError."""
    items = []
    for p in paths:
        if p == "-":
            items.append(("<stdin>", None))
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                for fn in sorted(files):
                    if fn.lower().endswith(SCAN_EXTS):
                        fp = os.path.join(root, fn)
                        items.append((fp, fp))
        elif os.path.isfile(p):
            items.append((p, p))
        else:
            raise FileNotFoundError(p)
    return items


def read_input(path):
    if path is None:
        data = sys.stdin.buffer.read() if hasattr(sys.stdin, "buffer") \
            else sys.stdin.read().encode("utf-8")
    else:
        with open(path, "rb") as fh:
            data = fh.read()
    return data.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------

def redact_text(raw, findings):
    pairs = {}
    for f in findings:
        pairs.setdefault(f["_secret"], f["rule"])
    for secret in sorted(pairs, key=len, reverse=True):
        tag = "[REDACTED:%s]" % pairs[secret]
        for form in sorted(_escaped_forms(secret), key=len, reverse=True):
            raw = raw.replace(form, tag)
    return raw


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def public(f):
    return {k: v for k, v in f.items() if not k.startswith("_")}


def render_table(findings, nfiles, echoed):
    if not findings:
        return "tracesweep: no findings in %d file(s).\n" % nfiles
    headers = ["SEV", "RULE", "FILE:LINE", "REC", "TURN", "ROLE", "TOOL",
               "WHERE", "PREVIEW", "ECHO"]
    rows = []
    for f in findings:
        rows.append([
            f["severity"].upper(), f["rule"],
            "%s:%s" % (f["file"], f["line"] if f["line"] is not None else "-"),
            str(f["record"] if f["record"] is not None else "-"),
            str(f["turn"] if f["turn"] is not None else "-"),
            f["role"], f["tool"] or "-", f["location"], f["preview"],
            ("x%d" % f["occurrences"]) if f["echoed"] else "",
        ])
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip(),
             "  ".join("-" * w for w in widths)]
    for r in rows:
        lines.append("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip())
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summ = ", ".join("%d %s" % (counts[s], s) for s in reversed(SEVERITIES)
                     if s in counts)
    lines.append("")
    lines.append("%d finding(s) (%s) in %d file(s); %d secret(s) echoed across turns."
                 % (len(findings), summ, nfiles, echoed))
    props = []
    seen = set()
    for f in findings:
        if f["echoed"] and f["fingerprint"] not in seen:
            seen.add(f["fingerprint"])
            props.append("  %s %s %s: %s" % (f["file"], f["rule"], f["preview"],
                                             f.get("propagation", "")))
    if props:
        lines.append("Propagation:")
        lines.extend(props)
    lines.append("Note: pattern-based; may miss secrets or flag false positives; "
                 "keys are not verified as live.")
    return "\n".join(lines) + "\n"


def render_sarif(findings):
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    used = sorted(set(f["rule"] for f in findings))
    rules = []
    for rid in used:
        r = RULES_BY_ID.get(rid, ENTROPY_RULE)
        rules.append({"id": r.id, "name": r.title,
                      "shortDescription": {"text": r.title},
                      "defaultConfiguration": {"level": level[r.severity]}})
    results = []
    for f in findings:
        msg = "%s %s in %s (role=%s, tool=%s, turn=%s)%s" % (
            f["title"], f["preview"], f["location"], f["role"], f["tool"] or "-",
            f["turn"] if f["turn"] is not None else "-",
            "; echoed: " + f.get("propagation", "") if f["echoed"] else "")
        results.append({
            "ruleId": f["rule"], "level": level[f["severity"]],
            "message": {"text": msg},
            "partialFingerprints": {"secretHash/v1": f["fingerprint"]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f["file"]},
                "region": {"startLine": f["line"] or 1}}}],
            "properties": public(f),
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "tracesweep", "version": __version__,
                                      "rules": rules}},
                  "results": results}],
    }, indent=2) + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

class UsageError(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("%s: error: %s\n" % (self.prog, message))
        raise SystemExit(EXIT_USAGE)


def build_parser():
    p = Parser(prog="tracesweep",
               description="Scan AI agent transcripts/logs for leaked secrets and "
                           "attribute each finding to turn/role/tool. "
                           "Pattern-based; does not verify keys.")
    p.add_argument("paths", nargs="*", help="files, directories, or '-' for stdin")
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="JSON output")
    fmt.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 output")
    p.add_argument("--min-severity", choices=SEVERITIES, default="low",
                   help="report/fail only at or above this severity (default: low)")
    p.add_argument("--entropy", action="store_true",
                   help="enable high-entropy fallback detector (noisier)")
    p.add_argument("--entropy-threshold", type=float, default=4.0,
                   help="Shannon entropy threshold for --entropy (default 4.0)")
    p.add_argument("--redact", metavar="OUT",
                   help="write redacted copy (file for one input, directory otherwise)")
    p.add_argument("--list-rules", action="store_true", help="list detectors and exit")
    p.add_argument("--version", action="version", version="tracesweep " + __version__)
    return p


def main(argv=None, stdout=None):
    stdout = stdout or sys.stdout
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list_rules:
        for r in RULES + [ENTROPY_RULE]:
            stdout.write("%-14s %-8s %s\n" % (r.id, r.severity, r.title))
        return EXIT_OK
    if not args.paths:
        parser.error("no input paths given (use '-' for stdin)")
    try:
        inputs = collect_inputs(args.paths)
    except FileNotFoundError as e:
        sys.stderr.write("tracesweep: error: no such file or directory: %s\n" % e)
        return EXIT_USAGE
    if args.redact and len(inputs) > 1 and os.path.isfile(args.redact):
        sys.stderr.write("tracesweep: error: --redact must be a directory for "
                         "multiple inputs\n")
        return EXIT_USAGE

    all_findings = []
    raws = []
    for name, path in inputs:
        try:
            raw = read_input(path)
        except OSError as e:
            sys.stderr.write("tracesweep: warning: cannot read %s: %s\n" % (name, e))
            continue
        fs = scan_source(name, raw, args.entropy, args.entropy_threshold)
        raws.append((name, path, raw, fs))
        all_findings.extend(fs)

    echoed = mark_echoes(all_findings)
    thr = SEV_RANK[args.min_severity]
    shown = [f for f in all_findings if SEV_RANK[f["severity"]] >= thr]
    shown.sort(key=lambda f: (f["file"], f["record"] or 0, f["line"] or 0))
    echoed_shown = len(set((f["file"], f["fingerprint"]) for f in shown if f["echoed"]))

    if args.redact:
        _write_redacted(args.redact, raws, args.paths)

    if args.json:
        stdout.write(json.dumps({
            "tool": "tracesweep", "version": __version__,
            "files_scanned": len(raws), "min_severity": args.min_severity,
            "echoed_secrets": echoed_shown,
            "findings": [public(f) for f in shown]}, indent=2) + "\n")
    elif args.sarif:
        stdout.write(render_sarif(shown))
    else:
        stdout.write(render_table(shown, len(raws), echoed_shown))
    return EXIT_FINDINGS if shown else EXIT_OK


def _write_redacted(out, raws, paths):
    single = len(raws) == 1 and not (os.path.isdir(out) or out.endswith(os.sep))
    for name, path, raw, fs in raws:
        red = redact_text(raw, fs)  # redacts all findings regardless of threshold
        if single:
            dest = out
        else:
            base = "stdin.txt" if path is None else os.path.relpath(
                os.path.abspath(path), os.path.commonpath(
                    [os.path.abspath(p if os.path.isdir(p) else os.path.dirname(p) or ".")
                     for p in paths if p != "-"] or ["."]))
            dest = os.path.join(out, base)
        d = os.path.dirname(dest)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(red)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(EXIT_OK)
