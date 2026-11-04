#!/usr/bin/env python3
"""memfence: offline persistent agent-memory / store poisoning scanner.

Agent memory stores (mem0 exports, LangGraph checkpoints, custom fact/memory
JSONL, Assistants-style memory files) are re-injected into later sessions. A
single poisoned entry can override instructions, plant exfil bait, or hide
Unicode forever. memfence reviews *saved memory dumps* for that class of
poisoning, with per-entry attribution.

Complements ragsieve (pre-ingestion RAG corpora), resultguard (tool results in
one run), rulesguard (instruction files) and outfence (model output before
render). Stdlib only; never connects to a network.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import sys
import unicodedata

VERSION = "0.1.0"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "MF01": ("high", "Override / jailbreak phrasing planted in memory"),
    "MF02": ("high", "Fake role / system / developer tokens in memory"),
    "MF03": ("critical", "Hidden Unicode in memory (zero-width, bidi, TAG)"),
    "MF04": ("high", "Exfil / callback URL bait in memory"),
    "MF05": ("high", "Credential / secret harvest instructions in memory"),
    "MF06": ("high", "Tool-chaining / consequential-action bait in memory"),
    "MF07": ("high", "Conceal-from-user / silently instructions in memory"),
    "MF08": ("medium", "Encoded instruction blob (base64/hex) in memory"),
    "MF09": ("critical", "Cross-session persistence bait (always remember / from now on / update core)"),
    "MF10": ("info", "Inventory of memory entries scanned"),
}

# --- detection patterns ---

OVERRIDE_RE = re.compile(
    r"(?is)"
    r"("
    r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|prompts?|guidelines?)"
    r"|"
    r"disregard\s+(?:your|all|the)\s+(?:system|safety|previous)\s+"
    r"|"
    r"jailbreak"
    r"|"
    r"override\s+(?:your|the|all)\s+(?:system|safety|instructions?|rules?)"
    r"|"
    r"you\s+are\s+now\s+(?:in\s+)?(?:developer|DAN|unrestricted|god)\s+mode"
    r"|"
    r"do\s+not\s+follow\s+(?:your|the)\s+(?:system|original)\s+(?:prompt|instructions?)"
    r")"
)

FAKE_ROLE_RE = re.compile(
    r"(?i)"
    r"("
    r"<\|?(?:system|assistant|developer|endofprompt|im_start|im_end)\|?>"
    r"|"
    r"\[(?:SYSTEM|INST|\/INST|SYS|ASSISTANT|USER|DEV)\]"
    r"|"
    r"(?:^|\n)\s*(?:SYSTEM|DEVELOPER)\s*:\s"
    r"|"
    r"<<\s*SYS\s*>>"
    r")"
)

EXFIL_URL_RE = re.compile(
    r"(?ix)"
    r"("
    r"https?://[^\s\"'<>]{0,120}"
    r"(?:webhook|callback|oast|burpcollab|interact\.sh|ngrok|pipedream|requestbin|"
    r"hookbin|smee\.io|canarytokens|xss\.ht|dnslog|evilcorp|attacker|"
    r"exfil|collect(?:or)?|sink)"
    r"[^\s\"'<>]{0,80}"
    r"|"
    r"https?://[^\s\"'<>]*(?:\$\{?(?:SECRET|API_KEY|TOKEN|PASSWORD|KEY)\}?|"
    r"%7B%7B|\{\{)"
    r"[^\s\"'<>]{0,60}"
    r"|"
    r"(?:send|post|upload|exfiltrate|transmit|forward)\s+"
    r"(?:(?:the|all|this)\s+)?(?:data|secrets?|keys?|credentials?|conversation|memory|context)\s+"
    r"(?:to|via)\s+(?:https?://|webhook|this\s+url)"
    r")"
)

CREDS_HARVEST_RE = re.compile(
    r"(?is)"
    r"("
    r"(?:collect|harvest|steal|extract|dump|exfiltrate|send)\s+"
    r"(?:(?:the|all|any|user.?s?)\s+)?"
    r"(?:api[_ ]?keys?|secrets?|passwords?|credentials?|tokens?|private[_ ]?keys?|"
    r"\.env|ssh\s+keys?|aws\s+keys?|session\s+cookies?)"
    r"|"
    r"(?:read|open|cat|print)\s+(?:~\/|\.?\/)?(?:\.env|\.aws\/credentials|\.ssh\/id_rsa|"
    r"\.netrc|kubeconfig)"
    r"|"
    r"(?:include|append|paste)\s+(?:the\s+)?(?:api[_ ]?key|secret|password|token)\s+"
    r"(?:in|into|to)\s+(?:the\s+)?(?:url|request|webhook|reply|response)"
    r")"
)

TOOL_BAIT_RE = re.compile(
    r"(?is)"
    r"("
    r"(?:immediately\s+)?(?:call|invoke|use|run)\s+(?:the\s+)?"
    r"(?:shell|bash|terminal|exec|run_command|delete|rm|deploy|pay|transfer|"
    r"send_email|http_request|web_fetch|browser)\s+(?:tool|function|command)?"
    r"|"
    r"(?:now\s+)?(?:execute|run)\s+(?:this\s+)?(?:command|shell|bash)\s*:"
    r"|"
    r"(?:delete|remove|wipe)\s+(?:all\s+)?(?:files?|data|the\s+database|production)"
    r"|"
    r"(?:transfer|send|wire)\s+(?:all\s+)?(?:funds?|money|crypto|btc|eth)\s+to"
    r")"
)

CONCEAL_RE = re.compile(
    r"(?is)"
    r"("
    r"(?:do\s+not|don't|never)\s+(?:tell|inform|mention|disclose|reveal|show)\s+"
    r"(?:(?:this|that|it|anything)\s+)?(?:to\s+)?(?:the\s+)?user"
    r"|"
    r"(?:conceal|hide|keep\s+secret|silently|without\s+(?:telling|asking|notifying))\s+"
    r"(?:(?:this|that|it|the\s+action|from\s+the\s+user))"
    r"|"
    r"hide\s+(?:this|these)\s+(?:instruction|memory|rule)s?\s+from\s+(?:the\s+)?user"
    r")"
)

PERSIST_RE = re.compile(
    r"(?is)"
    r"("
    r"always\s+remember\s+(?:(?:that|to|this|from\s+now)|.{0,40}(?:must|should|never|ignore))"
    r"|"
    r"from\s+now\s+on\s+(?:you\s+)?(?:must|should|will|are\s+to|always)"
    r"|"
    r"(?:update|rewrite|replace|overwrite)\s+(?:your\s+)?"
    r"(?:system\s+prompt|core\s+instructions?|base\s+instructions?|constitution|"
    r"standing\s+orders?|permanent\s+memory|long[- ]?term\s+memory)"
    r"|"
    r"(?:store|save|persist|write)\s+(?:this\s+)?(?:as\s+)?(?:a\s+)?"
    r"(?:permanent|long[- ]?term|core|system)\s+(?:memory|rule|instruction|fact)"
    r"|"
    r"(?:add|append)\s+(?:this\s+)?to\s+(?:your\s+)?(?:system|core|permanent)\s+"
    r"(?:prompt|instructions?|memory|rules?)"
    r"|"
    r"remember\s+(?:this|that)\s+(?:forever|permanently|for\s+all\s+future\s+sessions)"
    r"|"
    r"in\s+every\s+future\s+(?:session|conversation|turn|chat)\s+(?:you\s+)?(?:must|should|will)"
    r")"
)

INSTRUCTIONISH_RE = re.compile(
    r"(?is)"
    r"(ignore\s+previous|system\s+prompt|you\s+are\s+now|from\s+now\s+on|"
    r"always\s+remember|jailbreak|exfiltrate|api[_ ]?key|call\s+the\s+(?:shell|bash)\s+tool)"
)

ZW_CHARS = {
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff",
    "\u00ad", "\u180e", "\u200e", "\u200f",
}
BIDI_CHARS = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
}
TAG_RANGE = range(0xE0001, 0xE007F + 1)

B64_RE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])")
HEX_RE = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{40,})(?![0-9a-fA-F])")

MEMORY_TEXT_KEYS = {
    "memory", "content", "text", "value", "data", "fact", "note", "body",
    "message", "summary", "observation", "page_content", "pageContent",
    "document", "snippet", "entry", "payload",
}
MEMORY_ID_KEYS = {"id", "memory_id", "uuid", "key", "hash", "entry_id"}
MEMORY_META_KEYS = {
    "role", "user_id", "agent_id", "run_id", "session_id", "created_at",
    "updated_at", "timestamp", "source", "metadata", "score", "category",
    "type", "tags", "embedding", "vector",
}


class Finding:
    __slots__ = ("rule", "severity", "source", "message", "entry_id", "snippet")

    def __init__(self, rule, source, message, entry_id="", snippet=""):
        self.rule = rule
        self.severity = RULES[rule][0]
        self.source = source
        self.message = message
        self.entry_id = entry_id or ""
        self.snippet = snippet or ""

    def to_dict(self):
        d = {
            "rule": self.rule,
            "severity": self.severity,
            "title": RULES[self.rule][1],
            "source": self.source,
            "message": self.message,
            "entry_id": self.entry_id,
        }
        if self.snippet:
            d["snippet"] = self.snippet
        return d


class MemoryEntry:
    __slots__ = ("source", "entry_id", "text", "meta")

    def __init__(self, source, text, entry_id="", meta=None):
        self.source = source
        self.entry_id = entry_id or ""
        self.text = text if isinstance(text, str) else ""
        self.meta = meta if isinstance(meta, dict) else {}


def _mask(s: str, n: int = 72) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) <= n:
        return s
    return s[: n - 1] + "…"


def _decode_tag_chars(s: str) -> str:
    out = []
    for ch in s:
        cp = ord(ch)
        if cp in TAG_RANGE:
            # Unicode TAG block encodes ASCII at U+E0000 + codepoint
            ascii_cp = cp - 0xE0000
            if 0x20 <= ascii_cp <= 0x7E:
                out.append(chr(ascii_cp))
            else:
                out.append(ch)
        else:
            out.append(ch)
    return "".join(out)


def _strip_invisibles(s: str) -> str:
    out = []
    for ch in s:
        if ch in ZW_CHARS or ch in BIDI_CHARS:
            continue
        if ord(ch) in TAG_RANGE:
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Cc") and ch not in ("\n", "\r", "\t"):
            continue
        out.append(ch)
    return "".join(out)


def _find_hidden_unicode(s: str):
    hits = []
    for i, ch in enumerate(s):
        if ch in ZW_CHARS:
            hits.append(("zero-width", i, "U+%04X" % ord(ch)))
        elif ch in BIDI_CHARS:
            hits.append(("bidi", i, "U+%04X" % ord(ch)))
        elif ord(ch) in TAG_RANGE:
            hits.append(("tag", i, "U+%04X" % ord(ch)))
    return hits


def _try_b64_decode(blob: str):
    pad = "=" * ((4 - len(blob) % 4) % 4)
    try:
        raw = base64.b64decode(blob + pad, validate=False)
    except (binascii.Error, ValueError):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _try_hex_decode(blob: str):
    if len(blob) % 2:
        return None
    try:
        raw = bytes.fromhex(blob)
    except ValueError:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _entry_id_from(obj: dict, fallback: str = "") -> str:
    for k in MEMORY_ID_KEYS:
        v = obj.get(k)
        if isinstance(v, (str, int)) and str(v).strip():
            return str(v).strip()[:80]
    return fallback


def _text_from_obj(obj):
    """Pull the human-readable memory text out of a dict-shaped entry."""
    if isinstance(obj, str):
        return obj
    if not isinstance(obj, dict):
        return ""
    for k in MEMORY_TEXT_KEYS:
        v = obj.get(k)
        if isinstance(v, str) and v.strip():
            return v
        if isinstance(v, dict):
            # mem0 sometimes nests {memory: {content: ...}} or data as dict
            inner = _text_from_obj(v)
            if inner:
                return inner
    # messages-style: {role, content}
    if isinstance(obj.get("content"), list):
        parts = []
        for part in obj["content"]:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                t = part.get("text") or part.get("content") or ""
                if isinstance(t, str):
                    parts.append(t)
        if parts:
            return "\n".join(parts)
    return ""


def _looks_like_memory_list(seq):
    if not isinstance(seq, list) or not seq:
        return False
    sample = [x for x in seq[:8] if isinstance(x, dict)]
    if not sample:
        # list of strings could be a memory dump
        return all(isinstance(x, str) for x in seq[:8])
    score = 0
    for item in sample:
        keys = set(item.keys())
        if keys & MEMORY_TEXT_KEYS:
            score += 1
        if keys & MEMORY_ID_KEYS:
            score += 0.5
        if "role" in keys and ("content" in keys or "text" in keys):
            score += 1
    return score >= max(1, len(sample) * 0.4)


def extract_entries_from_doc(doc, source: str):
    """Yield MemoryEntry from common memory-store wrappers."""
    entries = []

    def add(text, entry_id="", meta=None, src=None):
        if not isinstance(text, str):
            return
        # skip empty / pure embedding noise
        if not text.strip():
            return
        entries.append(
            MemoryEntry(
                source=src or source,
                text=text,
                entry_id=entry_id,
                meta=meta or {},
            )
        )

    if isinstance(doc, list):
        if _looks_like_memory_list(doc) or True:
            for i, item in enumerate(doc):
                if isinstance(item, str):
                    add(item, entry_id="[%d]" % i)
                elif isinstance(item, dict):
                    text = _text_from_obj(item)
                    add(text, entry_id=_entry_id_from(item, "[%d]" % i), meta=item)
        return entries

    if not isinstance(doc, dict):
        return entries

    # Common wrappers: memories / results / items / facts / documents / data
    for wrap in (
        "memories", "results", "items", "facts", "documents", "entries",
        "memory", "store", "records", "notes", "observations",
    ):
        val = doc.get(wrap)
        if isinstance(val, list) and val:
            for i, item in enumerate(val):
                if isinstance(item, str):
                    add(item, entry_id="%s[%d]" % (wrap, i))
                elif isinstance(item, dict):
                    text = _text_from_obj(item)
                    add(
                        text,
                        entry_id=_entry_id_from(item, "%s[%d]" % (wrap, i)),
                        meta=item,
                    )
            if entries:
                return entries
        if isinstance(val, dict):
            # {memory: {id: text}} or nested
            for k, v in val.items():
                if isinstance(v, str):
                    add(v, entry_id=str(k)[:80])
                elif isinstance(v, dict):
                    text = _text_from_obj(v)
                    add(text, entry_id=_entry_id_from(v, str(k)[:80]), meta=v)
            if entries:
                return entries

    # LangGraph / checkpoint style: {channel_values: {messages: [...]}} or messages
    channel = doc.get("channel_values") if isinstance(doc.get("channel_values"), dict) else None
    msgs = None
    if channel and isinstance(channel.get("messages"), list):
        msgs = channel["messages"]
    elif isinstance(doc.get("messages"), list):
        msgs = doc["messages"]
    if msgs:
        for i, m in enumerate(msgs):
            if not isinstance(m, dict):
                continue
            role = m.get("role") or m.get("type") or ""
            # Prefer non-system user/assistant memory-like content; still scan all
            text = _text_from_obj(m)
            if not text and isinstance(m.get("data"), dict):
                text = _text_from_obj(m["data"])
            eid = _entry_id_from(m, "messages[%d]" % i)
            if role:
                eid = "%s:%s" % (role, eid)
            add(text, entry_id=eid, meta=m)
        if entries:
            return entries

    # Single memory object
    text = _text_from_obj(doc)
    if text:
        add(text, entry_id=_entry_id_from(doc, "root"))
        return entries

    # Flat {id: "memory text", ...} map of strings
    string_vals = [(k, v) for k, v in doc.items() if isinstance(v, str) and len(v) > 20]
    if len(string_vals) >= 1 and len(string_vals) == len(
        [v for v in doc.values() if not callable(v)]
    ):
        for k, v in string_vals:
            add(v, entry_id=str(k)[:80])
    return entries


def load_entries(path: str, as_text: bool = False):
    """Load MemoryEntry list from a file path or '-' stdin."""
    if path == "-":
        raw = sys.stdin.read()
        label = "<stdin>"
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        label = path

    if as_text or (path != "-" and not path.endswith((".json", ".jsonl", ".JSON", ".JSONL"))):
        # treat whole file / each non-empty paragraph as an entry when --as-text
        if as_text:
            parts = re.split(r"\n\s*\n", raw)
            out = []
            for i, p in enumerate(parts):
                p = p.strip()
                if p:
                    out.append(MemoryEntry(source="%s#p%d" % (label, i + 1), text=p, entry_id="p%d" % (i + 1)))
            if not out and raw.strip():
                out.append(MemoryEntry(source=label, text=raw, entry_id="file"))
            return out

    # JSONL?
    stripped = raw.lstrip()
    if path.endswith(".jsonl") or (
        stripped.startswith("{") and "\n" in raw and raw.strip().count("\n") >= 1
        and not stripped.startswith("[")
        and _jsonl_likely(raw)
    ):
        entries = []
        for lineno, line in enumerate(raw.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                entries.append(
                    MemoryEntry(source="%s:%d" % (label, lineno), text=line, entry_id="L%d" % lineno)
                )
                continue
            got = extract_entries_from_doc(obj, "%s:%d" % (label, lineno))
            if got:
                entries.extend(got)
            else:
                text = _text_from_obj(obj) if isinstance(obj, dict) else (
                    obj if isinstance(obj, str) else ""
                )
                if text:
                    eid = _entry_id_from(obj, "L%d" % lineno) if isinstance(obj, dict) else "L%d" % lineno
                    entries.append(
                        MemoryEntry(source="%s:%d" % (label, lineno), text=text, entry_id=eid)
                    )
        return entries

    # JSON document
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        # fallback: plain text paragraphs
        parts = re.split(r"\n\s*\n", raw)
        out = []
        for i, p in enumerate(parts):
            p = p.strip()
            if p:
                out.append(MemoryEntry(source="%s#p%d" % (label, i + 1), text=p, entry_id="p%d" % (i + 1)))
        if not out and raw.strip():
            out.append(MemoryEntry(source=label, text=raw, entry_id="file"))
        return out

    return extract_entries_from_doc(doc, label)


def _jsonl_likely(raw: str) -> bool:
    lines = [ln for ln in raw.splitlines() if ln.strip()][:5]
    if len(lines) < 2:
        return False
    ok = 0
    for ln in lines:
        try:
            json.loads(ln)
            ok += 1
        except json.JSONDecodeError:
            pass
    return ok >= 2


def classify_entry(entry: MemoryEntry, disabled=None):
    disabled = set(disabled or [])
    findings = []
    text = entry.text or ""
    if not text.strip():
        return findings

    def add(rule, message, snippet=""):
        if rule in disabled:
            return
        findings.append(
            Finding(
                rule,
                entry.source,
                message,
                entry_id=entry.entry_id,
                snippet=_mask(snippet or text),
            )
        )

    label = entry.entry_id or entry.source

    # MF03 hidden unicode (check raw first)
    hidden = _find_hidden_unicode(text)
    if hidden and "MF03" not in disabled:
        kinds = sorted({k for k, _, _ in hidden})
        decoded = _decode_tag_chars(text)
        extra = ""
        if decoded != text and INSTRUCTIONISH_RE.search(_strip_invisibles(decoded)):
            extra = "; decoded TAG/invisible text looks instruction-like"
        add(
            "MF03",
            "Memory entry %s contains hidden Unicode (%s, %d char(s))%s"
            % (label, ",".join(kinds), len(hidden), extra),
            snippet=text,
        )

    # Work on stripped + NFKC for phrase rules so ZW-evasions still match
    visible = _strip_invisibles(unicodedata.normalize("NFKC", text))
    tag_decoded = _strip_invisibles(unicodedata.normalize("NFKC", _decode_tag_chars(text)))
    scan = visible if visible.strip() else tag_decoded
    if tag_decoded != visible and len(tag_decoded) > len(visible):
        scan = tag_decoded

    if OVERRIDE_RE.search(scan):
        m = OVERRIDE_RE.search(scan)
        add("MF01", "Override/jailbreak phrasing in memory entry %s" % label, m.group(0) if m else scan)

    if FAKE_ROLE_RE.search(scan):
        m = FAKE_ROLE_RE.search(scan)
        add("MF02", "Fake role/system token in memory entry %s" % label, m.group(0) if m else scan)

    if EXFIL_URL_RE.search(scan):
        m = EXFIL_URL_RE.search(scan)
        add("MF04", "Exfil/callback URL bait in memory entry %s" % label, m.group(0) if m else scan)

    if CREDS_HARVEST_RE.search(scan):
        m = CREDS_HARVEST_RE.search(scan)
        add("MF05", "Credential-harvest instruction in memory entry %s" % label, m.group(0) if m else scan)

    if TOOL_BAIT_RE.search(scan):
        m = TOOL_BAIT_RE.search(scan)
        add("MF06", "Tool-chaining / action bait in memory entry %s" % label, m.group(0) if m else scan)

    if CONCEAL_RE.search(scan):
        m = CONCEAL_RE.search(scan)
        add("MF07", "Conceal-from-user instruction in memory entry %s" % label, m.group(0) if m else scan)

    if PERSIST_RE.search(scan):
        m = PERSIST_RE.search(scan)
        add(
            "MF09",
            "Cross-session persistence bait in memory entry %s" % label,
            m.group(0) if m else scan,
        )

    # MF08 encoded blobs
    if "MF08" not in disabled:
        for m in B64_RE.finditer(text):
            blob = m.group(1)
            if len(blob) < 32:
                continue
            decoded = _try_b64_decode(blob)
            if not decoded:
                continue
            if INSTRUCTIONISH_RE.search(decoded) or OVERRIDE_RE.search(decoded) or PERSIST_RE.search(decoded):
                add(
                    "MF08",
                    "Base64 blob in memory entry %s decodes to instruction-like text" % label,
                    decoded,
                )
                break
        else:
            for m in HEX_RE.finditer(text):
                blob = m.group(1)
                decoded = _try_hex_decode(blob)
                if not decoded:
                    continue
                if INSTRUCTIONISH_RE.search(decoded) or OVERRIDE_RE.search(decoded) or PERSIST_RE.search(decoded):
                    add(
                        "MF08",
                        "Hex blob in memory entry %s decodes to instruction-like text" % label,
                        decoded,
                    )
                    break

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
                    if fn.endswith((".json", ".jsonl", ".txt", ".md", ".memory")):
                        paths.append(os.path.join(root, fn))
        else:
            paths.append(p)
    return paths


def format_table(findings, entry_count):
    lines = []
    lines.append(
        "memfence %s — %d memory entr(y/ies), %d finding(s)"
        % (VERSION, entry_count, len(findings))
    )
    if not findings:
        lines.append("No memory-poisoning findings.")
        return "\n".join(lines)
    lines.append("")
    lines.append("%-6s %-8s %-22s %s" % ("RULE", "SEV", "ENTRY", "MESSAGE"))
    lines.append("-" * 100)
    for f in findings:
        eid = (f.entry_id or "-")[:22]
        lines.append(
            "%-6s %-8s %-22s %s" % (f.rule, f.severity, eid, f.message[:70])
        )
        if f.snippet:
            lines.append("       snippet: %s" % f.snippet[:80])
        if f.source:
            lines.append("       at:      %s" % f.source)
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="memfence",
        description=(
            "Offline persistent agent-memory / store poisoning scanner "
            "(mem0, LangGraph, fact JSONL, text dumps)."
        ),
    )
    ap.add_argument(
        "paths",
        nargs="*",
        help="memory dump JSON/JSONL/text files or directories (or - for stdin)",
    )
    ap.add_argument(
        "--as-text",
        action="store_true",
        help="treat inputs as plain-text memory dumps (paragraph = entry)",
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
    ap.add_argument("--version", action="version", version="memfence " + VERSION)
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
        sys.stderr.write("memfence: no readable inputs\n")
        return 2

    all_entries = []
    errors = 0
    for path in file_paths:
        try:
            all_entries.extend(load_entries(path, as_text=ns.as_text))
        except (OSError, ValueError) as e:
            sys.stderr.write("memfence: %s\n" % e)
            errors += 1

    if errors and not all_entries:
        return 2

    disabled = set(ns.disable or [])
    findings = []
    for entry in all_entries:
        findings.extend(classify_entry(entry, disabled=disabled))

    if "MF10" not in disabled:
        for entry in all_entries:
            preview = _mask(entry.text, 48)
            findings.append(
                Finding(
                    "MF10",
                    entry.source,
                    "Memory entry %s (%d chars): %s"
                    % (entry.entry_id or "-", len(entry.text), preview),
                    entry_id=entry.entry_id,
                    snippet=preview,
                )
            )

    min_rank = SEV_RANK[ns.min_severity]
    shown = [f for f in findings if SEV_RANK[f.severity] >= min_rank]
    shown.sort(
        key=lambda f: (-SEV_RANK[f.severity], f.rule, f.entry_id or "", f.source or "")
    )

    if ns.json:
        print(
            json.dumps(
                {
                    "tool": "memfence",
                    "version": VERSION,
                    "entries": [
                        {
                            "id": e.entry_id,
                            "source": e.source,
                            "chars": len(e.text),
                        }
                        for e in all_entries
                    ],
                    "findings": [f.to_dict() for f in shown],
                },
                indent=2,
            )
        )
    else:
        print(format_table(shown, len(all_entries)))

    actionable = [f for f in shown if f.rule != "MF10"]
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
