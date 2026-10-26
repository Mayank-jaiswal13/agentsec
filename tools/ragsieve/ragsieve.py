#!/usr/bin/env python3
"""ragsieve - offline, heuristic pre-ingestion scanner for RAG corpora.

Scans Markdown, HTML, plain text, CSV and JSON/JSONL documents for indirect
prompt-injection and data-exfiltration payload *shapes* before they are
ingested into a retrieval corpus or agent knowledge base.

Stdlib only. Heuristic / string based: a clean result does NOT mean safe.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import csv
import fnmatch
import io
import json
import os
import re
import sys
from html.parser import HTMLParser

__version__ = "0.1.0"
TOOL = "ragsieve"

SEVERITIES = ["info", "low", "medium", "high"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEV_WEIGHT = {"info": 1, "low": 5, "medium": 15, "high": 40}

DEFAULT_EXTS = {".md", ".markdown", ".mdx", ".html", ".htm", ".xhtml", ".txt", ".text",
                ".rst", ".csv", ".tsv", ".json", ".jsonl", ".ndjson"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache"}

RULES = {
    "RS01": ("hidden-html-text", "high",
             "Text inside an element hidden by CSS/attributes (display:none, visibility:hidden, "
             "font-size:0, opacity:0, color equal to background, off-screen, hidden attr). Humans "
             "never see it, but text extractors and LLMs do.",
             "Remove hidden elements before ingestion (ragsieve --strip) or extract only rendered text."),
    "RS02": ("comment-instruction", "high",
             "HTML/Markdown comment containing instruction-like text. Comments are invisible when "
             "rendered but are often kept by loaders and chunkers.",
             "Strip comments before ingestion (ragsieve --strip)."),
    "RS03": ("invisible-unicode", "medium",
             "Zero-width / invisible format characters. Can hide or split keywords to evade "
             "filters, or carry binary-encoded payloads.",
             "Remove zero-width characters (ragsieve --strip) unless the language genuinely needs them."),
    "RS04": ("unicode-tag-smuggling", "high",
             "Unicode TAG characters (U+E0000 block) render as nothing but many tokenizers read "
             "them as ASCII. Classic 'ASCII smuggling' of hidden instructions.",
             "Remove all U+E0000-U+E007F characters (ragsieve --strip)."),
    "RS05": ("bidi-control", "medium",
             "Bidirectional override/embedding/isolate controls can make displayed text differ "
             "from the logical text a model reads (Trojan-Source style).",
             "Remove bidi control characters unless the document legitimately mixes RTL/LTR text."),
    "RS06": ("variation-selector-smuggling", "high",
             "Runs of variation selectors (U+FE00-FE0F, U+E0100-E01EF) can encode arbitrary bytes "
             "invisibly after a visible character.",
             "Remove variation-selector runs (ragsieve --strip)."),
    "RS07": ("ai-directed-instruction", "high",
             "Imperative phrase addressed to an AI model (ignore previous instructions, you are now, "
             "system prompt, do not tell the user, ...). Typical indirect prompt injection.",
             "Review the passage; drop or quarantine the document if it is not legitimately about prompt injection."),
    "RS08": ("exfil-url", "high",
             "Image/link URL with template placeholders, secret-looking variables or encoded blobs in "
             "the query, or text asking to append conversation data to a URL. Auto-rendered images "
             "are a zero-click exfiltration channel.",
             "Remove the URL; disable automatic image rendering / restrict to an allowlist of hosts."),
    "RS09": ("tool-action-bait", "medium",
             "Text that tries to get an agent to call tools or take actions (call the X tool, send "
             "email to, curl, run this command, forward the conversation).",
             "Review; documents should not direct agents to act. Gate agent tool calls with human approval."),
    "RS10": ("fake-role-delimiter", "high",
             "Chat-template tokens or role/turn markers (<|im_start|>, [INST], <<SYS>>, 'System:', "
             "'### Assistant:') that try to fake a conversation turn inside retrieved content.",
             "Remove or escape role markers; never splice retrieved text into prompts unescaped."),
    "RS11": ("encoded-blob", "low",
             "Long base64/hex blob. Can hide instructions from keyword filters; escalated to high "
             "when it decodes to instruction-like text.",
             "Decode and review; remove if not needed for the document's purpose."),
    "RS12": ("attribute-injection", "high",
             "Instruction-like text in alt/title/aria-label/placeholder attributes or Markdown "
             "image alt/link title. Often extracted as text but rarely seen by reviewers.",
             "Rewrite or drop the attribute text."),
    "RS13": ("csv-formula", "medium",
             "CSV cell starting with a formula trigger (=, +, -, @). Dangerous if the corpus is "
             "later opened in a spreadsheet; =HYPERLINK/=WEBSERVICE/DDE can exfiltrate data.",
             "Prefix such cells with a single quote or reject them; never auto-open in spreadsheets."),
}

# ---------------------------------------------------------------- patterns
F = re.IGNORECASE
AI = r"(?:ai|a\.i\.|llm|language model|assistant|chat ?bot|agent|model|copilot|gpt|claude|gemini)"
AI_INSTRUCTION_PATTERNS = [
    ("ignore-previous", re.compile(
        r"\b(?:ignore|disregard|forget|override|bypass|skip)\s+(?:all\s+|any\s+|the\s+|your\s+|of\s+)*"
        r"(?:previous|prior|above|earlier|preceding|former|original|existing|system|safety)\s+"
        r"(?:instructions?|prompts?|messages?|context|rules|directions|guidelines|directives)", F)),
    ("you-are-now", re.compile(r"\byou\s+are\s+now\s+(?:a|an|the|in|my|no\s+longer|dan|unrestricted|unfiltered|jailbroken|free\s+of)\b", F)),
    ("new-instructions", re.compile(
        r"\b(?:new|updated|real|actual|revised|hidden|secret|important)\s+(?:system\s+)?instructions?\s*[:\-]", F)),
    ("system-prompt", re.compile(r"\b(?:system|developer|hidden)\s+prompt\b", F)),
    ("as-an-ai", re.compile(r"\bas\s+an?\s+" + AI + r"\b[^.\n]{0,40}\b(?:you|must|should|will)\b", F)),
    ("hide-from-user", re.compile(
        r"\b(?:do\s+not|don't|never)\s+(?:tell|inform|mention\s+(?:this\s+)?to|reveal\s+(?:this\s+)?to|"
        r"show|alert|notify|let)\s+(?:the|your)\s+user\b|\bwithout\s+(?:telling|informing|notifying|"
        r"alerting)\s+the\s+user\b|\bkeep\s+(?:this|it)\s+(?:a\s+)?secret\s+from\s+the\s+user\b", F)),
    ("addressed-to-ai", re.compile(
        r"\b(?:note|message|instructions?|attention)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?" + AI + r"s?\b"
        r"|\b(?:dear|hey|attention)\s+" + AI + r"\b"
        r"|\bif\s+you\s+are\s+an?\s+" + AI + r"\b"
        r"|\b" + AI + r"s?\s+(?:reading|processing|summari[sz]ing|parsing)\s+this\b", F)),
    ("reveal-prompt", re.compile(
        r"\b(?:reveal|print|output|repeat|leak|dump|disclose)\s+(?:your|the)\s+(?:system\s+prompt|"
        r"instructions|hidden\s+prompt|initial\s+prompt|rules|configuration)\b", F)),
    ("jailbreak", re.compile(r"\b(?:jailbreak|developer\s+mode\s+enabled|do\s+anything\s+now|DAN\s+mode)\b", F)),
    ("from-now-on", re.compile(
        r"\bfrom\s+now\s+on,?\s+(?:you|always|only|respond|answer|reply)\b|\b(?:respond|reply|answer)\s+"
        r"only\s+with\b|\bpretend\s+(?:to\s+be|you\s+are)\b", F)),
]
WEAK_INSTRUCTION = re.compile(
    r"\b(?:you\s+must|you\s+should|always\s+(?:say|respond|recommend|answer)|instead\s+(?:say|respond|"
    r"tell|recommend)|tell\s+the\s+user|the\s+user\s+(?:wants|asked)|recommend\s+(?:only|that)|"
    r"respond\s+with|say\s+that|instructions?)\b|\b" + AI + r"\b", F)

BAIT_PATTERNS = [
    ("call-tool", "medium", re.compile(
        r"\b(?:call|invoke|use|run|execute|trigger)\s+the\s+[`'\"]?[\w.\-]+[`'\"]?\s+(?:tool|function|action|plugin|api|endpoint)\b", F)),
    ("send-email", "medium", re.compile(
        r"\bsend\s+(?:an?\s+)?(?:e-?mail|message|dm|slack\s+message|text)\s+to\b", F)),
    ("forward-data", "high", re.compile(
        r"\b(?:forward|e-?mail|post|upload|send|transmit|exfiltrate)\s+(?:the\s+|this\s+|all\s+|your\s+|any\s+)*"
        r"(?:conversation|chat(?:\s+history)?|history|context|files?|documents?|data|credentials|secrets|"
        r"passwords?|api\s+keys?|tokens?|memory|messages)\s+to\b", F)),
    ("curl-wget", "medium", re.compile(r"\b(?:curl|wget|Invoke-WebRequest|iwr)\s+(?:-{1,2}[\w-]+\s+(?:\S+\s+)?)*['\"]?https?://", F)),
    ("run-command", "medium", re.compile(
        r"\b(?:run|execute|paste)\s+(?:this|the\s+following)\s+(?:command|script|code|snippet|in\s+(?:a\s+|the\s+)?terminal)\b"
        r"|\bexecute\s+the\s+following\b", F)),
    ("pipe-to-shell", "high", re.compile(r"\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\bpowershell(?:\.exe)?\s+.*-e(?:nc|ncodedcommand)?\s", F)),
    ("visit-url", "medium", re.compile(
        r"\b(?:visit|open|fetch|browse\s+to|navigate\s+to|load)\s+(?:this|the\s+following)\s+(?:url|link|page|site)\s+and\b", F)),
]

EXFIL_INSTRUCTION = re.compile(
    r"\b(?:append|add|include|insert|encode|put|attach|embed)\s+(?:the\s+|a\s+|your\s+)?(?:entire\s+|full\s+|whole\s+|complete\s+)?"
    r"(?:conversation|chat(?:\s+history)?|previous\s+messages|message\s+history|user'?s?\s+(?:data|messages?|question|e-?mail|"
    r"password|info(?:rmation)?|name|address)|secrets?|api\s+keys?|context|memory|summary\s+of\s+the\s+conversation)"
    r"[^.\n]{0,40}?\b(?:to|in|into|as|onto)\s+(?:the\s+|this\s+|a\s+|that\s+)?(?:following\s+|above\s+|below\s+|next\s+)?(?:url|link|image|query|parameter|src|markdown)", F)

ROLE_TOKENS = re.compile(
    r"<\|(?:im_start|im_end|im_sep|endoftext|system|user|assistant|eot_id|start_header_id|end_header_id|begin_of_text)\|>"
    r"|\[/?INST\]|<<\s*/?\s*SYS\s*>>|</?\s*(?:system|assistant|system_prompt)\s*>", F)
ROLE_LINE = re.compile(r"^[ \t>*_]*(?:#{1,6}[ \t]*)?\**(System|Assistant|Human|User|Developer)\**[ \t]*:", re.M)
ROLE_BOUNDARY = re.compile(
    r"\b(?:end\s+of\s+(?:document|context|user\s+input|retrieved\s+(?:text|content))|begin\s+(?:system\s+prompt|"
    r"new\s+instructions)|end\s+system\s+prompt)\b", F)

B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{60,}={0,2}(?![A-Za-z0-9+/=_-])")
HEX_BLOB = re.compile(r"\b(?:0x)?[0-9a-fA-F]{96,}\b")

MD_IMAGE = re.compile(r"!\[([^\]\n]*)\]\(\s*(<[^>\n]+>|[^)\s]+)(?:\s+[\"']([^\"'\n]*)[\"'])?\s*\)")
MD_LINK = re.compile(r"(?<!!)\[([^\]\n]*)\]\(\s*(<[^>\n]+>|[^)\s]+)(?:\s+[\"']([^\"'\n]*)[\"'])?\s*\)")
MD_REF_COMMENT = re.compile(r"^\[//\]:\s*#\s*[(\"'](.*)[)\"']\s*$", re.M)
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)

PLACEHOLDER = re.compile(
    r"\{\{?[^{}\s]{1,40}\}?\}|\$\{?[A-Z_][A-Z0-9_]{2,}\}?|%7B[^%]{1,40}%7D|<[A-Za-z_][\w-]{1,30}>"
    r"|\[(?:data|secret|conversation|chat|history|token|key|password|email|user|context|summary)[^\]]*\]", F)
SUSPICIOUS_QKEY = re.compile(
    r"[?&](?:q|d|data|payload|secret|token|key|conv|conversation|chat|history|msg|message|exfil|leak|info|ctx|context|memory|p)=([^&#\s]*)", F)

INVISIBLE = {0x200B: "ZERO WIDTH SPACE", 0x200C: "ZERO WIDTH NON-JOINER", 0x200D: "ZERO WIDTH JOINER",
             0x2060: "WORD JOINER", 0x2061: "FUNCTION APPLICATION", 0x2062: "INVISIBLE TIMES",
             0x2063: "INVISIBLE SEPARATOR", 0x2064: "INVISIBLE PLUS", 0xFEFF: "ZERO WIDTH NO-BREAK SPACE",
             0x180E: "MONGOLIAN VOWEL SEPARATOR", 0x115F: "HANGUL CHOSEONG FILLER",
             0x1160: "HANGUL JUNGSEONG FILLER", 0x3164: "HANGUL FILLER", 0x00AD: "SOFT HYPHEN",
             0x034F: "COMBINING GRAPHEME JOINER", 0x2028: "LINE SEPARATOR", 0x2029: "PARAGRAPH SEPARATOR"}
BIDI = {0x202A: "LRE", 0x202B: "RLE", 0x202C: "PDF", 0x202D: "LRO", 0x202E: "RLO",
        0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI"}
INVIS_RE = re.compile("[" + "".join(chr(c) for c in INVISIBLE) + "]+")
BIDI_RE = re.compile("[" + "".join(chr(c) for c in BIDI) + "]+")
TAG_RE = re.compile("[\U000E0000-\U000E007F]+")
VS_RE = re.compile("[\uFE00-\uFE0F\U000E0100-\U000E01EF]+")

ATTRS_TO_CHECK = {"alt", "title", "aria-label", "aria-description", "placeholder", "summary", "label"}
VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
             "source", "track", "wbr", "keygen"}


def is_instructiony(text: str, weak: bool = False) -> bool:
    for _, rx in AI_INSTRUCTION_PATTERNS:
        if rx.search(text):
            return True
    if EXFIL_INSTRUCTION.search(text) or ROLE_TOKENS.search(text):
        return True
    for _, sev, rx in BAIT_PATTERNS:
        if rx.search(text):
            return True
    return bool(weak and WEAK_INSTRUCTION.search(text))


# ---------------------------------------------------------------- helpers
def visible_repr(s: str) -> str:
    out = []
    for ch in s:
        cp = ord(ch)
        if cp in INVISIBLE or cp in BIDI or 0xE0000 <= cp <= 0xE007F or 0xFE00 <= cp <= 0xFE0F \
                or 0xE0100 <= cp <= 0xE01EF:
            out.append("<U+%04X>" % cp)
        elif ch in "\r\n\t":
            out.append(" ")
        elif cp < 32:
            out.append("\\x%02x" % cp)
        else:
            out.append(ch)
    return "".join(out)


_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{28,}")


def mask_snippet(s: str, limit: int = 110) -> str:
    s = visible_repr(s)
    s = re.sub(r"(?:<U\+[0-9A-F]{4,5}>){4,}", lambda m: m.group(0)[:16] + "...(%d invisible)" % m.group(0).count("<U+"), s)
    s = _LONG_TOKEN.sub(lambda m: m.group(0)[:8] + "...[%d chars]" % len(m.group(0)), s)
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > limit:
        s = s[:limit - 3] + "..."
    return s


def norm_color(v: str):
    v = v.strip().lower().replace(" ", "")
    v = v.replace("!important", "")
    named = {"white": "#ffffff", "black": "#000000", "red": "#ff0000", "transparent": "transparent",
             "snow": "#fffafa", "ivory": "#fffff0", "whitesmoke": "#f5f5f5"}
    if v in named:
        return named[v]
    m = re.fullmatch(r"#([0-9a-f]{3})", v)
    if m:
        return "#" + "".join(c * 2 for c in m.group(1))
    m = re.fullmatch(r"#([0-9a-f]{6})(?:[0-9a-f]{2})?", v)
    if m:
        return "#" + m.group(1)
    m = re.fullmatch(r"rgba?\((\d+),(\d+),(\d+)(?:,([\d.]+))?\)", v)
    if m:
        if m.group(4) is not None and float(m.group(4)) < 0.05:
            return "transparent"
        return "#%02x%02x%02x" % tuple(min(255, int(m.group(i))) for i in (1, 2, 3))
    return v or None


def parse_style(style: str) -> dict:
    d = {}
    for part in style.split(";"):
        if ":" in part:
            k, v = part.split(":", 1)
            d[k.strip().lower()] = v.strip().lower()
    return d


def _num(v: str):
    m = re.match(r"\s*(-?[\d.]+)\s*([a-z%]*)", v or "")
    if not m:
        return None, ""
    try:
        return float(m.group(1)), m.group(2)
    except ValueError:
        return None, ""


def hidden_reason(attrs: dict):
    """Return (reason, strong) if element attributes hide it, else None.
    strong=False means only flag when the text is instruction-like (aria-hidden)."""
    if "hidden" in attrs:
        return ("hidden attribute", True)
    st = parse_style(attrs.get("style") or "")
    if st:
        if st.get("display", "").startswith("none"):
            return ("display:none", True)
        if st.get("visibility", "").split(" ")[0] in ("hidden", "collapse"):
            return ("visibility:hidden", True)
        n, u = _num(st.get("font-size", ""))
        if n is not None and (n == 0 or (u == "px" and n < 2) or (u in ("em", "rem") and n < 0.15) or (u == "pt" and n < 1.5)):
            return ("font-size:%s" % st["font-size"], True)
        n, _ = _num(st.get("opacity", ""))
        if n is not None and n < 0.05:
            return ("opacity:%s" % st["opacity"], True)
        fg = norm_color(st["color"]) if "color" in st else None
        bgraw = st.get("background-color") or st.get("background")
        bg = norm_color(bgraw.split(" ")[0]) if bgraw else None
        if fg == "transparent":
            return ("color:transparent", True)
        if fg and bg and fg == bg:
            return ("color equals background (%s)" % fg, True)
        for k in ("left", "top", "right", "margin-left", "margin-top", "text-indent"):
            n, u = _num(st.get(k, ""))
            if n is not None and n <= -500 and u in ("px", "em", "rem", "pt", "vw", "vh", "") or \
                    (n is not None and n <= -50 and u in ("em", "rem", "vw", "vh", "%")):
                return ("off-screen %s:%s" % (k, st[k]), True)
        if re.search(r"rect\(\s*0(?:px)?[ ,]+0(?:px)?[ ,]+0(?:px)?[ ,]+0", st.get("clip", "")):
            return ("clip:rect(0,0,0,0)", True)
        if "scale(0" in st.get("transform", "").replace(" ", ""):
            return ("transform:scale(0)", True)
        if st.get("overflow", "").startswith("hidden"):
            for k in ("height", "width", "max-height", "max-width"):
                n, _ = _num(st.get(k, ""))
                if n is not None and n <= 1:
                    return ("%s:%s with overflow:hidden" % (k, st[k]), True)
    if (attrs.get("aria-hidden") or "").lower() == "true":
        return ("aria-hidden=true", False)
    return None


class Finding:
    __slots__ = ("path", "line", "col", "chunk", "rule", "severity", "message", "snippet", "offset")

    def __init__(self, path, line, col, chunk, rule, severity, message, snippet, offset):
        self.path, self.line, self.col, self.chunk = path, line, col, chunk
        self.rule, self.severity, self.message, self.snippet, self.offset = rule, severity, message, snippet, offset

    def to_dict(self):
        return {"file": self.path, "line": self.line, "column": self.col, "chunk": self.chunk,
                "rule": self.rule, "name": RULES[self.rule][0], "severity": self.severity,
                "message": self.message, "snippet": self.snippet}


class _HTMLScan(HTMLParser):
    def __init__(self, text, line_starts):
        super().__init__(convert_charrefs=True)
        self.text = text
        self.ls = line_starts
        self.stack = []          # [tag, reason, strong, start_off, textparts]
        self.hidden = []         # (start, end, reason, strong, text)
        self.attr_hits = []      # (offset, attrname, value, tag)
        self.urls = []           # (offset, url, kind)

    def _off(self):
        ln, col = self.getpos()
        return self.ls[ln - 1] + col

    def _attrs(self, tag, attrs, off):
        d = {}
        for k, v in attrs:
            d[k.lower()] = v if v is not None else ""
        for k, v in d.items():
            if v and (k in ATTRS_TO_CHECK or k.startswith("data-")):
                self.attr_hits.append((off, k, v, tag))
        if tag == "img" and d.get("src"):
            self.urls.append((off, d["src"], "image"))
        for k in ("srcset", "poster", "background"):
            if d.get(k):
                self.urls.append((off, d[k].split(" ")[0], "image"))
        if tag == "a" and d.get("href"):
            self.urls.append((off, d["href"], "link"))
        return d

    def handle_starttag(self, tag, attrs):
        off = self._off()
        d = self._attrs(tag, attrs, off)
        if tag in VOID_TAGS:
            return
        hr = hidden_reason(d)
        self.stack.append([tag, hr[0] if hr else None, hr[1] if hr else False, off, []])

    def handle_startendtag(self, tag, attrs):
        self._attrs(tag, attrs, self._off())

    def handle_endtag(self, tag):
        off = self._off()
        idx = None
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                idx = i
                break
        if idx is None:
            return
        gt = self.text.find(">", off)
        end = gt + 1 if gt >= 0 else off
        while len(self.stack) > idx:
            el = self.stack.pop()
            inner = "".join(el[4])
            if self.stack:
                self.stack[-1][4].append(inner)
            if el[1] and not any(s[1] for s in self.stack):
                self.hidden.append((el[3], end, el[1], el[2], inner))

    def handle_data(self, data):
        if self.stack and self.stack[-1][0] not in ("script", "style"):
            self.stack[-1][4].append(data)

    def close_all(self):
        # unclosed hidden elements: report from start tag to end of text
        while self.stack:
            el = self.stack.pop()
            inner = "".join(el[4])
            if self.stack:
                self.stack[-1][4].append(inner)
            if el[1] and not any(s[1] for s in self.stack):
                self.hidden.append((el[3], None, el[1], el[2], inner))


def line_starts_of(text):
    starts = [0]
    for m in re.finditer("\n", text):
        starts.append(m.end())
    return starts


def json_decoded_view(raw: str) -> str:
    """Replace JSON string literals by their decoded value, per line, keeping line structure."""
    def dec(m):
        try:
            v = json.loads(m.group(0))
        except Exception:
            return m.group(0)
        return '"' + v.replace("\r", " ").replace("\n", " ") + '"'
    return "\n".join(re.sub(r'"(?:[^"\\\n]|\\.)*"', dec, ln) for ln in raw.split("\n"))


def kind_of(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in (".csv", ".tsv"):
        return "csv"
    if ext in (".json", ".jsonl", ".ndjson"):
        return "json"
    if ext in (".html", ".htm", ".xhtml"):
        return "html"
    if ext in (".md", ".markdown", ".mdx"):
        return "markdown"
    return "text"


def decode_vs(run: str) -> str:
    bs = []
    for ch in run:
        cp = ord(ch)
        if 0xFE00 <= cp <= 0xFE0F:
            bs.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            bs.append(cp - 0xE0100 + 16)
    try:
        s = bytes(bs).decode("utf-8")
    except UnicodeDecodeError:
        return ""
    return s if s and all(c.isprintable() or c in "\n\t" for c in s) else ""


def try_b64(blob: str):
    s = blob.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        b = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if t and sum(c.isprintable() or c in "\n\t\r" for c in t) / len(t) > 0.95:
        return t
    return None


# ---------------------------------------------------------------- scanner
class Scanner:
    def __init__(self, chunk_size=2000, disabled=(), allow_inline=False, allowlist=()):
        self.chunk_size = max(1, int(chunk_size))
        self.disabled = set(disabled)
        self.allow_inline = allow_inline
        self.allowlist = list(allowlist)   # (glob, rule)

    def scan_text(self, text: str, path: str = "<text>", kind: str = None):
        kind = kind or kind_of(path)
        if text.startswith("\ufeff"):
            text = " " + text[1:]       # keep offsets; BOM at start is benign
        view = json_decoded_view(text) if kind == "json" else text
        ls = line_starts_of(view)
        lines = view.split("\n")
        found = []
        seen = set()

        def pos(off):
            lo, hi = 0, len(ls) - 1
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if ls[mid] <= off:
                    lo = mid
                else:
                    hi = mid - 1
            return lo + 1, off - ls[lo] + 1

        def add(off, rule, sev, msg, snip):
            if rule in self.disabled:
                return
            line, col = pos(off)
            key = (rule, line, msg)
            if key in seen:
                return
            seen.add(key)
            found.append(Finding(path, line, col, off // self.chunk_size, rule, sev, msg, mask_snippet(snip), off))

        # --- invisible unicode (RS03-RS06)
        for m in TAG_RE.finditer(view):
            hidden = "".join(chr(ord(c) - 0xE0000) for c in m.group(0) if 0x20 <= ord(c) - 0xE0000 < 0x7F)
            add(m.start(), "RS04", "high",
                "%d Unicode TAG chars; hidden ASCII decodes to: %r" % (len(m.group(0)), hidden[:200]),
                hidden or m.group(0))
        for m in VS_RE.finditer(view):
            run = m.group(0)
            supp = any(ord(c) > 0xFFFF for c in run)
            if len(run) >= 2 or supp:
                dec = decode_vs(run)
                sev = "high" if (dec or supp or len(run) >= 8) else "medium"
                msg = "run of %d variation selectors" % len(run)
                if dec:
                    msg += "; decodes to: %r" % dec[:200]
                add(m.start(), "RS06", sev, msg, view[max(0, m.start() - 10):m.end() + 10])
        for m in INVIS_RE.finditer(view):
            run = m.group(0)
            if set(run) <= {"\u00ad"}:
                sev = "info"
            elif set(run) <= {"\u200c", "\u200d"} and len(run) == 1:
                # ZWJ/ZWNJ are legitimate inside emoji sequences and in several scripts
                prev = view[m.start() - 1] if m.start() > 0 else ""
                nxt = view[m.end()] if m.end() < len(view) else ""
                if prev and nxt and ord(prev) > 0x7F and ord(nxt) > 0x7F:
                    continue
                sev = "low"
            else:
                sev = "high" if len(run) >= 8 else "medium"
            names = sorted({INVISIBLE[ord(c)] for c in run})
            add(m.start(), "RS03", sev, "%d invisible char(s): %s" % (len(run), ", ".join(names)),
                view[max(0, m.start() - 20):m.end() + 20])
        for m in BIDI_RE.finditer(view):
            sev = "high" if ("\u202e" in m.group(0) or "\u202d" in m.group(0)) else "medium"
            add(m.start(), "RS05", sev, "bidi control(s): %s" % ",".join(BIDI[ord(c)] for c in m.group(0)),
                view[max(0, m.start() - 20):m.end() + 30])

        # text with invisible chars removed for phrase matching (defeats z\u200bero-width splitting)
        # keep offsets by replacing with nothing only for matching on a per-line basis
        # --- phrase rules per line
        for i, ln in enumerate(lines):
            base = ls[i]
            clean = INVIS_RE.sub("", ln)
            shift = len(ln) != len(clean)
            def o(mo):
                return base + (0 if shift else mo.start())
            for name, rx in AI_INSTRUCTION_PATTERNS:
                for mo in rx.finditer(clean):
                    add(o(mo), "RS07", "high", "AI-directed instruction phrase (%s)%s" %
                        (name, " [after removing invisible chars]" if shift else ""), clean[max(0, mo.start() - 10):mo.end() + 50])
            for name, sev, rx in BAIT_PATTERNS:
                for mo in rx.finditer(clean):
                    add(o(mo), "RS09", sev, "tool/action bait (%s)" % name, clean[max(0, mo.start() - 10):mo.end() + 50])
            for mo in EXFIL_INSTRUCTION.finditer(clean):
                add(o(mo), "RS08", "high", "instruction to put conversation/user data into a URL",
                    clean[mo.start():mo.end() + 40])
            for mo in ROLE_TOKENS.finditer(clean):
                add(o(mo), "RS10", "high", "chat-template / role token %s" % mo.group(0), clean[max(0, mo.start() - 10):mo.end() + 50])
            for mo in ROLE_BOUNDARY.finditer(clean):
                add(o(mo), "RS10", "medium", "fake context boundary marker", clean[max(0, mo.start() - 10):mo.end() + 50])
        if kind != "csv":
            for mo in ROLE_LINE.finditer(view):
                rest = view[mo.end():view.find("\n", mo.end()) if view.find("\n", mo.end()) >= 0 else len(view)]
                role = mo.group(1)
                sev = "high" if role in ("System", "Developer") or "#" in mo.group(0) else "medium"
                if role in ("User", "Human") and "#" not in mo.group(0) and not is_instructiony(rest):
                    sev = "low"
                add(mo.start(), "RS10", sev, "line starts with a role/turn marker '%s:'" % role,
                    mo.group(0).strip() + rest)

        # --- comments (RS02)
        for mo in HTML_COMMENT.finditer(view):
            body = mo.group(1)
            if is_instructiony(body, weak=True):
                add(mo.start(), "RS02", "high", "HTML comment contains instruction-like text", body)
        for mo in MD_REF_COMMENT.finditer(view):
            if is_instructiony(mo.group(1), weak=True):
                add(mo.start(), "RS02", "high", "Markdown reference-style comment contains instruction-like text", mo.group(1))

        # --- HTML structure (RS01, RS12, URLs)
        urls = []
        hidden_spans = []
        if kind != "csv" and "<" in view:
            hp = _HTMLScan(view, ls)
            try:
                hp.feed(view)
                hp.close()
            except Exception:
                pass
            hp.close_all()
            for start, end, reason, strong, inner in hp.hidden:
                txt = inner.strip()
                if not txt:
                    continue
                instr = is_instructiony(txt, weak=True)
                if not strong and not instr:
                    continue
                sev = "high" if instr else "medium"
                add(start, "RS01", sev, "hidden element (%s) contains %stext" %
                    (reason, "instruction-like " if instr else ""), txt)
                if strong or instr:
                    hidden_spans.append((start, end))
            for off, attr, val, tag in hp.attr_hits:
                if is_instructiony(val, weak=(attr in ("alt", "title", "aria-label"))):
                    add(off, "RS12", "high", "instruction-like text in <%s %s=...>" % (tag, attr), val)
            urls.extend(hp.urls)
        for mo in MD_IMAGE.finditer(view):
            urls.append((mo.start(), mo.group(2), "image"))
            for txt, what in ((mo.group(1), "alt text"), (mo.group(3) or "", "title")):
                if txt and is_instructiony(txt, weak=True):
                    add(mo.start(), "RS12", "high", "instruction-like text in Markdown image %s" % what, txt)
        for mo in MD_LINK.finditer(view):
            urls.append((mo.start(), mo.group(2), "link"))
            if mo.group(3) and is_instructiony(mo.group(3), weak=True):
                add(mo.start(), "RS12", "high", "instruction-like text in Markdown link title", mo.group(3))
        for off, url, kindu in urls:
            self._check_url(add, off, url, kindu)

        # --- blobs (RS11)
        for mo in B64_BLOB.finditer(view):
            blob = mo.group(0)
            pre = view[max(0, mo.start() - 40):mo.start()].lower()
            if "base64," in pre[-12:] and re.search(r"data:(?:image|font)/", pre):
                continue
            if not (re.search(r"[A-Z]", blob) and re.search(r"[a-z]", blob) and re.search(r"\d", blob)):
                continue
            dec = try_b64(blob)
            if dec and is_instructiony(dec):
                add(mo.start(), "RS11", "high", "base64 blob (%d chars) decodes to instruction-like text: %r" %
                    (len(blob), mask_snippet(dec, 120)), blob)
            else:
                add(mo.start(), "RS11", "low", "long base64-like blob (%d chars)%s" %
                    (len(blob), "; decodes to text" if dec else ""), blob)
        for mo in HEX_BLOB.finditer(view):
            blob = mo.group(0)
            h = blob[2:] if blob.lower().startswith("0x") else blob
            dec = None
            try:
                dec = bytes.fromhex(h[: len(h) // 2 * 2]).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                pass
            if dec and is_instructiony(dec):
                add(mo.start(), "RS11", "high", "hex blob decodes to instruction-like text: %r" % mask_snippet(dec, 120), blob)
            else:
                add(mo.start(), "RS11", "low", "long hex blob (%d chars)" % len(blob), blob)

        # --- CSV formula (RS13)
        if kind == "csv":
            self._scan_csv(view, path, add, ls)

        # --- suppression
        found = [f for f in found if not self._suppressed(f, lines)]
        found.sort(key=lambda f: (f.line, f.col, f.rule))
        return found, {"chars": len(view), "chunks": max(1, -(-len(view) // self.chunk_size)),
                       "hidden_spans": hidden_spans}

    def _check_url(self, add, off, url, kindu):
        u = url.strip()
        if u.startswith("<") and u.endswith(">") and len(u) > 2:
            u = u[1:-1]
        if u.lower().startswith(("data:", "#", "mailto:")):
            return
        if u.lower().startswith("javascript:"):
            add(off, "RS08", "high", "javascript: URL in %s" % kindu, u)
            return
        q = u.split("?", 1)[1] if "?" in u else ""
        tail = u.split("://", 1)[-1]
        ph = PLACEHOLDER.search(q) or PLACEHOLDER.search(tail.split("/", 1)[1] if "/" in tail else "")
        if ph:
            add(off, "RS08", "high" if kindu == "image" else "medium",
                "%s URL contains a template placeholder %s (exfiltration shape)" % (kindu, ph.group(0)), u)
            return
        for mq in SUSPICIOUS_QKEY.finditer("?" + q if q else ""):
            val = mq.group(1)
            if len(val) >= 24 and re.fullmatch(r"[A-Za-z0-9+/=_%\-]+", val):
                add(off, "RS08", "high" if kindu == "image" else "medium",
                    "%s URL query carries a long encoded value (%d chars)" % (kindu, len(val)), u)
                return

    def _scan_csv(self, view, path, add, ls):
        delim = "\t" if path.lower().endswith(".tsv") else ","
        try:
            rdr = csv.reader(io.StringIO(view), delimiter=delim)
            prev_line = 1
            for row in rdr:
                for cell in row:
                    c = cell.lstrip(" ")
                    if not c:
                        continue
                    trig = c[0] in "=@" or c[0] in "\t\r" or (c[0] in "+-" and len(c) > 1 and not re.match(r"[+-]\s*[\d.,]+%?\s*$", c))
                    if not trig:
                        continue
                    danger = re.search(r"HYPERLINK|IMPORTXML|IMPORTDATA|IMPORTHTML|IMPORTFEED|IMPORTRANGE|WEBSERVICE|"
                                       r"\bcmd\b|DDE|powershell|mshta|rundll|\bEXEC\b|\bCALL\(|msexcel\|", c, F)
                    off = ls[min(prev_line, len(ls)) - 1]
                    idx = view.find(cell, off)
                    add(idx if idx >= 0 else off, "RS13", "high" if danger else "medium",
                        "CSV cell starts with formula trigger %r%s" % (c[0], " (dangerous function)" if danger else ""), c)
                prev_line = rdr.line_num + 1
        except csv.Error:
            pass

    def _suppressed(self, f, lines):
        for glob, rule in self.allowlist:
            if (rule in ("*", f.rule)) and (fnmatch.fnmatch(f.path, glob) or fnmatch.fnmatch(os.path.basename(f.path), glob)):
                return True
        if self.allow_inline and 0 < f.line <= len(lines):
            m = re.search(r"ragsieve:\s*ignore(?:\s+([A-Z0-9,\s]+))?", lines[f.line - 1])
            if m:
                ids = re.findall(r"RS\d\d", m.group(1) or "")
                return not ids or f.rule in ids
        return False


# ---------------------------------------------------------------- files
def iter_files(paths, exts, exclude_dirs=()):
    ex = [os.path.abspath(e) for e in exclude_dirs]
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")
                                 and os.path.abspath(os.path.join(root, d)) not in ex)
                for fn in sorted(files):
                    if os.path.splitext(fn)[1].lower() in exts:
                        yield os.path.join(root, fn), p
        else:
            yield p, None


def read_text(path, max_bytes):
    with open(path, "rb") as fh:
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("larger than --max-bytes (%d)" % max_bytes)
    if b"\x00" in data[:4096] and not data.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise ValueError("looks binary (NUL bytes); skipped")
    for enc in ("utf-8-sig", "utf-16"):
        if enc == "utf-16" and not data.startswith((b"\xff\xfe", b"\xfe\xff")):
            continue
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            pass
    return data.decode("utf-8", errors="replace")


def score(findings):
    return min(100, sum(SEV_WEIGHT[f.severity] for f in findings))


# ---------------------------------------------------------------- strip
def strip_text(text, kind, hidden_spans):
    """Return sanitized text and a dict of counts."""
    counts = {"hidden_elements": 0, "comments": 0, "invisible_chars": 0}
    if text.startswith("\ufeff"):
        text = text[1:]
        hidden_spans = [(s - 1, (e - 1) if e is not None else None) for s, e in hidden_spans]
    if kind in ("html", "markdown", "text"):
        spans = []
        for s, e in hidden_spans:
            spans.append((s, e if e is not None else len(text)))
            counts["hidden_elements"] += 1
        for m in HTML_COMMENT.finditer(text):
            spans.append((m.start(), m.end()))
            counts["comments"] += 1
        for m in MD_REF_COMMENT.finditer(text):
            spans.append((m.start(), m.end()))
            counts["comments"] += 1
        spans.sort()
        merged = []
        for s, e in spans:
            if merged and s <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], e))
            else:
                merged.append((s, e))
        out, last = [], 0
        for s, e in merged:
            out.append(text[last:s])
            last = e
        out.append(text[last:])
        text = "".join(out)
    if kind == "json":
        esc = r"\\u(?:200[bcdBCD]|206[0-4]|[fF][eE][fF][fF]|202[a-eA-E]|206[6-9]|00[aA][dD])" \
              r"|\\u[dD][bB]40\\u[dD][cdefCDEF][0-9a-fA-F]{2}"
        text, n = re.subn(esc, "", text)
        counts["invisible_chars"] += n
    before = len(text)
    text = TAG_RE.sub("", text)
    text = INVIS_RE.sub("", text)
    text = BIDI_RE.sub("", text)
    text = re.sub("[\U000E0100-\U000E01EF]+", "", text)
    text = re.sub("[\uFE00-\uFE0F]{2,}", "", text)
    counts["invisible_chars"] += before - len(text)
    return text, counts


def do_strip(file_results, outdir):
    outdir_abs = os.path.abspath(outdir)
    report = []
    for path, root, text, kind, meta in file_results:
        if root:
            rel = os.path.relpath(path, root)
        else:
            rel = os.path.basename(path)
        dest = os.path.join(outdir_abs, rel)
        if os.path.abspath(dest) == os.path.abspath(path):
            raise RuntimeError("refusing to overwrite original %s" % path)
        new, counts = strip_text(text, kind, meta.get("hidden_spans", []))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w", encoding="utf-8", newline="") as fh:
            fh.write(new)
        report.append((path, dest, counts))
    return report


# ---------------------------------------------------------------- output
def to_sarif(findings):
    level = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules = [{"id": rid, "name": r[0], "shortDescription": {"text": r[0]},
              "fullDescription": {"text": r[2]}, "help": {"text": r[3]},
              "defaultConfiguration": {"level": level[r[1]]}, "properties": {"severity": r[1]}}
             for rid, r in sorted(RULES.items())]
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule, "level": level[f.severity],
            "message": {"text": "%s | %s" % (f.message, f.snippet)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path.replace(os.sep, "/")},
                                                "region": {"startLine": f.line, "startColumn": f.col}}}],
            "partialFingerprints": {"ragsieve/v1": "%s:%s:%d:%s" % (f.path, f.rule, f.line, abs(hash(f.message)) % 10**8)},
            "properties": {"severity": f.severity, "chunk": f.chunk}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": TOOL, "version": __version__,
                                          "informationUri": "https://example.invalid/ragsieve", "rules": rules}},
                      "results": results}]}


def render_table(per_file, errors, totals, chunk_size, color=False):
    out = []
    sevs = totals["by_severity"]
    out.append("%s %s - %d file(s) scanned, %d finding(s) (high %d, medium %d, low %d, info %d)" %
               (TOOL, __version__, totals["files"], totals["findings"], sevs["high"], sevs["medium"], sevs["low"], sevs["info"]))
    for path, fs, meta in per_file:
        if not fs:
            continue
        chunks = {}
        for f in fs:
            chunks.setdefault(f.chunk, []).append(f)
        worst = max(chunks.items(), key=lambda kv: score(kv[1]))
        out.append("")
        out.append("%s  risk %d/100  (%d finding(s); %d/%d chunk(s) flagged @%d chars; worst chunk #%d = %d)" %
                   (path, score(fs), len(fs), len(chunks), meta["chunks"], chunk_size, worst[0], score(worst[1])))
        for f in fs:
            out.append("  L%-4d c%-3d %-6s %s %-28s %s" % (f.line, f.chunk, f.severity.upper(), f.rule, RULES[f.rule][0], f.message))
            out.append("        > %s" % f.snippet)
    for p, e in errors:
        out.append("ERROR %s: %s" % (p, e))
    if totals["findings"] == 0 and not errors:
        out.append("No findings. (Heuristic scan only - this does not prove the documents are safe.)")
    return "\n".join(out)


def list_rules():
    rows = []
    for rid, (name, sev, why, fix) in sorted(RULES.items()):
        rows.append("%s  %-28s %-6s %s\n      fix: %s" % (rid, name, sev, why, fix))
    return "\n".join(rows)


def load_allowlist(path):
    out = []
    with open(path, encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.split("#", 1)[0].strip()
            if not ln:
                continue
            parts = ln.split()
            if len(parts) == 1:
                parts = (["*", parts[0]] if re.fullmatch(r"RS\d\d", parts[0]) else [parts[0], "*"])
            out.append((parts[0], parts[1]))
    return out


def build_parser():
    p = argparse.ArgumentParser(prog=TOOL, description="Offline heuristic scanner for indirect prompt-injection "
                                "and exfiltration payloads in RAG corpus documents (pre-ingestion).")
    p.add_argument("paths", nargs="*", help="files or directories (directories are scanned recursively)")
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="JSON output")
    fmt.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 output")
    p.add_argument("--chunk-size", type=int, default=2000, help="chunk size in characters for per-chunk scores (default 2000)")
    p.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide findings below this severity")
    p.add_argument("--fail-on", choices=["high", "medium", "low", "any", "none"], default="high",
                   help="exit 1 if a reported finding is at/above this severity (default: high)")
    p.add_argument("--disable", default="", help="comma-separated rule IDs to disable, e.g. RS11,RS13")
    p.add_argument("--allowlist", metavar="FILE", help="file of '<path-glob> <RULEID|*>' lines to suppress")
    p.add_argument("--allow-inline-ignore", action="store_true",
                   help="honor 'ragsieve: ignore [RSxx]' markers in documents (OFF by default: attackers can write them too)")
    p.add_argument("--ext", default="", help="comma-separated extensions for directory scans (default: %s)" % ",".join(sorted(DEFAULT_EXTS)))
    p.add_argument("--max-bytes", type=int, default=10 * 1024 * 1024, help="skip files larger than this (default 10 MiB)")
    p.add_argument("--strip", metavar="OUTDIR", help="write sanitized copies (invisible chars, HTML comments, hidden elements removed) to OUTDIR; originals untouched")
    p.add_argument("--list-rules", action="store_true", help="print rules and exit")
    p.add_argument("--version", action="version", version="%s %s" % (TOOL, __version__))
    return p


def main(argv=None):
    p = build_parser()
    try:
        a = p.parse_args(argv)
    except SystemExit as e:
        return 0 if e.code == 0 else 2
    if a.list_rules:
        print(list_rules())
        return 0
    if not a.paths:
        print("ragsieve: error: no paths given (try --help)", file=sys.stderr)
        return 2
    exts = {("." + e.strip().lstrip(".")).lower() for e in a.ext.split(",") if e.strip()} or DEFAULT_EXTS
    disabled = {d.strip().upper() for d in a.disable.split(",") if d.strip()}
    bad = disabled - set(RULES)
    if bad:
        print("ragsieve: error: unknown rule id(s): %s" % ",".join(sorted(bad)), file=sys.stderr)
        return 2
    try:
        allow = load_allowlist(a.allowlist) if a.allowlist else []
    except OSError as e:
        print("ragsieve: error: cannot read allowlist: %s" % e, file=sys.stderr)
        return 2
    sc = Scanner(chunk_size=a.chunk_size, disabled=disabled, allow_inline=a.allow_inline_ignore, allowlist=allow)
    minrank = SEV_RANK[a.min_severity]
    per_file, errors, all_f, file_results = [], [], [], []
    fatal = False
    excl = [a.strip] if a.strip else []
    for path, root in iter_files(a.paths, exts, excl):
        if not os.path.exists(path):
            errors.append((path, "no such file or directory"))
            fatal = True
            continue
        try:
            text = read_text(path, a.max_bytes)
        except (OSError, ValueError) as e:
            errors.append((path, str(e)))
            if isinstance(e, OSError):
                fatal = True
            continue
        kind = kind_of(path)
        fs, meta = sc.scan_text(text, path, kind)
        fs = [f for f in fs if SEV_RANK[f.severity] >= minrank]
        per_file.append((path, fs, meta))
        all_f.extend(fs)
        file_results.append((path, root, text, kind, meta))
    by = {s: 0 for s in SEVERITIES}
    for f in all_f:
        by[f.severity] += 1
    totals = {"files": len(per_file), "findings": len(all_f), "by_severity": by}
    strip_report = None
    if a.strip and not fatal:
        try:
            strip_report = do_strip(file_results, a.strip)
        except (OSError, RuntimeError) as e:
            print("ragsieve: error: strip failed: %s" % e, file=sys.stderr)
            return 2
    if a.sarif:
        print(json.dumps(to_sarif(all_f), indent=2))
    elif a.json:
        files = []
        for path, fs, meta in per_file:
            chunks = {}
            for f in fs:
                chunks.setdefault(f.chunk, []).append(f)
            files.append({"file": path, "risk": score(fs), "chunks_total": meta["chunks"],
                          "chunks": [{"index": i, "score": score(c), "findings": len(c)} for i, c in sorted(chunks.items())],
                          "findings": [f.to_dict() for f in fs]})
        doc = {"tool": TOOL, "version": __version__, "chunk_size": sc.chunk_size, "summary": totals,
               "files": files, "errors": [{"file": p_, "error": e} for p_, e in errors],
               "disclaimer": "Heuristic string-based scan; false positives/negatives expected; a clean result is not proof of safety."}
        if strip_report is not None:
            doc["strip"] = [{"source": s, "output": d, "removed": c} for s, d, c in strip_report]
        print(json.dumps(doc, indent=2, ensure_ascii=False))
    else:
        print(render_table(per_file, errors, totals, sc.chunk_size))
        if strip_report is not None:
            print("\nSanitized copies written to %s:" % a.strip)
            for s, d, c in strip_report:
                print("  %s -> %s  (removed: %d hidden element(s), %d comment(s), %d invisible char(s))" %
                      (s, d, c["hidden_elements"], c["comments"], c["invisible_chars"]))
            print("  Note: --strip does not rewrite visible injection phrases, URLs or CSV formulas; review findings.")
    for p_, e in errors:
        if a.json or a.sarif:
            print("ragsieve: error: %s: %s" % (p_, e), file=sys.stderr)
    if fatal:
        return 2
    if a.fail_on == "none":
        return 0
    thr = 0 if a.fail_on == "any" else SEV_RANK[a.fail_on]
    return 1 if any(SEV_RANK[f.severity] >= thr for f in all_f) else 0


if __name__ == "__main__":
    sys.exit(main())
