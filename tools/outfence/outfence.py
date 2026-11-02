#!/usr/bin/env python3
"""outfence: offline scanner and sanitizer for LLM *output* before it is rendered.

Catches the output side of indirect prompt injection: markdown/HTML that auto-loads
attacker URLs (zero-click exfiltration), data-carrying links, terminal escape
sequences (OSC 52 clipboard writes, OSC 8 hidden hyperlinks, cursor tricks),
invisible Unicode, dangerous URL schemes and paste-to-shell commands.

Inputs: plain text/markdown files, stdin ("-"), or JSON/JSONL transcripts
(OpenAI / Anthropic / generic: assistant messages only, unless --all-roles).
Use --sanitize to print a neutralised copy of plain-text input to stdout.

Stdlib only. Exit codes: 0 clean, 1 findings at/above --fail-on, 2 usage/input error.
"""
import argparse
import fnmatch
import ipaddress
import json
import math
import os
import re
import sys
import unicodedata
from urllib.parse import urlsplit, parse_qsl, unquote

__version__ = "0.1.0"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "OF01": ("high", "Markdown image auto-loads an external URL (zero-click exfiltration channel)"),
    "OF02": ("high", "HTML/CSS element auto-loads an external resource"),
    "OF03": ("medium", "Link to an external host carries data-like parameters"),
    "OF04": ("critical", "URL appears to carry a secret or credential"),
    "OF05": ("high", "Dangerous URL scheme (javascript:, data:, vbscript:, file:)"),
    "OF06": ("high", "Terminal escape sequence (ANSI/OSC) in model output"),
    "OF07": ("medium", "Invisible or bidirectional Unicode in model output"),
    "OF08": ("medium", "Suggested command pipes remote content into a shell"),
    "OF09": ("low", "URL host is an IP literal, punycode or link-shortener"),
}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy"}

URL_RE = r"(?:https?:)?//[^\s)\"'<>\]]+"
MD_IMG_RE = re.compile(r"!\[([^\]]*)\]\(\s*<?(" + URL_RE + r"|[a-zA-Z][\w+.-]*:[^\s)]+)>?(?:\s+[\"'][^)]*[\"'])?\s*\)")
MD_IMG_REF_RE = re.compile(r"!\[([^\]]*)\]\[([^\]]*)\]")
MD_REFDEF_RE = re.compile(r"^\s{0,3}\[([^\]]+)\]:\s*<?(\S+?)>?(?:\s+.*)?$", re.M)
MD_LINK_RE = re.compile(r"(?<!!)\[([^\]]*)\]\(\s*<?((?:[^\s()<>]|\([^\s()]*\))+)>?(?:\s+[\"'][^)]*[\"'])?\s*\)")
HTML_SRC_RE = re.compile(
    r"<\s*(img|iframe|script|video|audio|source|embed|object|link|input|frame|track|image|use)\b[^>]*?"
    r"\b(src|href|data|poster|srcset|xlink:href)\s*=\s*[\"']?([^\"'\s>]+)", re.I)
META_REFRESH_RE = re.compile(r"<\s*meta\b[^>]*http-equiv\s*=\s*[\"']?refresh[^>]*url\s*=\s*([^\"'\s>]+)", re.I)
CSS_URL_RE = re.compile(r"(?:url\(\s*[\"']?|@import\s+[\"'])((?:https?:)?//[^\"')\s]+)", re.I)
BARE_URL_RE = re.compile(r"\b(?:https?://)[^\s<>\"'`)\]]+", re.I)
SCHEME_RE = re.compile(r"(?:\]\(\s*|href\s*=\s*[\"']?|src\s*=\s*[\"']?)\s*(javascript|vbscript|data|file):", re.I)
PIPE_SHELL_RE = re.compile(
    r"\b(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^\n|;]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b"
    r"|\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?python3?\b"
    r"|\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]*\|\s*iex\b"
    r"|\b(ba)?sh\s+-c\s+[\"']?\$\(\s*(curl|wget)\b", re.I)

SECRET_PATTERNS = [
    ("openai-style key", re.compile(r"sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}")),
    ("AWS access key id", re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}")),
    ("Slack token", re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{30,}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")),
    ("private key marker", re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY")),
]
SECRET_PARAM_RE = re.compile(r"(^|[_-])(api[_-]?key|apikey|token|secret|password|passwd|pwd|session|cookie|auth|credential|key)s?$", re.I)
TEMPLATE_RE = re.compile(r"\{\{[^}]*\}\}|\$\{[^}]*\}|\[(?:DATA|SECRET|INFO|CONVERSATION|HISTORY|USER[_ ]?DATA)\]|<(?:DATA|SECRET)>", re.I)

ESC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]|\x9b[0-9;?]*[@-~]|[\x07\x08](?=.)", re.S)
BIDI = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c")
ZERO_WIDTH = set("\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\u180e\ufeff")


# ---------------------------------------------------------------- helpers
def _entropy(s):
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def _line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def host_of(url):
    try:
        u = urlsplit(url if not url.startswith("//") else "https:" + url)
        return (u.hostname or "").lower()
    except ValueError:
        return ""


def host_allowed(host, allow):
    if not host:
        return True  # relative URL: same origin as the renderer
    for pat in allow:
        pat = pat.lower()
        if host == pat or fnmatch.fnmatch(host, pat):
            return True
        if pat.startswith("*.") and host == pat[2:]:
            return True
    return False


def data_signals(url):
    """Return list of reasons a URL looks like it is carrying data out."""
    reasons = []
    try:
        u = urlsplit(url if not url.startswith("//") else "https:" + url)
    except ValueError:
        return ["unparseable URL"]
    if TEMPLATE_RE.search(unquote(url)):
        reasons.append("template placeholder in URL")
    parts = [v for _, v in parse_qsl(u.query, keep_blank_values=True)]
    if u.query and not parts:
        parts = [u.query]
    parts += [seg for seg in u.path.split("/") if seg]
    if u.fragment:
        parts.append(u.fragment)
    for p in parts:
        v = unquote(p)
        if len(v) >= 24 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", v) and _entropy(v) >= 3.5:
            reasons.append("long encoded-looking value (%d chars)" % len(v))
            break
        if len(v) >= 40 and " " in v:
            reasons.append("free text in URL (%d chars)" % len(v))
            break
    if len(u.query) > 120:
        reasons.append("very long query string (%d chars)" % len(u.query))
    return reasons


def secret_signals(url):
    v = unquote(url)
    out = [name for name, rx in SECRET_PATTERNS if rx.search(v)]
    try:
        q = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        q = []
    for k, val in q:
        if SECRET_PARAM_RE.search(k) and len(val) >= 8:
            out.append("secret-named parameter '%s'" % k)
    return out


def odd_host(host):
    if not host:
        return None
    try:
        ipaddress.ip_address(host.strip("[]"))
        return "IP-literal host"
    except ValueError:
        pass
    if "xn--" in host:
        return "punycode host"
    if host in SHORTENERS:
        return "link shortener"
    return None


def mask(s, keep=6):
    return s if len(s) <= keep * 2 else s[:keep] + "…" + s[-4:]


# ---------------------------------------------------------------- scanning
def _f(rule, text, idx, snippet, detail, source, severity=None):
    return {"rule": rule, "severity": severity or RULES[rule][0], "title": RULES[rule][1],
            "source": source, "line": _line_of(text, idx), "detail": detail,
            "snippet": mask(snippet, 40) if len(snippet) > 100 else snippet}


def scan_text(text, source="<text>", allow=()):
    findings = []
    seen_urls = set()

    def url_checks(url, idx, kind, autoload):
        host = host_of(url)
        if not re.match(r"(?:https?:)?//", url, re.I):
            return
        allowed = host_allowed(host, allow)
        secrets = secret_signals(url)
        if secrets and not allowed:
            findings.append(_f("OF04", text, idx, mask(url, 30), "%s → %s (%s)" % (kind, host, ", ".join(secrets)), source))
        sig = data_signals(url)
        if autoload and not allowed:
            rule = "OF01" if kind.startswith("markdown image") else "OF02"
            sev = "critical" if sig else RULES[rule][0]
            det = "%s → %s" % (kind, host) + ("; " + "; ".join(sig) if sig else "")
            findings.append(_f(rule, text, idx, url, det, source, sev))
        elif not autoload and not allowed and sig and not secrets:
            findings.append(_f("OF03", text, idx, url, "%s → %s; %s" % (kind, host, "; ".join(sig)), source))
        odd = odd_host(host)
        if odd and not allowed:
            findings.append(_f("OF09", text, idx, url, "%s: %s" % (odd, host), source))

    refdefs = {m.group(1).strip().lower(): (m.group(2), m.start()) for m in MD_REFDEF_RE.finditer(text)}
    for m in MD_IMG_RE.finditer(text):
        seen_urls.add(m.group(2))
        url_checks(m.group(2), m.start(), "markdown image", True)
    for m in MD_IMG_REF_RE.finditer(text):
        ref = (m.group(2) or m.group(1)).strip().lower()
        if ref in refdefs:
            url, _ = refdefs[ref]
            seen_urls.add(url)
            url_checks(url, m.start(), "markdown image (reference '%s')" % ref, True)
    for m in HTML_SRC_RE.finditer(text):
        url = m.group(3)
        seen_urls.add(url)
        url_checks(url, m.start(), "<%s %s>" % (m.group(1).lower(), m.group(2).lower()), True)
    for m in META_REFRESH_RE.finditer(text):
        seen_urls.add(m.group(1))
        url_checks(m.group(1), m.start(), "<meta refresh>", True)
    for m in CSS_URL_RE.finditer(text):
        seen_urls.add(m.group(1))
        url_checks(m.group(1), m.start(), "CSS url()/@import", True)
    for m in MD_LINK_RE.finditer(text):
        if m.group(2) not in seen_urls:
            seen_urls.add(m.group(2))
            url_checks(m.group(2), m.start(), "markdown link", False)
    for key, (url, idx) in refdefs.items():
        if url not in seen_urls:
            seen_urls.add(url)
            url_checks(url, idx, "markdown link (reference '%s')" % key, False)
    for m in BARE_URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:!?")
        if url not in seen_urls and not any(url in s or s in url for s in seen_urls):
            seen_urls.add(url)
            url_checks(url, m.start(), "bare URL", False)

    for m in SCHEME_RE.finditer(text):
        scheme = m.group(1).lower()
        sev = "medium" if scheme == "data" and re.match(r"data:image/(png|gif|jpe?g|webp)", text[m.end() - 5:m.end() + 15], re.I) else "high"
        findings.append(_f("OF05", text, m.start(), text[m.start():m.start() + 60], "%s: URL" % scheme, source, sev))

    for m in ESC_RE.finditer(text):
        seq = m.group(0)
        if seq.startswith("\x1b]52"):
            sev, det = "critical", "OSC 52 clipboard write"
        elif seq.startswith("\x1b]8"):
            sev, det = "high", "OSC 8 hyperlink (link text can differ from target)"
        elif seq.startswith("\x1b]"):
            sev, det = "high", "OSC sequence (title/notification/terminal control)"
        elif seq in ("\x07", "\x08"):
            sev, det = "medium", "control character %r" % seq
        else:
            sev, det = "high", "CSI/ESC sequence (can hide, overwrite or recolour text)"
        findings.append(_f("OF06", text, m.start(), repr(seq[:40]), det, source, sev))

    hidden = {}
    for i, ch in enumerate(text):
        cp = ord(ch)
        kind = None
        if 0xE0000 <= cp <= 0xE007F:
            kind = "TAG"
        elif ch in BIDI:
            kind = "bidi"
        elif ch in ZERO_WIDTH and not (i == 0 and ch == "\ufeff"):
            kind = "zero-width"
        elif 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
            prev = text[i - 1] if i else ""
            if not prev or unicodedata.category(prev) not in ("So", "Sk") and not 0x1F000 <= ord(prev) <= 0x1FAFF and prev not in "\u200d":
                kind = "variation-selector"
        if kind:
            hidden.setdefault(kind, []).append(i)
    for kind, idxs in hidden.items():
        det = "%d %s char(s)" % (len(idxs), kind)
        sev = "medium"
        if kind == "TAG":
            decoded = "".join(chr(ord(text[i]) - 0xE0000) for i in idxs if 0x20 <= ord(text[i]) - 0xE0000 < 0x7f)
            det += "; decoded: %r" % decoded[:80]
            sev = "high"
        findings.append(_f("OF07", text, idxs[0], "", det, source, sev))

    for m in PIPE_SHELL_RE.finditer(text):
        findings.append(_f("OF08", text, m.start(), m.group(0)[:100], "remote content piped to an interpreter", source))

    findings.sort(key=lambda f: (f["line"], f["rule"]))
    return findings


# ---------------------------------------------------------------- sanitizing
def sanitize(text, allow=()):
    def keep(url):
        return host_allowed(host_of(url), allow) if re.match(r"(?:https?:)?//", url, re.I) else not re.match(r"(javascript|vbscript|data|file):", url, re.I)

    def img(m):
        return m.group(0) if keep(m.group(2)) else "[image removed: %s]" % (host_of(m.group(2)) or "blocked URL")
    text = MD_IMG_RE.sub(img, text)

    refdefs = {m.group(1).strip().lower(): m.group(2) for m in MD_REFDEF_RE.finditer(text)}

    def imgref(m):
        url = refdefs.get((m.group(2) or m.group(1)).strip().lower())
        return m.group(0) if url is None or keep(url) else "[image removed: %s]" % (host_of(url) or "blocked URL")
    text = MD_IMG_REF_RE.sub(imgref, text)

    def html(m):
        return m.group(0) if keep(m.group(3)) else "[%s removed: %s]" % (m.group(1).lower(), host_of(m.group(3)) or "blocked URL")
    text = re.sub(HTML_SRC_RE.pattern + r"[^>]*>", html, text, flags=re.I)
    text = re.sub(r"<\s*meta\b[^>]*http-equiv\s*=\s*[\"']?refresh[^>]*>", "[meta refresh removed]", text, flags=re.I)
    text = CSS_URL_RE.sub(lambda m: m.group(0) if keep(m.group(1)) else m.group(0).replace(m.group(1), "about:blank"), text)

    def link(m):
        url = m.group(2)
        if re.match(r"(javascript|vbscript|data|file):", url, re.I):
            return "%s [link removed: %s: URL]" % (m.group(1), url.split(":")[0].lower())
        if re.match(r"(?:https?:)?//", url, re.I) and not keep(url) and (data_signals(url) or secret_signals(url)):
            return "%s [link removed: %s]" % (m.group(1), host_of(url))
        return m.group(0)
    text = MD_LINK_RE.sub(link, text)

    def bare(m):
        url = m.group(0).rstrip(".,;:!?")
        if not keep(url) and secret_signals(url):
            return "[URL removed: %s]" % host_of(url) + m.group(0)[len(url):]
        return m.group(0)
    text = BARE_URL_RE.sub(bare, text)

    text = ESC_RE.sub("", text)
    out = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F or ch in BIDI or (ch in ZERO_WIDTH and ch != "\u200d") or 0xE0100 <= cp <= 0xE01EF:
            continue
        out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------- transcripts
def _content_text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for c in content:
            if isinstance(c, str):
                parts.append(c)
            elif isinstance(c, dict):
                if c.get("type") in ("text", "output_text", None) and isinstance(c.get("text"), str):
                    parts.append(c["text"])
        return "\n".join(parts)
    if isinstance(content, dict) and isinstance(content.get("text"), str):
        return content["text"]
    return ""


def _iter_messages(obj):
    if isinstance(obj, list):
        for x in obj:
            yield from _iter_messages(x)
    elif isinstance(obj, dict):
        if "role" in obj and ("content" in obj or "text" in obj):
            yield obj.get("role"), _content_text(obj.get("content", obj.get("text")))
            return
        for key in ("messages", "choices", "output", "data", "transcript", "turns"):
            if key in obj:
                yield from _iter_messages(obj[key])
                return
        if "message" in obj:
            yield from _iter_messages(obj["message"])
        elif "content" in obj and "type" in obj:
            yield obj.get("role", "assistant"), _content_text(obj["content"])


def load_units(path, all_roles=False):
    """Return list of (source_label, text)."""
    if path == "-":
        return [("<stdin>", sys.stdin.read())]
    with open(path, encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    ext = os.path.splitext(path)[1].lower()
    docs = []
    if ext == ".json":
        try:
            docs = [json.loads(raw)]
        except json.JSONDecodeError as e:
            raise ValueError("%s: invalid JSON (%s)" % (path, e))
    elif ext == ".jsonl":
        for n, line in enumerate(raw.splitlines(), 1):
            if line.strip():
                try:
                    docs.append(json.loads(line))
                except json.JSONDecodeError as e:
                    raise ValueError("%s:%d: invalid JSON (%s)" % (path, n, e))
    else:
        return [(path, raw)]
    units = []
    i = 0
    for d in docs:
        for role, text in _iter_messages(d):
            i += 1
            if text and (all_roles or role in ("assistant", "model", "ai")):
                units.append(("%s#msg%d(%s)" % (path, i, role), text))
    return units


def collect(paths):
    out = []
    for p in paths:
        if p != "-" and os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                for f in sorted(files):
                    if os.path.splitext(f)[1].lower() in (".txt", ".md", ".markdown", ".html", ".htm", ".json", ".jsonl", ".log", ".out"):
                        out.append(os.path.join(root, f))
        else:
            out.append(p)
    return out


# ---------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(prog="outfence", description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="*", help="files, directories, or - for stdin")
    ap.add_argument("--allow-host", action="append", default=[], metavar="GLOB",
                    help="trusted host (glob, e.g. '*.example.com'); repeatable")
    ap.add_argument("--all-roles", action="store_true", help="scan every message in transcripts, not just assistant")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--sanitize", action="store_true", help="print a neutralised copy of the (single, non-transcript) input to stdout")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="info")
    ap.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="medium")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)

    if a.list_rules:
        for k, (sev, title) in RULES.items():
            print("%s  %-8s %s" % (k, sev, title))
        return 0
    if not a.paths:
        ap.print_usage(sys.stderr)
        print("outfence: error: no input (give a path or -)", file=sys.stderr)
        return 2

    if a.sanitize:
        if len(a.paths) != 1:
            print("outfence: error: --sanitize takes exactly one input", file=sys.stderr)
            return 2
        p = a.paths[0]
        try:
            text = sys.stdin.read() if p == "-" else open(p, encoding="utf-8", errors="replace").read()
        except OSError as e:
            print("outfence: error: %s" % e, file=sys.stderr)
            return 2
        sys.stdout.write(sanitize(text, a.allow_host))
        return 0

    findings = []
    try:
        for p in collect(a.paths):
            for label, text in load_units(p, a.all_roles):
                findings.extend(scan_text(text, label, a.allow_host))
    except (OSError, ValueError) as e:
        print("outfence: error: %s" % e, file=sys.stderr)
        return 2
    findings = [f for f in findings if SEV_RANK[f["severity"]] >= SEV_RANK[a.min_severity]]

    if a.json:
        print(json.dumps({"tool": "outfence", "version": __version__, "findings": findings}, indent=2))
    else:
        if not findings:
            print("outfence: no findings")
        for f in findings:
            print("%-8s %s %s:%d  %s" % (f["severity"].upper(), f["rule"], f["source"], f["line"], f["title"]))
            print("         %s" % f["detail"])
        if findings:
            counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
            print("\n%d finding(s): %s" % (len(findings), ", ".join("%d %s" % (n, s) for s, n in reversed(list(counts.items())) if n)))
    if a.fail_on != "none" and any(SEV_RANK[f["severity"]] >= SEV_RANK[a.fail_on] for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
