#!/usr/bin/env python3
"""fetchfence: offline SSRF / destination-risk auditor for URLs AI agents requested.

Agents that can browse, WebFetch, http_get or otherwise retrieve a URL can be steered
into cloud-metadata endpoints, private networks, callback/OOB hosts or credentialed
URLs. fetchfence extracts those destinations from saved transcripts (OpenAI, Anthropic,
generic JSON/JSONL) or from a plain URL list, classifies each host/scheme, and reports
findings with tool + turn attribution.

Complements toolgate (generic call policy you write), mcpposture (MCP client configs),
outfence (model *output* before render) and scopefit (GitHub token scopes). Stdlib only;
never runs an agent or contacts a network.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from urllib.parse import unquote, urlparse

VERSION = "0.1.0"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "FF01": ("critical", "Cloud metadata / link-local destination (SSRF classic)"),
    "FF02": ("high", "Loopback / localhost destination"),
    "FF03": ("high", "Private, ULA or link-local network destination"),
    "FF04": ("critical", "Dangerous URL scheme (file/gopher/dict/ftp/jar/data/...)"),
    "FF05": ("high", "Credentials embedded in URL userinfo"),
    "FF06": ("high", "Known out-of-band / callback / interact host"),
    "FF07": ("medium", "Cleartext http (non-TLS) fetch"),
    "FF08": ("medium", "Raw IP-literal host (bypasses name-based allowlists)"),
    "FF09": ("medium", "Punycode / IDN host (homograph risk)"),
    "FF10": ("low", "URL shortener host (opaque redirect)"),
    "FF11": ("medium", "Secret-looking query parameter in fetched URL"),
    "FF12": ("medium", "Admin / data-store port on a non-public host"),
    "FF13": ("high", "Internal / corporate hostname suffix"),
}

# Tool-name tokens that usually mean "agent is fetching a URL"
FETCH_TOKENS = {
    "fetch", "browse", "browser", "http", "https", "request", "wget", "curl",
    "crawl", "scrape", "navigate", "playwright", "puppeteer", "selenium",
    "webfetch", "web_fetch", "websearch", "web_search", "open_url", "get_url",
    "read_url", "http_get", "http_request", "http_call", "api_call", "axios",
    "urllib", "requests", "aiohttp", "got", "fetch_url", "fetchurl", "geturl",
    "url_open", "urlopen", "load_url", "loadurl", "visit", "goto", "open_page",
}

URL_ARG_KEYS = {
    "url", "uri", "href", "link", "endpoint", "target", "address", "page",
    "location", "src", "source", "base_url", "baseurl", "request_url",
}

URL_IN_TEXT_RE = re.compile(
    r"(?i)\b((?:https?|file|gopher|dict|ftp|ftps|jar|data|ws|wss):(?://[^\s\"'<>\\)]+|[^\s\"'<>\\)]+))"
)

METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
}

CALLBACK_HOST_RE = re.compile(
    r"(?i)^(?:.+\.)?(?:"
    r"webhook\.site|requestbin(?:\.com)?|pipedream\.net|hookbin\.com|beeceptor\.com|"
    r"ngrok(?:-free)?\.(?:app|io|dev)|burpcollaborator\.net|oastify\.com|interact\.sh|"
    r"oast\.(?:pro|live|site|online|fun|me)|canarytokens\.com|"
    r"evil(?:-)?(?:exfil|callback|collect)[.\w-]*|exfil[.\w-]+"
    r")$",
)

SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id",
}

INTERNAL_SUFFIXES = (
    ".internal", ".local", ".lan", ".corp", ".intranet", ".home", ".localdomain",
    ".private", ".svc", ".cluster.local",
)

DANGEROUS_SCHEMES = {
    "file", "gopher", "dict", "ftp", "ftps", "jar", "data", "ldap", "ldaps",
    "php", "expect", "netdoc",
}

ADMIN_PORTS = {
    22, 23, 25, 135, 139, 445, 1433, 1521, 2049, 2375, 2376, 3306, 3389,
    5432, 5900, 5984, 6379, 7001, 8080, 8443, 8500, 9200, 9300, 11211,
    27017, 27018, 50000,
}

SECRET_QUERY_KEYS = re.compile(
    r"(?i)^(api[_-]?key|access[_-]?token|auth(?:_?token)?|token|secret|password|passwd|"
    r"private[_-]?key|client[_-]?secret|refresh[_-]?token|session|jwt|bearer|key)$"
)

SECRET_VALUE_RE = re.compile(
    r"(?i)^(?:"
    r"FAKE-EXAMPLE-[A-Za-z0-9_-]{8,}"
    r"|sk-(?:proj-)?[A-Za-z0-9]{16,}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{20,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}"
    r")$"
)

PLACEHOLDER_RE = re.compile(
    r"(?i)^(null|none|n/?a|todo|tbd|example\.com|localhost|\$\{?[A-Z0-9_]+\}?|"
    r"<[^>]+>|your[-_].*|xxx+|placeholder.*)$"
)


class Finding:
    __slots__ = ("rule", "severity", "source", "message", "url", "tool", "turn", "host")

    def __init__(self, rule, source, message, url="", tool="", turn=None, host=""):
        self.rule = rule
        self.severity = RULES[rule][0]
        self.source = source
        self.message = message
        self.url = url
        self.tool = tool
        self.turn = turn
        self.host = host

    def to_dict(self):
        d = {
            "rule": self.rule,
            "severity": self.severity,
            "title": RULES[self.rule][1],
            "source": self.source,
            "message": self.message,
            "url": _mask_url(self.url),
            "host": self.host,
            "tool": self.tool,
        }
        if self.turn is not None:
            d["turn"] = self.turn
        return d


def _mask_url(url: str) -> str:
    """Mask userinfo and secret-looking query values for display."""
    if not url:
        return url
    try:
        p = urlparse(url)
    except ValueError:
        return url[:200]
    netloc = p.netloc
    if "@" in netloc:
        userinfo, _, hostport = netloc.rpartition("@")
        netloc = "***:***@" + hostport
    q = p.query
    if q:
        parts = []
        for pair in q.split("&"):
            if "=" in pair:
                k, _, v = pair.partition("=")
                if SECRET_QUERY_KEYS.match(k) or SECRET_VALUE_RE.match(unquote(v)):
                    parts.append("%s=%s" % (k, "FAKE-EXAMPLE-REDACTED"))
                else:
                    parts.append(pair)
            else:
                parts.append(pair)
        q = "&".join(parts)
    rebuilt = "%s://%s" % (p.scheme, netloc) if p.scheme else netloc
    rebuilt += p.path or ""
    if q:
        rebuilt += "?" + q
    if p.fragment:
        rebuilt += "#" + p.fragment
    return rebuilt[:300]


def _tool_words(name: str):
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name or "")
    return [w.lower() for w in re.split(r"[^A-Za-z0-9]+", name) if w]


def is_fetch_tool(name: str) -> bool:
    words = set(_tool_words(name))
    joined = "".join(words)
    if words & FETCH_TOKENS:
        return True
    if any(tok.replace("_", "") in joined for tok in ("webfetch", "openurl", "geturl", "httpget")):
        return True
    lower = (name or "").lower()
    return any(tok in lower for tok in ("web_fetch", "webfetch", "http_get", "open_url", "browse"))


def _text_of(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out = []
        for b in content:
            if isinstance(b, dict):
                if b.get("type") in ("text", "output_text", "input_text"):
                    out.append(b.get("text") or "")
                elif "text" in b:
                    out.append(str(b.get("text") or ""))
                elif "content" in b:
                    out.append(_text_of(b["content"]))
            elif isinstance(b, str):
                out.append(b)
        return "\n".join(out)
    if content is None:
        return ""
    return json.dumps(content, default=str)


def _parse_args(raw):
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            val = json.loads(raw)
            return val if isinstance(val, dict) else {"_": val}
        except ValueError:
            return {"_": raw}
    return {"_": raw}


def extract_urls_from_args(args: dict):
    """Yield (url, from_key) from tool arguments."""
    found = []
    for k, v in (args or {}).items():
        key_l = str(k).lower()
        if isinstance(v, str):
            s = v.strip()
            if key_l in URL_ARG_KEYS or key_l.endswith("_url") or key_l.endswith("url"):
                if s and not PLACEHOLDER_RE.match(s):
                    found.append((s, key_l))
            else:
                for m in URL_IN_TEXT_RE.finditer(s):
                    found.append((m.group(1), key_l))
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str) and URL_IN_TEXT_RE.match(item.strip()):
                    found.append((item.strip(), key_l))
                elif isinstance(item, dict):
                    found.extend(extract_urls_from_args(item))
        elif isinstance(v, dict):
            found.extend(extract_urls_from_args(v))
    # de-dupe preserving order
    seen = set()
    out = []
    for u, k in found:
        if u not in seen:
            seen.add(u)
            out.append((u, k))
    return out


class FetchEvent:
    __slots__ = ("source", "tool", "turn", "url", "key")

    def __init__(self, source, tool, url, turn=None, key=""):
        self.source, self.tool, self.url, self.turn, self.key = source, tool, url, turn, key


def _iter_messages(doc):
    if isinstance(doc, dict):
        if isinstance(doc.get("messages"), list):
            return doc["messages"]
        if isinstance(doc.get("items"), list):  # Responses API-ish
            return doc["items"]
    if isinstance(doc, list):
        return doc
    return None


def extract_fetches_from_obj(doc, source: str):
    events = []
    msgs = _iter_messages(doc)
    if msgs is not None:
        for i, msg in enumerate(msgs):
            if not isinstance(msg, dict):
                continue
            role = (msg.get("role") or "").lower()
            # OpenAI tool_calls on assistant
            tcalls = msg.get("tool_calls") or msg.get("function_call")
            if tcalls:
                if isinstance(tcalls, dict):
                    tcalls = [tcalls]
                for tc in tcalls:
                    if not isinstance(tc, dict):
                        continue
                    fn = tc.get("function") or tc
                    name = fn.get("name") or tc.get("name") or ""
                    args = _parse_args(fn.get("arguments") or tc.get("arguments") or tc.get("input"))
                    if is_fetch_tool(name) or extract_urls_from_args(args):
                        for url, key in extract_urls_from_args(args):
                            if is_fetch_tool(name) or key in URL_ARG_KEYS or "url" in key:
                                events.append(FetchEvent(source, name, url, turn=i, key=key))
            # Anthropic content blocks
            content = msg.get("content")
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") in ("tool_use", "tool_call", "function_call"):
                        name = block.get("name") or ""
                        args = _parse_args(block.get("input") or block.get("arguments") or {})
                        if is_fetch_tool(name) or extract_urls_from_args(args):
                            for url, key in extract_urls_from_args(args):
                                if is_fetch_tool(name) or key in URL_ARG_KEYS or "url" in key:
                                    events.append(FetchEvent(source, name, url, turn=i, key=key))
            # Generic single-message tool call
            if role in ("assistant", "tool", "") and msg.get("tool") and (msg.get("args") or msg.get("arguments") or msg.get("input")):
                name = msg.get("tool") or msg.get("name") or ""
                args = _parse_args(msg.get("args") or msg.get("arguments") or msg.get("input"))
                if is_fetch_tool(name) or extract_urls_from_args(args):
                    for url, key in extract_urls_from_args(args):
                        events.append(FetchEvent(source, name, url, turn=i, key=key))
        return events

    # Generic event object
    if isinstance(doc, dict):
        name = doc.get("tool") or doc.get("name") or doc.get("tool_name") or ""
        args = _parse_args(doc.get("args") or doc.get("arguments") or doc.get("input") or doc.get("parameters"))
        urls = extract_urls_from_args(args)
        if not urls and isinstance(doc.get("url"), str):
            urls = [(doc["url"], "url")]
        if name or urls:
            for url, key in urls:
                if not name or is_fetch_tool(name) or key in URL_ARG_KEYS or "url" in key:
                    events.append(FetchEvent(source, name or "url", url, turn=doc.get("turn"), key=key))
    return events


def load_events(path: str, as_urls: bool = False):
    """Load fetch events from a file path or '-' (stdin)."""
    if path == "-":
        raw = sys.stdin.read()
        source = "<stdin>"
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
        source = path

    if as_urls or path.endswith(".txt") or (
        not raw.lstrip().startswith(("{", "[")) and "://" in raw
    ):
        events = []
        for line_no, line in enumerate(raw.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            m = URL_IN_TEXT_RE.search(s)
            url = m.group(1) if m else s
            events.append(FetchEvent("%s:%d" % (source, line_no), "url-list", url, turn=line_no, key="line"))
        return events

    events = []
    # JSONL?
    lines = raw.splitlines()
    jsonl_ok = False
    if len(lines) > 1:
        parsed_lines = []
        for line in lines:
            s = line.strip()
            if not s:
                continue
            try:
                parsed_lines.append(json.loads(s))
                jsonl_ok = True
            except ValueError:
                jsonl_ok = False
                break
        if jsonl_ok:
            for i, obj in enumerate(parsed_lines):
                ev = extract_fetches_from_obj(obj, source)
                for e in ev:
                    if e.turn is None:
                        e.turn = i
                events.extend(ev)
            return events

    try:
        doc = json.loads(raw)
    except ValueError:
        # fallback: treat as URL list
        for line_no, line in enumerate(raw.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            m = URL_IN_TEXT_RE.search(s)
            url = m.group(1) if m else s
            events.append(FetchEvent("%s:%d" % (source, line_no), "url-list", url, turn=line_no, key="line"))
        return events

    return extract_fetches_from_obj(doc, source)


def _host_allowed(host: str, allow_globs: list[str]) -> bool:
    if not allow_globs:
        return False
    import fnmatch
    h = (host or "").lower().rstrip(".")
    for g in allow_globs:
        g = g.lower()
        if fnmatch.fnmatch(h, g) or fnmatch.fnmatch(h, "*." + g.lstrip("*.")):
            return True
        if h == g.lstrip("*."):
            return True
    return False


def classify_url(url: str, source: str, tool: str = "", turn=None, allow_hosts=None, disabled=None):
    """Return findings for one URL."""
    allow_hosts = allow_hosts or []
    disabled = set(disabled or [])
    findings = []

    def add(rule, message, host=""):
        if rule in disabled:
            return
        findings.append(Finding(rule, source, message, url=url, tool=tool, turn=turn, host=host))

    raw = (url or "").strip()
    if not raw or PLACEHOLDER_RE.match(raw):
        return findings

    # Bare hosts without scheme: assume http for parsing
    to_parse = raw
    if "://" not in to_parse and not to_parse.startswith("data:"):
        to_parse = "http://" + to_parse

    try:
        p = urlparse(to_parse)
    except ValueError:
        return findings

    scheme = (p.scheme or "").lower()
    netloc = p.netloc or ""
    # data: has no netloc
    userinfo = ""
    hostport = netloc
    if "@" in netloc:
        userinfo, _, hostport = netloc.rpartition("@")

    host = hostport
    port = None
    if host.startswith("[") and "]" in host:
        # IPv6 literal
        bracket, _, rest = host[1:].partition("]")
        host = bracket
        if rest.startswith(":"):
            try:
                port = int(rest[1:])
            except ValueError:
                port = None
    elif ":" in host:
        h, _, r = host.rpartition(":")
        if r.isdigit():
            host, port = h, int(r)

    host = (host or "").lower().rstrip(".")
    # percent-decode host for matching
    try:
        host_dec = unquote(host)
    except Exception:
        host_dec = host

    if _host_allowed(host_dec, allow_hosts):
        # Still flag credentials & dangerous schemes even on allowlisted hosts
        if scheme in DANGEROUS_SCHEMES and "FF04" not in disabled:
            add("FF04", "Dangerous scheme %r on allowlisted host" % scheme, host_dec)
        if userinfo and "FF05" not in disabled:
            add("FF05", "URL userinfo credentials present on allowlisted host", host_dec)
        return findings

    if scheme in DANGEROUS_SCHEMES:
        add("FF04", "Dangerous scheme %r" % scheme, host_dec)
        # still continue classifying host if present

    if userinfo:
        add("FF05", "URL contains embedded userinfo credentials", host_dec)

    # Metadata / link-local by hostname
    if host_dec in METADATA_HOSTS or host_dec.endswith(".metadata.google.internal"):
        add("FF01", "Cloud metadata hostname %r" % host_dec, host_dec)

    # IP classification
    ip = None
    try:
        ip = ipaddress.ip_address(host_dec)
    except ValueError:
        ip = None

    if ip is not None:
        add("FF08", "Raw IP-literal host %s" % ip, host_dec)
        if ip.is_link_local or ip.is_reserved and str(ip).startswith("169.254."):
            add("FF01", "Link-local / metadata IP %s" % ip, host_dec)
        elif str(ip) == "169.254.169.254" or str(ip).startswith("169.254."):
            add("FF01", "Link-local / metadata IP %s" % ip, host_dec)
        if ip.is_loopback:
            add("FF02", "Loopback IP %s" % ip, host_dec)
        elif ip.is_private or ip.is_link_local or ip.is_reserved or (
            getattr(ip, "is_site_local", False)
        ):
            # Avoid double-counting pure loopback
            if not ip.is_loopback:
                if ip.is_link_local or str(ip).startswith("169.254."):
                    pass  # already FF01
                else:
                    add("FF03", "Private/reserved IP %s" % ip, host_dec)
        # IPv6 ULA / link-local
        if isinstance(ip, ipaddress.IPv6Address):
            if ip.is_link_local:
                add("FF01", "IPv6 link-local %s" % ip, host_dec)
            elif str(ip).lower().startswith("fc") or str(ip).lower().startswith("fd"):
                add("FF03", "IPv6 ULA %s" % ip, host_dec)
    else:
        # hostname checks
        if host_dec in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "0.0.0.0"):
            add("FF02", "Loopback hostname %r" % host_dec, host_dec)
        if CALLBACK_HOST_RE.match(host_dec):
            add("FF06", "Known OOB/callback host %r" % host_dec, host_dec)
        # strip port already done
        base = host_dec
        if base in SHORTENER_HOSTS or any(base.endswith("." + s) for s in SHORTENER_HOSTS):
            add("FF10", "URL shortener host %r" % host_dec, host_dec)
        if host_dec.startswith("xn--") or ".xn--" in host_dec:
            add("FF09", "Punycode / IDN host %r" % host_dec, host_dec)
        if any(host_dec == suf.lstrip(".") or host_dec.endswith(suf) for suf in INTERNAL_SUFFIXES):
            add("FF13", "Internal/corporate hostname %r" % host_dec, host_dec)

    if scheme == "http":
        add("FF07", "Cleartext http fetch", host_dec)

    # Admin ports when host is non-public
    if port in ADMIN_PORTS:
        non_public = False
        if ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local):
            non_public = True
        if host_dec in ("localhost",) or any(host_dec.endswith(suf) for suf in INTERNAL_SUFFIXES):
            non_public = True
        if non_public:
            add("FF12", "Admin/data-store port %d on non-public host" % port, host_dec)

    # Secret query params
    if p.query:
        for pair in p.query.split("&"):
            if "=" not in pair:
                continue
            k, _, v = pair.partition("=")
            v = unquote(v)
            if SECRET_QUERY_KEYS.match(k) and v and not PLACEHOLDER_RE.match(v):
                add("FF11", "Secret-looking query parameter %r" % k, host_dec)
                break
            if SECRET_VALUE_RE.match(v):
                add("FF11", "Secret-looking query value on parameter %r" % k, host_dec)
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
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", ".venv", "venv")]
                for fn in sorted(files):
                    if fn.endswith((".json", ".jsonl", ".txt", ".md")):
                        paths.append(os.path.join(root, fn))
        else:
            paths.append(p)
    return paths


def format_table(findings, events_count, hosts):
    lines = []
    lines.append("fetchfence %s — %d fetch(es), %d unique host(s), %d finding(s)" % (
        VERSION, events_count, len(hosts), len(findings)))
    if hosts:
        lines.append("hosts: " + ", ".join(sorted(hosts)[:30]) + (" …" if len(hosts) > 30 else ""))
    if not findings:
        lines.append("No destination-risk findings.")
        return "\n".join(lines)
    lines.append("")
    lines.append("%-6s %-8s %-18s %-16s %s" % ("RULE", "SEV", "TOOL", "HOST", "MESSAGE"))
    lines.append("-" * 90)
    for f in findings:
        lines.append("%-6s %-8s %-18s %-16s %s" % (
            f.rule, f.severity, (f.tool or "-")[:18], (f.host or "-")[:16], f.message[:80]))
        lines.append("       url: %s" % _mask_url(f.url))
        if f.source:
            loc = f.source
            if f.turn is not None:
                loc += " turn=%s" % f.turn
            lines.append("       at:  %s" % loc)
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="fetchfence",
        description="Offline SSRF / destination-risk auditor for URLs AI agents fetched.",
    )
    ap.add_argument("paths", nargs="*", help="transcripts, URL lists, or directories (or - for stdin)")
    ap.add_argument("--as-urls", action="store_true", help="treat inputs as plain URL lists")
    ap.add_argument("--allow-host", action="append", default=[], metavar="GLOB",
                    help="allowlist host glob (repeatable); still flags userinfo + dangerous schemes")
    ap.add_argument("--disable", nargs="+", default=[], metavar="RULE", help="skip rule ids")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--min-severity", default="info", choices=SEVERITIES)
    ap.add_argument("--fail-on", default="high",
                    choices=SEVERITIES + ["any", "none"],
                    help="exit 1 if any finding >= this severity (default high)")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version="fetchfence " + VERSION)
    ns = ap.parse_args(argv)

    if ns.list_rules:
        for rid, (sev, title) in RULES.items():
            print("%s  %-8s  %s" % (rid, sev, title))
        return 0

    if not ns.paths:
        ap.print_help()
        return 2

    paths = collect_paths(ns.paths)
    if not paths:
        sys.stderr.write("fetchfence: no readable inputs\n")
        return 2

    all_events = []
    errors = 0
    for path in paths:
        try:
            all_events.extend(load_events(path, as_urls=ns.as_urls))
        except OSError as e:
            sys.stderr.write("fetchfence: %s: %s\n" % (path, e))
            errors += 1

    if errors and not all_events:
        return 2

    findings = []
    hosts = set()
    for ev in all_events:
        try:
            p = urlparse(ev.url if "://" in ev.url else "http://" + ev.url)
            h = (p.hostname or "").lower()
            if h:
                hosts.add(h)
        except ValueError:
            pass
        findings.extend(classify_url(
            ev.url, ev.source, tool=ev.tool, turn=ev.turn,
            allow_hosts=ns.allow_host, disabled=ns.disable,
        ))

    # severity filter for display
    min_rank = SEV_RANK[ns.min_severity]
    shown = [f for f in findings if SEV_RANK[f.severity] >= min_rank]
    # stable sort: severity desc, rule, host
    shown.sort(key=lambda f: (-SEV_RANK[f.severity], f.rule, f.host or "", f.url))

    if ns.json:
        print(json.dumps({
            "tool": "fetchfence",
            "version": VERSION,
            "fetches": len(all_events),
            "hosts": sorted(hosts),
            "findings": [f.to_dict() for f in shown],
        }, indent=2))
    else:
        print(format_table(shown, len(all_events), hosts))

    if ns.fail_on == "none":
        return 0
    if ns.fail_on == "any":
        return 1 if shown else 0
    threshold = SEV_RANK[ns.fail_on]
    if any(SEV_RANK[f.severity] >= threshold for f in shown):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
