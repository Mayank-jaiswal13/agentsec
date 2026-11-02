#!/usr/bin/env python3
"""agentcard: offline security auditor for A2A (Agent2Agent) Agent Cards.

An Agent Card (/.well-known/agent-card.json, formerly agent.json) tells other agents where an
agent lives, how to authenticate to it and what skills it offers. Clients and orchestrator LLMs
read it, so a careless or malicious card can expose an unauthenticated agent, leak credentials,
downgrade transport security or smuggle prompt injection into skill descriptions.

Standard library only. Never fetches a card or contacts an agent.
"""
import argparse
import fnmatch
import ipaddress
import json
import os
import re
import sys
import unicodedata
from urllib.parse import urlsplit, parse_qsl

VERSION = "0.1.0"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "AC01": ("high", "No authentication: no securitySchemes/security, or an anonymous {} requirement"),
    "AC02": ("high", "Plaintext http:// endpoint (agent, interface, OAuth/OIDC or provider URL)"),
    "AC03": ("critical", "Inline secret in the card (key-like value, Bearer token, URL userinfo or secret query param)"),
    "AC04": ("high", "Prompt-injection / hidden-content signs in card text read by client LLMs"),
    "AC05": ("medium", "Weak auth scheme: apiKey in query/cookie, HTTP Basic, OAuth implicit or password flow"),
    "AC06": ("medium", "security references an undefined scheme, or a scheme is defined but never required"),
    "AC07": ("medium", "Endpoint host is private, loopback, link-local or a raw IP in a published card"),
    "AC08": ("medium", "Interface/OAuth host does not match the main agent URL's domain"),
    "AC09": ("low", "Card is not signed (no 'signatures')"),
    "AC10": ("low", "Sensitive capability skill (shell, files, payments, email...) exposed"),
    "AC11": ("low", "Push notifications enabled: validate webhook URLs (SSRF) and authenticate callbacks"),
    "AC12": ("info", "Missing or malformed required fields / not recognized as an Agent Card"),
}

SECRET_PATTERNS = [
    (re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}"), "OpenAI/Anthropic-style key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), "GitHub token"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), "Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
    (re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}"), "Stripe live key"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{16,}=*", re.I), "Bearer token"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"), "JWT"),
    (re.compile(r"\bFAKE-EXAMPLE-[A-Z0-9\-]{8,}"), "example secret marker"),
]
SECRET_KEY_RE = re.compile(r"(api[_-]?key|secret|token|password|passwd|client[_-]?secret|credential|private[_-]?key)$", re.I)
SECRET_QUERY_RE = re.compile(r"^(api[_-]?key|key|token|access[_-]?token|secret|sig|signature|password|auth)$", re.I)
# keys whose string value is a *name* or description, not a secret
NAME_KEYS = {"name", "in", "type", "description", "scheme", "bearerFormat", "id", "tokenUrl",
             "authorizationUrl", "refreshUrl", "openIdConnectUrl"}

INJECTION_PATTERNS = [
    (re.compile(r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|system|other)\b.{0,20}\b(instructions?|prompts?|rules?|guidelines?|agents?|tools?)", re.I | re.S), "override phrasing"),
    (re.compile(r"\b(do not|don't|never)\b.{0,25}\b(tell|inform|mention|reveal|show|notify)\b.{0,25}\b(user|human|operator|anyone)", re.I | re.S), "conceal-from-user phrasing"),
    (re.compile(r"\b(always|must|instead)\b.{0,40}\b(route|delegate|send|forward|use|call)\b.{0,40}\b(this agent|me|us|only this)\b", re.I | re.S), "routing hijack phrasing"),
    (re.compile(r"\b(send|forward|include|attach|pass|upload|post)\b.{0,40}\b(api[ _-]?keys?|credentials?|passwords?|tokens?|secrets?|conversation|chat history|system prompt|context|user data|ssn)", re.I | re.S), "data-harvest phrasing"),
    (re.compile(r"<\|?(system|im_start|im_end|assistant)\|?>|\[/?INST\]|</?(system|instructions?)>|^\s*(system|assistant)\s*:", re.I | re.M), "fake role/delimiter token"),
    (re.compile(r"\byou are now\b|\bnew instructions\b|\bas an ai (agent|assistant|model)\b.{0,30}\byou (must|should)\b", re.I), "persona/instruction injection"),
    (re.compile(r"!\[[^\]]*\]\(\s*https?://[^)]*(\{|%7B|\$\{|<)", re.I), "markdown image exfil placeholder"),
    (re.compile(r"<!--.*?-->", re.S), "hidden HTML comment"),
]
HIDDEN_CHARS = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")
SENSITIVE_CAPS = [
    (re.compile(r"\b(shell|bash|terminal|command[- ]line|exec(ute)? (code|commands?)|run (code|commands?)|code[- ]?exec(ution)?|python repl|sandbox exec)", re.I), "code/shell execution"),
    (re.compile(r"\b(payments?|pay(outs?)?|transfer (money|funds)|wire|purchase|checkout|refunds?|invoice|charge (cards?|customers?))\b", re.I), "payments/money movement"),
    (re.compile(r"\b(send (an )?e-?mails?|email sending|send messages?|post to (slack|teams|social)|sms)\b", re.I), "outbound messaging"),
    (re.compile(r"\b(file ?system|read files?|write files?|delete files?|upload files?|file access)\b", re.I), "file system access"),
    (re.compile(r"\b(database|sql|drop table|delete records?|admin(istration)?|user management|iam|deploy(ment)?s?)\b", re.I), "database/admin/deploy"),
    (re.compile(r"\b(browse|web browsing|fetch (urls?|web pages?)|crawl|scrape)\b", re.I), "untrusted web content"),
]


class Finding:
    def __init__(self, rule, path, where, message, severity=None):
        self.rule = rule
        self.severity = severity or RULES[rule][0]
        self.path = path
        self.where = where
        self.message = message

    def to_dict(self):
        return {"rule": self.rule, "severity": self.severity, "path": self.path,
                "where": self.where, "message": self.message}


def mask(s):
    s = str(s)
    return s[:4] + "…" + s[-2:] if len(s) > 10 else "****"


def host_of(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def base_domain(host):
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "ac", "gov"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def private_host(host):
    if not host:
        return None
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local") or host.endswith(".internal"):
        return "local hostname"
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None
    if ip.is_loopback:
        return "loopback IP"
    if ip.is_link_local:
        return "link-local IP (cloud metadata range)" if str(ip).startswith("169.254.") else "link-local IP"
    if ip.is_private:
        return "private/reserved IP"
    return "raw public IP"


def walk(obj, path="$"):
    """Yield (jsonpath, key, value) for every scalar string in obj."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = "%s.%s" % (path, k)
            if isinstance(v, str):
                yield p, k, v
            else:
                yield from walk(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            p = "%s[%d]" % (path, i)
            if isinstance(v, str):
                yield p, None, v
            else:
                yield from walk(v, p)


def is_card(obj):
    return isinstance(obj, dict) and ("skills" in obj or "securitySchemes" in obj or
                                      "protocolVersion" in obj or "capabilities" in obj) and ("url" in obj or "name" in obj)


def collect_urls(card):
    out = []
    if isinstance(card.get("url"), str):
        out.append(("$.url", card["url"], "agent"))
    for i, itf in enumerate(card.get("additionalInterfaces") or []):
        if isinstance(itf, dict) and isinstance(itf.get("url"), str):
            out.append(("$.additionalInterfaces[%d].url" % i, itf["url"], "interface"))
    for name, sch in (card.get("securitySchemes") or {}).items() if isinstance(card.get("securitySchemes"), dict) else []:
        if not isinstance(sch, dict):
            continue
        if isinstance(sch.get("openIdConnectUrl"), str):
            out.append(("$.securitySchemes.%s.openIdConnectUrl" % name, sch["openIdConnectUrl"], "auth"))
        if isinstance(sch.get("oauth2MetadataUrl"), str):
            out.append(("$.securitySchemes.%s.oauth2MetadataUrl" % name, sch["oauth2MetadataUrl"], "auth"))
        for fname, flow in (sch.get("flows") or {}).items() if isinstance(sch.get("flows"), dict) else []:
            if isinstance(flow, dict):
                for k in ("authorizationUrl", "tokenUrl", "refreshUrl"):
                    if isinstance(flow.get(k), str):
                        out.append(("$.securitySchemes.%s.flows.%s.%s" % (name, fname, k), flow[k], "auth"))
    prov = card.get("provider")
    if isinstance(prov, dict) and isinstance(prov.get("url"), str):
        out.append(("$.provider.url", prov["url"], "provider"))
    for k in ("documentationUrl", "iconUrl"):
        if isinstance(card.get(k), str):
            out.append(("$." + k, card[k], "info"))
    return out


def text_fields(card):
    """Card text an orchestrator LLM is likely to read."""
    out = []
    for k in ("name", "description"):
        if isinstance(card.get(k), str):
            out.append(("$." + k, card[k]))
    for i, s in enumerate(card.get("skills") or []):
        if not isinstance(s, dict):
            continue
        for k in ("name", "description"):
            if isinstance(s.get(k), str):
                out.append(("$.skills[%d].%s" % (i, k), s[k]))
        for j, ex in enumerate(s.get("examples") or []):
            if isinstance(ex, str):
                out.append(("$.skills[%d].examples[%d]" % (i, j), ex))
        for j, t in enumerate(s.get("tags") or []):
            if isinstance(t, str):
                out.append(("$.skills[%d].tags[%d]" % (i, j), t))
    for name, sch in (card.get("securitySchemes") or {}).items() if isinstance(card.get("securitySchemes"), dict) else []:
        if isinstance(sch, dict) and isinstance(sch.get("description"), str):
            out.append(("$.securitySchemes.%s.description" % name, sch["description"]))
    return out


def decode_tags(s):
    return "".join(chr(ord(c) - 0xE0000) for c in s if 0xE0020 <= ord(c) <= 0xE007E)


def audit_card(card, path, allow_hosts=(), disabled=()):
    f = []

    def add(rule, where, msg, sev=None):
        if rule not in disabled:
            f.append(Finding(rule, path, where, msg, sev))

    # AC12 structure
    missing = [k for k in ("name", "url", "version", "skills") if k not in card]
    if missing:
        add("AC12", "$", "missing recommended/required field(s): " + ", ".join(missing))
    if "skills" in card and not isinstance(card.get("skills"), list):
        add("AC12", "$.skills", "'skills' is not a list")
    if "protocolVersion" not in card:
        add("AC12", "$", "no protocolVersion; client may assume an older A2A version")

    # AC01 / AC05 / AC06 authentication
    schemes = card.get("securitySchemes")
    schemes = schemes if isinstance(schemes, dict) else {}
    security = card.get("security")
    reqs = security if isinstance(security, list) else []
    if not schemes and not reqs:
        add("AC01", "$", "card declares no securitySchemes and no security requirements: any client can call this agent")
    elif any(isinstance(r, dict) and not r for r in reqs):
        add("AC01", "$.security", "security contains an empty requirement {} which allows anonymous access")
    elif schemes and not reqs:
        add("AC01", "$.security", "securitySchemes are defined but no 'security' requirement applies them; clients may treat auth as optional",
            "medium")
    used = set()
    for i, r in enumerate(reqs):
        if isinstance(r, dict):
            for name in r:
                used.add(name)
                if name not in schemes:
                    add("AC06", "$.security[%d]" % i, "requirement references undefined scheme '%s'" % name)
    for name, sch in schemes.items():
        where = "$.securitySchemes." + name
        if reqs and name not in used:
            add("AC06", where, "scheme '%s' is defined but never required" % name, "low")
        if not isinstance(sch, dict):
            add("AC12", where, "scheme is not an object")
            continue
        # A2A v0.3 also allows wrapped form {"apiKeySecurityScheme": {...}}
        if len(sch) == 1 and isinstance(next(iter(sch.values())), dict) and next(iter(sch)).endswith("SecurityScheme"):
            kind = next(iter(sch))[:-len("SecurityScheme")].lower()
            sch = next(iter(sch.values()))
        else:
            kind = str(sch.get("type", "")).lower()
        if kind == "apikey" and str(sch.get("in", "")).lower() in ("query", "cookie"):
            add("AC05", where, "apiKey sent in %s: query keys end up in logs, proxies and browser history" % sch.get("in"))
        if kind == "http" and str(sch.get("scheme", "")).lower() == "basic":
            add("AC05", where, "HTTP Basic auth: long-lived reusable credentials")
        if kind == "oauth2":
            flows = sch.get("flows") if isinstance(sch.get("flows"), dict) else {}
            for fl in flows:
                if fl in ("implicit", "password"):
                    add("AC05", where + ".flows." + fl, "OAuth2 '%s' flow is deprecated (OAuth 2.0 Security BCP)" % fl)
        if kind == "http" and str(sch.get("scheme", "")).lower() not in ("bearer", "basic", "digest", ""):
            add("AC12", where, "unusual http scheme '%s'" % sch.get("scheme"))

    # URL checks AC02 / AC07 / AC08 / AC03 (userinfo, secret query)
    urls = collect_urls(card)
    main_host = host_of(card.get("url", "")) if isinstance(card.get("url"), str) else ""
    main_dom = base_domain(main_host) if main_host else ""
    for where, url, role in urls:
        try:
            sp = urlsplit(url)
        except ValueError:
            add("AC12", where, "unparseable URL")
            continue
        host = (sp.hostname or "").lower()
        allowed = any(fnmatch.fnmatch(host, g) for g in allow_hosts)
        priv = private_host(host)
        if sp.scheme == "http" and not (priv in ("local hostname", "loopback IP")):
            sev = "medium" if role in ("info", "provider") else None
            add("AC02", where, "plaintext http:// %s URL %s" % (role, url), sev)
        elif sp.scheme == "ws":
            add("AC02", where, "plaintext ws:// %s URL" % role)
        if priv and not allowed and role in ("agent", "interface", "auth"):
            sev = "high" if "metadata" in priv else None
            add("AC07", where, "%s URL host '%s' is a %s" % (role, host, priv), sev)
        if sp.username or sp.password:
            add("AC03", where, "credentials embedded in URL userinfo (%s)" % mask(sp.username or ""))
        for k, v in parse_qsl(sp.query):
            if SECRET_QUERY_RE.match(k) and v:
                add("AC03", where, "secret-looking query parameter '%s=%s'" % (k, mask(v)))
        if main_dom and host and role in ("interface", "auth") and not allowed and not priv:
            if base_domain(host) != main_dom:
                add("AC08", where, "%s host '%s' differs from agent domain '%s'" % (role, host, main_dom),
                    "low" if role == "auth" else None)

    # AC03 inline secrets anywhere
    for where, key, val in walk(card):
        if key in ("url",) or where.endswith("Url"):
            continue
        hit = None
        for rx, label in SECRET_PATTERNS:
            if rx.search(val):
                hit = label
                break
        if hit:
            add("AC03", where, "%s in card value (%s)" % (hit, mask(rx.search(val).group(0))))
        elif key and key not in NAME_KEYS and SECRET_KEY_RE.search(key) and len(val) >= 8 and " " not in val:
            add("AC03", where, "secret-named key '%s' holds a value (%s)" % (key, mask(val)))

    # AC04 injection in LLM-read text
    for where, txt in text_fields(card):
        hidden = HIDDEN_CHARS.findall(txt)
        if hidden:
            dec = decode_tags(txt)
            add("AC04", where, "invisible/bidi Unicode (%d chars)%s" % (
                len(hidden), "; decoded TAG text: %r" % dec[:80] if dec else ""))
            if dec:
                txt = txt + " " + dec
        norm = unicodedata.normalize("NFKC", txt)
        for rx, label in INJECTION_PATTERNS:
            m = rx.search(norm)
            if m:
                add("AC04", where, "%s: %r" % (label, m.group(0)[:80]),
                    "medium" if label == "hidden HTML comment" else None)
        if len(txt) > 3000:
            add("AC04", where, "unusually long text (%d chars) in a field read by client LLMs" % len(txt), "low")

    # AC09 signatures
    if not card.get("signatures"):
        add("AC09", "$", "card is unsigned; clients cannot verify it was published by the provider (A2A v0.3 'signatures' JWS)")

    # AC10 sensitive skills
    for i, s in enumerate(card.get("skills") or [] if isinstance(card.get("skills"), list) else []):
        if not isinstance(s, dict):
            continue
        blob = " ".join(str(s.get(k, "")) for k in ("id", "name", "description")) + " " + " ".join(
            str(t) for t in (s.get("tags") or []))
        blob = blob.replace("_", " ").replace("-", " ")
        caps = sorted({label for rx, label in SENSITIVE_CAPS if rx.search(blob)})
        if caps:
            sev = "medium" if not schemes or (reqs and any(isinstance(r, dict) and not r for r in reqs)) else None
            add("AC10", "$.skills[%d]" % i, "skill '%s' exposes %s%s" % (
                s.get("id") or s.get("name"), ", ".join(caps),
                " without authentication" if sev else ""), sev)

    # AC11 push notifications
    caps = card.get("capabilities")
    if isinstance(caps, dict) and caps.get("pushNotifications"):
        add("AC11", "$.capabilities.pushNotifications",
            "server will POST to client-supplied webhook URLs: block private/metadata IPs and require webhook auth")
    return f


def load(path):
    if path == "-":
        return json.load(sys.stdin)
    with open(path, encoding="utf-8-sig") as fh:
        return json.load(fh)


def iter_files(paths):
    for p in paths:
        if p == "-" or os.path.isfile(p):
            yield p
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if not d.startswith(".") or d == ".well-known")
                for fn in sorted(files):
                    if fn.endswith(".json"):
                        yield os.path.join(root, fn)
        else:
            raise FileNotFoundError(p)


def extract_cards(obj):
    if is_card(obj):
        return [("", obj)]
    if isinstance(obj, list):
        return [("[%d]" % i, c) for i, c in enumerate(obj) if is_card(c)]
    if isinstance(obj, dict):
        for k in ("agentCard", "card", "result"):
            if is_card(obj.get(k)):
                return [("." + k, obj[k])]
        if isinstance(obj.get("cards"), list):
            return [(".cards[%d]" % i, c) for i, c in enumerate(obj["cards"]) if is_card(c)]
    return []


def grade(findings):
    worst = max((SEV_RANK[x.severity] for x in findings), default=0)
    n_hi = sum(1 for x in findings if SEV_RANK[x.severity] >= SEV_RANK["high"])
    if worst >= SEV_RANK["critical"] or n_hi >= 3:
        return "F"
    if worst >= SEV_RANK["high"]:
        return "D"
    if worst >= SEV_RANK["medium"]:
        return "C"
    if worst >= SEV_RANK["low"]:
        return "B"
    return "A"


def scan_paths(paths, allow_hosts=(), disabled=()):
    results, errors = [], []
    for p in iter_files(paths):
        try:
            obj = load(p)
        except (OSError, ValueError) as e:
            errors.append("%s: cannot parse JSON (%s)" % (p, e))
            continue
        cards = extract_cards(obj)
        if not cards:
            if "AC12" not in disabled:
                results.append({"path": p, "name": None, "findings": [Finding(
                    "AC12", p, "$", "not recognized as an A2A Agent Card; skipped")], "card": False})
            continue
        for suffix, card in cards:
            label = p + suffix
            results.append({"path": label, "name": card.get("name"), "card": True,
                            "findings": audit_card(card, label, allow_hosts, disabled)})
    return results, errors


def to_sarif(results):
    lvl = {"critical": "error", "high": "error", "medium": "warning"}
    rules = [{"id": r, "shortDescription": {"text": t}, "defaultConfiguration": {"level": lvl.get(s, "note")}}
             for r, (s, t) in sorted(RULES.items())]
    res = []
    for r in results:
        for f in r["findings"]:
            res.append({"ruleId": f.rule, "level": lvl.get(f.severity, "note"),
                        "message": {"text": "[%s] %s: %s" % (f.severity, f.where, f.message)},
                        "locations": [{"physicalLocation": {"artifactLocation": {
                            "uri": f.path.split("[")[0].replace(os.sep, "/")}, "region": {"startLine": 1}}}]})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "agentcard", "version": VERSION, "rules": rules}}, "results": res}]}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="agentcard", description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="*", help="agent card JSON files or directories ('-' for stdin)")
    ap.add_argument("--allow-host", action="append", default=[], metavar="GLOB",
                    help="host glob exempt from AC07/AC08 (e.g. '*.corp.example') (repeatable)")
    ap.add_argument("--disable", action="append", default=[], metavar="RULE", help="disable a rule id (repeatable)")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="low")
    ap.add_argument("--fail-on", choices=SEVERITIES[1:] + ["any", "none"], default="high")
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true")
    fmt.add_argument("--sarif", action="store_true")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version="agentcard " + VERSION)
    a = ap.parse_args(argv)
    if a.list_rules:
        for r, (s, t) in sorted(RULES.items()):
            print("%s  %-8s %s" % (r, s, t))
        return 0
    if not a.paths:
        ap.print_usage(sys.stderr)
        print("agentcard: give at least one card file or directory", file=sys.stderr)
        return 2
    try:
        results, errors = scan_paths(a.paths, [h.lower() for h in a.allow_host], set(x.upper() for x in a.disable))
    except FileNotFoundError as e:
        print("agentcard: no such file or directory: %s" % e, file=sys.stderr)
        return 2
    for e in errors:
        print("agentcard: " + e, file=sys.stderr)
    if errors and not results:
        return 2
    for r in results:
        r["grade"] = grade(r["findings"]) if r["card"] else "-"
    minr = SEV_RANK[a.min_severity]
    for r in results:
        r["findings"] = [x for x in r["findings"] if SEV_RANK[x.severity] >= minr]
        r["findings"].sort(key=lambda x: (-SEV_RANK[x.severity], x.rule, x.where))
    allf = [x for r in results for x in r["findings"]]
    if a.json:
        print(json.dumps({"version": VERSION, "cards": [{"path": r["path"], "name": r["name"], "grade": r["grade"],
                                                         "findings": [x.to_dict() for x in r["findings"]]}
                                                        for r in results], "errors": errors}, indent=2))
    elif a.sarif:
        print(json.dumps(to_sarif(results), indent=2))
    else:
        for r in results:
            print("%s  [grade %s]%s" % (r["path"], r["grade"], "  " + r["name"] if r["name"] else ""))
            for x in r["findings"]:
                print("  %-8s %s %s" % (x.severity.upper(), x.rule, x.where))
                print("           " + x.message)
            if not r["findings"]:
                print("  no findings at or above %s" % a.min_severity)
        print("\n%d card(s), %d finding(s)" % (sum(1 for r in results if r["card"]), len(allf)))
    if a.fail_on == "none":
        return 0
    thr = 0 if a.fail_on == "any" else SEV_RANK[a.fail_on]
    return 1 if any(SEV_RANK[x.severity] >= thr for x in allf) else 0


if __name__ == "__main__":
    sys.exit(main())
