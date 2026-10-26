#!/usr/bin/env python3
"""scopefit - offline least-privilege checker for GitHub tokens used by AI agents.

Compares the permissions a GitHub token was GRANTED (supplied by you) against the
permissions REQUIRED by the GitHub REST calls an agent actually made (extracted
from transcripts or an endpoint list), using a built-in, best-effort, partial
endpoint->permission mapping. Stdlib only; never touches the network.
"""
import argparse
import json
import os
import re
import shlex
import sys

__version__ = "0.1.0"

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MAPPING = os.path.join(HERE, "scopefit_mapping.json")

LEVELS = {"none": 0, "read": 1, "write": 2, "admin": 3}
LEVEL_NAMES = {v: k for k, v in LEVELS.items()}
HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD")

# Classic OAuth scope implication (parent -> directly implied children).
CLASSIC_IMPLIES = {
    "repo": ["repo:status", "repo_deployment", "public_repo", "repo:invite", "security_events"],
    "admin:org": ["write:org", "manage_runners:org"],
    "write:org": ["read:org"],
    "admin:public_key": ["write:public_key"],
    "write:public_key": ["read:public_key"],
    "admin:repo_hook": ["write:repo_hook"],
    "write:repo_hook": ["read:repo_hook"],
    "admin:gpg_key": ["write:gpg_key"],
    "write:gpg_key": ["read:gpg_key"],
    "admin:ssh_signing_key": ["write:ssh_signing_key"],
    "write:ssh_signing_key": ["read:ssh_signing_key"],
    "user": ["read:user", "user:email", "user:follow"],
    "write:packages": ["read:packages"],
    "project": ["read:project"],
    "admin:enterprise": ["manage_runners:enterprise", "manage_billing:enterprise", "read:enterprise"],
    "manage_billing:enterprise": ["read:enterprise"],
    "audit_log": ["read:audit_log"],
    "codespace": ["codespace:secrets"],
}

HIGH_RISK_CLASSIC = {
    "delete_repo": "can permanently delete repositories",
    "admin:org": "full control of organizations, teams and memberships",
    "write:org": "can change org membership/teams",
    "admin:repo_hook": "can create/delete repo webhooks (exfiltration channel)",
    "write:repo_hook": "can create repo webhooks (exfiltration channel)",
    "admin:org_hook": "can manage organization webhooks",
    "workflow": "can modify GitHub Actions workflows (CI code execution, secret access)",
    "admin:enterprise": "full control of enterprises",
    "admin:public_key": "can manage user SSH keys",
    "admin:gpg_key": "can manage user GPG keys",
    "admin:ssh_signing_key": "can manage SSH signing keys",
    "delete:packages": "can delete packages",
    "write:packages": "can publish packages (supply-chain risk)",
    "site_admin": "GitHub Enterprise Server site administration",
    "codespace": "can create/manage codespaces",
    "repo": "full read/write to ALL private repositories the user can access",
    "user": "can modify the user profile",
}

HIGH_RISK_FINE = {
    # permission: (minimum level considered high risk, reason)
    "administration": (1, "repository settings, branch protection, deletion/transfer"),
    "secrets": (1, "Actions secrets"),
    "organization_secrets": (1, "organization Actions secrets"),
    "workflows": (2, "can modify workflow files (CI code execution, secret access)"),
    "actions": (2, "can trigger/cancel/re-run workflows"),
    "organization_administration": (1, "organization settings"),
    "members": (2, "organization membership changes"),
    "repository_hooks": (2, "webhooks (exfiltration channel)"),
    "organization_hooks": (2, "organization webhooks"),
    "environments": (2, "deployment environments and their secrets"),
    "packages": (2, "can publish packages (supply-chain risk)"),
    "contents": (2, "can push code"),
}

FINE_ALIASES = {
    "pull_request": "pull_requests", "pulls": "pull_requests", "prs": "pull_requests",
    "webhooks": "repository_hooks", "hooks": "repository_hooks",
    "commit_statuses": "statuses", "status": "statuses",
    "workflow": "workflows", "issue": "issues", "content": "contents",
    "deployment": "deployments", "check": "checks", "secret": "secrets",
    "email": "email_addresses", "emails": "email_addresses",
    "gist": "gists", "member": "members",
}

LEVEL_ALIASES = {
    "read": "read", "r": "read", "read-only": "read", "read_only": "read", "readonly": "read",
    "write": "write", "w": "write", "read-write": "write", "read_write": "write",
    "read and write": "write", "readwrite": "write", "rw": "write",
    "admin": "admin", "none": "none", "no access": "none", "no_access": "none",
}


class ScopefitError(Exception):
    pass


# --------------------------------------------------------------------- mapping
def load_mapping(path=None):
    path = path or DEFAULT_MAPPING
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ScopefitError("cannot load mapping %s: %s" % (path, exc))
    entries = []
    for e in data.get("endpoints", []):
        e = dict(e)
        e["method"] = e["method"].upper()
        e["_regex"] = template_regex(e["path"])
        e["_specificity"] = (
            sum(1 for s in e["path"].split("/") if s and not s.startswith("{")),
            -e["path"].count("+}"),
        )
        entries.append(e)
    return entries


def template_regex(tpl):
    parts = []
    for seg in tpl.strip("/").split("/"):
        m = re.fullmatch(r"\{(\w+)(\+?)\}", seg)
        if m:
            parts.append(".+" if m.group(2) else "[^/]+")
        else:
            parts.append(re.escape(seg))
    return re.compile("^/" + "/".join(parts) + "$")


def match_endpoint(method, path, mapping):
    cands = [e for e in mapping if e["method"] == method and e["_regex"].match(path)]
    if not cands:
        return None
    return max(cands, key=lambda e: e["_specificity"])


# ------------------------------------------------------------- normalization
def normalize_path(url):
    """Turn a URL / gh-api endpoint into a bare REST path (no host, query, slash)."""
    u = url.strip().strip("'\"")
    u = re.sub(r"^https?://api\.github\.com", "", u, flags=re.I)
    u = re.sub(r"^https?://[^/]+/api/v3", "", u, flags=re.I)  # GHES
    u = re.sub(r"^https?://[^/]+", "", u)
    u = u.split("#", 1)[0].split("?", 1)[0]
    if not u.startswith("/"):
        u = "/" + u
    u = re.sub(r"/{2,}", "/", u)
    # gh api style ":owner" placeholders -> {owner}
    u = re.sub(r"/:(\w+)", r"/{\1}", u)
    if len(u) > 1:
        u = u.rstrip("/")
    return u


def templatize(path):
    """Generic template for display when no mapping entry matched (never a guess at permissions)."""
    segs = path.strip("/").split("/")
    out = []
    for i, s in enumerate(segs):
        if i in (1, 2) and segs[0] == "repos":
            out.append("{owner}" if i == 1 else "{repo}")
        elif i == 1 and segs[0] in ("orgs", "users"):
            out.append("{org}" if segs[0] == "orgs" else "{username}")
        elif re.fullmatch(r"\d+", s):
            out.append("{number}")
        elif re.fullmatch(r"[0-9a-f]{40}", s):
            out.append("{sha}")
        else:
            out.append(s)
    return "/" + "/".join(out)


def looks_like_github_api(url):
    return bool(re.search(r"api\.github\.com|/api/v3/", url, re.I))


# ----------------------------------------------------------------- extraction
def parse_endpoint_lines(text, source="<text>"):
    calls = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z]+)\s+(\S+)", line)
        if not m or m.group(1).upper() not in HTTP_METHODS:
            raise ScopefitError("%s:%d: expected 'METHOD /path', got %r" % (source, n, line))
        calls.append({"method": m.group(1).upper(), "url": m.group(2), "source": "%s:%d" % (source, n)})
    return calls


def _split_shell(cmd):
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|")
        lex.whitespace_split = True
        toks = list(lex)
    except ValueError:
        toks = cmd.split()
    segs, cur = [], []
    for t in toks:
        if t and set(t) <= set(";&|"):
            if cur:
                segs.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    return segs


def parse_command_string(cmd):
    """Extract (method, url) from curl / gh api invocations inside a shell command string."""
    found = []
    if "curl" not in cmd and "gh" not in cmd:
        return found
    for seg in _split_shell(cmd):
        # skip env assignments / sudo etc.
        while seg and (re.match(r"^\w+=", seg[0]) or seg[0] in ("sudo", "env", "command", "exec")):
            seg = seg[1:]
        if not seg:
            continue
        prog = os.path.basename(seg[0])
        if prog == "curl":
            method, urls, has_data = None, [], False
            i = 1
            while i < len(seg):
                t = seg[i]
                if t in ("-X", "--request") and i + 1 < len(seg):
                    method = seg[i + 1].upper(); i += 2; continue
                if t.startswith("-X") and len(t) > 2:
                    method = t[2:].upper(); i += 1; continue
                if t.startswith("--request="):
                    method = t.split("=", 1)[1].upper(); i += 1; continue
                if t in ("-d", "--data", "--data-raw", "--data-binary", "--json", "-F", "--form"):
                    has_data = True; i += 2; continue
                if t in ("-I", "--head"):
                    method = method or "HEAD"; i += 1; continue
                if t in ("-H", "--header", "-o", "--output", "-u", "--user", "-A", "--user-agent", "-w", "--write-out"):
                    i += 2; continue
                if t.startswith("--url="):
                    urls.append(t.split("=", 1)[1]); i += 1; continue
                if t == "--url" and i + 1 < len(seg):
                    urls.append(seg[i + 1]); i += 2; continue
                if not t.startswith("-") and looks_like_github_api(t):
                    urls.append(t)
                i += 1
            for u in urls:
                if looks_like_github_api(u):
                    found.append((method or ("POST" if has_data else "GET"), u))
        elif prog == "gh" and len(seg) > 1 and seg[1] == "api":
            method, endpoint, has_fields = None, None, False
            i = 2
            while i < len(seg):
                t = seg[i]
                if t in ("-X", "--method") and i + 1 < len(seg):
                    method = seg[i + 1].upper(); i += 2; continue
                if t.startswith("--method="):
                    method = t.split("=", 1)[1].upper(); i += 1; continue
                if t in ("-f", "-F", "--field", "--raw-field", "--input"):
                    has_fields = True; i += 2; continue
                if t in ("-H", "--header", "-q", "--jq", "-t", "--template", "--hostname", "--cache", "-p", "--preview"):
                    i += 2; continue
                if t.startswith("-"):
                    i += 1; continue
                if endpoint is None:
                    endpoint = t
                i += 1
            if endpoint:
                if endpoint.lower() == "graphql":
                    found.append(("POST", "graphql"))
                else:
                    found.append((method or ("POST" if has_fields else "GET"), endpoint))
    return found


URL_KEYS = ("url", "uri", "endpoint", "path", "route", "api_path")
METHOD_KEYS = ("method", "http_method", "verb")


def _maybe_json(v):
    if isinstance(v, str) and v.strip()[:1] in ("{", "["):
        try:
            return json.loads(v)
        except ValueError:
            return v
    return v


def extract_from_args(args, source, out):
    """Walk tool-call arguments for method/url pairs and curl/gh command strings."""
    args = _maybe_json(args)
    if isinstance(args, dict):
        method = next((args[k] for k in METHOD_KEYS if isinstance(args.get(k), str)), None)
        url = next((args[k] for k in URL_KEYS if isinstance(args.get(k), str)), None)
        if url and (method and method.upper() in HTTP_METHODS) and (url.startswith("/") or looks_like_github_api(url) or url.startswith("repos/")):
            out.append({"method": method.upper(), "url": url, "source": source})
        elif url and not method and looks_like_github_api(url):
            out.append({"method": "GET", "url": url, "source": source})
        for k, v in args.items():
            if k in URL_KEYS or k in METHOD_KEYS:
                continue
            extract_from_args(v, source, out)
    elif isinstance(args, list):
        for v in args:
            extract_from_args(v, source, out)
    elif isinstance(args, str):
        for m, u in parse_command_string(args):
            out.append({"method": m, "url": u, "source": source})


def _iter_tool_calls(obj):
    """Yield (tool_name, args) for tool calls found anywhere in a transcript record.

    Only tool-call ARGUMENTS are inspected (never tool results), so API response
    bodies containing GitHub URLs are not mistaken for calls.
    """
    if isinstance(obj, list):
        for v in obj:
            yield from _iter_tool_calls(v)
        return
    if not isinstance(obj, dict):
        return
    # OpenAI chat: message.tool_calls[].function.{name,arguments}
    if isinstance(obj.get("tool_calls"), list):
        for tc in obj["tool_calls"]:
            if isinstance(tc, dict):
                fn = tc.get("function") or {}
                yield fn.get("name") or tc.get("name"), fn.get("arguments", tc.get("arguments", tc.get("args")))
    # OpenAI legacy function_call
    if isinstance(obj.get("function_call"), dict):
        fc = obj["function_call"]
        yield fc.get("name"), fc.get("arguments")
    typ = obj.get("type")
    # Anthropic tool_use block / OpenAI Responses function_call item
    if typ in ("tool_use", "server_tool_use") and "input" in obj:
        yield obj.get("name"), obj["input"]
    elif typ in ("function_call", "tool_call", "tool", "custom_tool_call", "local_shell_call") and any(
            k in obj for k in ("arguments", "args", "input", "action")):
        yield obj.get("name") or obj.get("tool"), obj.get("arguments", obj.get("args", obj.get("input", obj.get("action"))))
    elif typ is None and ("tool" in obj or "tool_name" in obj) and any(k in obj for k in ("args", "arguments", "input", "parameters")):
        yield obj.get("tool") or obj.get("tool_name"), obj.get("args", obj.get("arguments", obj.get("input", obj.get("parameters"))))
    # recurse into containers that may hold messages/blocks (but not results)
    for k, v in obj.items():
        if k in ("tool_calls", "function_call", "input", "arguments", "args", "parameters", "action",
                 "output", "result", "results", "tool_result", "observation"):
            continue
        if typ == "tool_result" or obj.get("role") == "tool":
            continue
        if isinstance(v, (list, dict)):
            yield from _iter_tool_calls(v)


def parse_transcript_text(text, source="<transcript>"):
    records = []
    stripped = text.strip()
    if not stripped:
        return []
    try:
        records = [(source, json.loads(stripped))]
    except ValueError:
        for n, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(("%s:%d" % (source, n), json.loads(line)))
            except ValueError:
                raise ScopefitError("%s:%d: not valid JSON/JSONL" % (source, n))
    calls = []
    for src, rec in records:
        for name, args in _iter_tool_calls(rec):
            extract_from_args(args, src + (" [%s]" % name if name else ""), calls)
    return calls


def load_calls(path, fmt="auto"):
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise ScopefitError("cannot read %s: %s" % (path, exc))
    name = os.path.basename(path)
    if fmt == "auto":
        s = text.lstrip()
        fmt = "transcript" if s[:1] in ("{", "[") else "endpoints"
    if fmt == "endpoints":
        return parse_endpoint_lines(text, name)
    return parse_transcript_text(text, name)


# --------------------------------------------------------------------- grants
def norm_perm_name(name):
    n = re.sub(r"[\s\-]+", "_", str(name).strip().lower())
    return FINE_ALIASES.get(n, n)


def norm_level(level):
    lv = str(level).strip().lower()
    lv = LEVEL_ALIASES.get(lv, LEVEL_ALIASES.get(lv.replace("_", " "), lv))
    if lv not in LEVELS:
        raise ScopefitError("unknown permission level %r (use read/write/admin/none)" % level)
    return lv


def _parse_yamlish(text):
    """Tiny parser for 'key: value' maps and '- item' / comma / whitespace lists."""
    mapping, items = {}, []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("- "):
            items.append(line[2:].strip().strip("'\""))
            continue
        m = re.match(r"^([A-Za-z_][\w\- ]*?)\s*(?::\s+|=\s*|:$)(.*)$", line)
        if m:
            key, val = m.group(1).strip(), m.group(2).strip().strip("'\"")
            if key.lower() in ("scopes", "permissions", "type"):
                if val:
                    mapping[key.lower()] = val
                continue
            if val:
                mapping[key] = val
                continue
        for tok in re.split(r"[,\s]+", line):
            if tok:
                items.append(tok.strip("'\"[]"))
    return mapping, items


def parse_grants(text, kind="auto"):
    """Return ('fine', {perm: level}) or ('classic', set(scopes))."""
    data = None
    try:
        data = json.loads(text)
    except ValueError:
        mapping, items = _parse_yamlish(text)
        mapping.pop("permissions", None)
        sc = mapping.pop("scopes", None)
        if sc:
            items.extend(t for t in re.split(r"[,\s\[\]'\"]+", sc) if t)
        mapping.pop("type", None)
        if items and not mapping:
            data = items
        elif mapping and not items:
            data = mapping
        elif not mapping and not items:
            raise ScopefitError("grants file is empty")
        else:
            raise ScopefitError("grants file mixes a permission map and a scope list")
    if isinstance(data, str):
        data = [t for t in re.split(r"[,\s]+", data) if t]
    if isinstance(data, dict):
        if isinstance(data.get("scopes"), (list, str)):
            s = data["scopes"]
            data = s if isinstance(s, list) else [t for t in re.split(r"[,\s]+", s) if t]
        elif isinstance(data.get("permissions"), dict):
            data = data["permissions"]
    if kind == "classic" or (kind == "auto" and isinstance(data, list)):
        if not isinstance(data, list):
            raise ScopefitError("classic grants must be a list of scopes")
        return "classic", {str(s).strip().lower() for s in data if str(s).strip()}
    if not isinstance(data, dict):
        raise ScopefitError("fine-grained grants must be a {permission: level} map")
    perms = {}
    for k, v in data.items():
        lv = norm_level(v)
        if lv != "none":
            perms[norm_perm_name(k)] = lv
    return "fine", perms


def load_grants(path, kind="auto"):
    try:
        with open(path, encoding="utf-8") as fh:
            return parse_grants(fh.read(), kind)
    except OSError as exc:
        raise ScopefitError("cannot read %s: %s" % (path, exc))


def classic_closure(scopes):
    seen, stack = set(), list(scopes)
    while stack:
        s = stack.pop()
        if s in seen:
            continue
        seen.add(s)
        stack.extend(CLASSIC_IMPLIES.get(s, []))
    return seen


# ------------------------------------------------------------------- analysis
def resolve_calls(calls, mapping, public_only=False):
    mapped, unmapped, graphql = [], [], []
    for c in calls:
        if c["url"].lower() in ("graphql", "/graphql") or normalize_path(c["url"]) == "/graphql":
            graphql.append(c)
            continue
        path = normalize_path(c["url"])
        e = match_endpoint(c["method"], path, mapping)
        rec = {"method": c["method"], "path": path, "source": c.get("source", "")}
        if e is None:
            rec["template"] = templatize(path)
            unmapped.append(rec)
        else:
            rec["template"] = e["path"]
            rec["fine"] = dict(e.get("fine", {}))
            if e.get("repo_scoped") and "metadata" not in rec["fine"]:
                rec["fine"]["metadata"] = "read"
            classic = e.get("classic")
            if public_only and "classic_public" in e:
                classic = e["classic_public"]
            rec["classic"] = classic
            if e.get("note"):
                rec["note"] = e["note"]
            mapped.append(rec)
    return mapped, unmapped, graphql


def required_fine(mapped):
    req = {}
    for r in mapped:
        for p, lv in r["fine"].items():
            if LEVELS[lv] > LEVELS.get(req.get(p, "none"), 0):
                req[p] = lv
    return req


def required_classic(mapped):
    return {r["classic"] for r in mapped if r.get("classic")}


def minimal_classic(required):
    """Drop scopes already implied by another required scope."""
    out = set()
    for s in required:
        if not any(s != o and s in classic_closure([o]) for o in required):
            out.add(s)
    return out


def analyze(kind, granted, mapped, unmapped, graphql):
    res = {"grant_type": kind, "over_granted": [], "missing": [], "high_risk": []}
    req_f = required_fine(mapped)
    req_c = required_classic(mapped)
    res["required_fine"] = dict(sorted(req_f.items()))
    res["required_classic"] = sorted(minimal_classic(req_c))
    if kind == "fine":
        res["granted"] = dict(sorted(granted.items()))
        for p, lv in sorted(granted.items()):
            need = req_f.get(p)
            if need is None:
                if p == "metadata" and lv == "read":
                    continue  # mandatory for fine-grained tokens
                res["over_granted"].append({"permission": p, "granted": lv, "needed": None, "reason": "never needed by observed calls"})
            elif LEVELS[lv] > LEVELS[need]:
                res["over_granted"].append({"permission": p, "granted": lv, "needed": need, "reason": "%s granted but %s suffices" % (lv, need)})
        for p, need in sorted(req_f.items()):
            have = granted.get(p, "none")
            if LEVELS[have] < LEVELS[need]:
                if p == "metadata" and granted:
                    continue  # implicitly granted with any repo permission
                res["missing"].append({"permission": p, "granted": have if have != "none" else None, "needed": need,
                                       "used_by": sorted({"%s %s" % (r["method"], r["template"]) for r in mapped if LEVELS[r["fine"].get(p, "none")] > LEVELS[have]})})
        for p, lv in sorted(granted.items()):
            hr = HIGH_RISK_FINE.get(p)
            if hr and LEVELS[lv] >= hr[0]:
                res["high_risk"].append({"grant": "%s:%s" % (p, lv), "reason": hr[1], "used": p in req_f and LEVELS[req_f[p]] >= hr[0]})
        res["suggested"] = dict(sorted(req_f.items()))
    else:
        res["granted"] = sorted(granted)
        eff = classic_closure(granted)
        for s in sorted(granted):
            cl = classic_closure([s])
            hits = cl & req_c
            if not hits:
                res["over_granted"].append({"scope": s, "reason": "never needed by observed calls"})
            elif s not in req_c:
                narrower = sorted(minimal_classic(hits))
                res["over_granted"].append({"scope": s, "reason": "broader than needed; %s suffices" % ", ".join(narrower), "narrower": narrower})
        for s in sorted(req_c):
            if s not in eff:
                res["missing"].append({"scope": s, "used_by": sorted({"%s %s" % (r["method"], r["template"]) for r in mapped if r.get("classic") == s})})
        for s in sorted(granted):
            if s in HIGH_RISK_CLASSIC:
                res["high_risk"].append({"grant": s, "reason": HIGH_RISK_CLASSIC[s], "used": s in req_c})
        res["suggested"] = sorted(minimal_classic(req_c))
    res["calls"] = mapped
    res["unmapped"] = unmapped
    res["graphql_calls"] = len(graphql)
    res["counts"] = {"calls": len(mapped) + len(unmapped) + len(graphql), "mapped": len(mapped),
                     "unmapped": len(unmapped), "graphql": len(graphql),
                     "over_granted": len(res["over_granted"]), "missing": len(res["missing"]),
                     "high_risk": len(res["high_risk"])}
    return res


def policy_failed(res, fail_on):
    c = res["counts"]
    if fail_on == "none":
        return False
    if fail_on == "over":
        return c["over_granted"] > 0
    if fail_on == "missing":
        return c["missing"] > 0
    return c["over_granted"] > 0 or c["missing"] > 0


# --------------------------------------------------------------------- output
def _table(rows, headers):
    if not rows:
        return "  (none)"
    w = [max(len(str(x)) for x in col) for col in zip(headers, *rows)]
    fmt = "  " + "  ".join("%%-%ds" % n for n in w)
    lines = [fmt % tuple(headers), fmt % tuple("-" * n for n in w)]
    lines += [fmt % tuple(str(x) for x in r) for r in rows]
    return "\n".join(l.rstrip() for l in lines)


def render_text(res):
    o = []
    c = res["counts"]
    o.append("scopefit %s - grant type: %s" % (__version__, "fine-grained" if res["grant_type"] == "fine" else "classic OAuth scopes"))
    o.append("Observed calls: %d (mapped %d, unmapped %d, graphql %d)" % (c["calls"], c["mapped"], c["unmapped"], c["graphql"]))
    o.append("")
    o.append("ENDPOINTS USED (deduplicated):")
    seen = {}
    for r in res["calls"]:
        k = (r["method"], r["template"])
        if k not in seen:
            fine = ", ".join("%s:%s" % kv for kv in sorted(r["fine"].items())) or "-"
            seen[k] = [r["method"], r["template"], fine, r.get("classic") or "-", 0]
        seen[k][4] += 1
    o.append(_table(list(seen.values()), ["METHOD", "ENDPOINT", "FINE-GRAINED", "CLASSIC", "N"]))
    o.append("")
    o.append("OVER-GRANTED:")
    if res["grant_type"] == "fine":
        o.append(_table([[x["permission"], x["granted"], x["needed"] or "-", x["reason"]] for x in res["over_granted"]],
                        ["PERMISSION", "GRANTED", "NEEDED", "WHY"]))
    else:
        o.append(_table([[x["scope"], x["reason"]] for x in res["over_granted"]], ["SCOPE", "WHY"]))
    o.append("")
    o.append("MISSING (needed but not granted):")
    if res["grant_type"] == "fine":
        o.append(_table([[x["permission"], x["granted"] or "-", x["needed"], "; ".join(x["used_by"])] for x in res["missing"]],
                        ["PERMISSION", "GRANTED", "NEEDED", "USED BY"]))
    else:
        o.append(_table([[x["scope"], "; ".join(x["used_by"])] for x in res["missing"]], ["SCOPE", "USED BY"]))
    o.append("")
    o.append("HIGH-RISK GRANTS:")
    o.append(_table([[x["grant"], "yes" if x["used"] else "NO", x["reason"]] for x in res["high_risk"]], ["GRANT", "USED", "RISK"]))
    o.append("")
    o.append("UNMAPPED ENDPOINTS (unknown to scopefit; permissions NOT guessed - check GitHub docs):")
    um = {}
    for r in res["unmapped"]:
        um.setdefault((r["method"], r["template"]), 0)
        um[(r["method"], r["template"])] += 1
    o.append(_table([[m, t, n] for (m, t), n in um.items()], ["METHOD", "ENDPOINT", "N"]))
    if res["graphql_calls"]:
        o.append("  note: %d GraphQL call(s) seen; GraphQL is NOT analyzed." % res["graphql_calls"])
    o.append("")
    o.append("SUGGESTED MINIMAL GRANT (observed usage only):")
    if res["grant_type"] == "fine":
        o.append("  " + json.dumps(res["suggested"]))
        if res["required_classic"]:
            o.append("  (classic equivalent: %s)" % json.dumps(res["required_classic"]))
    else:
        o.append("  " + json.dumps(res["suggested"]))
        o.append("  (fine-grained alternative, preferred: %s)" % json.dumps(res["required_fine"]))
    if res["unmapped"] or res["graphql_calls"]:
        o.append("  WARNING: unmapped/GraphQL calls may need more than this suggestion.")
    o.append("")
    o.append("Summary: %d over-granted, %d missing, %d high-risk, %d unmapped." %
             (c["over_granted"], c["missing"], c["high_risk"], c["unmapped"]))
    o.append("Mapping is a best-effort SUBSET from GitHub docs and may be out of date; future runs may need more.")
    return "\n".join(o)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="scopefit", description="Offline least-privilege checker for GitHub tokens used by AI agents.")
    ap.add_argument("--grants", "-g", required=True, help="file with the token's granted permissions (fine-grained map or classic scope list)")
    ap.add_argument("--calls", "-c", required=True, action="append", help="transcript (JSON/JSONL) or endpoints.txt; repeatable")
    ap.add_argument("--grant-type", choices=["auto", "fine", "classic"], default="auto")
    ap.add_argument("--calls-format", choices=["auto", "transcript", "endpoints"], default="auto")
    ap.add_argument("--mapping", help="alternate mapping JSON (default: bundled scopefit_mapping.json)")
    ap.add_argument("--public-repos", action="store_true", help="assume only public repos are touched (classic: public_repo / no scope for reads)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--fail-on", choices=["over", "missing", "any", "none"], default="any",
                    help="exit 1 when over-granted / missing / either / never (default: any)")
    ap.add_argument("--version", action="version", version="scopefit " + __version__)
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2
    try:
        mapping = load_mapping(args.mapping)
        kind, granted = load_grants(args.grants, args.grant_type)
        calls = []
        for p in args.calls:
            calls.extend(load_calls(p, args.calls_format))
        mapped, unmapped, graphql = resolve_calls(calls, mapping, args.public_repos)
        res = analyze(kind, granted, mapped, unmapped, graphql)
    except ScopefitError as exc:
        print("scopefit: error: %s" % exc, file=sys.stderr)
        return 2
    failed = policy_failed(res, args.fail_on)
    res["policy"] = {"fail_on": args.fail_on, "failed": failed}
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(render_text(res))
        print("Policy --fail-on %s: %s" % (args.fail_on, "FAIL" if failed else "OK"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
