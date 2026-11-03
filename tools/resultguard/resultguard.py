#!/usr/bin/env python3
"""resultguard: offline scanner for indirect prompt injection in AI agent *tool results*.

When an agent reads a page, file, ticket or API response, that content is fed back to the
model as a tool result. Attackers plant instructions there ("ignore prior rules", "call
send_email", "quietly fetch this webhook"). resultguard extracts tool results from saved
transcripts (OpenAI chat tool messages, Anthropic tool_result blocks, generic JSON/JSONL)
or scans standalone result files, and flags hijack / exfil bait patterns with tool+turn
attribution.

Complements ragsieve (pre-ingestion RAG corpora), toolpoison (tool *descriptions*),
outfence (model *output* before render) and canarytrap (live canary tests). Stdlib only;
never runs an agent or contacts a model.
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
    "TR01": ("high", "AI-directed override / jailbreak phrasing in a tool result"),
    "TR02": ("high", "Fake role delimiter or system/developer token in a tool result"),
    "TR03": ("critical", "Hidden Unicode (zero-width, bidi or TAG) smuggled in a tool result"),
    "TR04": ("high", "Tool-chaining / action bait telling the model to call another tool"),
    "TR05": ("high", "Exfiltration or callback URL bait aimed at the agent"),
    "TR06": ("medium", "Encoded blob in a tool result that decodes to instruction-like text"),
    "TR07": ("high", "Credential / secret harvest request inside a tool result"),
    "TR08": ("medium", "Conceal-from-user instruction in a tool result"),
    "TR09": ("medium", "Markdown/HTML auto-loading image or resource in a tool result"),
}

BIDI = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c")
ZERO_WIDTH = set("\u200b\u200c\u200d\u2060\ufeff\u180e")
# Unicode TAG block U+E0001..U+E007F often used for invisible smuggling
TAG_LO, TAG_HI = 0xE0001, 0xE007F

OVERRIDE_RE = re.compile(
    r"(?is)(?:"
    r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|prompts?|directives?)"
    r"|disregard\s+(?:your|the)\s+(?:system|safety|previous)\s+(?:prompt|instructions?|rules?)"
    r"|override\s+(?:your|the|all)\s+(?:system|safety|previous)?\s*(?:prompt|instructions?|rules?|policies)?"
    r"|you\s+are\s+now\s+(?:in\s+)?(?:DAN|developer|unrestricted|jailbreak|god)\b"
    r"|jailbreak(?:\s+mode)?"
    r"|new\s+(?:system\s+)?(?:instructions?|rules?|directive)\s*:"
    r"|from\s+now\s+on\s+you\s+(?:must|will|shall)\b"
    r"|do\s+not\s+follow\s+(?:your|the)\s+(?:system|original)\s+(?:prompt|instructions?)"
    r")"
)

ROLE_RE = re.compile(
    r"(?is)(?:"
    r"<\|(?:im_start|im_end|system|assistant|user|endoftext|redacted_start)\|>"
    r"|\[(?:INST|/INST|SYS|/SYS|SYSTEM|/SYSTEM)\]"
    r"|</?\s*(?:system|developer|assistant|tool_result|tool_call|function_response)\s*>"
    r"|^\s*(?:system|developer)\s*:\s*\S"
    r"|<<\s*SYS\s*>>"
    r")",
    re.M,
)

ACTION_BAIT_RE = re.compile(
    r"(?is)(?:"
    r"(?:please\s+|now\s+|immediately\s+|you\s+(?:must|should|need\s+to)\s+)?"
    r"(?:call|invoke|use|run|execute|trigger)\s+(?:the\s+)?"
    r"(?:`?[A-Za-z][\w./:-]{1,64}`?\s+)?(?:tool|function|command|action)\b"
    r"|(?:call|invoke|use)\s+`?[A-Za-z][\w./:-]{2,64}`?\s*(?:\(|with\b|to\b)"
    r"|(?:run|execute)\s+(?:bash|sh|zsh|powershell|cmd|shell|terminal)\b"
    r"|send(?:_|\s+)(?:email|mail|message|slack|telegram|tweet)\b"
    r"|exfiltrat(?:e|ion)|upload\s+(?:the\s+)?(?:secrets?|credentials?|keys?|files?)\b"
    r")"
)

EXFIL_HOST_RE = re.compile(
    r"(?i)\b(?:https?://)?(?:"
    r"webhook\.site|requestbin(?:\.com)?|pipedream\.net|hookbin\.com|beeceptor\.com|"
    r"ngrok(?:-free)?\.(?:app|io|dev)|burpcollaborator\.net|oastify\.com|interact\.sh|"
    r"evil(?:-)?(?:exfil|callback|collect)[.\w-]*|exfil[.\w-]+|"
    r"pastebin\.com|paste\.ee"
    r")/[^\s)\"'<>\]]*",
)

EXFIL_PHRASE_RE = re.compile(
    r"(?is)(?:"
    r"(?:fetch|get|post|put|send|upload|forward|exfiltrate|beacon|callback)\s+"
    r"(?:(?:this|the|all|any|those)\s+)?(?:data|content|secrets?|credentials?|keys?|tokens?|files?|history|conversation)\s+"
    r"(?:to|at|via)\s+(?:https?://|www\.)"
    r"|https?://[^\s)\"'<>\]]+[?&](?:data|secret|token|key|payload|q|content)="
    r")"
)

HARVEST_RE = re.compile(
    r"(?is)(?:"
    r"(?:paste|provide|include|send|share|reveal|print|dump|echo)\s+"
    r"(?:(?:me|us|here)\s+)?"
    r"(?:your|the|all)?\s*"
    r"(?:api\s*keys?|access\s*tokens?|secrets?|credentials?|passwords?|"
    r"private\s*keys?|ssh\s*keys?|\.env(?:\s+file)?|aws\s*keys?|"
    r"contents?\s+of\s+(?:~\/\.ssh|\/etc\/passwd|\.env))"
    r"|cat\s+(?:~\/\.ssh\/|\/home\/|\.env\b)"
    r")"
)

CONCEAL_RE = re.compile(
    r"(?is)(?:"
    r"(?:do\s+not|don't|never)\s+(?:tell|inform|notify|mention\s+to|alert)\s+(?:the\s+)?user"
    r"|hide\s+(?:this|it|the\s+(?:action|step|request))\s+from\s+(?:the\s+)?user"
    r"|(?:silently|quietly|covertly)\s+(?:do|perform|execute|run|call|send)"
    r"|without\s+(?:telling|informing|asking|notifying)\s+(?:the\s+)?user"
    r")"
)

MD_IMG_RE = re.compile(
    r"!\[([^\]]*)\]\(\s*<?((?:https?:)?//[^\s)\"'<>\]]+|[a-zA-Z][\w+.-]*:[^\s)]+)>?",
)
HTML_SRC_RE = re.compile(
    r"<\s*(?:img|iframe|script|link|embed|object|video|audio|source)\b[^>]*?"
    r"\b(?:src|href|data|poster)\s*=\s*[\"']?((?:https?:)?//[^\"'\s>]+)",
    re.I,
)

B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])")
HEX_RE = re.compile(r"(?<![0-9a-fA-F])((?:(?:0x)?[0-9a-fA-F]{2}[\s,]*){20,})(?![0-9a-fA-F])")
INSTR_HINT_RE = re.compile(
    r"(?is)\b(?:ignore|system|instruction|override|jailbreak|exfiltrat|api[_ ]?key|"
    r"call\s+the\s+tool|you\s+must|developer\s+mode)\b"
)

FAKE_SECRET_HINTS = (
    "FAKE-EXAMPLE-", "EXAMPLE-", "REDACTED", "YOUR_", "xxx", "placeholder",
    "dummy", "sample-", "test-", "not-a-real-",
)


class Result:
    __slots__ = ("idx", "tool", "text", "cid", "error")

    def __init__(self, idx, tool, text, cid=None, error=False):
        self.idx = idx
        self.tool = tool or "?"
        self.text = text if isinstance(text, str) else _text_of(text)
        self.cid = cid
        self.error = bool(error)


class Finding:
    def __init__(self, rule, source, tool, turn, message, excerpt="", severity=None):
        self.rule = rule
        self.source = source
        self.tool = tool
        self.turn = turn
        self.message = message
        self.excerpt = excerpt
        self.severity = severity or RULES[rule][0]

    def to_dict(self):
        return {
            "rule": self.rule,
            "severity": self.severity,
            "title": RULES[self.rule][1],
            "source": self.source,
            "tool": self.tool,
            "turn": self.turn,
            "message": self.message,
            "excerpt": self.excerpt,
        }


def _text_of(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, dict):
                if b.get("type") in ("text", "output_text", "input_text"):
                    parts.append(b.get("text", ""))
                elif "text" in b:
                    parts.append(str(b.get("text") or ""))
                elif "content" in b:
                    parts.append(_text_of(b["content"]))
            elif isinstance(b, str):
                parts.append(b)
        return "\n".join(parts)
    if content is None:
        return ""
    return json.dumps(content, default=str)


def _line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def _excerpt(text, idx, width=72):
    if idx < 0:
        idx = 0
    start = max(0, idx - 20)
    end = min(len(text), idx + width)
    snip = text[start:end].replace("\n", "\\n")
    if start:
        snip = "…" + snip
    if end < len(text):
        snip = snip + "…"
    # mask anything that looks like a real secret shape while keeping FAKE-EXAMPLE-*
    return snip[:160]


def _looks_fake(s):
    low = s.lower()
    return any(h.lower() in low for h in FAKE_SECRET_HINTS)


def parse_results(data):
    """Extract tool Result objects from an OpenAI / Anthropic / generic transcript."""
    if isinstance(data, dict):
        for k in ("messages", "events", "steps", "transcript", "items"):
            if isinstance(data.get(k), list):
                data = data[k]
                break
        else:
            # bare single tool result document
            if any(k in data for k in ("result", "output", "content")) and (
                data.get("tool") or data.get("tool_name") or data.get("role") == "tool"
            ):
                data = [data]
            else:
                data = [data]

    results = []
    pending = {}  # tool_call_id -> (tool_name, call_ordinal_placeholder)
    call_names = {}
    ordinal = 0

    for ev in data:
        if not isinstance(ev, dict):
            continue
        role = ev.get("role")

        if role == "assistant" and ev.get("tool_calls"):
            for tc in ev["tool_calls"]:
                fn = tc.get("function", tc)
                tid = tc.get("id")
                name = fn.get("name") or "?"
                if tid:
                    call_names[tid] = name
            continue

        if role == "tool":
            tid = ev.get("tool_call_id")
            name = ev.get("name") or call_names.get(tid) or "?"
            ordinal += 1
            results.append(Result(ordinal, name, _text_of(ev.get("content")), tid, ev.get("is_error")))
            continue

        # Anthropic-style content blocks on any role
        content = ev.get("content")
        if isinstance(content, list) and any(
            isinstance(b, dict) and b.get("type") in ("tool_use", "tool_result") for b in content
        ):
            for b in content:
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "tool_use":
                    if b.get("id"):
                        call_names[b["id"]] = b.get("name") or "?"
                elif b.get("type") == "tool_result":
                    tid = b.get("tool_use_id")
                    name = call_names.get(tid) or "?"
                    ordinal += 1
                    results.append(
                        Result(ordinal, name, _text_of(b.get("content")), tid, b.get("is_error"))
                    )
            continue

        # generic tool event with result/output
        tool = ev.get("tool") or ev.get("tool_name")
        if not tool and ev.get("type") in ("tool_result", "function_response", "tool_response"):
            tool = ev.get("name") or call_names.get(ev.get("tool_call_id") or ev.get("id")) or "?"
        if tool and any(k in ev for k in ("result", "output", "content", "error")):
            text = ev.get("result", ev.get("output", ev.get("content")))
            if ev.get("error") not in (None, "", False) and not text:
                text = ev.get("error")
                err = True
            else:
                err = bool(ev.get("is_error")) or (ev.get("error") not in (None, "", False))
            ordinal += 1
            results.append(Result(ordinal, tool, _text_of(text), ev.get("id"), err))
            continue

    return results


def find_hidden_unicode(text):
    hits = []
    for i, ch in enumerate(text):
        o = ord(ch)
        if ch in ZERO_WIDTH:
            hits.append((i, "zero-width", unicodedata.name(ch, "U+%04X" % o)))
        elif ch in BIDI:
            hits.append((i, "bidi", unicodedata.name(ch, "U+%04X" % o)))
        elif TAG_LO <= o <= TAG_HI:
            hits.append((i, "TAG", "U+%05X" % o))
    return hits


def decode_candidates(text):
    """Yield (kind, decoded_str, start_idx) for base64/hex blobs that look instructive."""
    out = []
    for m in B64_RE.finditer(text):
        raw = m.group(1)
        if _looks_fake(raw):
            continue
        pad = (-len(raw)) % 4
        try:
            dec = base64.b64decode(raw + ("=" * pad), validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            s = dec.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(s) >= 12 and INSTR_HINT_RE.search(s):
            out.append(("base64", s, m.start()))
    for m in HEX_RE.finditer(text):
        hx = re.sub(r"[^0-9a-fA-F]", "", m.group(1))
        if len(hx) < 40 or len(hx) % 2:
            continue
        try:
            dec = bytes.fromhex(hx)
            s = dec.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if len(s) >= 12 and INSTR_HINT_RE.search(s):
            out.append(("hex", s, m.start()))
    return out


def scan_text(text, source, tool, turn, disabled=None):
    """Run TR01–TR09 against one tool-result body."""
    disabled = set(disabled or [])
    findings = []
    if not text:
        return findings

    def add(rule, msg, idx=0):
        if rule in disabled:
            return
        findings.append(Finding(rule, source, tool, turn, msg, _excerpt(text, idx)))

    if "TR01" not in disabled:
        for m in OVERRIDE_RE.finditer(text):
            add("TR01", "override/jailbreak phrasing at line %d" % _line_of(text, m.start()), m.start())
            break  # one per result is enough

    if "TR02" not in disabled:
        for m in ROLE_RE.finditer(text):
            add("TR02", "fake role/system token %r at line %d" % (m.group(0)[:40], _line_of(text, m.start())),
                m.start())
            break

    if "TR03" not in disabled:
        hidden = find_hidden_unicode(text)
        if hidden:
            kinds = sorted({k for _, k, _ in hidden})
            add("TR03", "%d hidden Unicode codepoint(s) (%s), first at line %d"
                % (len(hidden), ", ".join(kinds), _line_of(text, hidden[0][0])), hidden[0][0])

    if "TR04" not in disabled:
        for m in ACTION_BAIT_RE.finditer(text):
            add("TR04", "action/tool-chaining bait at line %d: %r"
                % (_line_of(text, m.start()), m.group(0)[:60]), m.start())
            break

    if "TR05" not in disabled:
        hit = False
        for m in EXFIL_HOST_RE.finditer(text):
            add("TR05", "known callback/exfil-style host at line %d: %s"
                % (_line_of(text, m.start()), m.group(0)[:80]), m.start())
            hit = True
            break
        if not hit:
            for m in EXFIL_PHRASE_RE.finditer(text):
                add("TR05", "exfil/callback phrasing at line %d" % _line_of(text, m.start()), m.start())
                break

    if "TR06" not in disabled:
        for kind, decoded, idx in decode_candidates(text):
            add("TR06", "%s blob decodes to instruction-like text at line %d: %r"
                % (kind, _line_of(text, idx), decoded[:60]), idx)
            break

    if "TR07" not in disabled:
        for m in HARVEST_RE.finditer(text):
            add("TR07", "credential harvest request at line %d: %r"
                % (_line_of(text, m.start()), m.group(0)[:60]), m.start())
            break

    if "TR08" not in disabled:
        for m in CONCEAL_RE.finditer(text):
            add("TR08", "conceal-from-user phrasing at line %d" % _line_of(text, m.start()), m.start())
            break

    if "TR09" not in disabled:
        for m in MD_IMG_RE.finditer(text):
            add("TR09", "markdown image loads external URL at line %d: %s"
                % (_line_of(text, m.start()), m.group(2)[:80]), m.start())
            break
        else:
            for m in HTML_SRC_RE.finditer(text):
                add("TR09", "HTML element auto-loads URL at line %d: %s"
                    % (_line_of(text, m.start()), m.group(1)[:80]), m.start())
                break

    return findings


def load_raw(path):
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def load_jsonish(text):
    try:
        return json.loads(text), "json"
    except ValueError:
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                return None, "text"
        return (rows if rows else None), ("jsonl" if rows else "text")


def extract_from_path(path, as_result=False, tool_name="file"):
    text = load_raw(path)
    if as_result:
        return [Result(1, tool_name, text)]
    data, kind = load_jsonish(text)
    if kind == "text" or data is None:
        # plain file treated as one synthetic tool result
        return [Result(1, tool_name, text)]
    results = parse_results(data)
    if not results and isinstance(data, (dict, list)):
        # JSON but no tool-result shape: treat whole body as one result
        results = [Result(1, tool_name, text if isinstance(data, list) and not data
                          else json.dumps(data, indent=2) if not isinstance(data, str) else data)]
    return results


def iter_paths(paths):
    for p in paths:
        if p == "-":
            yield p
            continue
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in sorted(files):
                    if f.endswith((".json", ".jsonl", ".txt", ".md", ".html", ".log")):
                        yield os.path.join(root, f)
        else:
            yield p


def scan_paths(paths, as_result=False, tool_name="file", tools_filter=None, disable=None):
    findings, stats = [], []
    filt = set(t.lower() for t in (tools_filter or []))
    for path in iter_paths(paths):
        try:
            results = extract_from_path(path, as_result=as_result, tool_name=tool_name)
        except OSError as e:
            sys.stderr.write("resultguard: cannot read %s: %s\n" % (path, e))
            continue
        if filt:
            results = [r for r in results if r.tool.lower() in filt]
        stats.append({
            "source": path,
            "results": len(results),
            "bytes": sum(len(r.text) for r in results),
        })
        for r in results:
            findings.extend(scan_text(r.text, path, r.tool, r.idx, disabled=disable))
    return findings, stats


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="resultguard",
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("paths", nargs="*", default=["-"],
                    help="transcript/result files or dirs, '-' for stdin")
    ap.add_argument("--as-result", action="store_true",
                    help="treat each file body as one tool result (skip transcript parsing)")
    ap.add_argument("--tool-name", default="file",
                    help="tool name used with --as-result / plain files (default: file)")
    ap.add_argument("--tools", nargs="+", metavar="NAME",
                    help="only scan results from these tool names")
    ap.add_argument("--disable", nargs="+", metavar="RULE",
                    help="disable rule ids (e.g. TR09)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="info")
    ap.add_argument("--fail-on", choices=SEVERITIES[1:] + ["any", "none"], default="high",
                    help="exit 1 if any finding >= this (default: high)")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version="resultguard " + VERSION)
    a = ap.parse_args(argv)

    if a.list_rules:
        for r, (sev, title) in sorted(RULES.items()):
            print("%s  %-8s %s" % (r, sev, title))
        return 0

    disable = set(a.disable or [])
    unknown = disable - set(RULES)
    if unknown:
        ap.error("unknown rules: %s" % ", ".join(sorted(unknown)))

    findings, stats = scan_paths(
        a.paths, as_result=a.as_result, tool_name=a.tool_name,
        tools_filter=a.tools, disable=disable,
    )
    if not stats and a.paths != ["-"]:
        sys.stderr.write("resultguard: no readable inputs\n")
        return 2
    shown = [f for f in findings if SEV_RANK[f.severity] >= SEV_RANK[a.min_severity]]
    shown.sort(key=lambda f: (f.source, f.turn, -SEV_RANK[f.severity], f.rule))

    if a.json:
        print(json.dumps({
            "version": VERSION,
            "sources": stats,
            "findings": [f.to_dict() for f in shown],
        }, indent=2))
    else:
        for s in stats:
            print("%s: %d tool result(s), %d bytes scanned" % (s["source"], s["results"], s["bytes"]))
        if not shown:
            print("No findings at or above --min-severity %s." % a.min_severity)
        for f in shown:
            print("[%s] %s %s  tool=%s turn=#%d  %s"
                  % (f.severity.upper(), f.rule, f.source, f.tool, f.turn, f.message))
            if f.excerpt:
                print("         excerpt: %s" % f.excerpt)
        if shown:
            print("Note: resultguard is heuristic. Benign docs can match; tune --disable / --tools.")

    if a.fail_on == "none":
        return 0
    threshold = SEV_RANK["info"] if a.fail_on == "any" else SEV_RANK[a.fail_on]
    if any(SEV_RANK[f.severity] >= threshold for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
