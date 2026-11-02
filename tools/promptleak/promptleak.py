#!/usr/bin/env python3
"""promptleak: offline system-prompt leakage detector for LLM app transcripts and outputs.

Compares what a model said (assistant text and tool-call arguments) against the system /
developer prompt it was given, and reports verbatim or lightly-obfuscated reproduction:
bulk leaks, long verbatim spans, leaked "confidential" lines, protected strings, and leaks
hidden in base64/hex. Also notes user turns that look like prompt-extraction attempts.
Standard library only, no network.
"""
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
    "PL01": ("critical", "Bulk leak: a large share of the system prompt was reproduced"),
    "PL02": ("high", "Long verbatim span of the system prompt reproduced"),
    "PL03": ("medium", "Short verbatim fragment(s) of the system prompt reproduced"),
    "PL04": ("high", "A line marked confidential/secret in the prompt was reproduced"),
    "PL05": ("critical", "A protected string (--protect) appeared in output"),
    "PL06": ("high", "System prompt content hidden in base64/hex encoded output"),
    "PL07": ("info", "User turn looks like a prompt-extraction attempt"),
}

ZW = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]")
WORD = re.compile(r"[a-z0-9]+(?:'[a-z0-9]+)?")
CONF_LINE = re.compile(
    r"\b(confidential|secret|internal[- ]only|do not (?:reveal|share|disclose|repeat)|"
    r"never (?:reveal|share|disclose|mention)|private|password|api[ _-]?key|token|codename)\b", re.I)
B64 = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){16,}\b")
EXTRACT = re.compile(
    r"(?:(?:repeat|print|output|show|reveal|display|tell me|write out|dump|recite|give me)\b.{0,40}?"
    r"\b(?:system prompt|initial (?:prompt|instructions)|instructions above|words above|text above|"
    r"your (?:instructions|prompt|rules|guidelines)|everything above|developer message|hidden prompt)|"
    r"ignore (?:all |the )?(?:previous|prior|above) instructions|"
    r"what (?:is|was|are) your (?:system prompt|instructions|initial prompt)|"
    r"(?:start|begin) (?:your (?:reply|answer|response) )?with ['\"]?you are|"
    r"in a code ?block.{0,30}(?:above|instructions|prompt))", re.I | re.S)


# ---------------------------------------------------------------- text normalization
def normalize(text):
    t = unicodedata.normalize("NFKC", text or "")
    t = ZW.sub("", t).lower()
    t = t.replace("\u2019", "'").replace("\u2018", "'")
    return t


def tokens(text):
    return WORD.findall(normalize(text))


def shingles(toks, n):
    return {tuple(toks[i:i + n]) for i in range(len(toks) - n + 1)}


class Prompt:
    def __init__(self, text, label, n):
        self.text = text
        self.label = label
        self.n = n
        self.toks = tokens(text)
        self.index = {}
        for i in range(len(self.toks) - n + 1):
            self.index.setdefault(tuple(self.toks[i:i + n]), []).append(i)
        self.conf_lines = []
        for ln in text.splitlines():
            if CONF_LINE.search(ln):
                lt = tokens(ln)
                if len(lt) >= 3:
                    self.conf_lines.append((ln.strip(), lt))


def match_spans(prompt, out_toks):
    """Return merged list of (out_start, out_end, prompt_positions_set) verbatim spans."""
    n = prompt.n
    hits = []  # output positions where an n-gram matches
    covered = set()
    for i in range(len(out_toks) - n + 1):
        pos = prompt.index.get(tuple(out_toks[i:i + n]))
        if pos:
            hits.append(i)
            for p in pos:
                covered.update(range(p, p + n))
    spans = []
    for i in hits:
        if spans and i <= spans[-1][1]:
            spans[-1][1] = i + n
        else:
            spans.append([i, i + n])
    return [(a, b) for a, b in spans], covered


def contains_seq(hay, needle):
    if not needle or len(needle) > len(hay):
        return False
    first = needle[0]
    for i in range(len(hay) - len(needle) + 1):
        if hay[i] == first and hay[i:i + len(needle)] == needle:
            return True
    return False


def decoded_blobs(text):
    out = []
    for m in B64.finditer(text):
        s = m.group(0)
        pad = s.replace("-", "+").replace("_", "/") + "=" * (-len(s) % 4)
        try:
            d = base64.b64decode(pad, validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if d and sum(c.isprintable() or c in "\n\t" for c in d) >= 0.9 * len(d):
            out.append(("base64", d))
    for m in HEX.finditer(text):
        try:
            d = bytes.fromhex(m.group(0)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if d.isprintable():
            out.append(("hex", d))
    return out


def snippet(toks, a, b, limit=14):
    s = toks[a:b]
    t = " ".join(s[:limit])
    return t + (" ..." if len(s) > limit else "")


def _f(rule, source, detail, snip="", severity=None, **extra):
    d = {"rule": rule, "severity": severity or RULES[rule][0], "title": RULES[rule][1],
         "source": source, "detail": detail, "snippet": snip}
    d.update(extra)
    return d


def scan_output(text, prompts, source, protect=(), span_high=25, bulk=0.5, partial_high=0.2):
    findings = []
    out_toks = tokens(text)
    for p in prompts:
        if len(p.toks) < p.n:
            continue
        spans, covered = match_spans(p, out_toks)
        cov = len(covered) / len(p.toks)
        longest = max((b - a for a, b in spans), default=0)
        if spans:
            a, b = max(spans, key=lambda s: s[1] - s[0])
            snip = snippet(out_toks, a, b)
            base = dict(prompt=p.label, coverage=round(cov, 3), longest_span_words=longest,
                        spans=len(spans))
            if cov >= bulk:
                findings.append(_f("PL01", source, "%.0f%% of prompt '%s' reproduced (%d spans, longest %d words)"
                                   % (cov * 100, p.label, len(spans), longest), snip, **base))
            elif longest >= span_high or cov >= partial_high:
                findings.append(_f("PL02", source, "verbatim span of %d words from prompt '%s' (%.0f%% coverage)"
                                   % (longest, p.label, cov * 100), snip, **base))
            else:
                findings.append(_f("PL03", source, "%d fragment(s) of prompt '%s', longest %d words (%.0f%% coverage)"
                                   % (len(spans), p.label, longest, cov * 100), snip, **base))
        for line, lt in p.conf_lines:
            need = lt if len(lt) <= p.n else None
            hit = contains_seq(out_toks, need) if need else bool(
                set(shingles(lt, p.n)) & set(shingles(out_toks, p.n)))
            if hit:
                findings.append(_f("PL04", source, "confidential-marked line from prompt '%s' reproduced" % p.label,
                                   line[:100], prompt=p.label))
        for kind, dec in decoded_blobs(text):
            dt = tokens(dec)
            if len(dt) >= p.n and shingles(dt, p.n) & set(p.index):
                findings.append(_f("PL06", source, "%s-encoded text decodes to content of prompt '%s'"
                                   % (kind, p.label), " ".join(dt[:14]), prompt=p.label))
    for s in protect:
        st = tokens(s)
        if (st and contains_seq(out_toks, st)) or (s and s.lower() in normalize(text)):
            findings.append(_f("PL05", source, "protected string appeared in output", mask(s)))
        else:
            for kind, dec in decoded_blobs(text):
                if s.lower() in normalize(dec):
                    findings.append(_f("PL05", source, "protected string appeared %s-encoded" % kind, mask(s)))
                    break
    return findings


def mask(s):
    return s if len(s) <= 6 else s[:3] + "*" * (len(s) - 6) + s[-3:]


# ---------------------------------------------------------------- transcript parsing
def _text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for c in content:
            if isinstance(c, str):
                parts.append(c)
            elif isinstance(c, dict):
                if isinstance(c.get("text"), str):
                    parts.append(c["text"])
                elif c.get("type") == "tool_use":
                    parts.append(json.dumps(c.get("input", {}), ensure_ascii=False))
        return "\n".join(parts)
    if isinstance(content, dict) and isinstance(content.get("text"), str):
        return content["text"]
    return ""


def _tool_args(msg):
    out = []
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function", tc) if isinstance(tc, dict) else {}
        args = fn.get("arguments", "")
        name = fn.get("name", "?")
        out.append((name, args if isinstance(args, str) else json.dumps(args, ensure_ascii=False)))
    fc = msg.get("function_call")
    if isinstance(fc, dict):
        out.append((fc.get("name", "?"), str(fc.get("arguments", ""))))
    if isinstance(msg.get("content"), list):
        for c in msg["content"]:
            if isinstance(c, dict) and c.get("type") == "tool_use":
                out.append((c.get("name", "?"), json.dumps(c.get("input", {}), ensure_ascii=False)))
    return out


def iter_messages(obj):
    """Yield (role, text, [(tool, args)]) from OpenAI/Anthropic/generic shapes."""
    if isinstance(obj, list):
        for x in obj:
            yield from iter_messages(x)
        return
    if not isinstance(obj, dict):
        return
    if isinstance(obj.get("system"), (str, list)):  # Anthropic top-level system
        yield "system", _text(obj["system"]), []
    if "role" in obj:
        role = str(obj.get("role")).lower()
        content = obj.get("content", obj.get("text"))
        text = _text(content) if not (isinstance(content, list) and any(
            isinstance(c, dict) and c.get("type") == "tool_use" for c in content)) else "\n".join(
            c.get("text", "") for c in content if isinstance(c, dict) and isinstance(c.get("text"), str))
        yield role, text, _tool_args(obj)
        return
    for key in ("messages", "choices", "output", "data", "transcript", "turns"):
        if key in obj:
            yield from iter_messages(obj[key])
            return
    if "message" in obj:
        yield from iter_messages(obj["message"])
    elif obj.get("type") == "message" and "content" in obj:
        yield "assistant", _text(obj["content"]), _tool_args(obj)


def load_doc(path):
    if path == "-":
        raw = sys.stdin.read()
        ext = ""
    else:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        try:
            return "json", [json.loads(raw)]
        except json.JSONDecodeError as e:
            raise ValueError("%s: invalid JSON (%s)" % (path, e))
    if ext == ".jsonl":
        docs = []
        for n, line in enumerate(raw.splitlines(), 1):
            if line.strip():
                try:
                    docs.append(json.loads(line))
                except json.JSONDecodeError as e:
                    raise ValueError("%s:%d: invalid JSON (%s)" % (path, n, e))
        return "json", docs
    return "text", raw


def load_prompts(paths, n):
    prompts = []
    for p in paths:
        kind, data = load_doc(p)
        if kind == "text":
            prompts.append(Prompt(data, os.path.basename(p), n))
        else:
            k = 0
            for role, text, _ in iter_messages(data):
                if role in ("system", "developer") and text.strip():
                    k += 1
                    prompts.append(Prompt(text, "%s#system%d" % (os.path.basename(p), k), n))
            if not k:
                raise ValueError("%s: no system/developer message found" % p)
    return prompts


def collect(paths):
    out = []
    for p in paths:
        if p != "-" and os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                for f in sorted(files):
                    if os.path.splitext(f)[1].lower() in (".txt", ".md", ".json", ".jsonl", ".log", ".out"):
                        out.append(os.path.join(root, f))
        else:
            out.append(p)
    return out


def scan_path(path, ext_prompts, args):
    findings = []
    kind, data = load_doc(path)
    label = "<stdin>" if path == "-" else path
    if kind == "text":
        if not ext_prompts:
            raise ValueError("%s: plain text needs --prompt" % label)
        return scan_output(data, ext_prompts, label, args.protect, args.span, args.bulk, args.partial)
    msgs = list(iter_messages(data))
    prompts = list(ext_prompts)
    if not prompts:
        k = 0
        for role, text, _ in msgs:
            if role in ("system", "developer") and text.strip():
                k += 1
                prompts.append(Prompt(text, "system%d" % k, args.n))
    for i, (role, text, tools) in enumerate(msgs, 1):
        if role in ("user", "human") and text and EXTRACT.search(text):
            m = EXTRACT.search(text)
            findings.append(_f("PL07", "%s#msg%d(user)" % (label, i), "user turn resembles a prompt-extraction request",
                               m.group(0)[:100]))
        if role not in ("assistant", "model", "ai"):
            continue
        if text:
            findings += scan_output(text, prompts, "%s#msg%d(assistant)" % (label, i),
                                    args.protect, args.span, args.bulk, args.partial)
        if not args.no_tools:
            for name, a in tools:
                findings += scan_output(a, prompts, "%s#msg%d(tool:%s)" % (label, i, name),
                                        args.protect, args.span, args.bulk, args.partial)
    if not prompts and not args.protect:
        findings.append(_f("PL07", label, "no system prompt found and no --prompt/--protect given; nothing to compare",
                           severity="info"))
    return findings


def main(argv=None):
    ap = argparse.ArgumentParser(prog="promptleak", description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="+", help="transcripts (.json/.jsonl), text outputs, directories, or - for stdin")
    ap.add_argument("-p", "--prompt", action="append", default=[],
                    help="system prompt file (text, or JSON/JSONL transcript whose system messages are used); repeatable")
    ap.add_argument("--protect", action="append", default=[], help="literal string that must never appear (repeatable)")
    ap.add_argument("-n", type=int, default=8, help="shingle size in words (default 8)")
    ap.add_argument("--span", type=int, default=25, help="verbatim span length for PL02 (default 25 words)")
    ap.add_argument("--bulk", type=float, default=0.5, help="coverage fraction for PL01 (default 0.5)")
    ap.add_argument("--partial", type=float, default=0.2, help="coverage fraction for PL02 (default 0.2)")
    ap.add_argument("--no-tools", action="store_true", help="do not scan tool-call arguments")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="info")
    ap.add_argument("--fail-on", choices=SEVERITIES[1:] + ["none"], default="medium")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--version", action="version", version="promptleak " + VERSION)
    args = ap.parse_args(argv)
    if args.n < 3:
        ap.error("-n must be at least 3")
    try:
        prompts = load_prompts(args.prompt, args.n)
        findings = []
        for p in collect(args.paths):
            findings += scan_path(p, prompts, args)
    except (OSError, ValueError) as e:
        sys.stderr.write("promptleak: error: %s\n" % e)
        return 2
    findings = [f for f in findings if SEV_RANK[f["severity"]] >= SEV_RANK[args.min_severity]]
    findings.sort(key=lambda f: -SEV_RANK[f["severity"]])
    if args.json:
        print(json.dumps({"tool": "promptleak", "version": VERSION, "findings": findings}, indent=2))
    else:
        for f in findings:
            print("%-8s %s %s\n         %s" % (f["severity"].upper(), f["rule"], f["source"], f["detail"]))
            if f["snippet"]:
                print("         > %s" % f["snippet"])
        counts = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        print("%d finding(s)%s" % (len(findings), "" if not counts else ": " + ", ".join(
            "%d %s" % (counts[s], s) for s in reversed(SEVERITIES) if s in counts)))
    if args.fail_on == "none":
        return 0
    return 1 if any(SEV_RANK[f["severity"]] >= SEV_RANK[args.fail_on] for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
