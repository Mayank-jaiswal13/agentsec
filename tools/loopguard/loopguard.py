#!/usr/bin/env python3
"""loopguard: offline detector of runaway loops and retry storms in AI agent transcripts.

Agents that get stuck burn tokens, hammer APIs and can repeat side effects (sending the same
email ten times, re-running a deploy). loopguard reads saved transcripts and flags identical
repeated tool calls, A-B-A-B cycles, error retry storms, stalled polling (same result again
and again), call-count blowups, single-tool domination and runs that end mid-tool-call.

Standard library only. Never runs an agent or contacts a model.
"""
import argparse
import hashlib
import json
import os
import re
import sys

VERSION = "0.1.0"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "LG01": ("high", "Identical tool call (same tool + same arguments) repeated back-to-back"),
    "LG02": ("high", "Repeating cycle of tool calls (e.g. A,B,A,B,A,B)"),
    "LG03": ("high", "Error retry storm: the same tool failing repeatedly in a row"),
    "LG04": ("medium", "Stalled progress: the same tool returning the identical result repeatedly"),
    "LG05": ("medium", "Run exceeds the tool-call budget (--max-calls)"),
    "LG06": ("low", "One tool dominates the run"),
    "LG07": ("low", "Run ends on a tool call/result with no final assistant answer"),
    "LG08": ("critical", "Repeated side-effecting call (send/post/delete/pay/deploy...) with identical arguments"),
}

SIDE_EFFECT_WORDS = {"send", "post", "create", "delete", "remove", "drop", "pay", "charge", "transfer",
                     "deploy", "publish", "push", "merge", "write", "update", "submit", "email", "tweet",
                     "order", "purchase", "refund", "execute", "exec", "run", "shell", "bash", "rm"}


def tool_words(name):
    """Split a tool name like 'gmail.sendEmail' or 'create_issue' into lowercase words."""
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name or "")
    return [w.lower() for w in re.split(r"[^A-Za-z0-9]+", name) if w]


def is_side_effect(name):
    return any(w in SIDE_EFFECT_WORDS for w in tool_words(name))


ERROR_RE = re.compile(r"^\s*(error|exception|traceback|failed|failure|fatal)\b|\b(timed? ?out|rate.?limit|"
                      r"status(?: code)?[:= ]+[45]\d\d|HTTP [45]\d\d|permission denied|not found)\b", re.I)


class Call:
    __slots__ = ("idx", "tool", "args", "key", "result", "error", "cid")

    def __init__(self, idx, tool, args, cid=None):
        self.idx, self.tool, self.cid = idx, tool or "?", cid
        if isinstance(args, str):
            try:
                args = json.loads(args) if args.strip() else {}
            except ValueError:
                pass
        self.args = args
        self.key = self.tool + "\x00" + json.dumps(args, sort_keys=True, default=str)
        self.result, self.error = None, False

    def set_result(self, text, is_error=False):
        if not isinstance(text, str):
            text = json.dumps(text, sort_keys=True, default=str)
        self.result = text
        self.error = bool(is_error) or bool(ERROR_RE.search(text[:300]))


class Finding:
    def __init__(self, rule, source, message, calls=None, severity=None):
        self.rule, self.source, self.message = rule, source, message
        self.severity = severity or RULES[rule][0]
        self.calls = calls or []

    def to_dict(self):
        return {"rule": self.rule, "severity": self.severity, "title": RULES[self.rule][1],
                "source": self.source, "message": self.message, "calls": self.calls}


def _text_of(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out = []
        for b in content:
            if isinstance(b, dict):
                if b.get("type") in ("text", "output_text", "input_text"):
                    out.append(b.get("text", ""))
                elif "content" in b:
                    out.append(_text_of(b["content"]))
            elif isinstance(b, str):
                out.append(b)
        return "\n".join(out)
    if content is None:
        return ""
    return json.dumps(content, default=str)


def parse_events(data):
    """Return (calls, ended_with_answer) from an OpenAI, Anthropic or generic transcript."""
    if isinstance(data, dict):
        for k in ("messages", "events", "steps", "transcript", "items"):
            if isinstance(data.get(k), list):
                data = data[k]
                break
        else:
            data = [data]
    calls, by_id, last = [], {}, None  # last: "call" | "result" | "answer"
    for ev in data:
        if not isinstance(ev, dict):
            continue
        role = ev.get("role")
        # OpenAI chat: assistant.tool_calls + role=tool
        if role == "assistant" and ev.get("tool_calls"):
            for tc in ev["tool_calls"]:
                fn = tc.get("function", tc)
                c = Call(len(calls), fn.get("name"), fn.get("arguments", {}), tc.get("id"))
                calls.append(c)
                by_id[c.cid] = c
            last = "call"
            continue
        if role == "tool":
            c = by_id.get(ev.get("tool_call_id")) or (calls[-1] if calls else None)
            if c:
                c.set_result(_text_of(ev.get("content")), ev.get("is_error"))
            last = "result"
            continue
        # Anthropic content blocks
        if isinstance(ev.get("content"), list) and any(
                isinstance(b, dict) and b.get("type") in ("tool_use", "tool_result") for b in ev["content"]):
            for b in ev["content"]:
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "tool_use":
                    c = Call(len(calls), b.get("name"), b.get("input", {}), b.get("id"))
                    calls.append(c)
                    by_id[c.cid] = c
                    last = "call"
                elif b.get("type") == "tool_result":
                    c = by_id.get(b.get("tool_use_id")) or (calls[-1] if calls else None)
                    if c:
                        c.set_result(_text_of(b.get("content")), b.get("is_error"))
                    last = "result"
            continue
        # generic: {"tool": ..., "args"/"input": ..., "result"/"output"/"error": ...}
        tool = ev.get("tool") or ev.get("tool_name") or (ev.get("name") if ev.get("type") in ("tool_call", "function_call") else None)
        if tool:
            c = Call(len(calls), tool, ev.get("args", ev.get("arguments", ev.get("input", {}))), ev.get("id"))
            calls.append(c)
            if ev.get("error") not in (None, "", False):
                c.set_result(_text_of(ev.get("error")), True)
                last = "result"
            elif any(k in ev for k in ("result", "output")):
                c.set_result(_text_of(ev.get("result", ev.get("output"))), ev.get("is_error"))
                last = "result"
            else:
                last = "call"
            continue
        if role == "assistant" or ev.get("type") in ("final", "answer", "message"):
            if _text_of(ev.get("content", ev.get("text"))).strip():
                last = "answer"
    return calls, last == "answer"


def _runs(seq):
    """Yield (start, length, value) for maximal runs of equal consecutive values."""
    i = 0
    while i < len(seq):
        j = i
        while j + 1 < len(seq) and seq[j + 1] == seq[i]:
            j += 1
        yield i, j - i + 1, seq[i]
        i = j + 1


def _short(args, n=80):
    s = json.dumps(args, sort_keys=True, default=str)
    return s if len(s) <= n else s[:n - 3] + "..."


def analyze(calls, source, answered=True, repeat=3, max_calls=50, dominance=0.7, dom_min=20):
    out = []
    keys = [c.key for c in calls]
    covered = set()
    for start, n, _ in _runs(keys):
        if n >= repeat:
            c = calls[start]
            idxs = list(range(start, start + n))
            covered.update(idxs)
            side = is_side_effect(c.tool)
            rule = "LG08" if side else "LG01"
            out.append(Finding(rule, source, "%s called %d times in a row with identical args %s (calls #%d-#%d)"
                               % (c.tool, n, _short(c.args), start + 1, start + n), idxs))
    # cycles of period 2..4 repeated >= repeat times
    p_seen = set()
    for p in (2, 3, 4):
        i = 0
        while i + p * repeat <= len(keys):
            pat = keys[i:i + p]
            if len(set(pat)) < 2:
                i += 1
                continue
            reps = 1
            while keys[i + reps * p:i + (reps + 1) * p] == pat:
                reps += 1
            if reps >= repeat and not any(j in p_seen for j in range(i, i + reps * p)):
                idxs = list(range(i, i + reps * p))
                p_seen.update(idxs)
                tools = ",".join(calls[i + k].tool for k in range(p))
                out.append(Finding("LG02", source, "cycle [%s] repeated %d times (calls #%d-#%d)"
                                   % (tools, reps, i + 1, i + reps * p), idxs))
                i += reps * p
            else:
                i += 1
    # error storms: same tool, consecutive errors
    errs = [(c.tool if c.error else None) for c in calls]
    for start, n, tool in _runs(errs):
        if tool and n >= repeat:
            last = (calls[start + n - 1].result or "").strip().splitlines()[:1]
            out.append(Finding("LG03", source, "%s failed %d times in a row (calls #%d-#%d); last error: %s"
                               % (tool, n, start + 1, start + n, (last[0][:100] if last else "?")),
                               list(range(start, start + n))))
    # stalled: same tool + same result, differing args, consecutive among that tool's calls
    for start, n, val in _runs([(c.tool, hashlib.sha256(c.result.encode()).hexdigest())
                                if c.result is not None and not c.error else None for c in calls]):
        if val and n >= repeat:
            idxs = list(range(start, start + n))
            if set(idxs) <= covered:
                continue
            out.append(Finding("LG04", source, "%s returned the identical result %d times in a row (calls #%d-#%d)"
                               % (val[0], n, start + 1, start + n), idxs))
    if max_calls and len(calls) > max_calls:
        out.append(Finding("LG05", source, "%d tool calls (budget %d)" % (len(calls), max_calls)))
    if len(calls) >= dom_min:
        counts = {}
        for c in calls:
            counts[c.tool] = counts.get(c.tool, 0) + 1
        tool, cnt = max(counts.items(), key=lambda kv: kv[1])
        if cnt / len(calls) >= dominance:
            out.append(Finding("LG06", source, "%s is %d of %d calls (%.0f%%)" % (tool, cnt, len(calls), 100.0 * cnt / len(calls))))
    if calls and not answered:
        out.append(Finding("LG07", source, "transcript ends after call #%d (%s) without a final answer; truncated or runaway?"
                           % (len(calls), calls[-1].tool)))
    return out


def load(path):
    if path == "-":
        text = sys.stdin.read()
    else:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    try:
        return json.loads(text)
    except ValueError:
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
        return rows


def iter_files(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in sorted(files):
                    if f.endswith((".json", ".jsonl")):
                        yield os.path.join(root, f)
        else:
            yield p


def scan(paths, **kw):
    findings, stats = [], []
    for path in iter_files(paths):
        try:
            calls, answered = parse_events(load(path))
        except OSError as e:
            sys.stderr.write("loopguard: cannot read %s: %s\n" % (path, e))
            continue
        stats.append({"source": path, "calls": len(calls), "errors": sum(c.error for c in calls)})
        findings.extend(analyze(calls, path, answered, **kw))
    return findings, stats


def main(argv=None):
    ap = argparse.ArgumentParser(prog="loopguard", description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="*", default=["-"], help="transcript files or dirs (.json/.jsonl), '-' for stdin")
    ap.add_argument("--repeat", type=int, default=3, help="repetitions that count as a loop (default 3)")
    ap.add_argument("--max-calls", type=int, default=50, help="tool-call budget per run, 0 = off (default 50)")
    ap.add_argument("--dominance", type=float, default=0.7, help="share of calls for LG06 (default 0.7)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="info")
    ap.add_argument("--fail-on", choices=SEVERITIES[1:] + ["any", "none"], default="high")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version="loopguard " + VERSION)
    a = ap.parse_args(argv)
    if a.list_rules:
        for r, (sev, t) in sorted(RULES.items()):
            print("%s  %-8s %s" % (r, sev, t))
        return 0
    if a.repeat < 2:
        ap.error("--repeat must be >= 2")
    findings, stats = scan(a.paths, repeat=a.repeat, max_calls=a.max_calls, dominance=a.dominance)
    shown = [f for f in findings if SEV_RANK[f.severity] >= SEV_RANK[a.min_severity]]
    shown.sort(key=lambda f: (f.source, -SEV_RANK[f.severity], f.rule))
    if a.json:
        print(json.dumps({"version": VERSION, "runs": stats, "findings": [f.to_dict() for f in shown]}, indent=2))
    else:
        for s in stats:
            print("%s: %d tool calls, %d errors" % (s["source"], s["calls"], s["errors"]))
        for f in shown:
            print("[%s] %s %s  %s" % (f.severity.upper(), f.rule, f.source, f.message))
        if not shown:
            print("No loop findings.")
        print("Note: loopguard is heuristic. Legitimate polling or batch work can look like a loop; tune --repeat/--max-calls.")
    if a.fail_on == "none":
        return 0
    thr = 0 if a.fail_on == "any" else SEV_RANK[a.fail_on]
    return 1 if any(SEV_RANK[f.severity] >= thr for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
