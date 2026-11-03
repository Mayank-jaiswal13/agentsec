#!/usr/bin/env python3
"""ctxbudget: offline tool-result size / context-window DoS budget checker.

Oversized or pathological tool results can exhaust an agent's context window,
hide payloads inside huge blobs, or starve later turns of budget. ctxbudget
reads saved transcripts (OpenAI, Anthropic, generic JSON/JSONL), measures each
tool result, and flags absolute size, share-of-run, base64/binary blobs,
pathological line lengths, result floods from one tool, and total tool-result
byte budgets.

Complements runledger (token/cost totals), loopguard (identical-call loops) and
resultguard (injection phrasing in results). Stdlib only; never runs an agent
or contacts a network.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict

VERSION = "0.1.0"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "CB01": ("high", "Single tool result exceeds absolute byte budget"),
    "CB02": ("critical", "Single tool result exceeds critical byte budget"),
    "CB03": ("high", "Tool result consumes a large share of total tool-result bytes"),
    "CB04": ("medium", "Large base64 / hex blob inside a tool result"),
    "CB05": ("high", "Pathological single-line length (likely minified dump or dump-hide)"),
    "CB06": ("medium", "Null bytes / obvious binary content in a text tool result"),
    "CB07": ("high", "Same tool emitted many oversized results (result flood)"),
    "CB08": ("medium", "Total tool-result bytes exceed run budget"),
    "CB09": ("low", "Deeply nested JSON result (expansion / parser DoS shape)"),
    "CB10": ("info", "Tool-result size inventory (largest results)"),
}

# Defaults tuned for typical 128k–200k context coding agents; override via flags.
DEFAULT_MAX_BYTES = 100_000          # CB01
DEFAULT_CRITICAL_BYTES = 500_000     # CB02
DEFAULT_SHARE = 0.40                 # CB03: fraction of total tool-result bytes
DEFAULT_BLOB_BYTES = 8_192           # CB04
DEFAULT_LINE_BYTES = 32_768          # CB05
DEFAULT_FLOOD_COUNT = 5              # CB07: N oversized results from one tool
DEFAULT_FLOOD_MIN_BYTES = 20_000     # CB07: what counts as oversized for flood
DEFAULT_TOTAL_BYTES = 1_000_000      # CB08
DEFAULT_MAX_DEPTH = 32               # CB09
DEFAULT_TOP_N = 5                    # CB10 inventory

BASE64_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])"
    r"(?:[A-Za-z0-9+/]{64,}={0,2})"
    r"(?![A-Za-z0-9+/=])"
)
HEX_BLOB_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{128,})(?![0-9a-fA-F])")

PLACEHOLDER_RE = re.compile(
    r"(?i)^(null|none|n/?a|todo|tbd|\$\{?[A-Z0-9_]+\}?|<[^>]+>|xxx+|placeholder.*)$"
)


class Finding:
    __slots__ = ("rule", "severity", "source", "message", "tool", "turn", "bytes", "detail")

    def __init__(self, rule, source, message, tool="", turn=None, nbytes=0, detail=""):
        self.rule = rule
        self.severity = RULES[rule][0]
        self.source = source
        self.message = message
        self.tool = tool
        self.turn = turn
        self.bytes = int(nbytes or 0)
        self.detail = detail

    def to_dict(self):
        d = {
            "rule": self.rule,
            "severity": self.severity,
            "title": RULES[self.rule][1],
            "source": self.source,
            "message": self.message,
            "tool": self.tool,
            "bytes": self.bytes,
        }
        if self.turn is not None:
            d["turn"] = self.turn
        if self.detail:
            d["detail"] = self.detail
        return d


class ResultEvent:
    __slots__ = ("source", "tool", "turn", "text", "nbytes")

    def __init__(self, source, tool, turn, text):
        self.source = source
        self.tool = tool or ""
        self.turn = turn
        self.text = text if isinstance(text, str) else _text_of(text)
        self.nbytes = len(self.text.encode("utf-8", errors="replace"))


def _text_of(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, dict):
                if item.get("type") == "text" and "text" in item:
                    parts.append(str(item.get("text") or ""))
                elif "text" in item:
                    parts.append(str(item.get("text") or ""))
                elif "content" in item:
                    parts.append(_text_of(item["content"]))
                else:
                    parts.append(json.dumps(item, ensure_ascii=False, sort_keys=True))
            else:
                parts.append(_text_of(item))
        return "\n".join(parts)
    if isinstance(value, dict):
        if "text" in value and isinstance(value["text"], str):
            return value["text"]
        if "content" in value:
            return _text_of(value["content"])
        if "body" in value:
            return _text_of(value["body"])
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            return str(value)
    return str(value)


def _json_depth(obj, limit=64) -> int:
    """Return approximate max nesting depth (capped)."""
    stack = [(obj, 1)]
    deepest = 0
    seen = 0
    while stack:
        cur, depth = stack.pop()
        if depth > deepest:
            deepest = depth
        if deepest >= limit:
            return deepest
        seen += 1
        if seen > 50_000:
            return deepest
        if isinstance(cur, dict):
            for v in cur.values():
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
        elif isinstance(cur, list):
            for v in cur:
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
    return deepest


def _try_parse_json(text: str):
    text = text.strip()
    if not text or text[0] not in "{[":
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _max_line_bytes(text: str) -> int:
    if not text:
        return 0
    return max((len(line.encode("utf-8", errors="replace")) for line in text.splitlines()), default=0)


def _blob_spans(text: str):
    """Yield (kind, start, end, nbytes) for large base64/hex spans."""
    for m in BASE64_RE.finditer(text):
        span = m.group(0)
        # Require base64-ish alphabet variety (+/ or =, or mixed case + digits)
        has_special = ("+" in span) or ("/" in span) or ("=" in span)
        has_mixed = (
            any(c.islower() for c in span)
            and any(c.isupper() for c in span)
            and any(c.isdigit() for c in span)
        )
        if not (has_special or has_mixed):
            continue
        nbytes = len(span.encode("utf-8", errors="replace"))
        yield ("base64", m.start(), m.end(), nbytes)
    for m in HEX_BLOB_RE.finditer(text):
        span = m.group(0)
        # Skip mono-char / tiny-alphabet runs (AAAA..., deadbeef-deadbeef noise)
        alphabet = set(span.lower())
        if len(alphabet) < 6:
            continue
        nbytes = len(span.encode("utf-8", errors="replace"))
        yield ("hex", m.start(), m.end(), nbytes)


def load_events(path: str) -> list:
    if path == "-":
        raw = sys.stdin.read()
        source = "<stdin>"
        return _parse_content(raw, source)

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    return _parse_content(raw, path)


def _parse_content(raw: str, source: str) -> list:
    raw_strip = raw.strip()
    if not raw_strip:
        return []

    # JSONL?
    if "\n" in raw_strip and not raw_strip.lstrip().startswith(("{", "[")):
        return _parse_jsonl(raw, source)
    # Could still be JSONL of objects
    if raw_strip.startswith("{") and "\n{" in raw:
        # Ambiguous: try full JSON first
        try:
            data = json.loads(raw)
            return _extract_from_obj(data, source)
        except json.JSONDecodeError:
            return _parse_jsonl(raw, source)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Treat as JSONL attempt or empty
        events = _parse_jsonl(raw, source)
        if events:
            return events
        return []

    return _extract_from_obj(data, source)


def _parse_jsonl(raw: str, source: str) -> list:
    events = []
    for i, line in enumerate(raw.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        events.extend(_extract_from_obj(obj, "%s:%d" % (source, i), turn_hint=i))
    return events


def _extract_from_obj(data, source: str, turn_hint=None) -> list:
    events = []
    if isinstance(data, list):
        # Could be messages array or list of events
        if data and isinstance(data[0], dict) and (
            "role" in data[0] or "type" in data[0] or "tool" in data[0]
            or "tool_call_id" in data[0] or "tool_use_id" in data[0]
        ):
            events.extend(_extract_from_messages(data, source))
        else:
            for i, item in enumerate(data):
                if isinstance(item, dict):
                    events.extend(_extract_from_obj(item, source, turn_hint=i))
        return events

    if not isinstance(data, dict):
        return events

    # Wrapped shapes
    for key in ("messages", "conversation", "turns", "items", "data", "events"):
        if isinstance(data.get(key), list):
            events.extend(_extract_from_obj(data[key], source))
            if events:
                return events

    # Anthropic content blocks at top level
    if isinstance(data.get("content"), list) and any(
        isinstance(b, dict) and b.get("type") in ("tool_result", "tool_use")
        for b in data["content"]
    ):
        events.extend(_extract_anthropic_content(data["content"], source, turn_hint))
        return events

    # Single generic event
    ev = _generic_result_event(data, source, turn_hint)
    if ev:
        events.append(ev)
        return events

    # OpenAI-ish single message
    if data.get("role") == "tool" or "tool_call_id" in data:
        text = _text_of(data.get("content"))
        if text:
            events.append(ResultEvent(
                source, data.get("name") or data.get("tool") or "", turn_hint, text
            ))
        return events

    return events


def _extract_from_messages(messages: list, source: str) -> list:
    events = []
    # Map tool_call id -> name for OpenAI
    call_names = {}
    for i, msg in enumerate(messages):
        if not isinstance(msg, dict):
            continue
        role = (msg.get("role") or "").lower()
        # OpenAI assistant tool_calls — record names
        tcalls = msg.get("tool_calls") or []
        if isinstance(tcalls, list):
            for tc in tcalls:
                if not isinstance(tc, dict):
                    continue
                tid = tc.get("id") or ""
                fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
                name = fn.get("name") or tc.get("name") or ""
                if tid:
                    call_names[tid] = name
        # OpenAI tool role
        if role == "tool" or "tool_call_id" in msg:
            tid = msg.get("tool_call_id") or ""
            name = msg.get("name") or call_names.get(tid) or msg.get("tool") or ""
            text = _text_of(msg.get("content"))
            if text:
                events.append(ResultEvent(source, name, i, text))
            continue
        # Anthropic-style message with content blocks
        content = msg.get("content")
        if isinstance(content, list):
            # Collect tool_use names in this and previous messages
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    bid = block.get("id") or ""
                    if bid:
                        call_names[bid] = block.get("name") or ""
            events.extend(_extract_anthropic_content(content, source, i, call_names))
        # Generic role=tool_result
        if role in ("tool_result", "function") and msg.get("content") is not None:
            text = _text_of(msg.get("content"))
            if text:
                events.append(ResultEvent(
                    source,
                    msg.get("name") or msg.get("tool") or call_names.get(msg.get("tool_call_id") or "", ""),
                    i,
                    text,
                ))
    return events


def _extract_anthropic_content(content: list, source: str, turn=None, call_names=None) -> list:
    call_names = call_names or {}
    events = []
    for block in content:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "tool_use":
            bid = block.get("id") or ""
            if bid:
                call_names[bid] = block.get("name") or ""
        if block.get("type") == "tool_result":
            tid = block.get("tool_use_id") or block.get("tool_call_id") or ""
            name = block.get("name") or call_names.get(tid) or ""
            text = _text_of(block.get("content"))
            # Anthropic sometimes uses is_error; still count size
            if text:
                events.append(ResultEvent(source, name, turn, text))
    return events


def _generic_result_event(data: dict, source: str, turn_hint=None):
    """Accept {tool, result|output|content|response} or {type: tool_result, ...}."""
    typ = (data.get("type") or data.get("event") or "").lower()
    tool = data.get("tool") or data.get("name") or data.get("tool_name") or ""
    turn = data.get("turn", turn_hint)

    result = None
    for key in ("result", "output", "tool_result", "response", "content", "body", "text"):
        if key in data and data[key] is not None:
            # Skip if this looks like an assistant message with tool_calls only
            if key == "content" and data.get("role") == "assistant":
                continue
            if key == "content" and isinstance(data.get("content"), list):
                # Maybe anthropic blocks — handled elsewhere
                if any(isinstance(b, dict) and b.get("type") in ("tool_result", "tool_use", "text")
                       for b in data["content"]):
                    return None
            result = data[key]
            break

    if result is None:
        return None

    # Require some signal this is a tool result, not a user prompt
    if typ in ("tool_result", "function_result", "tool.result", "tool_output"):
        pass
    elif tool or "tool_call_id" in data or "tool_use_id" in data:
        pass
    elif "result" in data or "tool_result" in data or "output" in data:
        pass
    else:
        return None

    text = _text_of(result)
    if not text or PLACEHOLDER_RE.match(text.strip()):
        return None
    return ResultEvent(source, tool, turn, text)


def classify_result(ev: ResultEvent, *, total_bytes: int, budgets: dict, disabled=None) -> list:
    """Classify one tool result against budgets. CB03/CB07/CB08 need run-level context
    and are handled in analyze_run; this covers per-result rules."""
    disabled = set(disabled or [])
    findings = []

    def add(rule, message, detail="", severity_override=None):
        if rule in disabled:
            return
        f = Finding(rule, ev.source, message, tool=ev.tool, turn=ev.turn,
                    nbytes=ev.nbytes, detail=detail)
        if severity_override:
            f.severity = severity_override
        findings.append(f)

    max_bytes = budgets["max_bytes"]
    critical_bytes = budgets["critical_bytes"]
    blob_bytes = budgets["blob_bytes"]
    line_bytes = budgets["line_bytes"]
    max_depth = budgets["max_depth"]

    if ev.nbytes >= critical_bytes:
        add("CB02", "Tool result is %d bytes (critical budget %d)" % (ev.nbytes, critical_bytes))
    elif ev.nbytes >= max_bytes:
        add("CB01", "Tool result is %d bytes (budget %d)" % (ev.nbytes, max_bytes))

    # Blobs
    biggest_blob = 0
    blob_kind = ""
    for kind, _a, _b, nbytes in _blob_spans(ev.text):
        if nbytes > biggest_blob:
            biggest_blob = nbytes
            blob_kind = kind
    if biggest_blob >= blob_bytes:
        add(
            "CB04",
            "Large %s blob (%d bytes) inside tool result" % (blob_kind or "encoded", biggest_blob),
            detail="blob_bytes=%d" % biggest_blob,
        )

    # Pathological line
    ml = _max_line_bytes(ev.text)
    if ml >= line_bytes:
        add("CB05", "Longest line is %d bytes (budget %d)" % (ml, line_bytes),
            detail="max_line=%d" % ml)

    # Binary / nulls
    if "\x00" in ev.text:
        add("CB06", "Null byte(s) present in tool result text")
    else:
        # High ratio of non-text control chars (excluding tab/newline/cr)
        ctrl = sum(1 for ch in ev.text if ord(ch) < 32 and ch not in "\t\n\r")
        if ev.nbytes >= 256 and ctrl / max(len(ev.text), 1) > 0.05:
            add("CB06", "High control-character ratio (%.1f%%) suggests binary content"
                % (100.0 * ctrl / max(len(ev.text), 1)))

    # Deep JSON
    parsed = _try_parse_json(ev.text)
    if parsed is not None:
        depth = _json_depth(parsed, limit=max_depth + 5)
        if depth >= max_depth:
            add("CB09", "JSON nesting depth %d exceeds %d" % (depth, max_depth),
                detail="depth=%d" % depth)

    return findings


def analyze_run(events: list, budgets: dict, disabled=None, top_n: int = DEFAULT_TOP_N) -> list:
    disabled = set(disabled or [])
    findings = []
    total = sum(ev.nbytes for ev in events)

    # Per-result
    oversized_by_tool = defaultdict(int)
    for ev in events:
        findings.extend(classify_result(ev, total_bytes=total, budgets=budgets, disabled=disabled))
        if ev.nbytes >= budgets["flood_min_bytes"]:
            oversized_by_tool[ev.tool or "(unknown)"] += 1

    # CB03 share
    if "CB03" not in disabled and total > 0:
        share = budgets["share"]
        for ev in events:
            if ev.nbytes / total >= share and ev.nbytes >= budgets["max_bytes"] // 2:
                findings.append(Finding(
                    "CB03", ev.source,
                    "Tool result is %.0f%% of all tool-result bytes (%d / %d)"
                    % (100.0 * ev.nbytes / total, ev.nbytes, total),
                    tool=ev.tool, turn=ev.turn, nbytes=ev.nbytes,
                    detail="share=%.3f" % (ev.nbytes / total),
                ))

    # CB07 flood
    if "CB07" not in disabled:
        for tool, count in oversized_by_tool.items():
            if count >= budgets["flood_count"]:
                # Attach to last oversized event for that tool
                last = None
                for ev in events:
                    if (ev.tool or "(unknown)") == tool and ev.nbytes >= budgets["flood_min_bytes"]:
                        last = ev
                src = last.source if last else ""
                turn = last.turn if last else None
                findings.append(Finding(
                    "CB07", src,
                    "Tool %r produced %d oversized results (>= %d bytes each)"
                    % (tool, count, budgets["flood_min_bytes"]),
                    tool=tool if tool != "(unknown)" else "",
                    turn=turn,
                    nbytes=last.nbytes if last else 0,
                    detail="flood_count=%d" % count,
                ))

    # CB08 total
    if "CB08" not in disabled and total >= budgets["total_bytes"]:
        findings.append(Finding(
            "CB08", events[0].source if events else "",
            "Total tool-result bytes %d exceed run budget %d" % (total, budgets["total_bytes"]),
            nbytes=total, detail="total_bytes=%d" % total,
        ))

    # CB10 inventory (info) — only when there is at least one result
    if "CB10" not in disabled and events:
        ranked = sorted(events, key=lambda e: -e.nbytes)[: max(1, top_n)]
        summary = ", ".join(
            "%s=%dB" % ((e.tool or "?")[:24], e.nbytes) for e in ranked
        )
        findings.append(Finding(
            "CB10", events[0].source,
            "Largest tool results: %s (total %d bytes across %d result(s))"
            % (summary, total, len(events)),
            tool=ranked[0].tool, turn=ranked[0].turn, nbytes=ranked[0].nbytes,
            detail="top=%d" % len(ranked),
        ))

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
                    if fn.endswith((".json", ".jsonl")):
                        paths.append(os.path.join(root, fn))
        else:
            paths.append(p)
    return paths


def format_table(findings, events_count, total_bytes):
    lines = []
    lines.append("ctxbudget %s — %d tool result(s), %d total bytes, %d finding(s)" % (
        VERSION, events_count, total_bytes, len(findings)))
    if not findings:
        lines.append("No context-budget findings.")
        return "\n".join(lines)
    lines.append("")
    lines.append("%-6s %-8s %-18s %10s  %s" % ("RULE", "SEV", "TOOL", "BYTES", "MESSAGE"))
    lines.append("-" * 96)
    for f in findings:
        lines.append("%-6s %-8s %-18s %10d  %s" % (
            f.rule, f.severity, (f.tool or "-")[:18], f.bytes, f.message[:78]))
        if f.source:
            loc = f.source
            if f.turn is not None:
                loc += " turn=%s" % f.turn
            lines.append("       at:  %s" % loc)
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="ctxbudget",
        description="Offline tool-result size / context-window DoS budget checker for agent transcripts.",
    )
    ap.add_argument("paths", nargs="*", help="transcripts or directories (or - for stdin)")
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                    help="CB01 absolute size budget per result (default %d)" % DEFAULT_MAX_BYTES)
    ap.add_argument("--critical-bytes", type=int, default=DEFAULT_CRITICAL_BYTES,
                    help="CB02 critical size budget (default %d)" % DEFAULT_CRITICAL_BYTES)
    ap.add_argument("--share", type=float, default=DEFAULT_SHARE,
                    help="CB03 fraction of total tool-result bytes (default %.2f)" % DEFAULT_SHARE)
    ap.add_argument("--blob-bytes", type=int, default=DEFAULT_BLOB_BYTES,
                    help="CB04 minimum encoded blob size (default %d)" % DEFAULT_BLOB_BYTES)
    ap.add_argument("--line-bytes", type=int, default=DEFAULT_LINE_BYTES,
                    help="CB05 max single-line bytes (default %d)" % DEFAULT_LINE_BYTES)
    ap.add_argument("--flood-count", type=int, default=DEFAULT_FLOOD_COUNT,
                    help="CB07 oversized-result count from one tool (default %d)" % DEFAULT_FLOOD_COUNT)
    ap.add_argument("--flood-min-bytes", type=int, default=DEFAULT_FLOOD_MIN_BYTES,
                    help="CB07 minimum bytes to count toward flood (default %d)" % DEFAULT_FLOOD_MIN_BYTES)
    ap.add_argument("--total-bytes", type=int, default=DEFAULT_TOTAL_BYTES,
                    help="CB08 total tool-result byte budget (default %d)" % DEFAULT_TOTAL_BYTES)
    ap.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH,
                    help="CB09 JSON nesting depth budget (default %d)" % DEFAULT_MAX_DEPTH)
    ap.add_argument("--top", type=int, default=DEFAULT_TOP_N, help="CB10 inventory size")
    ap.add_argument("--disable", nargs="+", default=[], metavar="RULE", help="skip rule ids")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--min-severity", default="info", choices=SEVERITIES)
    ap.add_argument("--fail-on", default="high",
                    choices=SEVERITIES + ["any", "none"],
                    help="exit 1 if any finding >= this severity (default high)")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version="ctxbudget " + VERSION)
    ns = ap.parse_args(argv)

    if ns.list_rules:
        for rid, (sev, title) in RULES.items():
            print("%s  %-8s  %s" % (rid, sev, title))
        return 0

    if not ns.paths:
        ap.print_help()
        return 2

    if ns.max_bytes < 1 or ns.critical_bytes < 1 or ns.total_bytes < 1:
        sys.stderr.write("ctxbudget: budgets must be positive integers\n")
        return 2
    if not (0.0 < ns.share <= 1.0):
        sys.stderr.write("ctxbudget: --share must be in (0, 1]\n")
        return 2

    paths = collect_paths(ns.paths)
    if not paths:
        sys.stderr.write("ctxbudget: no readable inputs\n")
        return 2

    budgets = {
        "max_bytes": ns.max_bytes,
        "critical_bytes": ns.critical_bytes,
        "share": ns.share,
        "blob_bytes": ns.blob_bytes,
        "line_bytes": ns.line_bytes,
        "flood_count": ns.flood_count,
        "flood_min_bytes": ns.flood_min_bytes,
        "total_bytes": ns.total_bytes,
        "max_depth": ns.max_depth,
    }

    all_events = []
    errors = 0
    for path in paths:
        try:
            all_events.extend(load_events(path))
        except OSError as e:
            sys.stderr.write("ctxbudget: %s: %s\n" % (path, e))
            errors += 1

    if errors and not all_events:
        return 2

    findings = analyze_run(all_events, budgets, disabled=ns.disable, top_n=ns.top)
    total_bytes = sum(ev.nbytes for ev in all_events)

    min_rank = SEV_RANK[ns.min_severity]
    shown = [f for f in findings if SEV_RANK[f.severity] >= min_rank]
    shown.sort(key=lambda f: (-SEV_RANK[f.severity], f.rule, f.tool or "", -f.bytes))

    if ns.json:
        print(json.dumps({
            "tool": "ctxbudget",
            "version": VERSION,
            "results": len(all_events),
            "total_bytes": total_bytes,
            "budgets": budgets,
            "findings": [f.to_dict() for f in shown],
        }, indent=2))
    else:
        print(format_table(shown, len(all_events), total_bytes))

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
