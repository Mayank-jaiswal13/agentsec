#!/usr/bin/env python3
"""runledger - offline token & cost accounting for AI agent runs.

Reads transcripts / usage logs (JSONL, JSON, directories, or stdin), auto-detects
OpenAI-style, Anthropic-style, and generic usage shapes, and reports per-run,
per-model, per-tool and per-session totals, cache hit ratio, the most expensive
turns, and an optional budget check.

It counts what the logs report. It cannot verify billing. Costs are ESTIMATES
computed from a user-editable price table.

Exit codes: 0 ok, 1 budget exceeded, 2 error.
Standard library only.
"""
import argparse
import csv
import io
import json
import os
import re
import sys
from collections import OrderedDict

__version__ = "0.1.0"

EXIT_OK, EXIT_BUDGET, EXIT_ERROR = 0, 1, 2
DEFAULT_PRICES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prices.json")
TOKEN_FIELDS = ("input", "cache_read", "cache_write", "output", "reasoning")
NONE_TOOL = "(none)"

SESSION_KEYS = ("session_id", "sessionId", "session", "conversation_id", "conversationId", "thread_id", "threadId")
RUN_KEYS = ("run_id", "runId", "trace_id", "traceId")
TS_KEYS = ("timestamp", "ts", "time", "created_at", "createdAt", "created", "date")
TOOL_KEYS = ("tool", "tool_name", "toolName")
HISTORY_KEYS = ("messages", "request", "input", "prompt", "history", "contents")
USAGE_KEYS = ("usage", "usageMetadata", "usage_metadata", "token_usage", "tokenUsage")


class RunledgerError(Exception):
    pass


# --------------------------------------------------------------------------- input

def iter_paths(paths):
    for p in paths:
        if p == "-":
            yield "-"
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs.sort()
                for f in sorted(files):
                    if f.lower().endswith((".jsonl", ".json", ".ndjson")):
                        yield os.path.join(root, f)
        elif os.path.isfile(p):
            yield p
        else:
            raise RunledgerError("input not found: %s" % p)


def _records_from_obj(obj):
    if isinstance(obj, list):
        for x in obj:
            if isinstance(x, dict):
                yield x
    elif isinstance(obj, dict):
        for k in ("records", "events", "turns", "entries", "data", "items", "logs"):
            if isinstance(obj.get(k), list) and any(isinstance(x, dict) for x in obj[k]):
                for x in obj[k]:
                    if isinstance(x, dict):
                        yield x
                return
        yield obj


def parse_text(text, source, warnings):
    """Yield (source, line_no, record) from JSON or JSONL text."""
    stripped = text.strip()
    if not stripped:
        return
    if stripped[0] in "[{":
        try:
            obj = json.loads(stripped)
        except ValueError:
            obj = None
        else:
            for i, rec in enumerate(_records_from_obj(obj), 1):
                yield source, i, rec
            return
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            warnings.append("%s:%d: skipped non-JSON line" % (source, n))
            continue
        for rec in _records_from_obj(obj):
            yield source, n, rec


def load_records(paths, warnings, stdin=None):
    out = []
    for p in iter_paths(paths):
        if p == "-":
            text = (stdin or sys.stdin).read()
            src = "<stdin>"
        else:
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError as e:
                raise RunledgerError("cannot read %s: %s" % (p, e))
            src = p
        out.extend(parse_text(text, src, warnings))
    return out


# --------------------------------------------------------------------------- usage detection

def _int(v):
    if isinstance(v, bool):
        return 0
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, str) and v.strip().isdigit():
        return int(v.strip())
    return 0


def _walk(obj, skip=(), depth=0):
    """Yield (key, value, parent) for every dict entry, breadth-first-ish."""
    if depth > 12:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in skip:
                continue
            yield k, v, obj
        for k, v in obj.items():
            if k in skip:
                continue
            if isinstance(v, (dict, list)):
                for item in _walk(v, skip, depth + 1):
                    yield item
    elif isinstance(obj, list):
        for v in obj:
            for item in _walk(v, skip, depth + 1):
                yield item


def find_usage_dict(rec):
    for k, v, _ in _walk(rec):
        if k in USAGE_KEYS and isinstance(v, dict):
            return v
    return None


def normalize_usage(u):
    """Return (shape, tokens dict) or (None, None).

    tokens: input = uncached input, cache_read, cache_write, output (incl. reasoning),
    reasoning (subset of output, informational).
    """
    if not isinstance(u, dict):
        return None, None
    if "prompt_tokens" in u or "completion_tokens" in u:
        prompt = _int(u.get("prompt_tokens"))
        cached = _int((u.get("prompt_tokens_details") or {}).get("cached_tokens"))
        out = _int(u.get("completion_tokens"))
        reasoning = _int((u.get("completion_tokens_details") or {}).get("reasoning_tokens"))
        cached = min(cached, prompt)
        return "openai", dict(input=prompt - cached, cache_read=cached, cache_write=0,
                              output=out, reasoning=reasoning)
    if "input_tokens" in u or "output_tokens" in u:
        if "input_tokens_details" in u or "output_tokens_details" in u or "total_tokens" in u:
            # OpenAI Responses API: input_tokens INCLUDES cached tokens
            inp = _int(u.get("input_tokens"))
            cached = min(_int((u.get("input_tokens_details") or {}).get("cached_tokens")), inp)
            reasoning = _int((u.get("output_tokens_details") or {}).get("reasoning_tokens"))
            return "openai", dict(input=inp - cached, cache_read=cached, cache_write=0,
                                  output=_int(u.get("output_tokens")), reasoning=reasoning)
        # Anthropic: input_tokens EXCLUDES cache reads/writes
        return "anthropic", dict(input=_int(u.get("input_tokens")),
                                 cache_read=_int(u.get("cache_read_input_tokens")),
                                 cache_write=_int(u.get("cache_creation_input_tokens")),
                                 output=_int(u.get("output_tokens")), reasoning=0)
    return None, None


_GEN_IN = re.compile(r"^(input|prompt)_?tokens?(_?count)?$|^tokens?_?(in|input|prompt)$|^prompt_?token_?count$", re.I)
_GEN_OUT = re.compile(r"^(output|completion|candidates?|generated)_?tokens?(_?count)?$|^tokens?_?(out|output|completion)$", re.I)
_GEN_CACHE_R = re.compile(r"^(cache_?read(_?input)?|cached(_?content|_?input|_?prompt)?)_?tokens?(_?count)?$", re.I)
_GEN_CACHE_W = re.compile(r"^(cache_?(write|creation)(_?input)?)_?tokens?(_?count)?$", re.I)
_GEN_REASON = re.compile(r"^(reasoning|thoughts?|thinking)_?tokens?(_?count)?$", re.I)


def generic_usage(rec):
    """Fallback: look for input/output-ish token fields at any nesting."""
    found = {}
    prompt_style = False
    for k, v, _ in _walk(rec, skip=("messages", "history", "contents")):
        if not isinstance(k, str) or isinstance(v, (dict, list, bool)) or not isinstance(v, (int, float)):
            continue
        key = k.replace("-", "_")
        key_snake = re.sub(r"(?<!^)([A-Z])", r"_\1", key)
        for name, rx in (("cache_read", _GEN_CACHE_R), ("cache_write", _GEN_CACHE_W),
                         ("reasoning", _GEN_REASON), ("input", _GEN_IN), ("output", _GEN_OUT)):
            if name not in found and (rx.match(key) or rx.match(key_snake)):
                found[name] = _int(v)
                if name == "input" and "prompt" in key.lower():
                    prompt_style = True
                break
    if "input" not in found and "output" not in found:
        return None
    t = {f: found.get(f, 0) for f in TOKEN_FIELDS}
    if prompt_style and t["cache_read"]:
        # prompt-style counts (OpenAI/Gemini convention) include cached tokens
        t["cache_read"] = min(t["cache_read"], t["input"])
        t["input"] -= t["cache_read"]
    return t


# --------------------------------------------------------------------------- metadata

def _first_str(rec, keys, skip=HISTORY_KEYS):
    for k, v, _ in _walk(rec, skip=skip):
        if k in keys and isinstance(v, (str, int)) and not isinstance(v, bool) and str(v).strip():
            return str(v)
    return None


def find_model(rec):
    for k, v, _ in _walk(rec, skip=("messages", "history", "contents")):
        if k in ("model", "model_name", "modelName", "modelVersion", "model_id") and isinstance(v, str) and v:
            return v
    return None


def _tool_names_in(obj):
    names = []
    for k, v, parent in _walk(obj):
        if k == "tool_calls" and isinstance(v, list):
            for c in v:
                if isinstance(c, dict):
                    n = (c.get("function") or {}).get("name") if isinstance(c.get("function"), dict) else None
                    n = n or c.get("name")
                    if n:
                        names.append(str(n))
        elif k == "function_call" and isinstance(v, dict) and v.get("name"):
            names.append(str(v["name"]))
        elif k == "type" and v in ("tool_use", "function_call", "server_tool_use") and parent.get("name"):
            names.append(str(parent["name"]))
    # dedupe preserving order of distinct calls (keep duplicates of same tool once)
    seen, out = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def tools_made(rec):
    """Tool calls made BY this turn (in the response, not the request history)."""
    if isinstance(rec.get("response"), (dict, list)):
        return _tool_names_in(rec["response"])
    trimmed = {k: v for k, v in rec.items() if k not in HISTORY_KEYS}
    return _tool_names_in(trimmed)


def _history(rec):
    for container in (rec, rec.get("request") if isinstance(rec.get("request"), dict) else None):
        if not container:
            continue
        for k in ("messages", "input", "history"):
            if isinstance(container.get(k), list):
                return container[k]
    return None


def tool_answered(rec):
    """If the request's last message is a tool result, return that tool's name."""
    msgs = _history(rec)
    if not msgs or not isinstance(msgs[-1], dict):
        return None
    id_to_name = {}
    for m in msgs:
        if not isinstance(m, dict):
            continue
        for c in m.get("tool_calls") or []:
            if isinstance(c, dict) and c.get("id"):
                fn = c.get("function") if isinstance(c.get("function"), dict) else {}
                id_to_name[c["id"]] = fn.get("name") or c.get("name")
        if isinstance(m.get("content"), list):
            for b in m["content"]:
                if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("id"):
                    id_to_name[b["id"]] = b.get("name")
        if m.get("type") == "function_call" and m.get("call_id"):
            id_to_name[m["call_id"]] = m.get("name")
    last = msgs[-1]
    if last.get("role") in ("tool", "function"):
        return last.get("name") or id_to_name.get(last.get("tool_call_id"))
    if last.get("type") == "function_call_output":
        return id_to_name.get(last.get("call_id"))
    if isinstance(last.get("content"), list):
        for b in last["content"]:
            if isinstance(b, dict) and b.get("type") == "tool_result":
                return b.get("name") or id_to_name.get(b.get("tool_use_id"))
    return None


# --------------------------------------------------------------------------- pricing

_VERSION_SUFFIX = re.compile(r"^[-@:](\d{4}-?\d{2}-?\d{2}|\d{6,8}|latest|v\d[\w.]*|\d{3,4})$")


def load_prices(path):
    if path is None:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as e:
        raise RunledgerError("cannot read price table %s: %s" % (path, e))
    except ValueError as e:
        raise RunledgerError("invalid JSON in price table %s: %s" % (path, e))
    models = data.get("models", data) if isinstance(data, dict) else None
    if not isinstance(models, dict):
        raise RunledgerError("price table must be an object with a 'models' map")
    out = {}
    for name, p in models.items():
        if name.startswith("_"):
            continue
        if not isinstance(p, dict) or not isinstance(p.get("input"), (int, float)) \
                or not isinstance(p.get("output"), (int, float)):
            raise RunledgerError("price entry %r needs numeric 'input' and 'output' (USD per 1M tokens)" % name)
        out[name] = p
    return out


def resolve_price(model, prices):
    """Exact match, provider-prefix strip, or dated/versioned suffix. Never fuzzy."""
    if not model or not prices:
        return None, None
    cands = [model]
    if "/" in model:
        cands.append(model.split("/", 1)[1])
    for c in cands:
        if c in prices:
            return c, prices[c]
    for c in cands:
        best = None
        for key in prices:
            if c.startswith(key) and _VERSION_SUFFIX.match(c[len(key):]):
                if best is None or len(key) > len(best):
                    best = key
        if best:
            return best, prices[best]
    return None, None


def turn_cost(tokens, price):
    if price is None:
        return None
    inp = float(price["input"])
    cr = float(price.get("cache_read", inp))
    cw = float(price.get("cache_write", inp))
    out = float(price["output"])
    return (tokens["input"] * inp + tokens["cache_read"] * cr +
            tokens["cache_write"] * cw + tokens["output"] * out) / 1_000_000.0


# --------------------------------------------------------------------------- build turns

def build_turns(records, prices):
    turns = []
    pending_tool = {}  # session -> tool name called by previous turn
    for source, line, rec in records:
        u = find_usage_dict(rec)
        shape, tokens = normalize_usage(u)
        if tokens is None:
            tokens = generic_usage(rec)
            shape = "generic" if tokens else None
        base = os.path.basename(source)
        run = _first_str(rec, RUN_KEYS) or base
        session = _first_str(rec, SESSION_KEYS) or run
        if tokens is None:
            # non-usage event; still track standalone tool-call events for attribution
            names = tools_made(rec)
            if not names and rec.get("type") in ("tool_call", "tool_use") and _first_str(rec, ("name",) + TOOL_KEYS):
                names = [_first_str(rec, ("name",) + TOOL_KEYS)]
            if names:
                pending_tool[session] = names
            continue
        made = tools_made(rec)
        explicit = None
        for k in TOOL_KEYS:
            if isinstance(rec.get(k), str) and rec[k]:
                explicit = rec[k]
                break
        answered = tool_answered(rec)
        if made:
            tools, how = made, "called"
        elif explicit:
            tools, how = [explicit], "field"
        elif answered:
            tools, how = [answered], "answered"
        elif pending_tool.get(session):
            tools, how = pending_tool[session], "answered"
        else:
            tools, how = [NONE_TOOL], ""
        pending_tool[session] = made or None
        model = find_model(rec) or "(unknown)"
        price_key, price = resolve_price(model, prices)
        turns.append(OrderedDict([
            ("id", "%s:%d" % (base, line)),
            ("source", source), ("line", line), ("run", run), ("session", session),
            ("timestamp", _first_str(rec, TS_KEYS)), ("model", model),
            ("price_key", price_key), ("shape", shape),
            ("tools", tools), ("tool_attribution", how),
            ("input", tokens["input"]), ("cache_read", tokens["cache_read"]),
            ("cache_write", tokens["cache_write"]), ("output", tokens["output"]),
            ("reasoning", tokens["reasoning"]),
            ("total", tokens["input"] + tokens["cache_read"] + tokens["cache_write"] + tokens["output"]),
            ("cost", turn_cost(tokens, price)),
        ]))
    return turns


# --------------------------------------------------------------------------- aggregate

def _new_bucket():
    b = OrderedDict((f, 0.0) for f in ("turns",) + TOKEN_FIELDS + ("total",))
    b["cost"] = 0.0
    b["unpriced_turns"] = 0
    return b


def _add(b, t, frac=1.0):
    b["turns"] += frac
    for f in TOKEN_FIELDS + ("total",):
        b[f] += t[f] * frac
    if t["cost"] is None:
        b["unpriced_turns"] += frac
    else:
        b["cost"] += t["cost"] * frac


def cache_ratio(b):
    denom = b["input"] + b["cache_read"] + b["cache_write"]
    return (b["cache_read"] / denom) if denom else 0.0


def _finish(b):
    out = OrderedDict()
    for k, v in b.items():
        out[k] = round(v, 6) if k == "cost" else (int(round(v)) if isinstance(v, float) and abs(v - round(v)) < 1e-9 else round(v, 2))
    out["cache_hit_ratio"] = round(cache_ratio(b), 4)
    return out


def aggregate(turns, top_n=5):
    total = _new_bucket()
    groups = OrderedDict((g, OrderedDict()) for g in ("run", "model", "tool", "session"))
    for t in turns:
        _add(total, t)
        for g in ("run", "model", "session"):
            _add(groups[g].setdefault(t[g], _new_bucket()), t)
        tools = t["tools"] or [NONE_TOOL]
        for name in tools:  # multi-tool turns are split evenly
            _add(groups["tool"].setdefault(name, _new_bucket()), t, 1.0 / len(tools))
    unpriced_models = sorted({t["model"] for t in turns if t["cost"] is None})
    ranked = sorted(turns, key=lambda t: (t["cost"] if t["cost"] is not None else -1, t["total"]), reverse=True)
    report = OrderedDict()
    report["totals"] = _finish(total)
    for g, d in groups.items():
        report["by_" + g] = OrderedDict(
            (k, _finish(v)) for k, v in sorted(d.items(), key=lambda kv: (-kv[1]["cost"], -kv[1]["total"], kv[0])))
    report["top_turns"] = [_turn_public(t) for t in ranked[:max(top_n, 0)]]
    report["unpriced_models"] = unpriced_models
    return report


def _turn_public(t):
    d = OrderedDict(t)
    d["cost"] = None if t["cost"] is None else round(t["cost"], 6)
    return d


# --------------------------------------------------------------------------- render

def fmt_cost(c, unpriced=0):
    if c is None:
        return "unpriced"
    s = "$%.4f" % c
    if unpriced:
        s += "*"
    return s


def fmt_int(n):
    return "{:,}".format(int(round(n)))


def _table(headers, rows):
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))
    line = lambda cells: "  ".join(c.ljust(widths[i]) if i == 0 else c.rjust(widths[i]) for i, c in enumerate(cells))
    out = [line(headers), "  ".join("-" * w for w in widths)]
    out.extend(line(r) for r in rows)
    return "\n".join(out)


def render_table(report, budget=None):
    o = []
    t = report["totals"]
    o.append("runledger %s - token & cost ESTIMATES from logs (not a bill)" % __version__)
    o.append("")
    o.append("Turns: %s   Input: %s   Cache read: %s   Cache write: %s   Output: %s (reasoning %s)" % (
        fmt_int(t["turns"]), fmt_int(t["input"]), fmt_int(t["cache_read"]), fmt_int(t["cache_write"]),
        fmt_int(t["output"]), fmt_int(t["reasoning"])))
    o.append("Total tokens: %s   Cache hit ratio: %.1f%%   Estimated cost: %s" % (
        fmt_int(t["total"]), t["cache_hit_ratio"] * 100, fmt_cost(t["cost"], t["unpriced_turns"])))
    if t["unpriced_turns"]:
        o.append("* %s turn(s) unpriced (models not in price table: %s) - excluded from cost" % (
            fmt_int(t["unpriced_turns"]), ", ".join(report["unpriced_models"])))
    if budget is not None:
        o.append("Budget: $%.4f -> %s" % (budget, "EXCEEDED" if t["cost"] > budget else "ok"))
    heads = ["turns", "input", "cache_rd", "cache_wr", "output", "total", "cache%", "cost"]
    for g in ("run", "model", "tool", "session"):
        rows = []
        for k, b in report["by_" + g].items():
            rows.append([k, ("%g" % b["turns"]), fmt_int(b["input"]), fmt_int(b["cache_read"]),
                         fmt_int(b["cache_write"]), fmt_int(b["output"]), fmt_int(b["total"]),
                         "%.1f" % (b["cache_hit_ratio"] * 100),
                         "unpriced" if b["unpriced_turns"] == b["turns"] else fmt_cost(b["cost"], b["unpriced_turns"])])
        o.append("")
        o.append("By %s:" % g)
        o.append(_table([g] + heads, rows))
    if report["top_turns"]:
        o.append("")
        o.append("Top %d most expensive turns:" % len(report["top_turns"]))
        rows = [[x["id"], x["model"], ",".join(x["tools"]), fmt_int(x["total"]), fmt_cost(x["cost"])]
                for x in report["top_turns"]]
        o.append(_table(["turn", "model", "tool", "tokens", "cost"], rows))
    return "\n".join(o) + "\n"


CSV_TURN_FIELDS = ["id", "source", "line", "run", "session", "timestamp", "model", "price_key", "shape",
                   "tools", "tool_attribution", "input", "cache_read", "cache_write", "output",
                   "reasoning", "total", "cost"]


def render_csv(turns, report, group):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    if group == "turn":
        w.writerow(CSV_TURN_FIELDS)
        for t in turns:
            row = []
            for f in CSV_TURN_FIELDS:
                v = t[f]
                if f == "tools":
                    v = ";".join(v)
                elif f == "cost":
                    v = "unpriced" if v is None else "%.6f" % v
                row.append("" if v is None else v)
            w.writerow(row)
    else:
        fields = ["turns", "input", "cache_read", "cache_write", "output", "reasoning", "total",
                  "cache_hit_ratio", "cost", "unpriced_turns"]
        w.writerow([group] + fields)
        for k, b in report["by_" + group].items():
            w.writerow([k] + [b[f] for f in fields])
    return buf.getvalue()


# --------------------------------------------------------------------------- CLI

def build_parser():
    p = argparse.ArgumentParser(prog="runledger", description=(
        "Offline token & cost accounting for AI agent runs. Counts what the logs report; "
        "costs are estimates from a user-editable price table, not a bill."))
    p.add_argument("inputs", nargs="*", default=["-"], help="JSONL/JSON files, directories, or - for stdin (default)")
    p.add_argument("--prices", help="price table JSON (default: prices.json next to runledger.py, an EXAMPLE)")
    p.add_argument("--no-prices", action="store_true", help="ignore any price table; everything is unpriced")
    p.add_argument("--budget", type=float, help="USD budget; warn and exit 1 if estimated cost exceeds it")
    p.add_argument("--budget-tokens", type=int, help="token budget; warn and exit 1 if total tokens exceed it")
    p.add_argument("--top", type=int, default=5, help="number of most expensive turns to show (default 5)")
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="JSON report")
    fmt.add_argument("--csv", action="store_true", help="CSV output (see --csv-group)")
    p.add_argument("--csv-group", choices=["turn", "run", "model", "tool", "session"], default="turn",
                   help="rows for --csv (default: one row per turn)")
    p.add_argument("--quiet", action="store_true", help="suppress warnings on stderr")
    p.add_argument("--version", action="version", version="runledger " + __version__)
    return p


def main(argv=None, stdin=None, stdout=None, stderr=None):
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as e:
        return EXIT_OK if e.code == 0 else EXIT_ERROR
    try:
        if args.budget is not None and args.budget < 0:
            raise RunledgerError("--budget must be >= 0")
        if args.no_prices:
            prices_path = None
        elif args.prices:
            prices_path = args.prices
        else:
            prices_path = DEFAULT_PRICES if os.path.isfile(DEFAULT_PRICES) else None
        prices = load_prices(prices_path)
        warnings = []
        records = load_records(args.inputs, warnings, stdin=stdin)
        turns = build_turns(records, prices)
    except RunledgerError as e:
        stderr.write("runledger: error: %s\n" % e)
        return EXIT_ERROR
    report = aggregate(turns, args.top)
    report["price_table"] = prices_path
    report["note"] = "Estimates only: counts what the logs report; cannot verify billing."
    over = []
    if args.budget is not None and report["totals"]["cost"] > args.budget:
        over.append("estimated cost $%.4f exceeds budget $%.4f" % (report["totals"]["cost"], args.budget))
    if args.budget_tokens is not None and report["totals"]["total"] > args.budget_tokens:
        over.append("total tokens %s exceed token budget %s" % (fmt_int(report["totals"]["total"]),
                                                                  fmt_int(args.budget_tokens)))
    report["budget"] = OrderedDict([("usd", args.budget), ("tokens", args.budget_tokens), ("exceeded", bool(over))])
    if args.json:
        stdout.write(json.dumps(report, indent=2) + "\n")
    elif args.csv:
        stdout.write(render_csv(turns, report, args.csv_group))
    else:
        stdout.write(render_table(report, args.budget))
    if not args.quiet:
        for w in warnings:
            stderr.write("runledger: warning: %s\n" % w)
        if not turns:
            stderr.write("runledger: warning: no usage records found\n")
        if report["totals"]["unpriced_turns"] and args.budget is not None:
            stderr.write("runledger: warning: %s unpriced turn(s) not counted against budget\n"
                         % fmt_int(report["totals"]["unpriced_turns"]))
    for msg in over:
        stderr.write("runledger: BUDGET EXCEEDED: %s\n" % msg)
    return EXIT_BUDGET if over else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
