#!/usr/bin/env python3
"""rundiff - offline behavioral diff for two AI agent run transcripts.

Part of the agentsec kit. Stdlib-only Python 3. MIT licensed.

Compares a baseline run and a candidate run (OpenAI chat, Anthropic
messages, or a simple generic event format; auto-detected) and reports
added / removed / reordered tool calls, argument changes, result
divergence, final-answer similarity and heuristic "new surface" risk notes
(new tools, network hosts, filesystem paths, shell commands).

Exit codes: 0 = ok (or no gated differences), 1 = --fail-on condition met,
2 = usage / input error.
"""
from __future__ import annotations

import argparse
import difflib
import fnmatch
import hashlib
import json
import os
import re
import shlex
import sys
from urllib.parse import urlparse

__version__ = "0.1.0"

FORMATS = ("auto", "openai", "anthropic", "generic")
FAIL_ON = ("any", "new-surface", "args", "none")


class RundiffError(Exception):
    """Input/usage problem -> exit 2."""


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def load_records(path):
    """Return a list of dict records from a JSON or JSONL file."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise RundiffError("cannot read %s: %s" % (path, exc))
    return parse_records(text, source=path)


def parse_records(text, source="<input>"):
    text = text.strip()
    if not text:
        raise RundiffError("%s: empty transcript" % source)
    data = None
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if data is not None:
        if isinstance(data, list):
            recs = data
        elif isinstance(data, dict):
            for key in ("messages", "events", "transcript", "items"):
                if isinstance(data.get(key), list):
                    recs = list(data[key])
                    if isinstance(data.get("usage"), dict):
                        recs.append({"_usage_only": True, "usage": data["usage"]})
                    break
            else:
                recs = [data]
        else:
            raise RundiffError("%s: unsupported JSON top-level type" % source)
    else:
        recs = []
        for n, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                recs.append(json.loads(line))
            except ValueError as exc:
                raise RundiffError("%s:%d: invalid JSON line: %s" % (source, n, exc))
    out = []
    for r in recs:
        if not isinstance(r, dict):
            continue
        # unwrap {"message": {...}, "usage": ...} envelopes
        if isinstance(r.get("message"), dict) and "role" not in r and "type" not in r:
            m = dict(r["message"])
            if "usage" in r and "usage" not in m:
                m["usage"] = r["usage"]
            r = m
        out.append(r)
    if not out:
        raise RundiffError("%s: no JSON object records found" % source)
    return out


def detect_format(records):
    generic = anthropic = openai = 0
    for r in records:
        t = r.get("type")
        if t in ("tool_call", "tool_result") and "role" not in r:
            generic += 1
        c = r.get("content")
        if isinstance(c, list):
            for b in c:
                if isinstance(b, dict) and b.get("type") in ("tool_use", "tool_result"):
                    anthropic += 1
        if r.get("tool_calls") or r.get("role") == "tool" or r.get("function_call"):
            openai += 1
    if generic and generic >= max(anthropic, openai):
        return "generic"
    if anthropic and anthropic >= openai:
        return "anthropic"
    if openai:
        return "openai"
    if any(r.get("type") for r in records) and not any(r.get("role") for r in records):
        return "generic"
    return "openai"  # plain chat with no tools


# --------------------------------------------------------------------------
# Normalization helpers
# --------------------------------------------------------------------------

def _key_ignored(key, ignore):
    return any(fnmatch.fnmatchcase(str(key), pat) for pat in ignore)


def strip_keys(obj, ignore):
    if not ignore:
        return obj
    if isinstance(obj, dict):
        return {k: strip_keys(v, ignore) for k, v in obj.items() if not _key_ignored(k, ignore)}
    if isinstance(obj, list):
        return [strip_keys(v, ignore) for v in obj]
    return obj


def parse_args_value(raw):
    if raw is None:
        return {}
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return {}
        try:
            v = json.loads(s)
        except ValueError:
            return {"_raw": raw}
        return v if isinstance(v, dict) else {"_value": v}
    if isinstance(raw, dict):
        return raw
    return {"_value": raw}


def content_to_text(content):
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, str):
                parts.append(b)
            elif isinstance(b, dict):
                if b.get("type") in ("tool_use", "tool_result"):
                    continue
                if isinstance(b.get("text"), str):
                    parts.append(b["text"])
                elif "content" in b:
                    parts.append(content_to_text(b["content"]))
        return "\n".join(p for p in parts if p)
    if isinstance(content, dict):
        if isinstance(content.get("text"), str):
            return content["text"]
        return json.dumps(content, sort_keys=True)
    return str(content)


def result_to_text(res):
    if res is None:
        return None
    if isinstance(res, str):
        return res
    if isinstance(res, list):
        texts = []
        for b in res:
            if isinstance(b, dict) and isinstance(b.get("text"), str):
                texts.append(b["text"])
            else:
                texts.append(json.dumps(b, sort_keys=True) if not isinstance(b, str) else b)
        return "\n".join(texts)
    return json.dumps(res, sort_keys=True)


def normalize_result(text, ignore):
    """Canonical text used for hashing; JSON results get ignore-keys applied."""
    if text is None:
        return None
    s = text.strip()
    try:
        v = json.loads(s)
    except ValueError:
        return " ".join(s.split())
    return json.dumps(strip_keys(v, ignore), sort_keys=True, separators=(",", ":"))


def short_hash(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]


def summarize(text, n=80):
    if text is None:
        return None
    s = " ".join(text.split())
    return s if len(s) <= n else s[: n - 1] + "\u2026"


# --------------------------------------------------------------------------
# Run model
# --------------------------------------------------------------------------

class Call:
    __slots__ = ("index", "tool", "args", "raw_args", "call_id", "result", "result_hash", "result_summary")

    def __init__(self, index, tool, raw_args, call_id=None):
        self.index = index
        self.tool = str(tool or "?")
        self.raw_args = parse_args_value(raw_args)
        self.args = {}
        self.call_id = call_id
        self.result = None
        self.result_hash = None
        self.result_summary = None

    def finalize(self, ignore):
        self.args = strip_keys(self.raw_args, ignore)
        norm = normalize_result(self.result, ignore)
        self.result_hash = short_hash(norm) if norm is not None else None
        self.result_summary = summarize(self.result)

    def args_key(self):
        return json.dumps(self.args, sort_keys=True)

    def to_dict(self):
        return {"index": self.index, "tool": self.tool, "args": self.args,
                "result_hash": self.result_hash, "result_summary": self.result_summary}


class Run:
    def __init__(self, fmt, source=""):
        self.format = fmt
        self.source = source
        self.calls = []
        self.final_answer = ""
        self.assistant_turns = 0
        self.user_turns = 0
        self.tokens = {"input": 0, "output": 0, "total": 0}
        self.has_usage = False

    def add_usage(self, u):
        if not isinstance(u, dict):
            return
        inp = u.get("input_tokens", u.get("prompt_tokens"))
        out = u.get("output_tokens", u.get("completion_tokens"))
        tot = u.get("total_tokens")
        got = False
        for k, v in (("input", inp), ("output", out)):
            if isinstance(v, (int, float)):
                self.tokens[k] += int(v)
                got = True
        if isinstance(tot, (int, float)):
            self.tokens["total"] += int(tot)
            got = True
        elif got:
            self.tokens["total"] += int(inp or 0) + int(out or 0)
        if got:
            self.has_usage = True

    def stats(self):
        d = {"calls": len(self.calls), "turns": self.assistant_turns,
             "user_turns": self.user_turns,
             "unique_tools": len({c.tool for c in self.calls})}
        d["tokens"] = dict(self.tokens) if self.has_usage else None
        return d


def _attach(run, pending, call_id, result_text, tool=None):
    target = None
    if call_id is not None:
        target = pending.pop(call_id, None)
    if target is None:
        # fall back: oldest unresolved call (optionally same tool name)
        for c in run.calls:
            if c.result is None and (tool is None or c.tool == tool):
                target = c
                break
        if target is not None and target.call_id in pending:
            pending.pop(target.call_id, None)
    if target is not None:
        target.result = result_text if result_text is not None else ""


def build_run(records, fmt="auto", ignore=(), source=""):
    if fmt == "auto":
        fmt = detect_format(records)
    run = Run(fmt, source)
    pending = {}
    last_answer = ""

    def new_call(tool, args, cid):
        c = Call(len(run.calls), tool, args, cid)
        run.calls.append(c)
        if cid is not None:
            pending[cid] = c
        return c

    for r in records:
        if r.get("_usage_only"):
            run.add_usage(r.get("usage"))
            continue
        run.add_usage(r.get("usage"))
        role = r.get("role")
        if fmt == "generic" and r.get("type") in ("tool_call", "tool_result") and not role:
            if r["type"] == "tool_call":
                new_call(r.get("tool") or r.get("name"),
                         r.get("args", r.get("arguments", r.get("input"))), r.get("id"))
            else:
                res = r.get("result", r.get("output", r.get("content")))
                _attach(run, pending, r.get("id", r.get("call_id")), result_to_text(res), r.get("tool"))
            continue
        if fmt == "generic" and not role:
            t = r.get("type")
            if t in ("final", "final_answer", "answer"):
                role = "assistant"
            elif t in ("user", "assistant", "message"):
                role = r.get("role") or ("user" if t == "user" else "assistant")
            else:
                continue
        if role == "assistant":
            run.assistant_turns += 1
            content = r.get("content", r.get("text", r.get("answer")))
            if fmt == "anthropic" or isinstance(content, list):
                if isinstance(content, list):
                    for b in content:
                        if isinstance(b, dict) and b.get("type") == "tool_use":
                            new_call(b.get("name"), b.get("input"), b.get("id"))
            for tc in r.get("tool_calls") or []:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get("function") or {}
                new_call(fn.get("name") or tc.get("name"),
                         fn.get("arguments", tc.get("arguments")), tc.get("id"))
            fc = r.get("function_call")
            if isinstance(fc, dict):
                new_call(fc.get("name"), fc.get("arguments"), None)
            txt = content_to_text(content)
            if txt.strip():
                last_answer = txt
        elif role in ("tool", "function"):
            _attach(run, pending, r.get("tool_call_id"), result_to_text(r.get("content")),
                    r.get("name") if role == "function" else None)
        elif role == "user":
            content = r.get("content")
            is_result = False
            if isinstance(content, list):
                for b in content:
                    if isinstance(b, dict) and b.get("type") == "tool_result":
                        is_result = True
                        _attach(run, pending, b.get("tool_use_id"), result_to_text(b.get("content")))
            if not is_result:
                run.user_turns += 1
    run.final_answer = last_answer.strip()
    for c in run.calls:
        c.finalize(ignore)
    return run


# --------------------------------------------------------------------------
# Diffing
# --------------------------------------------------------------------------

_MISSING = object()


def json_diff(a, b, path=""):
    """Key-level diff -> list of {path, change, old, new}."""
    out = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            p = "%s.%s" % (path, k) if path else str(k)
            if k not in a:
                out.append({"path": p, "change": "added", "old": None, "new": b[k]})
            elif k not in b:
                out.append({"path": p, "change": "removed", "old": a[k], "new": None})
            else:
                out.extend(json_diff(a[k], b[k], p))
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            out.extend(json_diff(x, y, "%s[%d]" % (path, i)))
    elif a != b:
        out.append({"path": path or "$", "change": "changed", "old": a, "new": b})
    return out


def align(base, cand):
    a = [c.tool for c in base.calls]
    b = [c.tool for c in cand.calls]
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    matched, removed, added = [], [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                matched.append((base.calls[i1 + k], cand.calls[j1 + k]))
        else:
            removed.extend(base.calls[i1:i2])
            added.extend(cand.calls[j1:j2])
    # Reorder detection: a removed call whose tool reappears among added calls.
    reordered = []
    for r in list(removed):
        same = [x for x in added if x.tool == r.tool]
        if not same:
            continue
        exact = [x for x in same if x.args_key() == r.args_key()]
        pick = exact[0] if exact else same[0]
        reordered.append((r, pick))
        removed.remove(r)
        added.remove(pick)
    return matched, removed, added, reordered


# ---- new-surface extraction (heuristic) ----------------------------------

URL_RE = re.compile(r"""\b(?:https?|wss?|ftp|sftp)://[^\s'"<>`)\]]+""", re.I)
PATH_RE = re.compile(r"""(?:(?<=\s)|(?<=^)|(?<=[=:'"(]))((?:~|\.{1,2})?/[\w.\-~@+%/]+|[A-Za-z]:\\[\w.\-\\ ]+)""")
PATH_KEYS = {"path", "file", "filename", "file_path", "filepath", "dir", "directory",
             "cwd", "dest", "destination", "target", "src", "source", "output", "out",
             "input_path", "output_path", "root", "folder"}
CMD_KEYS = {"command", "cmd", "script", "shell", "commandline", "command_line"}
SHELL_TOOL_RE = re.compile(r"(shell|bash|terminal|exec|run_command|run_cmd|subprocess|powershell|cmd)", re.I)
SHELL_WRAPPERS = {"sudo", "env", "nohup", "time", "xargs", "exec", "command"}


def _strings(obj, key=None):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _strings(v, k)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v, key)
    elif isinstance(obj, str):
        yield key, obj


def extract_hosts(args):
    hosts = set()
    for _, s in _strings(args):
        for u in URL_RE.findall(s):
            try:
                h = urlparse(u).hostname
            except ValueError:
                h = None
            if h:
                hosts.add(h.lower())
    return hosts


def extract_paths(args):
    paths = set()
    for key, s in _strings(args):
        clean = URL_RE.sub(" ", s)
        if key is not None and str(key).lower() in PATH_KEYS and clean.strip() and "\n" not in clean \
                and not URL_RE.match(s.strip()):
            paths.add(clean.strip())
            continue
        for m in PATH_RE.findall(clean):
            if len(m) > 1:
                paths.add(m.rstrip(".,;:"))
    return paths


def _dir_of(p):
    if p.endswith("/") or p.endswith("\\"):
        return p.rstrip("/\\") or p
    if "\\" in p and "/" not in p:
        d = p.rsplit("\\", 1)[0]
    else:
        d = os.path.dirname(p)
    return d or "."


def command_programs(cmd):
    progs = []
    try:
        toks = shlex.split(cmd, posix=True)
    except ValueError:
        toks = cmd.split()
    expect = True
    for t in toks:
        if t in ("|", "||", "&&", ";", "&"):
            expect = True
            continue
        # tokens glued to separators, e.g. 'a;b'
        if expect:
            if re.match(r"^\w+=", t) or t in SHELL_WRAPPERS:
                continue
            progs.append(os.path.basename(t))
            expect = False
        if t.endswith(("|", ";", "&&")):
            expect = True
    return progs


def extract_commands(call):
    cmds = []
    for key, s in _strings(call.args):
        if key is not None and str(key).lower() in CMD_KEYS:
            cmds.append(s)
    if not cmds and SHELL_TOOL_RE.search(call.tool):
        for _, s in _strings(call.args):
            cmds.append(s)
            break
    return cmds


def surface(run):
    s = {"tools": {}, "hosts": {}, "paths": {}, "dirs": {}, "commands": {}}

    def note(bucket, item, call):
        s[bucket].setdefault(item, []).append(call.index)

    for c in run.calls:
        note("tools", c.tool, c)
        for h in extract_hosts(c.args):
            note("hosts", h, c)
        for p in extract_paths(c.args):
            note("paths", p, c)
            note("dirs", _dir_of(p), c)
        for cmd in extract_commands(c):
            for prog in command_programs(cmd):
                note("commands", prog, c)
    return s


RISK_NOTES = {
    "tools": "candidate uses a tool never used in baseline; review its permissions/side effects",
    "hosts": "candidate contacts a network host not seen in baseline; possible exfiltration or untrusted fetch",
    "paths": "candidate touches a filesystem path not seen in baseline",
    "dirs": "candidate touches a directory not seen in baseline",
    "commands": "candidate runs a shell program not seen in baseline",
}


def new_surface(base, cand):
    sb, sc = surface(base), surface(cand)
    flags = []
    for bucket in ("tools", "hosts", "paths", "dirs", "commands"):
        for item in sorted(set(sc[bucket]) - set(sb[bucket])):
            ex = cand.calls[sc[bucket][item][0]]
            flags.append({"kind": bucket[:-1] if bucket != "dirs" else "dir", "value": item,
                          "calls": sc[bucket][item], "example_tool": ex.tool,
                          "risk_note": RISK_NOTES[bucket] + " (heuristic)"})
    return flags


def diff_runs(base, cand):
    matched, removed, added, reordered = align(base, cand)
    arg_changes, divergence = [], []
    for b, c in matched + reordered:
        d = json_diff(b.args, c.args)
        if d:
            arg_changes.append({"tool": b.tool, "baseline_index": b.index,
                                "candidate_index": c.index, "changes": d})
        if b.result_hash and c.result_hash and b.result_hash != c.result_hash:
            divergence.append({"tool": b.tool, "baseline_index": b.index,
                               "candidate_index": c.index,
                               "baseline_hash": b.result_hash, "candidate_hash": c.result_hash,
                               "baseline_summary": b.result_summary,
                               "candidate_summary": c.result_summary})
    fa, fb = base.final_answer, cand.final_answer
    ratio = 1.0 if fa == fb else difflib.SequenceMatcher(None, fa, fb, autojunk=False).ratio()
    report = {
        "rundiff_version": __version__,
        "baseline": {"source": base.source, "format": base.format, "stats": base.stats(),
                     "tool_sequence": [c.tool for c in base.calls]},
        "candidate": {"source": cand.source, "format": cand.format, "stats": cand.stats(),
                      "tool_sequence": [c.tool for c in cand.calls]},
        "matched": len(matched),
        "added": [c.to_dict() for c in added],
        "removed": [c.to_dict() for c in removed],
        "reordered": [{"tool": b.tool, "baseline_index": b.index, "candidate_index": c.index}
                      for b, c in reordered],
        "arg_changes": arg_changes,
        "result_divergence": divergence,
        "final_answer": {"similarity": round(ratio, 4), "identical": fa == fb,
                         "baseline": summarize(fa, 160), "candidate": summarize(fb, 160)},
        "new_surface": new_surface(base, cand),
        "heuristic": True,
    }
    report["has_differences"] = bool(added or removed or reordered or arg_changes or divergence
                                     or fa != fb or report["new_surface"])
    return report


def gate(report, fail_on):
    if fail_on == "none":
        return 0
    if fail_on == "any":
        return 1 if report["has_differences"] else 0
    if fail_on == "args":
        return 1 if report["arg_changes"] else 0
    if fail_on == "new-surface":
        return 1 if report["new_surface"] else 0
    raise RundiffError("unknown --fail-on value %r" % fail_on)


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

class Style:
    def __init__(self, enabled):
        self.enabled = enabled

    def _w(self, code, s):
        return "\033[%sm%s\033[0m" % (code, s) if self.enabled else s

    def red(self, s): return self._w("31", s)
    def green(self, s): return self._w("32", s)
    def yellow(self, s): return self._w("33", s)
    def cyan(self, s): return self._w("36", s)
    def bold(self, s): return self._w("1", s)


def _j(v, n=60):
    s = json.dumps(v, sort_keys=True) if not isinstance(v, str) else json.dumps(v)
    return s if len(s) <= n else s[: n - 1] + "\u2026"


def render_text(rep, color=False):
    st = Style(color)
    L = []
    b, c = rep["baseline"], rep["candidate"]
    L.append(st.bold("rundiff %s  (heuristic behavioral diff)" % rep["rundiff_version"]))
    L.append("baseline : %s [%s]" % (b["source"], b["format"]))
    L.append("candidate: %s [%s]" % (c["source"], c["format"]))
    L.append("")
    L.append(st.bold("Summary"))
    L.append("  %-14s %10s %10s" % ("", "baseline", "candidate"))
    for k in ("calls", "turns", "user_turns", "unique_tools"):
        L.append("  %-14s %10s %10s" % (k, b["stats"][k], c["stats"][k]))
    for k in ("input", "output", "total"):
        bt = b["stats"]["tokens"][k] if b["stats"]["tokens"] else "-"
        ct = c["stats"]["tokens"][k] if c["stats"]["tokens"] else "-"
        if bt != "-" or ct != "-":
            L.append("  %-14s %10s %10s" % ("tokens." + k, bt, ct))
    L.append("  matched calls: %d" % rep["matched"])
    L.append("")
    L.append(st.bold("Tool-call changes"))
    if not (rep["added"] or rep["removed"] or rep["reordered"]):
        L.append("  (none)")
    for x in rep["removed"]:
        L.append(st.red("  - removed  #%d %s %s" % (x["index"], x["tool"], _j(x["args"]))))
    for x in rep["added"]:
        L.append(st.green("  + added    #%d %s %s" % (x["index"], x["tool"], _j(x["args"]))))
    for x in rep["reordered"]:
        L.append(st.yellow("  ~ reordered %s: baseline #%d -> candidate #%d"
                           % (x["tool"], x["baseline_index"], x["candidate_index"])))
    L.append("")
    L.append(st.bold("Argument changes"))
    if not rep["arg_changes"]:
        L.append("  (none)")
    for a in rep["arg_changes"]:
        L.append("  %s (baseline #%d / candidate #%d)" % (a["tool"], a["baseline_index"], a["candidate_index"]))
        for ch in a["changes"]:
            if ch["change"] == "added":
                L.append(st.green("    + %s = %s" % (ch["path"], _j(ch["new"]))))
            elif ch["change"] == "removed":
                L.append(st.red("    - %s (was %s)" % (ch["path"], _j(ch["old"]))))
            else:
                L.append(st.yellow("    ~ %s: %s -> %s" % (ch["path"], _j(ch["old"]), _j(ch["new"]))))
    L.append("")
    L.append(st.bold("Result divergence"))
    if not rep["result_divergence"]:
        L.append("  (none)")
    for d in rep["result_divergence"]:
        L.append(st.yellow("  ~ %s (#%d/#%d) hash %s -> %s" % (d["tool"], d["baseline_index"],
                 d["candidate_index"], d["baseline_hash"], d["candidate_hash"])))
    L.append("")
    fa = rep["final_answer"]
    L.append(st.bold("Final answer"))
    L.append("  similarity: %.2f%s" % (fa["similarity"], " (identical)" if fa["identical"] else ""))
    if not fa["identical"]:
        L.append("  baseline : %s" % fa["baseline"])
        L.append("  candidate: %s" % fa["candidate"])
    L.append("")
    L.append(st.bold("New surface in candidate (heuristic risk notes)"))
    if not rep["new_surface"]:
        L.append("  (none)")
    for f in rep["new_surface"]:
        L.append(st.red("  ! new %-7s %s" % (f["kind"], f["value"])) +
                 "  [calls %s via %s]" % (",".join("#%d" % i for i in f["calls"]), f["example_tool"]))
        L.append("      risk: %s" % f["risk_note"])
    L.append("")
    L.append("Note: alignment and surface extraction are heuristic; nondeterministic agents "
             "differ naturally. rundiff does not judge which run is better.")
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="rundiff",
                                description="Offline behavioral diff of two AI agent run transcripts.")
    p.add_argument("baseline", help="baseline transcript (JSON or JSONL)")
    p.add_argument("candidate", help="candidate transcript (JSON or JSONL)")
    p.add_argument("--format", choices=FORMATS, default="auto",
                   help="transcript format for both inputs (default: auto-detect each)")
    p.add_argument("--ignore-keys", default="",
                   help="comma-separated arg/result keys to ignore (fnmatch globs), e.g. id,*_at,timestamp")
    p.add_argument("--json", action="store_true", help="emit JSON report")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--fail-on", choices=FAIL_ON, default="none",
                   help="exit 1 when this kind of difference is found (default: none)")
    p.add_argument("--version", action="version", version="rundiff " + __version__)
    return p


def main(argv=None, stdout=None):
    stdout = stdout or sys.stdout
    parser = build_parser()
    try:
        ns = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2
    ignore = [k.strip() for k in ns.ignore_keys.split(",") if k.strip()]
    try:
        base = build_run(load_records(ns.baseline), ns.format, ignore, ns.baseline)
        cand = build_run(load_records(ns.candidate), ns.format, ignore, ns.candidate)
        rep = diff_runs(base, cand)
        code = gate(rep, ns.fail_on)
    except RundiffError as exc:
        sys.stderr.write("rundiff: error: %s\n" % exc)
        return 2
    if ns.json:
        rep["exit_code"] = code
        stdout.write(json.dumps(rep, indent=2, sort_keys=False, default=str) + "\n")
    else:
        color = (not ns.no_color and not os.environ.get("NO_COLOR")
                 and hasattr(stdout, "isatty") and stdout.isatty())
        stdout.write(render_text(rep, color))
    return code


if __name__ == "__main__":
    sys.exit(main())
