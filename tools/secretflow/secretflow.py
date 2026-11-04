#!/usr/bin/env python3
"""secretflow: offline data-flow secret-propagation detector for agent transcripts.

tracesweep asks "did a secret *appear* in this run?". secretflow asks the next
question: "once a secret showed up in a tool result (or earlier message), was
that *same value* later passed into another tool's arguments?" — especially
outbound HTTP/webhook/email tools or a shell. That reuse pattern is the classic
agent exfiltration hop: read .env → post to webhook.

Complements tracesweep (presence), fetchfence (URL destinations), shellfence
(dangerous commands), pathfence (sensitive paths), and resultguard (injection
in results). Stdlib only; never connects to a network.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import OrderedDict

VERSION = "0.1.0"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "FL01": ("critical", "Secret from a tool result propagated into an outbound/exfil tool's arguments"),
    "FL02": ("critical", "Secret from a tool result propagated into a shell/command tool's arguments"),
    "FL03": ("high", "Secret from a tool result reused in a later tool call's arguments"),
    "FL04": ("critical", "Auth/session token (Bearer, JWT, Cookie, Authorization) reused in later tool args"),
    "FL05": ("high", "Secret echoed by the assistant, then passed into a subsequent tool call"),
    "FL06": ("high", "Multi-hop: same secret value appears in arguments of two or more distinct tools"),
    "FL07": ("high", "Labeled secret value (api_key=/password=/token=/secret=) from a result reused later"),
    "FL08": ("medium", "User-supplied secret forwarded into an outbound/exfil tool"),
    "FL09": ("medium", "Secret from a tool result written to a file/log/memory sink tool"),
    "FL10": ("info", "Inventory of tainted secret sources and observed sinks"),
}

# Tools whose args leaving the agent boundary are especially risky.
OUTBOUND_RE = re.compile(
    r"(?i)("
    r"http|fetch|browse|web_?fetch|url_?fetch|request|webhook|post_?(?:json|data|message)?|"
    r"send_?(?:email|mail|sms|slack|message|tweet)|email|mail|slack|discord|telegram|"
    r"notify|pagerduty|upload|exfil|callback|oob|pastebin|ngrok"
    r")"
)
SHELL_RE = re.compile(
    r"(?i)(?:^(?:bash|shell|exec|execute|terminal|powershell|pwsh|cmd|zsh|sh|fish|"
    r"run_?(?:command|shell|bash|terminal)|command)$|"
    r"(?:run_command|execute_command|shell_command|bash_command))"
)
SINK_WRITE_RE = re.compile(
    r"(?i)("
    r"write_?(?:file|text|notes)?|save_?(?:file|memory|note)|append_?(?:file|log)|"
    r"create_?(?:file|note)|log_?(?:write|event)|memory_?(?:add|put|store|write)|"
    r"mem0|store_fact|update_memory"
    r")"
)

PLACEHOLDER_RE = re.compile(
    r"(?i)^(null|none|n/?a|todo|tbd|\$\{?[A-Z0-9_]+\}?|<[^>]+>|xxx+|placeholder.*|"
    r"your[_-]?api[_-]?key|redacted|\*{3,}|•+)$"
)

# --- secret extractors --------------------------------------------------------

# Explicit fake / demo tokens used in this kit (safe to match fully).
FAKE_EXAMPLE_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(FAKE-EXAMPLE-[A-Za-z0-9_\-]{4,80})(?![A-Za-z0-9_-])"
)

# Bearer / Authorization header values
BEARER_RE = re.compile(
    r"(?i)\b(?:authorization\s*[:=]\s*)?(?:bearer)\s+([A-Za-z0-9_\-\.=+/]{12,})"
)
AUTH_HEADER_RE = re.compile(
    r"(?i)\bauthorization\s*[:=]\s*([A-Za-z0-9_\-\.=+/]{12,})"
)
COOKIE_RE = re.compile(
    r"(?i)\b(?:cookie|set-cookie)\s*[:=]\s*([^\s;\"']{8,120})"
)

# JWT (three base64url segments)
JWT_RE = re.compile(
    r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"
)

# Labeled assignments: api_key=..., "password": "..."
LABELED_RE = re.compile(
    r"(?i)(?:^|[\s,\"'{(\[])(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|"
    r"client[_-]?secret|auth[_-]?token|access[_-]?token|refresh[_-]?token|"
    r"session[_-]?id|session[_-]?token|password|passwd|pwd|token|secret|"
    r"private[_-]?key|credential)\s*[\"']?\s*[:=]\s*[\"']?"
    r"([A-Za-z0-9_\-+/=.]{8,120})"
)

# Common provider-shaped keys (only match clearly non-live demo forms or long bodies)
PROVIDER_RE = re.compile(
    r"(?<![A-Za-z0-9_-])("
    r"(?:sk|rk)_(?:test|live|demo)_[A-Za-z0-9]{8,}|"
    r"sk-ant-(?:api\d+-)?[A-Za-z0-9_\-]{12,}|"
    r"sk-(?:proj-|svcacct-)?[A-Za-z0-9]{12,}|"
    r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{12,}|"
    r"github_pat_[A-Za-z0-9_]{12,}|"
    r"(?:AKIA|ASIA)[A-Z0-9]{12,}|"
    r"xox[baprs]-[A-Za-z0-9\-]{10,}|"
    r"AIza[A-Za-z0-9_\-]{20,}"
    r")(?![A-Za-z0-9_-])"
)

# Env-file style KEY=VALUE where KEY looks secret-ish
ENV_LINE_RE = re.compile(
    r"(?m)^(?:export\s+)?([A-Z][A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASSWD|CREDENTIAL|"
    r"API_KEY|AUTH)[A-Z0-9_]*)\s*=\s*[\"']?([^\s\"'#]{8,120})"
)


class Finding:
    __slots__ = (
        "rule", "severity", "source", "message", "tool", "turn",
        "secret_kind", "masked", "from_tool", "from_turn", "detail",
    )

    def __init__(
        self, rule, source, message, tool="", turn=None,
        secret_kind="", masked="", from_tool="", from_turn=None, detail="",
    ):
        self.rule = rule
        self.severity = RULES[rule][0]
        self.source = source
        self.message = message
        self.tool = tool or ""
        self.turn = turn
        self.secret_kind = secret_kind or ""
        self.masked = masked or ""
        self.from_tool = from_tool or ""
        self.from_turn = from_turn
        self.detail = detail or ""

    def to_dict(self):
        d = {
            "rule": self.rule,
            "severity": self.severity,
            "title": RULES[self.rule][1],
            "source": self.source,
            "message": self.message,
            "tool": self.tool,
        }
        if self.turn is not None:
            d["turn"] = self.turn
        if self.secret_kind:
            d["secret_kind"] = self.secret_kind
        if self.masked:
            d["masked"] = self.masked
        if self.from_tool:
            d["from_tool"] = self.from_tool
        if self.from_turn is not None:
            d["from_turn"] = self.from_turn
        if self.detail:
            d["detail"] = self.detail
        return d


class Event:
    __slots__ = ("kind", "role", "tool", "args", "text", "turn", "cid")

    def __init__(self, kind, role="", tool="", args=None, text="", turn=None, cid=None):
        self.kind = kind  # user | assistant | tool_call | tool_result
        self.role = role
        self.tool = tool or ""
        self.args = args if args is not None else {}
        self.text = text or ""
        self.turn = turn
        self.cid = cid


class Taint:
    """A secret value observed at a source event."""
    __slots__ = ("value", "kind", "source_kind", "tool", "turn", "labeled")

    def __init__(self, value, kind, source_kind, tool="", turn=None, labeled=False):
        self.value = value
        self.kind = kind
        self.source_kind = source_kind  # tool_result | user | assistant
        self.tool = tool or ""
        self.turn = turn
        self.labeled = labeled


def mask_secret(value: str) -> str:
    if not value:
        return ""
    v = value.strip()
    if len(v) <= 8:
        return v[:2] + "***"
    return v[:4] + "…" + v[-4:]


def _text_of(content) -> str:
    if isinstance(content, str):
        return content
    if content is None:
        return ""
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, dict):
                if b.get("type") in ("text", "output_text", "input_text"):
                    parts.append(str(b.get("text") or ""))
                elif "text" in b:
                    parts.append(str(b.get("text") or ""))
                elif "content" in b:
                    parts.append(_text_of(b["content"]))
            elif isinstance(b, str):
                parts.append(b)
        return "\n".join(parts)
    if isinstance(content, (int, float, bool)):
        return str(content)
    return json.dumps(content, default=str)


def _parse_args(args):
    if isinstance(args, str):
        s = args.strip()
        if not s:
            return {}
        try:
            return json.loads(s)
        except ValueError:
            return {"_raw": args}
    if isinstance(args, dict):
        return args
    return {"_value": args}


def _args_blob(args) -> str:
    if args is None:
        return ""
    if isinstance(args, str):
        return args
    try:
        return json.dumps(args, default=str, sort_keys=True)
    except (TypeError, ValueError):
        return str(args)


def is_outbound_tool(name: str) -> bool:
    return bool(name and OUTBOUND_RE.search(name.replace("-", "_")))


def is_shell_tool(name: str) -> bool:
    return bool(name and SHELL_RE.search(name.replace("-", "_")))


def is_write_sink(name: str) -> bool:
    return bool(name and SINK_WRITE_RE.search(name.replace("-", "_")))


def extract_secrets(text: str):
    """Yield (value, kind, labeled) for secret-shaped spans in text."""
    if not text:
        return
    seen = set()

    def emit(val, kind, labeled=False):
        if not val:
            return
        v = val.strip().strip("\"'`")
        if len(v) < 8:
            return
        if PLACEHOLDER_RE.match(v):
            return
        # Avoid flagging pure hostnames / emails as secrets
        if "@" in v and "://" not in v and re.match(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$", v):
            return
        key = (v, kind)
        if key in seen:
            return
        seen.add(key)
        yield_box.append((v, kind, labeled))

    yield_box = []

    for m in FAKE_EXAMPLE_RE.finditer(text):
        emit(m.group(1), "fake_example", False)
    for m in JWT_RE.finditer(text):
        emit(m.group(1), "jwt", False)
    for m in BEARER_RE.finditer(text):
        emit(m.group(1), "bearer", False)
    for m in AUTH_HEADER_RE.finditer(text):
        emit(m.group(1), "authorization", False)
    for m in COOKIE_RE.finditer(text):
        emit(m.group(1), "cookie", False)
    for m in LABELED_RE.finditer(text):
        emit(m.group(1), "labeled", True)
    for m in PROVIDER_RE.finditer(text):
        emit(m.group(1), "provider_key", False)
    for m in ENV_LINE_RE.finditer(text):
        emit(m.group(2), "env_secret", True)

    # Prefer labeled=True when the same value was also seen unlabeled
    merged = {}
    for v, kind, labeled in yield_box:
        prev = merged.get(v)
        if prev is None:
            merged[v] = (v, kind, labeled)
        else:
            _, pk, pl = prev
            # keep more specific kind preference: labeled/env/auth over fake_example
            prefer_kind = kind if (labeled and not pl) or kind in (
                "jwt", "bearer", "cookie", "authorization", "env_secret", "labeled"
            ) else pk
            merged[v] = (v, prefer_kind, pl or labeled)
    for item in merged.values():
        yield item


def parse_events(data) -> list:
    """Normalize OpenAI / Anthropic / generic transcripts into Event list."""
    if isinstance(data, dict):
        for k in ("messages", "events", "steps", "transcript", "items", "conversation"):
            if isinstance(data.get(k), list):
                data = data[k]
                break
        else:
            data = [data]

    events = []
    turn = 0
    for ev in data:
        if not isinstance(ev, dict):
            continue
        turn += 1
        role = (ev.get("role") or "").lower()
        etype = (ev.get("type") or "").lower()

        # Anthropic-style content blocks (tool_result often arrives on role=user)
        content = ev.get("content")
        if isinstance(content, list) and any(
            isinstance(b, dict) and b.get("type") in ("tool_use", "tool_result", "text")
            for b in content
        ):
            for b in content:
                if not isinstance(b, dict):
                    continue
                bt = b.get("type")
                if bt == "text":
                    text = str(b.get("text") or "")
                    if role == "user":
                        events.append(Event("user", role="user", text=text, turn=turn))
                    elif text.strip():
                        events.append(Event("assistant", role=role or "assistant",
                                            text=text, turn=turn))
                elif bt == "tool_use":
                    name = b.get("name") or ""
                    args = _parse_args(b.get("input", {}))
                    events.append(Event("tool_call", role="assistant", tool=name, args=args,
                                        turn=turn, cid=b.get("id")))
                elif bt == "tool_result":
                    text = _text_of(b.get("content"))
                    events.append(Event("tool_result", role="tool", text=text,
                                        turn=turn, cid=b.get("tool_use_id")))
            continue

        if role == "assistant" and ev.get("tool_calls"):
            text = _text_of(ev.get("content"))
            if text.strip():
                events.append(Event("assistant", role="assistant", text=text, turn=turn))
            for tc in ev["tool_calls"]:
                fn = tc.get("function", tc)
                name = fn.get("name") or tc.get("name") or ""
                args = _parse_args(fn.get("arguments", tc.get("arguments", tc.get("input", {}))))
                events.append(Event("tool_call", role="assistant", tool=name, args=args,
                                    turn=turn, cid=tc.get("id")))
            continue

        if role == "tool" or etype == "tool_result":
            name = ev.get("name") or ev.get("tool") or ""
            text = _text_of(ev.get("content", ev.get("result", ev.get("output"))))
            events.append(Event("tool_result", role="tool", tool=name, text=text,
                                turn=turn, cid=ev.get("tool_call_id") or ev.get("tool_use_id")))
            continue

        if role == "user" or etype in ("user", "human", "input"):
            text = _text_of(ev.get("content", ev.get("text", ev.get("message"))))
            events.append(Event("user", role="user", text=text, turn=turn))
            continue

        tool = ev.get("tool") or ev.get("tool_name")
        if not tool and etype in ("tool_call", "function_call", "tool"):
            tool = ev.get("name")
        if tool:
            args = _parse_args(ev.get("args", ev.get("arguments", ev.get("input", {}))))
            events.append(Event("tool_call", role="assistant", tool=tool, args=args,
                                turn=turn, cid=ev.get("id")))
            if any(k in ev for k in ("result", "output", "content")) and role != "assistant":
                text = _text_of(ev.get("result", ev.get("output", ev.get("content"))))
                if text.strip():
                    events.append(Event("tool_result", role="tool", tool=tool,
                                        text=text, turn=turn))
            elif "result" in ev or "output" in ev:
                text = _text_of(ev.get("result", ev.get("output")))
                events.append(Event("tool_result", role="tool", tool=tool,
                                    text=text, turn=turn))
            continue

        if role == "assistant" or etype in ("assistant", "ai", "model", "final", "answer", "message"):
            text = _text_of(ev.get("content", ev.get("text", ev.get("message"))))
            if text.strip():
                events.append(Event("assistant", role="assistant", text=text, turn=turn))
            continue

    by_id = {}
    for e in events:
        if e.kind == "tool_call" and e.cid:
            by_id[e.cid] = e
    for e in events:
        if e.kind == "tool_result" and not e.tool and e.cid in by_id:
            e.tool = by_id[e.cid].tool
    return events


def _value_in_blob(secret: str, blob: str) -> bool:
    if not secret or not blob:
        return False
    if secret in blob:
        return True
    # Also check without trivial quoting differences
    if len(secret) >= 12 and secret.strip("\"'") in blob:
        return True
    return False


def analyze(events, source, disabled=None):
    """Walk events chronologically; track taint; flag propagations."""
    disabled = set(disabled or [])
    findings = []
    taints = []  # list[Taint]
    # value -> list of sink tool names (for multi-hop)
    sink_tools = {}  # value -> OrderedDict of tool -> (turn, rule_hint)
    assistant_echoed = {}  # value -> turn where assistant restated it

    def add_taints_from(text, source_kind, tool="", turn=None):
        for value, kind, labeled in extract_secrets(text or ""):
            taints.append(Taint(value, kind, source_kind, tool=tool, turn=turn, labeled=labeled))

    def matching_taints(blob, after_turn=None, source_kinds=None):
        out = []
        seen_vals = set()
        for t in taints:
            if t.value in seen_vals:
                continue
            if source_kinds and t.source_kind not in source_kinds:
                continue
            if after_turn is not None and t.turn is not None and t.turn >= after_turn:
                # source must be strictly earlier
                continue
            if _value_in_blob(t.value, blob):
                out.append(t)
                seen_vals.add(t.value)
        return out

    for e in events:
        if e.kind == "user":
            add_taints_from(e.text, "user", turn=e.turn)
            continue

        if e.kind == "assistant":
            # Mark secrets the assistant restates (for FL05); also register as weak taint
            for value, kind, labeled in extract_secrets(e.text or ""):
                # Only count as echo if we already had this value from a tool_result
                prior = [t for t in taints if t.value == value and t.source_kind == "tool_result"]
                if prior:
                    assistant_echoed[value] = e.turn
                # Do not add assistant text as a new *source* for FL03 — only for FL05 path
            continue

        if e.kind == "tool_result":
            add_taints_from(e.text, "tool_result", tool=e.tool, turn=e.turn)
            continue

        if e.kind != "tool_call":
            continue

        blob = _args_blob(e.args)
        if not blob.strip():
            continue

        # Result-sourced propagations
        hits = matching_taints(blob, after_turn=e.turn, source_kinds={"tool_result"})
        for t in hits:
            masked = mask_secret(t.value)
            is_auth = t.kind in ("bearer", "jwt", "cookie", "authorization") or (
                t.kind == "labeled" and re.search(r"(?i)token|session|auth|bearer|jwt|cookie", t.kind)
            )
            # More precise auth: kind itself
            is_auth = t.kind in ("bearer", "jwt", "cookie", "authorization")

            sink_tools.setdefault(t.value, OrderedDict())
            sink_tools[t.value][e.tool or "?"] = e.turn

            if is_outbound_tool(e.tool) and "FL01" not in disabled:
                findings.append(Finding(
                    "FL01", source,
                    "Secret %s (%s) from tool %r turn %s flowed into outbound tool %r"
                    % (masked, t.kind, t.tool or "?", t.turn, e.tool),
                    tool=e.tool, turn=e.turn, secret_kind=t.kind, masked=masked,
                    from_tool=t.tool, from_turn=t.turn,
                    detail="outbound",
                ))
            elif is_shell_tool(e.tool) and "FL02" not in disabled:
                findings.append(Finding(
                    "FL02", source,
                    "Secret %s (%s) from tool %r turn %s flowed into shell tool %r"
                    % (masked, t.kind, t.tool or "?", t.turn, e.tool),
                    tool=e.tool, turn=e.turn, secret_kind=t.kind, masked=masked,
                    from_tool=t.tool, from_turn=t.turn,
                    detail="shell",
                ))
            elif is_write_sink(e.tool) and "FL09" not in disabled:
                findings.append(Finding(
                    "FL09", source,
                    "Secret %s (%s) from tool %r turn %s written via sink tool %r"
                    % (masked, t.kind, t.tool or "?", t.turn, e.tool),
                    tool=e.tool, turn=e.turn, secret_kind=t.kind, masked=masked,
                    from_tool=t.tool, from_turn=t.turn,
                    detail="write_sink",
                ))
            elif "FL03" not in disabled:
                findings.append(Finding(
                    "FL03", source,
                    "Secret %s (%s) from tool %r turn %s reused in later tool %r"
                    % (masked, t.kind, t.tool or "?", t.turn, e.tool),
                    tool=e.tool, turn=e.turn, secret_kind=t.kind, masked=masked,
                    from_tool=t.tool, from_turn=t.turn,
                ))

            if is_auth and "FL04" not in disabled:
                findings.append(Finding(
                    "FL04", source,
                    "Auth/session token %s (%s) from %r reused in tool %r"
                    % (masked, t.kind, t.tool or "?", e.tool),
                    tool=e.tool, turn=e.turn, secret_kind=t.kind, masked=masked,
                    from_tool=t.tool, from_turn=t.turn,
                ))

            if (t.labeled or t.kind in ("labeled", "env_secret")) and "FL07" not in disabled:
                findings.append(Finding(
                    "FL07", source,
                    "Labeled secret %s from %r reused in tool %r"
                    % (masked, t.tool or "?", e.tool),
                    tool=e.tool, turn=e.turn, secret_kind=t.kind, masked=masked,
                    from_tool=t.tool, from_turn=t.turn,
                ))

            if t.value in assistant_echoed and "FL05" not in disabled:
                findings.append(Finding(
                    "FL05", source,
                    "Secret %s echoed by assistant (turn %s) then passed to tool %r"
                    % (masked, assistant_echoed[t.value], e.tool),
                    tool=e.tool, turn=e.turn, secret_kind=t.kind, masked=masked,
                    from_tool=t.tool, from_turn=t.turn,
                    detail="assistant_echo_turn=%s" % assistant_echoed[t.value],
                ))

        # User-sourced → outbound (FL08)
        if is_outbound_tool(e.tool) and "FL08" not in disabled:
            for t in matching_taints(blob, after_turn=e.turn, source_kinds={"user"}):
                masked = mask_secret(t.value)
                findings.append(Finding(
                    "FL08", source,
                    "User-supplied secret %s forwarded into outbound tool %r"
                    % (masked, e.tool),
                    tool=e.tool, turn=e.turn, secret_kind=t.kind, masked=masked,
                    from_tool="(user)", from_turn=t.turn,
                ))

    # FL06 multi-hop
    if "FL06" not in disabled:
        for value, tools_map in sink_tools.items():
            if len(tools_map) >= 2:
                masked = mask_secret(value)
                tool_list = ", ".join("%s@%s" % (n, tr) for n, tr in tools_map.items())
                last_tool = list(tools_map.keys())[-1]
                last_turn = tools_map[last_tool]
                findings.append(Finding(
                    "FL06", source,
                    "Secret %s hopped across %d tools: %s" % (masked, len(tools_map), tool_list),
                    tool=last_tool, turn=last_turn, secret_kind="multi_hop",
                    masked=masked, detail=tool_list,
                ))

    # FL10 inventory
    if "FL10" not in disabled:
        # unique sources
        src_keys = OrderedDict()
        for t in taints:
            k = (t.value, t.source_kind, t.tool, t.turn)
            if k not in src_keys:
                src_keys[k] = t
        for t in src_keys.values():
            sinks = list(sink_tools.get(t.value, {}).keys())
            findings.append(Finding(
                "FL10", source,
                "Taint source %s (%s) from %s %r turn %s → sinks: %s"
                % (mask_secret(t.value), t.kind, t.source_kind, t.tool or "-",
                   t.turn, ", ".join(sinks) if sinks else "(none)"),
                tool=t.tool, turn=t.turn, secret_kind=t.kind,
                masked=mask_secret(t.value),
                detail="sinks=%s" % (sinks,),
            ))

    return findings


def load(path):
    if path == "-":
        raw = sys.stdin.read()
        source = "<stdin>"
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
        source = path

    lines = raw.splitlines()
    # JSONL?
    if len(lines) > 1:
        objs = []
        ok = True
        for line in lines:
            s = line.strip()
            if not s:
                continue
            try:
                objs.append(json.loads(s))
            except ValueError:
                ok = False
                break
        if ok and objs and all(isinstance(o, dict) for o in objs):
            # If each line looks like a message/event, treat as transcript list
            if any(
                ("role" in o) or ("tool" in o) or ("type" in o) or ("tool_calls" in o)
                for o in objs
            ):
                return objs, source

    try:
        return json.loads(raw), source
    except ValueError as e:
        raise ValueError("%s: not valid JSON/JSONL (%s)" % (source, e))


def iter_files(paths):
    out = []
    for p in paths:
        if p == "-":
            out.append(p)
            continue
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs
                           if d not in (".git", "node_modules", "__pycache__", ".venv", "venv")]
                for fn in sorted(files):
                    if fn.endswith((".json", ".jsonl")):
                        out.append(os.path.join(root, fn))
        else:
            out.append(p)
    return out


def format_table(findings, n_events, n_files):
    lines = []
    lines.append(
        "secretflow %s — %d file(s), %d event(s), %d finding(s)"
        % (VERSION, n_files, n_events, len(findings))
    )
    actionable = [f for f in findings if f.rule != "FL10"]
    if not actionable and not findings:
        lines.append("No secret-propagation findings.")
        return "\n".join(lines)
    if not actionable:
        lines.append("No propagation findings (inventory only).")
    lines.append("")
    lines.append("%-6s %-8s %-16s %s" % ("RULE", "SEV", "TOOL", "MESSAGE"))
    lines.append("-" * 100)
    for f in findings:
        lines.append(
            "%-6s %-8s %-16s %s"
            % (f.rule, f.severity, (f.tool or "-")[:16], f.message[:88])
        )
        loc = f.source
        if f.turn is not None:
            loc += " turn=%s" % f.turn
        if f.from_tool or f.from_turn is not None:
            loc += "  ← %s turn=%s" % (f.from_tool or "?", f.from_turn)
        if f.masked:
            loc += "  secret=%s" % f.masked
        lines.append("       at: %s" % loc)
    return "\n".join(lines)


def scan(paths, disabled=None):
    disabled = set(disabled or [])
    all_findings = []
    total_events = 0
    files = iter_files(paths)
    errors = 0
    for path in files:
        try:
            data, source = load(path)
        except (OSError, ValueError) as e:
            sys.stderr.write("secretflow: %s\n" % e)
            errors += 1
            continue
        events = parse_events(data)
        total_events += len(events)
        all_findings.extend(analyze(events, source, disabled=disabled))
    return all_findings, total_events, files, errors


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="secretflow",
        description=(
            "Offline data-flow secret-propagation detector for AI agent transcripts: "
            "flags when a secret from a tool result (or user message) later appears in "
            "another tool's arguments."
        ),
    )
    ap.add_argument("paths", nargs="*", help="transcripts or directories (or - for stdin)")
    ap.add_argument("--disable", nargs="+", default=[], metavar="RULE", help="skip rule ids")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--min-severity", default="info", choices=SEVERITIES)
    ap.add_argument(
        "--fail-on",
        default="high",
        choices=SEVERITIES + ["any", "none"],
        help="exit 1 if any finding >= this severity (default high)",
    )
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version="secretflow " + VERSION)
    ns = ap.parse_args(argv)

    if ns.list_rules:
        for rid, (sev, title) in RULES.items():
            print("%s  %-8s  %s" % (rid, sev, title))
        return 0

    if not ns.paths:
        ap.print_help()
        return 2

    findings, n_events, files, errors = scan(ns.paths, disabled=ns.disable)
    if errors and not files:
        return 2
    if not files:
        sys.stderr.write("secretflow: no readable inputs\n")
        return 2

    min_rank = SEV_RANK[ns.min_severity]
    shown = [f for f in findings if SEV_RANK[f.severity] >= min_rank]
    shown.sort(key=lambda f: (-SEV_RANK[f.severity], f.rule, f.tool or "", f.turn or 0))

    if ns.json:
        print(json.dumps({
            "tool": "secretflow",
            "version": VERSION,
            "files": len(files),
            "events": n_events,
            "findings": [f.to_dict() for f in shown],
        }, indent=2))
    else:
        print(format_table(shown, n_events, len(files)))

    actionable = [f for f in shown if f.rule != "FL10"]
    if ns.fail_on == "none":
        return 0
    if ns.fail_on == "any":
        return 1 if actionable else 0
    threshold = SEV_RANK[ns.fail_on]
    pool = shown if ns.fail_on == "info" else actionable
    if any(SEV_RANK[f.severity] >= threshold for f in pool):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
