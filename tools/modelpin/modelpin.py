#!/usr/bin/env python3
"""modelpin: pin expected model IDs and detect floating aliases / switches / provider drift.

Agents and LLM apps often log the model that actually served each turn. Floating
aliases (gpt-4o, claude-3-5-sonnet-latest), silent mid-run switches, provider
routing changes (OpenAI → Bedrock) and accidental downgrades change behaviour
and break evals. modelpin reads a small JSON policy (or CLI flags), extracts
model IDs from saved transcripts (OpenAI, Anthropic, generic JSON/JSONL), and
reports findings with turn attribution.

Complements aibom (repo inventory that *notes* floating aliases in source) and
runledger (cost by model). modelpin is a CI gate over *observed* transcript
models vs an allowlist / pin. Stdlib only; never runs an agent or contacts a
network.
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
    "MD01": ("high", "Observed model is not in the allowlist / policy"),
    "MD02": ("high", "Floating / unversioned model alias (not a dated snapshot)"),
    "MD03": ("high", "Mid-run model switch (multiple distinct models in one transcript)"),
    "MD04": ("high", "Provider drift vs policy expected providers"),
    "MD05": ("medium", "Exact pinned model mismatch"),
    "MD06": ("medium", "Missing / empty model field on a model-bearing record"),
    "MD07": ("low", "Soft-deprecated or retired model family"),
    "MD08": ("high", "Suspected capability downgrade vs pinned / allowed tier"),
    "MD09": ("info", "Inventory of models observed"),
}

MODEL_KEYS = (
    "model", "model_name", "modelName", "model_id", "modelId",
    "modelVersion", "model_version", "llm", "llm_model",
)

# Family names / aliases that resolve to whatever the provider ships today.
FLOATING_EXACT = {
    "gpt-4", "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4-turbo-preview",
    "gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano", "gpt-3.5-turbo", "gpt-3.5-turbo-16k",
    "chatgpt-4o-latest", "o1", "o1-mini", "o1-preview", "o3", "o3-mini", "o4-mini",
    "claude-3-opus-latest", "claude-3-sonnet-latest", "claude-3-haiku-latest",
    "claude-3-5-sonnet-latest", "claude-3-5-haiku-latest", "claude-3-7-sonnet-latest",
    "claude-sonnet-4-0", "claude-opus-4-0", "claude-haiku-4-0",
    "claude-sonnet-4", "claude-opus-4", "claude-haiku-4",
    "gemini-pro", "gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash",
    "gemini-2.0-pro", "gemini-2.5-pro", "gemini-2.5-flash", "gemini-flash-latest",
    "gemini-pro-latest", "command", "command-r", "command-r-plus",
    "mistral-large", "mistral-small", "mistral-medium", "mixtral-8x7b",
    "grok-2", "grok-3", "grok-beta",
}

FLOATING_SUFFIX_RE = re.compile(
    r"(?i)(?:-latest|-current|-stable|-preview|-alias)$"
)
# Dated snapshot: ...-YYYYMMDD or ...-YYYY-MM-DD near the end
DATED_RE = re.compile(r"(?:-|\.)(?:20\d{2})(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:$|[^0-9])")
DATED_DASH_RE = re.compile(r"-20\d{2}-\d{2}-\d{2}(?:$|[^0-9])")

DEPRECATED_PREFIXES = (
    "gpt-3.5", "text-davinci", "text-curie", "text-babbage", "text-ada",
    "davinci", "curie", "babbage", "ada", "code-davinci",
    "claude-instant", "claude-1", "claude-2", "claude-v1", "claude-v2",
    "palm-", "chat-bison", "text-bison",
)

# Capability tier hints for MD08 downgrade detection (higher = stronger).
TIER_PATTERNS = [
    (re.compile(r"(?i)\b(opus|o1(?!-mini)|o3(?!-mini)|gpt-4(?!o-mini)(?!\.1-mini)(?!\.1-nano)|gpt-4\.1(?!-mini|-nano)|claude-3-opus|claude-opus|gemini-(?:1\.5|2\.5)?-pro|mistral-large|command-r-plus|grok-3)\b"), 3),
    (re.compile(r"(?i)\b(sonnet|gpt-4o(?!-mini)|gpt-4-turbo|claude-3-5-sonnet|claude-3-7-sonnet|claude-sonnet|gemini-2\.0-pro|mistral-medium|command-r|grok-2|o1-mini|o3-mini|o4-mini)\b"), 2),
    (re.compile(r"(?i)\b(haiku|mini|nano|flash|small|tiny|gpt-3\.5|claude-3-haiku|gemini-.*flash|mistral-small|command(?!-r))\b"), 1),
]

PROVIDER_RULES = [
    ("openai", re.compile(r"(?i)^(?:openai/|ft:)?(?:gpt-|chatgpt-|o[1-9]|text-davinci|davinci|curie|babbage|ada)")),
    ("anthropic", re.compile(r"(?i)^(?:anthropic[./])?claude-")),
    ("google", re.compile(r"(?i)^(?:google/|models/)?(?:gemini-|palm-|chat-bison|text-bison)")),
    ("bedrock", re.compile(r"(?i)^(?:bedrock/|aws/)?(?:(?:us|eu|ap)\.)?(?:anthropic\.|amazon\.|meta\.|cohere\.|mistral\.|ai21\.)")),
    ("azure", re.compile(r"(?i)^(?:azure/|azure-openai/|openai\.azure)")),
    ("mistral", re.compile(r"(?i)^(?:mistral/)?(?:mistral-|mixtral-|codestral-|pixtral-|open-mistral|open-mixtral)")),
    ("meta", re.compile(r"(?i)^(?:meta/|meta-llama/)?(?:llama-|meta-llama)")),
    ("cohere", re.compile(r"(?i)^(?:cohere/)?(?:command)")),
    ("xai", re.compile(r"(?i)^(?:xai/)?grok-")),
    ("together", re.compile(r"(?i)^together/")),
    ("fireworks", re.compile(r"(?i)^fireworks/")),
    ("groq", re.compile(r"(?i)^groq/")),
    ("ollama", re.compile(r"(?i)^(?:ollama/|local/)")),
]

PLACEHOLDER_RE = re.compile(
    r"(?i)^(null|none|n/?a|todo|tbd|\$\{?[A-Z0-9_]+\}?|<[^>]+>|xxx+|placeholder.*|"
    r"your[-_].*|example.*|fake-.*)$"
)


class Finding:
    __slots__ = ("rule", "severity", "source", "message", "model", "turn", "provider", "detail")

    def __init__(self, rule, source, message, model="", turn=None, provider="", detail=""):
        self.rule = rule
        self.severity = RULES[rule][0]
        self.source = source
        self.message = message
        self.model = model or ""
        self.turn = turn
        self.provider = provider or ""
        self.detail = detail or ""

    def to_dict(self):
        d = {
            "rule": self.rule,
            "severity": self.severity,
            "title": RULES[self.rule][1],
            "source": self.source,
            "message": self.message,
            "model": self.model,
            "provider": self.provider,
        }
        if self.turn is not None:
            d["turn"] = self.turn
        if self.detail:
            d["detail"] = self.detail
        return d


class ModelEvent:
    __slots__ = ("source", "model", "turn", "provider", "missing")

    def __init__(self, source, model, turn=None, missing=False):
        self.source = source
        self.model = (model or "").strip()
        self.turn = turn
        self.missing = bool(missing)
        self.provider = infer_provider(self.model) if self.model else ""


def infer_provider(model: str) -> str:
    if not model:
        return ""
    m = model.strip()
    # Explicit provider prefix "provider/rest"
    if "/" in m:
        head = m.split("/", 1)[0].lower()
        known = {
            "openai", "anthropic", "google", "bedrock", "azure", "azure-openai",
            "mistral", "meta", "meta-llama", "cohere", "xai", "together",
            "fireworks", "groq", "ollama", "aws",
        }
        if head in known:
            if head in ("azure-openai",):
                return "azure"
            if head in ("meta-llama",):
                return "meta"
            if head == "aws":
                return "bedrock"
            return head
    for name, rx in PROVIDER_RULES:
        if rx.search(m):
            return name
    return "unknown"


def is_floating_alias(model: str) -> bool:
    if not model:
        return False
    m = model.strip()
    # Strip provider prefix for alias checks
    bare = m.split("/", 1)[1] if "/" in m and not m.lower().startswith(("meta-llama/",)) else m
    if bare.lower() in {x.lower() for x in FLOATING_EXACT}:
        return True
    if FLOATING_SUFFIX_RE.search(bare):
        return True
    # Bedrock dated IDs often end with :0 — treat as pinned if they have a date
    if DATED_RE.search(bare) or DATED_DASH_RE.search(bare):
        return False
    # Short family tokens without date/version digits beyond major
    # e.g. "claude-3-5-sonnet" (no date) is floating; "claude-3-5-sonnet-20241022" is not
    if re.match(r"(?i)^claude-\d", bare) and not re.search(r"20\d{2}", bare):
        return True
    if re.match(r"(?i)^gpt-", bare) and not re.search(r"20\d{2}", bare):
        # gpt-4o already in FLOATING_EXACT; catch gpt-4o-2024-xx as pinned
        return True
    if re.match(r"(?i)^gemini-", bare) and not re.search(r"20\d{2}|-\d{3,}$", bare):
        if re.search(r"(?i)-(latest|pro|flash|flash-lite)$", bare) or bare.lower() in {
            "gemini-pro", "gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash",
            "gemini-2.0-pro", "gemini-2.5-pro", "gemini-2.5-flash",
        }:
            return True
    return False


def is_deprecated(model: str) -> bool:
    bare = model.split("/", 1)[-1].lower()
    return any(bare.startswith(p) for p in DEPRECATED_PREFIXES)


def capability_tier(model: str) -> int:
    """Return 3/2/1/0 for high/mid/low/unknown capability tier."""
    if not model:
        return 0
    for rx, tier in TIER_PATTERNS:
        if rx.search(model):
            return tier
    return 0


def models_match(a: str, b: str) -> bool:
    if not a or not b:
        return False
    return a.strip().lower() == b.strip().lower()


def model_allowed(model: str, allowed) -> bool:
    if not allowed:
        return True
    ml = model.strip().lower()
    bare = ml.split("/", 1)[-1]
    for a in allowed:
        al = a.strip().lower()
        if ml == al or bare == al or ml == al.split("/", 1)[-1]:
            return True
        # fnmatch-ish: trailing *
        if al.endswith("*") and (ml.startswith(al[:-1]) or bare.startswith(al[:-1])):
            return True
    return False


# --------------------------------------------------------------------------- loading

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
                    if fn.endswith((".json", ".jsonl", ".ndjson")):
                        paths.append(os.path.join(root, fn))
        else:
            paths.append(p)
    return paths


def load_events(path: str) -> list:
    if path == "-":
        raw = sys.stdin.read()
        return _parse_content(raw, "<stdin>")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    return _parse_content(raw, path)


def _parse_content(raw: str, source: str) -> list:
    raw_strip = raw.strip()
    if not raw_strip:
        return []
    if raw_strip.startswith("{") and "\n{" in raw:
        try:
            data = json.loads(raw)
            return _extract_from_obj(data, source)
        except json.JSONDecodeError:
            return _parse_jsonl(raw, source)
    if "\n" in raw_strip and not raw_strip.lstrip().startswith(("[",)):
        # Prefer JSONL when multiple top-level objects
        if raw_strip.lstrip().startswith("{") and raw.count("\n{") >= 1:
            # Could be pretty JSON — try full parse first
            try:
                data = json.loads(raw)
                return _extract_from_obj(data, source)
            except json.JSONDecodeError:
                return _parse_jsonl(raw, source)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return _parse_jsonl(raw, source)
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


def _first_model_in(obj, skip_containers=True):
    """Return first model-like string found, preferring top-level keys."""
    if not isinstance(obj, dict):
        return None
    for k in MODEL_KEYS:
        v = obj.get(k)
        if isinstance(v, str) and v.strip() and not PLACEHOLDER_RE.match(v.strip()):
            return v.strip()
        if isinstance(v, dict):
            # Azure / some SDKs: {"model": {"id": "..."}}
            for kk in ("id", "name", "model"):
                vv = v.get(kk)
                if isinstance(vv, str) and vv.strip() and not PLACEHOLDER_RE.match(vv.strip()):
                    return vv.strip()
    # Nested response / request
    for nest in ("response", "request", "body", "params", "parameters", "config", "metadata"):
        child = obj.get(nest)
        if isinstance(child, dict):
            found = _first_model_in(child, skip_containers=True)
            if found:
                return found
    return None


def _looks_model_bearing(obj: dict) -> bool:
    """Heuristic: record that should have carried a model id."""
    if any(k in obj for k in MODEL_KEYS):
        return True
    if obj.get("object") in ("chat.completion", "response"):
        return True
    typ = (obj.get("type") or obj.get("event") or "").lower()
    if typ in ("message", "response", "completion", "llm_call", "model_call", "generation"):
        return True
    # OpenAI chat completion shape
    if "choices" in obj and ("usage" in obj or "id" in obj):
        return True
    # Anthropic message
    if obj.get("type") == "message" and "content" in obj and "role" in obj:
        return True
    # usage + messages wrapper
    if "usage" in obj and ("messages" in obj or "response" in obj):
        return True
    return False


def _extract_from_obj(data, source: str, turn_hint=None) -> list:
    events = []
    if isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, dict):
                events.extend(_extract_from_obj(item, source, turn_hint=i if turn_hint is None else turn_hint))
        return events

    if not isinstance(data, dict):
        return events

    # Wrapper lists
    for key in ("records", "events", "turns", "entries", "data", "items", "logs", "runs"):
        if isinstance(data.get(key), list) and any(isinstance(x, dict) for x in data[key]):
            # Also capture top-level model as default for children missing one
            parent_model = _first_model_in(data)
            for i, item in enumerate(data[key]):
                if not isinstance(item, dict):
                    continue
                child_events = _extract_from_obj(item, "%s#%s[%d]" % (source, key, i), turn_hint=i)
                if not child_events and parent_model:
                    # child had no model; if it looks like a turn, attribute parent
                    if _looks_model_bearing(item) or item.get("role") == "assistant" or "usage" in item:
                        child_events = [ModelEvent(source, parent_model, turn=i)]
                # Fill missing model from parent
                for ev in child_events:
                    if ev.missing and parent_model:
                        ev.model = parent_model
                        ev.missing = False
                        ev.provider = infer_provider(parent_model)
                    elif not ev.model and parent_model:
                        ev.model = parent_model
                        ev.provider = infer_provider(parent_model)
                events.extend(child_events)
            if events:
                return events

    # Chat transcript with top-level model + messages
    model = _first_model_in(data)
    if "messages" in data and isinstance(data["messages"], list):
        # One event for the whole transcript unless per-message models exist
        per_msg = []
        for i, msg in enumerate(data["messages"]):
            if not isinstance(msg, dict):
                continue
            m = _first_model_in(msg)
            if m:
                per_msg.append(ModelEvent(source, m, turn=i))
        if per_msg:
            return per_msg
        if model:
            return [ModelEvent(source, model, turn=turn_hint)]
        # messages present but no model anywhere
        if _looks_model_bearing(data) or any(
            isinstance(m, dict) and (m.get("role") == "assistant" or "tool_calls" in m)
            for m in data["messages"]
        ):
            return [ModelEvent(source, "", turn=turn_hint, missing=True)]
        return []

    # Anthropic-style single message object
    if model:
        events.append(ModelEvent(source, model, turn=turn_hint))
        return events

    if _looks_model_bearing(data):
        events.append(ModelEvent(source, "", turn=turn_hint, missing=True))
    return events


# --------------------------------------------------------------------------- policy

def load_policy(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("policy must be a JSON object")
    return normalize_policy(data)


def normalize_policy(data: dict) -> dict:
    allowed = data.get("allowed") or data.get("allow") or data.get("models") or []
    if isinstance(allowed, str):
        allowed = [allowed]
    providers = data.get("providers") or data.get("provider") or []
    if isinstance(providers, str):
        providers = [providers]
    pinned = data.get("pinned") or data.get("pin") or ""
    if isinstance(pinned, list):
        pinned = pinned[0] if pinned else ""
    return {
        "allowed": [str(x) for x in allowed if x],
        "providers": [str(x).lower() for x in providers if x],
        "pinned": str(pinned) if pinned else "",
        "forbid_aliases": bool(data.get("forbid_aliases", data.get("forbidAliases", True))),
        "forbid_switch": bool(data.get("forbid_switch", data.get("forbidSwitch", True))),
        "forbid_downgrade": bool(data.get("forbid_downgrade", data.get("forbidDowngrade", True))),
    }


def default_policy() -> dict:
    return {
        "allowed": [
            "gpt-4o-2024-08-06",
            "claude-3-5-sonnet-20241022",
        ],
        "providers": ["openai", "anthropic"],
        "pinned": "",
        "forbid_aliases": True,
        "forbid_switch": True,
        "forbid_downgrade": True,
    }


# --------------------------------------------------------------------------- analyze

def analyze(events: list, policy: dict, disabled=None) -> list:
    disabled = set(disabled or [])
    findings = []
    allowed = policy.get("allowed") or []
    providers = policy.get("providers") or []
    pinned = policy.get("pinned") or ""
    forbid_aliases = policy.get("forbid_aliases", True)
    forbid_switch = policy.get("forbid_switch", True)
    forbid_downgrade = policy.get("forbid_downgrade", True)

    def add(rule, source, message, model="", turn=None, provider="", detail=""):
        if rule in disabled:
            return
        findings.append(Finding(rule, source, message, model=model, turn=turn,
                                provider=provider, detail=detail))

    # Group by source file (strip JSONL line / #key suffixes for switch detection)
    by_run = OrderedDict()
    for ev in events:
        run_key = re.sub(r":\d+$", "", ev.source)
        run_key = re.sub(r"#.*$", "", run_key)
        by_run.setdefault(run_key, []).append(ev)

    seen_models = OrderedDict()

    for run_key, run_events in by_run.items():
        models_in_run = []
        for ev in run_events:
            if ev.missing or not ev.model:
                add("MD06", ev.source,
                    "Model-bearing record has no usable model id",
                    model="", turn=ev.turn, detail="missing")
                continue

            seen_models.setdefault(ev.model, 0)
            seen_models[ev.model] += 1
            models_in_run.append(ev)

            if allowed and not model_allowed(ev.model, allowed):
                add("MD01", ev.source,
                    "Model '%s' is not in the allowlist (%d entr%s)" % (
                        ev.model, len(allowed), "y" if len(allowed) == 1 else "ies"),
                    model=ev.model, turn=ev.turn, provider=ev.provider)

            if forbid_aliases and is_floating_alias(ev.model):
                add("MD02", ev.source,
                    "Floating alias '%s' — pin a dated snapshot for reproducible behaviour" % ev.model,
                    model=ev.model, turn=ev.turn, provider=ev.provider)

            if providers and ev.provider and ev.provider != "unknown":
                if ev.provider.lower() not in providers:
                    add("MD04", ev.source,
                        "Provider '%s' for model '%s' not in expected providers %s" % (
                            ev.provider, ev.model, providers),
                        model=ev.model, turn=ev.turn, provider=ev.provider)

            if pinned and not models_match(ev.model, pinned):
                # Exact pin: any other model is MD05; also check downgrade
                add("MD05", ev.source,
                    "Observed '%s' but policy pins '%s'" % (ev.model, pinned),
                    model=ev.model, turn=ev.turn, provider=ev.provider,
                    detail="pinned=%s" % pinned)
                if forbid_downgrade:
                    pt, ot = capability_tier(pinned), capability_tier(ev.model)
                    if pt and ot and ot < pt:
                        add("MD08", ev.source,
                            "Suspected downgrade: pinned '%s' (tier %d) vs observed '%s' (tier %d)" % (
                                pinned, pt, ev.model, ot),
                            model=ev.model, turn=ev.turn, provider=ev.provider)

            if is_deprecated(ev.model):
                add("MD07", ev.source,
                    "Soft-deprecated / retired model family: '%s'" % ev.model,
                    model=ev.model, turn=ev.turn, provider=ev.provider)

            # Downgrade vs allowlist highest tier (when no exact pin)
            if forbid_downgrade and not pinned and allowed:
                best = max((capability_tier(a) for a in allowed), default=0)
                ot = capability_tier(ev.model)
                if best and ot and ot < best and model_allowed(ev.model, allowed):
                    # Allowed but lower tier than other allowed entries — only flag if
                    # the allowlist clearly mixes tiers and this is the low one while
                    # a high one exists. Keep quiet unless observed is strictly lower
                    # than every non-matching higher entry... Actually only flag when
                    # the observed model is allowed AND lower than the max allowed tier
                    # AND the policy has an explicit higher-tier allow. That's noisy.
                    # Skip allowlist-relative downgrade; pin handles it.
                    pass

        if forbid_switch and len({ev.model.lower() for ev in models_in_run if ev.model}) > 1:
            uniq = list(OrderedDict((ev.model, True) for ev in models_in_run if ev.model).keys())
            # Attribute to the first event that differs from the first model
            first = models_in_run[0].model
            switched = next((ev for ev in models_in_run if not models_match(ev.model, first)), models_in_run[-1])
            add("MD03", switched.source,
                "Mid-run model switch: %s" % " → ".join(uniq),
                model=switched.model, turn=switched.turn, provider=switched.provider,
                detail="models=%s" % ",".join(uniq))

    if seen_models and "MD09" not in disabled:
        summary = ", ".join("%s×%d" % (m, c) for m, c in seen_models.items())
        first_model = next(iter(seen_models))
        add("MD09", next(iter(by_run)) if by_run else "<run>",
            "Models observed: %s (%d distinct)" % (summary, len(seen_models)),
            model=first_model, provider=infer_provider(first_model),
            detail="distinct=%d" % len(seen_models))

    return findings


def format_table(findings, event_count, distinct_models):
    lines = []
    lines.append("modelpin %s — %d model event(s), %d distinct model(s), %d finding(s)" % (
        VERSION, event_count, distinct_models, len(findings)))
    if not findings:
        lines.append("No model-pin findings.")
        return "\n".join(lines)
    lines.append("")
    lines.append("%-6s %-8s %-28s %-10s  %s" % ("RULE", "SEV", "MODEL", "PROVIDER", "MESSAGE"))
    lines.append("-" * 100)
    for f in findings:
        lines.append("%-6s %-8s %-28s %-10s  %s" % (
            f.rule, f.severity, (f.model or "-")[:28], (f.provider or "-")[:10], f.message[:72]))
        if f.source:
            loc = f.source
            if f.turn is not None:
                loc += " turn=%s" % f.turn
            lines.append("       at:  %s" % loc)
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="modelpin",
        description="Pin expected model IDs and detect floating aliases, switches and provider drift in transcripts.",
    )
    ap.add_argument("paths", nargs="*", help="transcripts, directories, or - for stdin (omit with init/--list-rules)")
    ap.add_argument("-p", "--policy", help="JSON policy file (allowed/providers/pinned/forbid_*)")
    ap.add_argument("--allow", nargs="+", default=[], metavar="MODEL",
                    help="allowed model ids / globs (merged with policy)")
    ap.add_argument("--pinned", default="", help="exact model id that must be used")
    ap.add_argument("--providers", default="",
                    help="comma-separated expected providers (openai,anthropic,...)")
    ap.add_argument("--forbid-aliases", action="store_true", default=None,
                    help="flag floating aliases (default: on when policy/allow present, else on)")
    ap.add_argument("--allow-aliases", action="store_true",
                    help="do not flag floating aliases")
    ap.add_argument("--forbid-switch", action="store_true", default=None)
    ap.add_argument("--allow-switch", action="store_true",
                    help="allow multiple models in one transcript")
    ap.add_argument("--no-downgrade-check", action="store_true",
                    help="disable MD08 capability-downgrade checks")
    ap.add_argument("--init", metavar="FILE", nargs="?", const="modelpin.policy.json",
                    help="write a starter policy JSON and exit")
    ap.add_argument("--disable", nargs="+", default=[], metavar="RULE", help="skip rule ids")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--min-severity", default="info", choices=SEVERITIES)
    ap.add_argument("--fail-on", default="high",
                    choices=SEVERITIES + ["any", "none"],
                    help="exit 1 if any finding >= this severity (default high)")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version="modelpin " + VERSION)
    ns = ap.parse_args(argv)

    if ns.list_rules:
        for rid, (sev, title) in RULES.items():
            print("%s  %-8s  %s" % (rid, sev, title))
        return 0

    if ns.init is not None:
        path = ns.init
        if os.path.exists(path) and path != "-":
            sys.stderr.write("modelpin: refusing to overwrite %s (delete it first)\n" % path)
            return 2
        doc = default_policy()
        text = json.dumps(doc, indent=2) + "\n"
        if path == "-":
            sys.stdout.write(text)
        else:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            sys.stderr.write("modelpin: wrote starter policy to %s\n" % path)
        return 0

    if not ns.paths:
        ap.print_help()
        return 2

    policy = default_policy()
    # When no --policy/--allow/--pinned/--providers, still run alias/switch/deprecated/inventory
    # but with empty allowlist (MD01 off) and empty providers (MD04 off) and empty pin (MD05 off)
    policy["allowed"] = []
    policy["providers"] = []
    policy["pinned"] = ""

    if ns.policy:
        try:
            policy = load_policy(ns.policy)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            sys.stderr.write("modelpin: policy: %s\n" % e)
            return 2

    if ns.allow:
        policy["allowed"] = list(dict.fromkeys(policy["allowed"] + list(ns.allow)))
    if ns.pinned:
        policy["pinned"] = ns.pinned
    if ns.providers:
        policy["providers"] = [p.strip().lower() for p in ns.providers.split(",") if p.strip()]

    if ns.allow_aliases:
        policy["forbid_aliases"] = False
    elif ns.forbid_aliases:
        policy["forbid_aliases"] = True

    if ns.allow_switch:
        policy["forbid_switch"] = False
    elif ns.forbid_switch:
        policy["forbid_switch"] = True

    if ns.no_downgrade_check:
        policy["forbid_downgrade"] = False

    paths = collect_paths(ns.paths)
    if not paths:
        sys.stderr.write("modelpin: no readable inputs\n")
        return 2

    all_events = []
    errors = 0
    for path in paths:
        try:
            all_events.extend(load_events(path))
        except OSError as e:
            sys.stderr.write("modelpin: %s: %s\n" % (path, e))
            errors += 1

    if errors and not all_events:
        return 2
    if not all_events:
        sys.stderr.write("modelpin: no model events found in inputs\n")
        return 2

    findings = analyze(all_events, policy, disabled=ns.disable)
    distinct = len({ev.model for ev in all_events if ev.model})

    min_rank = SEV_RANK[ns.min_severity]
    shown = [f for f in findings if SEV_RANK[f.severity] >= min_rank]
    shown.sort(key=lambda f: (-SEV_RANK[f.severity], f.rule, f.model or "", f.source or ""))

    if ns.json:
        print(json.dumps({
            "tool": "modelpin",
            "version": VERSION,
            "events": len(all_events),
            "distinct_models": distinct,
            "policy": {
                "allowed": policy.get("allowed") or [],
                "providers": policy.get("providers") or [],
                "pinned": policy.get("pinned") or "",
                "forbid_aliases": policy.get("forbid_aliases", True),
                "forbid_switch": policy.get("forbid_switch", True),
                "forbid_downgrade": policy.get("forbid_downgrade", True),
            },
            "findings": [f.to_dict() for f in shown],
        }, indent=2))
    else:
        print(format_table(shown, len(all_events), distinct))

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
