#!/usr/bin/env python3
"""tmplfence: offline prompt-template injection scanner for LLM apps.

Reviews Jinja2 / Mustache / Handlebars prompt templates and Python prompt-
construction code for the classic failure mode: user-controlled placeholders
interpolated into system/developer (privileged) prompt sections, plus unescaped
output, role-delimiter adjacency, dangerous Jinja2 constructs, and dynamic
includes.

Complements promptleak (leakage of system prompts in transcripts), canarytrap
(live injection harness), ragsieve (RAG corpus text), rulesguard (instruction
files), and outfence (model output). Stdlib only; never connects to a network.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys

VERSION = "0.1.0"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "TM01": ("critical", "User-controlled variable interpolated into a system/developer prompt"),
    "TM02": ("high", "Unescaped / raw rendering of a user-ish variable (|safe, {{{ }}}, autoescape off)"),
    "TM03": ("high", "User-ish variable adjacent to role delimiters or instruction boundaries"),
    "TM04": ("high", "Dangerous Jinja2 construct in a prompt template ({%, |attr, __class__, …)"),
    "TM05": ("high", "Python f-string / .format / % formatting of user data into a system prompt"),
    "TM06": ("medium", "System instructions and user placeholders share one undifferentiated template"),
    "TM07": ("medium", "Dynamic include/extends/import with a variable path"),
    "TM08": ("medium", "Triple-mustache or |safe/|raw on any placeholder in a prompt template"),
    "TM09": ("low", "Broad catch-all placeholder (input/query/message/text) in a privileged section"),
    "TM10": ("info", "Inventory of templates and placeholders scanned"),
}

# Placeholder name heuristics -------------------------------------------------

USERISH_EXACT = {
    "user", "user_input", "userinput", "user_message", "usermessage", "user_msg",
    "user_query", "userquery", "user_prompt", "userprompt", "user_text", "usertext",
    "user_content", "human", "human_message", "human_input", "customer",
    "customer_message", "query", "question", "input", "message", "msg", "prompt",
    "utterance", "request", "request_body", "chat", "chat_message", "text",
    "content", "body", "payload", "client_message", "client_msg", "end_user",
    "enduser", "speaker", "transcript", "raw_input", "untrusted", "external",
    "document", "doc", "page", "email_body", "ticket", "issue", "comment",
}

USERISH_PREFIXES = (
    "user_", "user.", "human_", "customer_", "client_", "untrusted_", "external_",
    "incoming_", "raw_",
)

USERISH_SUFFIXES = (
    "_input", "_query", "_message", "_msg", "_prompt", "_text", "_content",
    "_body", "_request",
)

SYSTEMISH_EXACT = {
    "system", "system_prompt", "systemprompt", "system_message", "systemmessage",
    "system_msg", "developer", "developer_prompt", "developer_message",
    "developer_msg", "instructions", "instruction", "base_prompt", "baseprompt",
    "core_prompt", "core_instructions", "persona", "policy", "constitution",
    "sys_prompt", "sysprompt", "role_system",
}

SYSTEMISH_PREFIXES = ("system_", "developer_", "sys_", "instruction_")
SYSTEMISH_SUFFIXES = ("_system", "_developer", "_instructions", "_instruction")

BROAD_PLACEHOLDERS = {
    "input", "query", "message", "msg", "text", "content", "body", "prompt",
    "data", "payload", "request",
}

# Template syntax -------------------------------------------------------------

# Jinja2 / Mustache / Handlebars expressions: {{ var }}, {{ var|filter }}, {{{ var }}}
JINJA_EXPR_RE = re.compile(
    r"\{\{\{?\s*([a-zA-Z_][\w.]*(?:\[[^\]]+\])?)\s*"
    r"((?:\|[^}]+)?)\}{2,3}"
)
# Triple mustache specifically
TRIPLE_MUSTACHE_RE = re.compile(
    r"\{\{\{\s*([a-zA-Z_][\w.]*)\s*\}\}\}"
)
# Jinja2 statements
JINJA_STMT_RE = re.compile(r"\{%[+-]?\s*(.*?)\s*[+-]?%\}", re.DOTALL)
# Mustache sections / partials
MUSTACHE_PARTIAL_RE = re.compile(r"\{\{>\s*([^\s}]+)\s*\}\}")
MUSTACHE_SECTION_RE = re.compile(r"\{\{[#^/]\s*([a-zA-Z_][\w.]*)\s*\}\}")

# Python f-string / format leftovers inside templates sometimes appear as {var}
# but we primarily parse .py via AST. Still catch simple {user_input} in .tpl.
SIMPLE_BRACE_RE = re.compile(r"(?<!\{)\{([a-zA-Z_][\w]*)\}(?!\})")

ROLE_DELIMITER_RE = re.compile(
    r"(?is)"
    r"("
    r"<\|?(?:system|assistant|developer|endofprompt|im_start|im_end)\|?>"
    r"|"
    r"\[(?:SYSTEM|INST|/INST|SYS|ASSISTANT|USER|DEV)\]"
    r"|"
    r"(?:^|\n)\s*(?:SYSTEM|DEVELOPER|ASSISTANT|USER)\s*:\s"
    r"|"
    r"<<\s*SYS\s*>>"
    r"|"
    r"###\s*(?:System|Developer|Instructions?)\b"
    r"|"
    r"<system(?:_prompt|_message)?>"
    r")"
)

SAFE_FILTER_RE = re.compile(r"(?i)\|\s*(safe|raw|safehtml)\b")
ATTR_FILTER_RE = re.compile(
    r"(?i)\|\s*(attr|joinpath|list|map|selectattr|rejectattr|pprint)\b"
)
DANGEROUS_JINJA_TOKEN_RE = re.compile(
    r"(?i)(__class__|__mro__|__subclasses__|__globals__|__builtins__|"
    r"__import__|lipsum|cycler|joiner|namespace\s*\(|config\.|request\.|"
    r"self\.__|varargs|kwargs)"
)
AUTOESCAPE_OFF_RE = re.compile(
    r"(?is)\{\%\s*autoescape\s+(false|False|off)\s*\%\}"
)
INCLUDE_RE = re.compile(
    r"(?is)\{\%\s*(?:include|extends|import|from)\s+([^\s%]+)"
)

SYSTEM_ROLE_MARKERS_RE = re.compile(
    r"(?is)\b(system(?:[_\s-]?prompt|[_\s-]?message)?|developer(?:[_\s-]?prompt)?|"
    r"core\s+instructions?|you\s+are\s+(?:a|an|the)\b|your\s+(?:role|job|task)\s+is\b)"
)

TEMPLATE_EXTS = (
    ".j2", ".jinja", ".jinja2", ".mustache", ".hbs", ".tpl", ".prompt",
    ".txt", ".md", ".json", ".jsonl", ".py", ".yml", ".yaml",
)


class Finding:
    __slots__ = ("rule", "severity", "source", "message", "template_id", "placeholder", "snippet")

    def __init__(self, rule, source, message, template_id="", placeholder="", snippet=""):
        self.rule = rule
        self.severity = RULES[rule][0]
        self.source = source
        self.message = message
        self.template_id = template_id
        self.placeholder = placeholder
        self.snippet = (snippet or "").replace("\n", "\\n")[:120]

    def to_dict(self):
        return {
            "rule": self.rule,
            "severity": self.severity,
            "source": self.source,
            "template_id": self.template_id,
            "placeholder": self.placeholder,
            "message": self.message,
            "snippet": self.snippet,
        }


class TemplateUnit:
    """One scannable template blob with optional role/context metadata."""

    __slots__ = ("source", "template_id", "text", "role", "kind", "var_name")

    def __init__(self, source, text, template_id="", role="", kind="template", var_name=""):
        self.source = source
        self.template_id = template_id or source
        self.text = text or ""
        self.role = (role or "").lower()  # system / developer / user / assistant / ""
        self.kind = kind  # template | python | chat_message
        self.var_name = var_name  # enclosing Python/JSON variable name if known


# --- helpers -----------------------------------------------------------------

def _base_name(name: str) -> str:
    name = (name or "").strip()
    if "." in name:
        name = name.split(".", 1)[0]
    if "[" in name:
        name = name.split("[", 1)[0]
    return name.lower()


def is_userish(name: str) -> bool:
    n = _base_name(name)
    if not n:
        return False
    if n in USERISH_EXACT:
        return True
    if any(n.startswith(p.rstrip(".").lower()) or n.startswith(p.replace(".", "_"))
           for p in USERISH_PREFIXES):
        # tighten: user_ / human_ etc.
        for p in ("user_", "human_", "customer_", "client_", "untrusted_", "external_",
                  "incoming_", "raw_"):
            if n.startswith(p):
                return True
    if any(n.endswith(s) for s in USERISH_SUFFIXES):
        # avoid flagging system_message as userish
        if n.startswith(("system", "developer", "assistant", "sys_")):
            return False
        return True
    return False


def is_systemish_name(name: str) -> bool:
    n = _base_name(name)
    if not n:
        return False
    if n in SYSTEMISH_EXACT:
        return True
    if any(n.startswith(p) for p in SYSTEMISH_PREFIXES):
        return True
    if any(n.endswith(s) for s in SYSTEMISH_SUFFIXES):
        return True
    return False


def is_broad(name: str) -> bool:
    return _base_name(name) in BROAD_PLACEHOLDERS


def _path_suggests_system(path: str) -> bool:
    base = os.path.basename(path).lower()
    return bool(re.search(
        r"(system|developer|sys[_-]?prompt|instructions?|persona|constitution)",
        base,
    ))


def _unit_is_privileged(unit: TemplateUnit) -> bool:
    if unit.role in ("system", "developer"):
        return True
    if is_systemish_name(unit.var_name):
        return True
    if _path_suggests_system(unit.source) and unit.role not in ("user", "assistant"):
        return True
    # Inline markers in the template text itself
    if unit.role not in ("user", "assistant") and SYSTEM_ROLE_MARKERS_RE.search(unit.text[:400]):
        # only if it looks like a system prompt opener, not a random mention
        head = unit.text[:400]
        if re.search(r"(?is)^\s*(?:system|developer)\s*:", head) or \
           re.search(r"(?is)<\|?system\|?>|\[SYSTEM\]|###\s*System", head) or \
           re.search(r"(?is)^\s*you\s+are\s+(?:a|an|the)\b", head):
            return True
    return False


def _snippet_around(text: str, start: int, end: int, pad: int = 40) -> str:
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    return text[a:b]


def _extract_placeholders(text: str):
    """Yield (name, start, end, raw, filters, style) for each placeholder."""
    seen_spans = set()
    for m in TRIPLE_MUSTACHE_RE.finditer(text):
        span = m.span()
        seen_spans.add(span)
        yield m.group(1), span[0], span[1], m.group(0), "", "triple"
    for m in JINJA_EXPR_RE.finditer(text):
        span = m.span()
        if span in seen_spans:
            continue
        # Skip if this was the double-brace core of a triple (already counted)
        name = m.group(1)
        filters = (m.group(2) or "").strip()
        style = "triple" if m.group(0).startswith("{{{") else "jinja"
        yield name, span[0], span[1], m.group(0), filters, style
    # Simple {name} — only when no jinja braces dominate the file heavily
    if "{{" not in text and "{%" not in text:
        for m in SIMPLE_BRACE_RE.finditer(text):
            yield m.group(1), m.start(), m.end(), m.group(0), "", "brace"


# --- loaders -----------------------------------------------------------------

def _load_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def load_units_from_text_file(path: str, text: str | None = None) -> list[TemplateUnit]:
    if text is None:
        text = _load_text(path)
    role = ""
    if _path_suggests_system(path):
        role = "system"
    return [TemplateUnit(source=path, text=text, template_id=os.path.basename(path),
                         role=role, kind="template")]


def _walk_json_for_templates(obj, source: str, path_keys=(), units=None):
    if units is None:
        units = []
    if isinstance(obj, dict):
        # Chat-message shaped
        role = obj.get("role") or obj.get("type") or ""
        content = obj.get("content") or obj.get("text") or obj.get("prompt") or obj.get("template")
        if isinstance(role, str) and isinstance(content, str) and (
            "{{" in content or "{%" in content or "{{{ " in content or
            (role.lower() in ("system", "developer", "user", "assistant") and "{" in content)
        ):
            units.append(TemplateUnit(
                source=source,
                text=content,
                template_id="/".join(str(k) for k in path_keys + ("content",)),
                role=role.lower(),
                kind="chat_message",
                var_name=str(role),
            ))
        # Named prompt fields
        for key, val in obj.items():
            if isinstance(val, str) and (
                is_systemish_name(key) or is_userish(key) or
                key.lower() in ("template", "prompt", "prompt_template", "system",
                                "developer", "messages_template")
            ):
                if "{{" in val or "{%" in val or "{" in val or len(val) > 40:
                    role = "system" if is_systemish_name(key) else ""
                    units.append(TemplateUnit(
                        source=source,
                        text=val,
                        template_id="/".join(str(k) for k in path_keys + (key,)),
                        role=role,
                        kind="template",
                        var_name=key,
                    ))
            else:
                _walk_json_for_templates(val, source, path_keys + (key,), units)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _walk_json_for_templates(item, source, path_keys + (i,), units)
    return units


def load_units_from_json(path: str) -> list[TemplateUnit]:
    text = _load_text(path)
    units: list[TemplateUnit] = []
    if path.endswith(".jsonl"):
        for i, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            _walk_json_for_templates(obj, path, (f"line{i}",), units)
        return units
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        # fall back to raw template scan
        return load_units_from_text_file(path, text)
    units = _walk_json_for_templates(obj, path)
    if not units and ("{{" in text or "{%" in text):
        return load_units_from_text_file(path, text)
    return units


def _py_string_value(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):  # f-string
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            elif isinstance(v, ast.FormattedValue):
                try:
                    parts.append("{%s}" % ast.unparse(v.value))
                except Exception:
                    parts.append("{…}")
            else:
                parts.append("")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        left = _py_string_value(node.left)
        right = _py_string_value(node.right)
        if left is not None and right is not None:
            if isinstance(node.op, ast.Add):
                return left + right
            return left  # % formatting — return left template
    if isinstance(node, ast.Call):
        # "…".format(...)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            base = _py_string_value(node.func.value)
            if base is not None:
                return base
    return None


def _name_of(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name_of(node.value)
        return ("%s.%s" % (base, node.attr)) if base else node.attr
    return ""


class _PyPromptVisitor(ast.NodeVisitor):
    def __init__(self, source_path: str):
        self.source_path = source_path
        self.units: list[TemplateUnit] = []
        self.findings_early: list[Finding] = []

    def _record_assign(self, target_name: str, value_node, lineno: int):
        privileged = is_systemish_name(target_name)
        role = "system" if privileged else ""
        tid = "%s:%s:L%d" % (os.path.basename(self.source_path), target_name or "expr", lineno)

        # TM05 early: concatenation of userish names into system-ish targets
        # even when the full expression is not a pure string literal.
        if privileged and isinstance(value_node, ast.BinOp) and isinstance(value_node.op, ast.Add):
            for side in (value_node.left, value_node.right):
                n = _name_of(side)
                if is_userish(n) or is_broad(n):
                    self.findings_early.append(Finding(
                        "TM05",
                        self.source_path,
                        "string concatenation of %s into system prompt variable %s"
                        % (n, target_name),
                        template_id=tid,
                        placeholder=n,
                        snippet=n,
                    ))

        text = _py_string_value(value_node)
        if text is None:
            # Still try %-format / .format when RHS is not a recovered string
            if privileged and isinstance(value_node, ast.BinOp) and isinstance(value_node.op, ast.Mod):
                right = value_node.right
                candidates = []
                if isinstance(right, (ast.Name, ast.Attribute)):
                    candidates = [right]
                elif isinstance(right, ast.Tuple):
                    candidates = list(right.elts)
                elif isinstance(right, ast.Dict):
                    candidates = list(right.values)
                for elt in candidates:
                    n = _name_of(elt)
                    if is_userish(n) or is_broad(n):
                        self.findings_early.append(Finding(
                            "TM05",
                            self.source_path,
                            "%%-format interpolates %s into system prompt variable %s"
                            % (n, target_name),
                            template_id=tid,
                            placeholder=n,
                            snippet=n,
                        ))
            return
        # Only keep interesting strings
        interesting = (
            privileged
            or "{{" in text
            or "{%" in text
            or ROLE_DELIMITER_RE.search(text)
            or SYSTEM_ROLE_MARKERS_RE.search(text[:300])
            or bool(SIMPLE_BRACE_RE.search(text))
        )
        if not interesting:
            return
        unit = TemplateUnit(
            source=self.source_path,
            text=text,
            template_id=tid,
            role=role,
            kind="python",
            var_name=target_name,
        )
        self.units.append(unit)

        # TM05: f-string / format / % with userish names into system prompt
        if privileged and isinstance(value_node, ast.JoinedStr):
            for v in value_node.values:
                if isinstance(v, ast.FormattedValue):
                    n = _name_of(v.value)
                    if is_userish(n) or is_broad(n):
                        self.findings_early.append(Finding(
                            "TM05",
                            self.source_path,
                            "f-string interpolates %s into system prompt variable %s"
                            % (n or "expression", target_name),
                            template_id=tid,
                            placeholder=n,
                            snippet=text[:120],
                        ))
        if privileged and isinstance(value_node, ast.Call):
            if isinstance(value_node.func, ast.Attribute) and value_node.func.attr == "format":
                for arg in list(value_node.args) + [kw.value for kw in value_node.keywords]:
                    n = _name_of(arg)
                    if is_userish(n) or is_broad(n):
                        self.findings_early.append(Finding(
                            "TM05",
                            self.source_path,
                            ".format() passes %s into system prompt variable %s"
                            % (n or "expression", target_name),
                            template_id=tid,
                            placeholder=n,
                            snippet=text[:120],
                        ))
        if privileged and isinstance(value_node, ast.BinOp) and isinstance(value_node.op, ast.Mod):
            # system_prompt % user_input  or  system_prompt % {...}
            right = value_node.right
            if isinstance(right, (ast.Name, ast.Attribute)):
                n = _name_of(right)
                if is_userish(n) or is_broad(n):
                    self.findings_early.append(Finding(
                        "TM05",
                        self.source_path,
                        "%%-format interpolates %s into system prompt variable %s"
                        % (n, target_name),
                        template_id=tid,
                        placeholder=n,
                        snippet=text[:120],
                    ))
            elif isinstance(right, ast.Tuple):
                for elt in right.elts:
                    n = _name_of(elt)
                    if is_userish(n) or is_broad(n):
                        self.findings_early.append(Finding(
                            "TM05",
                            self.source_path,
                            "%%-format interpolates %s into system prompt variable %s"
                            % (n, target_name),
                            template_id=tid,
                            placeholder=n,
                            snippet=text[:120],
                        ))
            elif isinstance(right, ast.Dict):
                for key_node, val_node in zip(right.keys, right.values):
                    n = _name_of(val_node)
                    if is_userish(n) or is_broad(n):
                        self.findings_early.append(Finding(
                            "TM05",
                            self.source_path,
                            "%%-format dict value %s into system prompt variable %s"
                            % (n, target_name),
                            template_id=tid,
                            placeholder=n,
                            snippet=text[:120],
                        ))

    def visit_Assign(self, node: ast.Assign):
        for tgt in node.targets:
            name = _name_of(tgt)
            if name:
                self._record_assign(name, node.value, getattr(node, "lineno", 0))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if node.value is not None:
            name = _name_of(node.target)
            if name:
                self._record_assign(name, node.value, getattr(node, "lineno", 0))
        self.generic_visit(node)


def load_units_from_python(path: str) -> tuple[list[TemplateUnit], list[Finding]]:
    text = _load_text(path)
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError as e:
        raise ValueError("cannot parse %s: %s" % (path, e))
    visitor = _PyPromptVisitor(path)
    visitor.visit(tree)
    return visitor.units, visitor.findings_early


def load_units(path: str) -> tuple[list[TemplateUnit], list[Finding]]:
    if path == "-":
        text = sys.stdin.read()
        return [TemplateUnit(source="-", text=text, template_id="stdin", kind="template")], []
    lower = path.lower()
    if lower.endswith(".py"):
        return load_units_from_python(path)
    if lower.endswith((".json", ".jsonl")):
        return load_units_from_json(path), []
    return load_units_from_text_file(path), []


# --- classification ----------------------------------------------------------

def classify_unit(unit: TemplateUnit, disabled: set[str] | None = None) -> list[Finding]:
    disabled = disabled or set()
    findings: list[Finding] = []
    text = unit.text or ""
    if not text.strip():
        return findings
    privileged = _unit_is_privileged(unit)
    label = unit.template_id or unit.source

    def add(rule, message, placeholder="", snippet=""):
        if rule in disabled:
            return
        findings.append(Finding(
            rule, unit.source, message,
            template_id=label, placeholder=placeholder, snippet=snippet,
        ))

    placeholders = list(_extract_placeholders(text))
    userish_placeholders = [(n, a, b, raw, filt, style) for n, a, b, raw, filt, style in placeholders
                            if is_userish(n)]

    # TM01 — userish var in privileged template
    if privileged and "TM01" not in disabled:
        for n, a, b, raw, filt, style in userish_placeholders:
            add(
                "TM01",
                "User-controlled placeholder %s interpolated into privileged template %s"
                % (n, label),
                placeholder=n,
                snippet=_snippet_around(text, a, b),
            )

    # TM02 — unescaped userish
    if "TM02" not in disabled:
        for n, a, b, raw, filt, style in userish_placeholders:
            unsafe = style == "triple" or SAFE_FILTER_RE.search(filt or "")
            if unsafe:
                add(
                    "TM02",
                    "Unescaped rendering of user-ish placeholder %s in %s"
                    % (n, label),
                    placeholder=n,
                    snippet=_snippet_around(text, a, b),
                )
        if AUTOESCAPE_OFF_RE.search(text) and userish_placeholders:
            add(
                "TM02",
                "autoescape disabled while user-ish placeholders present in %s" % label,
                snippet="autoescape false/off",
            )

    # TM08 — triple / safe on ANY placeholder (even non-userish) in prompt templates
    if "TM08" not in disabled:
        for n, a, b, raw, filt, style in placeholders:
            if style == "triple" or SAFE_FILTER_RE.search(filt or ""):
                # Avoid double-counting with TM02 for userish; still report TM08 for others
                if is_userish(n) and "TM02" not in disabled:
                    continue
                add(
                    "TM08",
                    "Raw/unescaped placeholder %s in prompt template %s" % (n, label),
                    placeholder=n,
                    snippet=_snippet_around(text, a, b),
                )

    # TM03 — userish adjacent to role delimiters
    if "TM03" not in disabled:
        for m in ROLE_DELIMITER_RE.finditer(text):
            window_start = max(0, m.start() - 80)
            window_end = min(len(text), m.end() + 80)
            window = text[window_start:window_end]
            for n, a, b, raw, filt, style in placeholders:
                if not is_userish(n):
                    continue
                if window_start <= a <= window_end or window_start <= b <= window_end:
                    add(
                        "TM03",
                        "User-ish placeholder %s adjacent to role delimiter in %s"
                        % (n, label),
                        placeholder=n,
                        snippet=_snippet_around(text, min(a, m.start()), max(b, m.end())),
                    )

    # TM04 — dangerous Jinja2
    if "TM04" not in disabled:
        if DANGEROUS_JINJA_TOKEN_RE.search(text):
            m = DANGEROUS_JINJA_TOKEN_RE.search(text)
            add(
                "TM04",
                "Dangerous Jinja2 token %s in prompt template %s"
                % (m.group(0), label),
                snippet=_snippet_around(text, m.start(), m.end()),
            )
        for m in JINJA_STMT_RE.finditer(text):
            body = m.group(1).strip()
            # flag non-comment statements in prompt templates
            if body.startswith("#") or body.startswith("set ") or body.startswith("if ") \
               or body.startswith("for ") or body.startswith("endif") \
               or body.startswith("endfor") or body.startswith("else") \
               or body.startswith("elif") or body.startswith("block") \
               or body.startswith("endblock") or body.startswith("macro") \
               or body.startswith("filter") or body.startswith("with") \
               or body.startswith("autoescape") or body.startswith("raw") \
               or body.startswith("endraw") or body.startswith("include") \
               or body.startswith("extends") or body.startswith("import") \
               or body.startswith("from "):
                # statements in LLM prompt templates are unusual / risky
                if body.startswith(("endif", "endfor", "else", "elif", "endblock",
                                    "endraw", "#")):
                    continue
                add(
                    "TM04",
                    "Jinja2 statement '{%% %s %%}' in prompt template %s (code-exec / logic surface)"
                    % (body[:60], label),
                    snippet=m.group(0)[:80],
                )
        for n, a, b, raw, filt, style in placeholders:
            if ATTR_FILTER_RE.search(filt or ""):
                add(
                    "TM04",
                    "Dangerous Jinja2 filter on %s in %s" % (n, label),
                    placeholder=n,
                    snippet=_snippet_around(text, a, b),
                )

    # TM06 — mixed system instructions + user placeholders without role separation
    if "TM06" not in disabled and userish_placeholders:
        has_system_voice = bool(SYSTEM_ROLE_MARKERS_RE.search(text))
        has_role_markers = bool(ROLE_DELIMITER_RE.search(text))
        # undifferentiated: system voice present, user placeholders present, no role markers
        if has_system_voice and not has_role_markers and unit.role not in ("user", "assistant"):
            # Avoid overlapping pure TM01-only cases when already clearly role=system with markers
            # TM06 is specifically the "one blob" anti-pattern
            if unit.role == "" or not ROLE_DELIMITER_RE.search(text):
                add(
                    "TM06",
                    "System-style instructions and user placeholders share one undifferentiated "
                    "template %s" % label,
                    placeholder=userish_placeholders[0][0],
                    snippet=text[:100],
                )

    # TM07 — dynamic include/extends
    if "TM07" not in disabled:
        for m in INCLUDE_RE.finditer(text):
            target = m.group(1).strip().strip("\"'")
            if target.startswith("{{") or target.startswith(("{%", "(")) or \
               re.match(r"^[a-zA-Z_][\w.]*$", target):
                # variable or expression path (not a quoted literal filename alone)
                if not (target.startswith('"') or target.startswith("'") or
                        re.match(r"^[\w./\-]+$", target)):
                    add(
                        "TM07",
                        "Dynamic template include/extends path in %s: %s" % (label, target[:60]),
                        snippet=m.group(0)[:80],
                    )
                elif "{{" in m.group(0) or not re.search(r'["\'].+["\']', m.group(0)):
                    # {% include page %} or {% include {{ name }} %}
                    if not re.search(r'["\'][\w./\-]+["\']', m.group(0)):
                        add(
                            "TM07",
                            "Dynamic template include/extends with variable path in %s"
                            % label,
                            snippet=m.group(0)[:80],
                        )
        for m in MUSTACHE_PARTIAL_RE.finditer(text):
            target = m.group(1)
            if "{{" in target or target.startswith("(") or is_userish(target):
                add(
                    "TM07",
                    "Dynamic Mustache partial %s in %s" % (target, label),
                    placeholder=target,
                    snippet=m.group(0),
                )

    # TM09 — broad placeholders in privileged section
    if privileged and "TM09" not in disabled:
        for n, a, b, raw, filt, style in placeholders:
            if is_broad(n):
                add(
                    "TM09",
                    "Broad catch-all placeholder %s in privileged template %s"
                    % (n, label),
                    placeholder=n,
                    snippet=_snippet_around(text, a, b),
                )

    return findings


def classify_all(units, early_findings=None, disabled=None):
    disabled = disabled or set()
    findings = list(early_findings or [])
    findings = [f for f in findings if f.rule not in disabled]
    for unit in units:
        findings.extend(classify_unit(unit, disabled=disabled))
    return findings


# --- I/O / CLI ---------------------------------------------------------------

def collect_paths(args_paths):
    paths = []
    for p in args_paths:
        if p == "-":
            paths.append(p)
            continue
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [
                    d for d in dirs
                    if d not in (".git", "node_modules", "__pycache__", ".venv", "venv",
                                 "tests", "examples")
                ]
                # still allow explicit examples/ when passed as the path itself
                for fn in sorted(files):
                    lower = fn.lower()
                    if lower.endswith(TEMPLATE_EXTS):
                        paths.append(os.path.join(root, fn))
        else:
            paths.append(p)
    return paths


def format_table(findings, unit_count):
    lines = []
    lines.append(
        "tmplfence %s — %d template(s), %d finding(s)"
        % (VERSION, unit_count, len(findings))
    )
    if not findings:
        lines.append("No prompt-template injection findings.")
        return "\n".join(lines)
    lines.append("")
    lines.append("%-6s %-8s %-28s %s" % ("RULE", "SEV", "TEMPLATE", "MESSAGE"))
    lines.append("-" * 100)
    for f in findings:
        tid = (f.template_id or "-")[:28]
        lines.append("%-6s %-8s %-28s %s" % (f.rule, f.severity, tid, f.message[:70]))
        if f.snippet:
            lines.append("       snippet: %s" % f.snippet[:80])
        if f.source:
            lines.append("       at:      %s" % f.source)
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="tmplfence",
        description=(
            "Offline prompt-template injection scanner for Jinja2/Mustache/"
            "f-string LLM prompt templates (user-controlled vars into system prompts)."
        ),
    )
    ap.add_argument(
        "paths",
        nargs="*",
        help="template / Python / JSON files or directories (or - for stdin)",
    )
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
    ap.add_argument("--version", action="version", version="tmplfence " + VERSION)
    ns = ap.parse_args(argv)

    if ns.list_rules:
        for rid, (sev, title) in RULES.items():
            print("%s  %-8s  %s" % (rid, sev, title))
        return 0

    if not ns.paths:
        ap.print_help()
        return 2

    file_paths = collect_paths(ns.paths)
    if not file_paths:
        sys.stderr.write("tmplfence: no readable inputs\n")
        return 2

    # When user passes examples/ explicitly, collect_paths skipped nested examples
    # only when walking from a parent — re-walk if the arg itself is examples-like
    repaired = []
    for p in ns.paths:
        if p != "-" and os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__",
                                                         ".venv", "venv")]
                for fn in sorted(files):
                    if fn.lower().endswith(TEMPLATE_EXTS):
                        repaired.append(os.path.join(root, fn))
        elif p == "-" or os.path.isfile(p):
            repaired.append(p)
    file_paths = repaired or file_paths

    all_units: list[TemplateUnit] = []
    early: list[Finding] = []
    errors = 0
    for path in file_paths:
        try:
            units, early_f = load_units(path)
            all_units.extend(units)
            early.extend(early_f)
        except (OSError, ValueError) as e:
            sys.stderr.write("tmplfence: %s\n" % e)
            errors += 1

    if errors and not all_units and not early:
        return 2

    disabled = set(ns.disable or [])
    findings = classify_all(all_units, early_findings=early, disabled=disabled)

    if "TM10" not in disabled:
        for unit in all_units:
            ph = sorted({_base_name(n) for n, *_ in _extract_placeholders(unit.text) if n})
            preview = unit.text.replace("\n", " ")[:48]
            findings.append(Finding(
                "TM10",
                unit.source,
                "Template %s role=%s kind=%s placeholders=%s (%d chars): %s"
                % (unit.template_id, unit.role or "-", unit.kind,
                   ",".join(ph) if ph else "-", len(unit.text), preview),
                template_id=unit.template_id,
                snippet=preview,
            ))

    min_rank = SEV_RANK[ns.min_severity]
    shown = [f for f in findings if SEV_RANK[f.severity] >= min_rank]
    shown.sort(
        key=lambda f: (-SEV_RANK[f.severity], f.rule, f.template_id or "", f.source or "")
    )

    if ns.json:
        print(json.dumps({
            "tool": "tmplfence",
            "version": VERSION,
            "templates": [
                {
                    "id": u.template_id,
                    "source": u.source,
                    "role": u.role,
                    "kind": u.kind,
                    "chars": len(u.text),
                }
                for u in all_units
            ],
            "findings": [f.to_dict() for f in shown],
        }, indent=2))
    else:
        print(format_table(shown, len(all_units)))

    actionable = [f for f in shown if f.rule != "TM10"]
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
