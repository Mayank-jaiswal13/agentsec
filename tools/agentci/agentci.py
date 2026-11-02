#!/usr/bin/env python3
"""agentci: offline prompt-injection and privilege auditor for GitHub Actions workflows that run AI agents.

Finds workflows that invoke an AI coding agent or LLM (Claude Code, Codex, Gemini CLI, actions/ai-inference,
custom CLI/API calls) and checks whether untrusted issue/PR/comment text can reach the agent's prompt,
whether outsiders can trigger it, and how much power (tokens, secrets, shell, write scopes) it holds.
Standard library only; no network. Heuristic review aid, not a security boundary.
"""
import argparse
import fnmatch
import json
import os
import re
import sys

VERSION = "0.1.0"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "AC01": ("critical", "Untrusted event text interpolated into an AI agent step (prompt injection)"),
    "AC02": ("medium", "AI agent can be triggered by outsiders (untrusted trigger without actor gate)"),
    "AC03": ("critical", "Privileged trigger checks out untrusted PR code for an AI job"),
    "AC04": ("medium", "AI job holds broad GITHUB_TOKEN permissions"),
    "AC05": ("high", "Agent given unrestricted shell / sandbox or approvals disabled"),
    "AC06": ("medium", "Non-model secrets exposed to the AI job"),
    "AC07": ("low", "AI action not pinned to a full commit SHA"),
    "AC08": ("low", "Checkout in AI job persists credentials for the agent to read"),
    "AC09": ("info", "AI agent usage detected (inventory)"),
}

# ---------------------------------------------------------------- minimal YAML subset parser

class YMap(dict):
    """dict that remembers the source line of each key."""
    def __init__(self):
        super().__init__()
        self.lines = {}


class YList(list):
    def __init__(self):
        super().__init__()
        self.lines = []


def _strip_comment(s):
    q = None
    for i, c in enumerate(s):
        if q:
            if c == q:
                q = None
        elif c in "'\"":
            if i == 0 or s[i - 1] in " :[{,-":
                q = c
        elif c == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i].rstrip()
    return s.rstrip()


def _split_flow(s):
    out, depth, q, cur = [], 0, None, ""
    for c in s:
        if q:
            cur += c
            if c == q:
                q = None
            continue
        if c in "'\"":
            q = c
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
        if c == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += c
    if cur.strip():
        out.append(cur.strip())
    return out


def _scalar(s):
    s = s.strip()
    if not s:
        return ""
    if s[0] == '"' and s.endswith('"') and len(s) >= 2:
        body = s[1:-1]
        return body.replace('\\"', '"').replace("\\n", "\n").replace("\\t", "\t").replace("\\\\", "\\")
    if s[0] == "'" and s.endswith("'") and len(s) >= 2:
        return s[1:-1].replace("''", "'")
    if s[0] == "[" and s.endswith("]"):
        lst = YList()
        for part in _split_flow(s[1:-1]):
            lst.append(_scalar(part))
        return lst
    if s[0] == "{" and s.endswith("}"):
        m = YMap()
        for part in _split_flow(s[1:-1]):
            k, _, v = part.partition(":")
            m[_scalar(k)] = _scalar(v)
        return m
    return s


_KEY_RE = re.compile(r"""^("[^"]*"|'[^']*'|[^\s'"#][^:#]*?)\s*:(?:\s+|$)(.*)$""")


class YamlError(ValueError):
    pass


class _Parser:
    def __init__(self, text):
        self.raw = text.replace("\t", "  ").splitlines()
        # [indent, content, lineno] for significant lines
        self.lines = []
        for n, line in enumerate(self.raw, 1):
            st = line.strip()
            if not st or st.startswith("#") or st in ("---", "...") or st.startswith("%"):
                continue
            self.lines.append([len(line) - len(line.lstrip(" ")), line.strip(), n])

    def parse(self):
        if not self.lines:
            return YMap()
        node, i = self.block(0, self.lines[0][0])
        return node

    def block(self, i, ind):
        if i >= len(self.lines):
            return "", i
        text = self.lines[i][1]
        if text == "-" or text.startswith("- "):
            return self.seq(i, ind)
        if _KEY_RE.match(text):
            return self.mapping(i, ind)
        # plain multi-line scalar
        parts = []
        while i < len(self.lines) and self.lines[i][0] >= ind:
            parts.append(self.lines[i][1])
            i += 1
        return _scalar(" ".join(parts)), i

    def block_scalar(self, lineno, ind, style):
        out, n = [], lineno  # lineno is 1-based line of the indicator; content starts after
        base = None
        while n < len(self.raw):
            line = self.raw[n].replace("\t", "  ")
            if line.strip() == "":
                out.append("")
                n += 1
                continue
            cur = len(line) - len(line.lstrip(" "))
            if cur <= ind:
                break
            if base is None:
                base = cur
            out.append(line[base:] if cur >= base else line.strip())
            n += 1
        while out and out[-1] == "":
            out.pop()
        # skip consumed significant lines
        text = ("\n" if style == "|" else " ").join(out)
        return text, n

    def _skip_to_line(self, i, n):
        while i < len(self.lines) and self.lines[i][2] <= n:
            i += 1
        return i

    def value(self, rest, i, ind, lineno):
        """parse the value part after 'key:' or '- '. i points to next significant line."""
        rest = _strip_comment(rest)
        if rest[:1] in ("|", ">"):
            text, n = self.block_scalar(lineno, ind, rest[0])
            return text, self._skip_to_line(i, n)
        if rest.startswith("&"):
            rest = rest.split(None, 1)[1] if " " in rest else ""
        if rest == "":
            if i < len(self.lines):
                nind, ntext = self.lines[i][0], self.lines[i][1]
                if nind > ind or (nind == ind and (ntext == "-" or ntext.startswith("- "))):
                    return self.block(i, nind)
            return "", i
        # unterminated flow collection spanning lines
        if rest[0] in "[{" and rest.count(rest[0]) > rest.count("]" if rest[0] == "[" else "}"):
            while i < len(self.lines) and rest.count(rest[0]) > rest.count("]" if rest[0] == "[" else "}"):
                rest += " " + _strip_comment(self.lines[i][1])
                i += 1
        # plain/quoted scalar continued on deeper lines
        if rest[0] in "'\"" and not (len(rest) > 1 and rest.endswith(rest[0])):
            while i < len(self.lines) and not rest.endswith(rest[0]):
                rest += " " + self.lines[i][1]
                i += 1
        elif rest[0] not in "'\"[{":
            while i < len(self.lines) and self.lines[i][0] > ind and not _KEY_RE.match(self.lines[i][1]) \
                    and not self.lines[i][1].startswith("- "):
                rest += " " + _strip_comment(self.lines[i][1])
                i += 1
        return _scalar(rest), i

    def mapping(self, i, ind):
        m = YMap()
        while i < len(self.lines):
            lind, text, n = self.lines[i]
            if lind < ind:
                break
            if lind > ind:
                raise YamlError("line %d: unexpected indentation" % n)
            if text == "-" or text.startswith("- "):
                break
            km = _KEY_RE.match(text)
            if not km:
                raise YamlError("line %d: expected 'key: value'" % n)
            key = _scalar(km.group(1))
            m.lines[key] = n
            m[key], i = self.value(km.group(2), i + 1, ind, n)
        return m, i

    def seq(self, i, ind):
        lst = YList()
        while i < len(self.lines):
            lind, text, n = self.lines[i]
            if lind != ind or not (text == "-" or text.startswith("- ")):
                break
            content = text[1:].lstrip()
            lst.lines.append(n)
            if content and (_KEY_RE.match(content) or content.startswith("- ")) and content[0] not in "'\"[{":
                off = len(text) - len(content)
                self.lines[i] = [ind + off, content, n]
                val, i = self.block(i, ind + off)
            else:
                val, i = self.value(content, i + 1, ind, n)
            lst.append(val)
        return lst, i


def parse_yaml(text):
    return _Parser(text).parse()

# ---------------------------------------------------------------- detection data

AI_ACTIONS = [
    "anthropics/claude-code-action", "anthropics/claude-code-base-action", "openai/codex-action",
    "google-github-actions/run-gemini-cli", "google-gemini/gemini-cli-action", "actions/ai-inference",
    "github/copilot-*", "coderabbitai/ai-pr-reviewer", "*/ai-pr-reviewer", "*/ai-code-review*",
    "*/*-ai-review*", "*/gpt-*review*", "*/chatgpt-*", "*/openai-*", "*/llm-*", "*/aider*",
    "*/opencode*", "*/cursor-agent*", "block/goose*", "*/qwen-code*",
]
AI_RUN_RE = re.compile(
    r"(?:^|[\s;&|(])(?:npx\s+(?:-y\s+)?)?(?:@anthropic-ai/claude-code|claude|codex|gemini|@google/gemini-cli|aider|"
    r"opencode|goose|cursor-agent|qwen|llm)\s+(?:[^\n|;&]*?\s)?(?:-p\b|--print\b|exec\b|--prompt\b|-m\b|run\b|--message\b|\"|')"
    r"|api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|models\.github\.ai"
    r"|models\.inference\.ai\.azure\.com|openrouter\.ai/api",
    re.I | re.M)

UNTRUSTED_TRIGGERS = {"issues", "issue_comment", "pull_request_target", "pull_request_review",
                      "pull_request_review_comment", "discussion", "discussion_comment", "workflow_run",
                      "pull_request"}
PRIVILEGED_TRIGGERS = {"pull_request_target", "workflow_run"}

UNTRUSTED_EXPR = re.compile(
    r"github\.event\.(?:issue\.(?:title|body)|comment\.body|review\.body|review_comment\.body"
    r"|pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch)"
    r"|discussion\.(?:title|body)|pages\.[\w*\[\]]+\.page_name|commits(?:\.[\w*\[\]]+)*\.(?:message|author\.(?:email|name))"
    r"|head_commit\.(?:message|author\.(?:email|name))|workflow_run\.(?:head_branch|display_title|head_commit\.message))"
    r"|github\.head_ref|toJSON\(\s*github\.event\s*\)|toJSON\(\s*github\s*\)",
    re.I)
EXPR_RE = re.compile(r"\$\{\{(.*?)\}\}", re.S)

GATE_RE = re.compile(
    r"author_association|github\.actor\b|github\.triggering_actor|event\.sender\.login|repository_owner"
    r"|\.user\.login|event\.label\.name|contains\(\s*github\.event\.(?:issue|pull_request)\.labels", re.I)
GATE_ACTIONS = ["*check-user-permission*", "*permission-check*", "*actor-permission*", "*check-permissions*",
                "*/is-collaborator*", "*team-membership*"]

UNTRUSTED_REF = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs/pull/|github\.event\.workflow_run\.head_(?:sha|branch)"
    r"|github\.event\.issue\.number|steps\.[\w-]+\.outputs\.(?:head|pr)", re.I)

DANGEROUS_FLAGS = [
    (re.compile(r"Bash\(\s*\*?\s*\)|Bash\(\*:?\*\)|\bShell\(\*\)"), "wildcard shell permission"),
    (re.compile(r"--dangerously-skip-permissions"), "--dangerously-skip-permissions"),
    (re.compile(r"--dangerously-bypass-approvals-and-sandbox"), "--dangerously-bypass-approvals-and-sandbox"),
    (re.compile(r"danger-full-access"), "sandbox danger-full-access"),
    (re.compile(r"(?:^|\s)--yolo\b|approval-mode[=\s:]+[\"']?yolo"), "Gemini YOLO mode"),
    (re.compile(r"permission-mode[=\s]+[\"']?bypassPermissions|bypassPermissions"), "bypassPermissions mode"),
    (re.compile(r"approval[_-]policy[=\s:]+[\"']?never|ask-for-approval[=\s]+never"), "approvals set to never"),
    (re.compile(r"--allowedTools[=\s]+[\"']?Bash(?:[\"',\s]|$)"), "unrestricted Bash tool"),
]
SAFETY_KEYS = {"safety-strategy": {"unsafe", "danger-full-access"}, "sandbox": {"danger-full-access"}}
TOOL_LIST_KEYS = {"allowed_tools", "allowed-tools", "allowedtools"}
MODEL_SECRET_RE = re.compile(r"(?:API_?KEY|OAUTH_TOKEN|_TOKEN_AI)$|^GITHUB_TOKEN$|^(?:ANTHROPIC|OPENAI|GEMINI|GOOGLE_AI|AZURE_OPENAI|"
                             r"MISTRAL|GROQ|XAI|OPENROUTER|DEEPSEEK|COHERE)_\w*$", re.I)
WRITE_SCOPES_RISKY = {"contents", "actions", "workflows", "packages", "deployments", "pages", "security-events",
                      "id-token", "pull-requests", "issues", "checks", "statuses", "discussions"}

# ---------------------------------------------------------------- helpers


def _flatten(node, path=""):
    """yield (path, string) for every scalar under node."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _flatten(v, "%s.%s" % (path, k) if path else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _flatten(v, "%s[%d]" % (path, i))
    elif node is not None:
        yield path, str(node)


def triggers_of(wf):
    on = wf.get("on", wf.get(True, wf.get("true")))
    if isinstance(on, str):
        return {on.strip()} if on.strip() else set()
    if isinstance(on, list):
        return {str(x).strip() for x in on}
    if isinstance(on, dict):
        return {str(k) for k in on}
    return set()


def uses_ref(uses):
    name, _, ref = uses.partition("@")
    return name.strip().lower(), ref.strip()


def is_ai_action(uses, extra=()):
    name, _ = uses_ref(uses)
    if name.startswith("./") or name.startswith("docker://"):
        return any(fnmatch.fnmatch(name, p) for p in extra)
    return any(fnmatch.fnmatch(name, p.lower()) for p in list(AI_ACTIONS) + list(extra))


def untrusted_exprs(text):
    found = []
    for m in EXPR_RE.finditer(text):
        for u in UNTRUSTED_EXPR.finditer(m.group(1)):
            found.append(u.group(0))
    return found


def mask_secret_name(name):
    return name  # secret NAMES are not secret; values never appear in workflows


class Finding:
    def __init__(self, rule, path, line, job, step, message, severity=None):
        self.rule, self.path, self.line, self.job, self.step = rule, path, line, job, step
        self.severity = severity or RULES[rule][0]
        self.message = message

    def to_dict(self):
        return {"rule": self.rule, "severity": self.severity, "title": RULES[self.rule][1], "path": self.path,
                "line": self.line, "job": self.job, "step": self.step, "message": self.message}


# ---------------------------------------------------------------- analysis


def step_label(step, idx):
    if isinstance(step, dict):
        return str(step.get("name") or step.get("id") or step.get("uses") or "step %d" % (idx + 1))[:60]
    return "step %d" % (idx + 1)


def ai_steps(job, extra_actions):
    out = []
    steps = job.get("steps") if isinstance(job, dict) else None
    if not isinstance(steps, list):
        return out
    for idx, st in enumerate(steps):
        if not isinstance(st, dict):
            continue
        uses = str(st.get("uses", ""))
        run = st.get("run")
        if uses and is_ai_action(uses, extra_actions):
            out.append((idx, st, "action " + uses_ref(uses)[0]))
        elif isinstance(run, str) and AI_RUN_RE.search(run):
            m = AI_RUN_RE.search(run)
            out.append((idx, st, "run command (%s)" % m.group(0).strip()[:40]))
    return out


def effective_permissions(wf, job):
    if isinstance(job, dict) and "permissions" in job:
        return job["permissions"], "job"
    if "permissions" in wf:
        return wf["permissions"], "workflow"
    return None, None


def has_gate(job, step, steps):
    for node in (job, step):
        if isinstance(node, dict) and isinstance(node.get("if"), str) and GATE_RE.search(node["if"]):
            return True
    for st in steps or []:
        if isinstance(st, dict) and any(fnmatch.fnmatch(str(st.get("uses", "")).lower(), p) for p in GATE_ACTIONS):
            return True
    return False


def scan_workflow(path, text, extra_actions=()):
    findings = []
    try:
        wf = parse_yaml(text)
    except YamlError as e:
        raise ValueError("%s: YAML parse error: %s" % (path, e))
    if not isinstance(wf, dict) or not isinstance(wf.get("jobs"), dict):
        return findings, False
    trig = triggers_of(wf)
    untrusted_trig = sorted(trig & UNTRUSTED_TRIGGERS)
    privileged = sorted(trig & PRIVILEGED_TRIGGERS)
    outsider_trig = [t for t in untrusted_trig if t != "pull_request"]
    jobs = wf["jobs"]
    any_ai = False
    for jname, job in jobs.items():
        if not isinstance(job, dict):
            continue
        jline = jobs.lines.get(jname)
        steps = job.get("steps") if isinstance(job.get("steps"), list) else []
        ais = ai_steps(job, extra_actions)
        if not ais:
            continue
        any_ai = True
        slines = steps.lines if isinstance(steps, YList) else []

        def line_of(idx):
            return slines[idx] if idx < len(slines) else jline

        for idx, st, how in ais:
            label = step_label(st, idx)
            findings.append(Finding("AC09", path, line_of(idx), jname, label,
                                    "AI agent via %s; triggers: %s" % (how, ", ".join(sorted(trig)) or "?")))
        # AC01: untrusted expressions in AI steps, or anywhere in run/env of AI job
        ai_idx = {i for i, _, _ in ais}
        for idx, st in enumerate(steps):
            if not isinstance(st, dict):
                continue
            label = step_label(st, idx)
            scopes = []
            if idx in ai_idx:
                scopes = list(_flatten({k: v for k, v in st.items() if k != "if"}))
            else:
                for key in ("run", "env"):
                    if key in st:
                        scopes += list(_flatten(st[key], key))
                if isinstance(st.get("with"), dict):
                    scopes += [(p, v) for p, v in _flatten(st["with"], "with")
                               if re.search(r"prompt|instruction|message|input|body|content|query", p, re.I)]
            seen = set()
            for p, v in scopes:
                for e in untrusted_exprs(v):
                    if (p, e) in seen:
                        continue
                    seen.add((p, e))
                    sev = "critical" if idx in ai_idx else "high"
                    where = "the agent step" if idx in ai_idx else "a step in the AI job (output can reach the agent)"
                    findings.append(Finding("AC01", path, line_of(idx), jname, label,
                                            "${{ %s }} in %s field '%s'; pass it via env and treat as data, "
                                            "or let the agent fetch it with read-only tools" % (e, where, p), sev))
        for p, v in _flatten(job.get("env", {}), "env"):
            for e in untrusted_exprs(v):
                findings.append(Finding("AC01", path, jline, jname, "-",
                                        "${{ %s }} in job-level %s of AI job" % (e, p), "high"))
        # AC02: outsider triggers without gate
        if outsider_trig:
            for idx, st, how in ais:
                w = st.get("with") if isinstance(st.get("with"), dict) else {}
                uses = uses_ref(str(st.get("uses", "")))[0]
                label = step_label(st, idx)
                nonwrite = str(w.get("allowed_non_write_users", "")).strip()
                bots = str(w.get("allowed_bots", "")).strip()
                if uses.startswith("anthropics/claude-code"):
                    if nonwrite == "*" or bots == "*":
                        findings.append(Finding("AC02", path, line_of(idx), jname, label,
                                                "allowed_non_write_users/allowed_bots is '*': any GitHub user can drive "
                                                "the agent via %s" % ", ".join(outsider_trig), "high"))
                    elif nonwrite:
                        findings.append(Finding("AC02", path, line_of(idx), jname, label,
                                                "allowed_non_write_users=%s lets non-writers trigger the agent" % nonwrite,
                                                "medium"))
                    continue  # action enforces write-access check by default
                if not has_gate(job, st, steps):
                    findings.append(Finding("AC02", path, line_of(idx), jname, label,
                                            "triggered by %s with no author_association/actor/label gate in job or "
                                            "step 'if:'; anyone who can open an issue/comment can drive it"
                                            % ", ".join(outsider_trig)))
        # AC03: privileged trigger + checkout of untrusted ref
        if privileged:
            for idx, st in enumerate(steps):
                if not isinstance(st, dict):
                    continue
                if uses_ref(str(st.get("uses", "")))[0] == "actions/checkout" and isinstance(st.get("with"), dict):
                    ref = " ".join(str(st["with"].get(k, "")) for k in ("ref", "repository"))
                    if UNTRUSTED_REF.search(ref):
                        findings.append(Finding("AC03", path, line_of(idx), jname, step_label(st, idx),
                                                "%s + checkout of '%s': the agent reads (and may run) attacker-controlled "
                                                "files such as CLAUDE.md/AGENTS.md, scripts and configs with secrets "
                                                "in scope" % ("/".join(privileged), ref.strip())))
                run = st.get("run")
                if isinstance(run, str) and re.search(r"gh\s+pr\s+checkout|git\s+fetch[^\n]*pull/", run):
                    findings.append(Finding("AC03", path, line_of(idx), jname, step_label(st, idx),
                                            "%s job runs '%s' to fetch PR head code before the agent runs"
                                            % ("/".join(privileged), re.search(r"gh\s+pr\s+checkout|git\s+fetch[^\n]*",
                                                                                run).group(0)[:60]), "high"))
        # AC04: permissions
        perms, level = effective_permissions(wf, job)
        if perms is None:
            findings.append(Finding("AC04", path, jline, jname, "-",
                                    "no 'permissions:' block; token scope falls back to the repo/org default "
                                    "(possibly read-write). Declare least privilege explicitly", "low"))
        elif isinstance(perms, str):
            if perms.strip() == "write-all":
                findings.append(Finding("AC04", path, jline, jname, "-",
                                        "permissions: write-all (%s level)" % level, "high"))
        elif isinstance(perms, dict):
            writes = sorted(k for k, v in perms.items() if str(v).strip() == "write")
            risky = [k for k in writes if k in WRITE_SCOPES_RISKY]
            if "id-token" in writes:
                findings.append(Finding("AC04", path, jline, jname, "-",
                                        "id-token: write lets the agent job mint cloud OIDC credentials", "high"))
            heavy = [k for k in risky if k in ("contents", "actions", "workflows", "packages", "deployments", "pages",
                                               "security-events")]
            if heavy:
                findings.append(Finding("AC04", path, jline, jname, "-",
                                        "write access to %s (%s level)%s" % (
                                            ", ".join(heavy), level,
                                            " with untrusted trigger(s) " + ", ".join(untrusted_trig)
                                            if untrusted_trig else ""),
                                        "high" if outsider_trig else "medium"))
        # AC05: dangerous agent flags
        for idx, st, how in ais:
            label = step_label(st, idx)
            hits = set()
            for p, v in _flatten({k: st.get(k) for k in ("with", "run", "env") if k in st}):
                key = p.split(".")[-1].lower()
                if key in SAFETY_KEYS and v.strip().lower() in SAFETY_KEYS[key]:
                    hits.add("%s: %s" % (key, v.strip()))
                    continue
                for rx, desc in DANGEROUS_FLAGS:
                    if rx.search(v):
                        hits.add(desc)
                if key in TOOL_LIST_KEYS:
                    toks = [t.strip().strip("\"'") for t in re.split(r"[,\n]", v)]
                    if "Bash" in toks or "Bash(*)" in toks:
                        hits.add("allowed_tools grants unrestricted Bash")
            for h in sorted(hits):
                findings.append(Finding("AC05", path, line_of(idx), jname, label,
                                        h + ("; combined with untrusted trigger(s) this is remote code execution "
                                             "by prompt" if untrusted_trig else ""),
                                        "critical" if outsider_trig else "high"))
        # AC06: secrets
        exposed = {}
        nodes = [("workflow env", wf.get("env", {})), ("job env", job.get("env", {}))]
        for idx, st, how in ais:
            nodes.append((step_label(st, idx), {k: st.get(k) for k in ("with", "env") if k in st}))
        for where, node in nodes:
            for p, v in _flatten(node):
                if re.search(r"toJSON\(\s*secrets\s*\)", v, re.I):
                    findings.append(Finding("AC06", path, jline, jname, where,
                                            "toJSON(secrets) hands every repository secret to the agent", "critical"))
                for m in re.finditer(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)", v):
                    name = m.group(1)
                    if not MODEL_SECRET_RE.search(name):
                        exposed.setdefault(name, where)
        for name, where in sorted(exposed.items()):
            findings.append(Finding("AC06", path, jline, jname, where,
                                    "secret %s is not a model/API key but is reachable by the agent (prompt injection "
                                    "can exfiltrate it)" % mask_secret_name(name),
                                    "high" if untrusted_trig else "medium"))
        # AC07: pinning
        for idx, st, how in ais:
            uses = str(st.get("uses", ""))
            if not uses:
                continue
            name, ref = uses_ref(uses)
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                sev = "medium" if ref.lower() in ("", "main", "master", "latest", "beta", "head") else "low"
                findings.append(Finding("AC07", path, line_of(idx), jname, step_label(st, idx),
                                        "%s@%s is a movable ref; pin to a full commit SHA" % (name, ref or "<none>"),
                                        sev))
        # AC08: checkout persist-credentials
        for idx, st in enumerate(steps):
            if isinstance(st, dict) and uses_ref(str(st.get("uses", "")))[0] == "actions/checkout":
                w = st.get("with") if isinstance(st.get("with"), dict) else {}
                if str(w.get("persist-credentials", "true")).strip().lower() != "false":
                    findings.append(Finding("AC08", path, line_of(idx), jname, step_label(st, idx),
                                            "actions/checkout leaves GITHUB_TOKEN in .git/config where the agent's shell "
                                            "can read it; set persist-credentials: false"))
    return findings, any_ai


def discover(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in (".git", "node_modules", ".venv", "venv", "__pycache__"))
                for f in sorted(files):
                    if f.endswith((".yml", ".yaml")):
                        out.append(os.path.join(root, f))
        elif os.path.isfile(p):
            out.append(p)
        else:
            raise FileNotFoundError(p)
    return out


def scan_paths(paths, extra_actions=(), disable=()):
    results, errors = [], []
    for f in discover(paths):
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            fnd, ai = scan_workflow(f, text, extra_actions)
        except ValueError as e:
            errors.append(str(e))
            continue
        fnd = [x for x in fnd if x.rule not in disable]
        results.append({"path": f, "ai": ai, "findings": fnd})
    return results, errors


def to_sarif(results):
    rules = [{"id": r, "shortDescription": {"text": t}, "defaultConfiguration": {
        "level": {"critical": "error", "high": "error", "medium": "warning"}.get(s, "note")}}
        for r, (s, t) in sorted(RULES.items())]
    res = []
    for r in results:
        for f in r["findings"]:
            res.append({"ruleId": f.rule, "level": {"critical": "error", "high": "error", "medium": "warning"}.get(
                f.severity, "note"), "message": {"text": "[%s] job %s: %s" % (f.severity, f.job, f.message)},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path.replace(os.sep, "/")},
                                                    "region": {"startLine": f.line or 1}}}]})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "agentci", "version": VERSION, "rules": rules}}, "results": res}]}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="agentci", description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="*", default=[".github/workflows"],
                    help="workflow files or directories (default .github/workflows)")
    ap.add_argument("--ai-action", action="append", default=[], metavar="GLOB",
                    help="extra 'owner/action' glob to treat as an AI agent step (repeatable)")
    ap.add_argument("--disable", action="append", default=[], metavar="RULE", help="disable a rule id (repeatable)")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="low")
    ap.add_argument("--fail-on", choices=SEVERITIES[1:] + ["any", "none"], default="high")
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true")
    fmt.add_argument("--sarif", action="store_true")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version="agentci " + VERSION)
    a = ap.parse_args(argv)
    if a.list_rules:
        for r, (s, t) in sorted(RULES.items()):
            print("%s  %-8s %s" % (r, s, t))
        return 0
    try:
        results, errors = scan_paths(a.paths, [x.lower() for x in a.ai_action], set(a.disable))
    except FileNotFoundError as e:
        print("agentci: no such file or directory: %s" % e, file=sys.stderr)
        return 2
    for e in errors:
        print("agentci: " + e, file=sys.stderr)
    if errors and not results:
        return 2
    minr = SEV_RANK[a.min_severity]
    for r in results:
        r["findings"] = [f for f in r["findings"] if SEV_RANK[f.severity] >= minr]
        r["findings"].sort(key=lambda f: (-SEV_RANK[f.severity], f.line or 0, f.rule))
    allf = [f for r in results for f in r["findings"]]
    if a.json:
        print(json.dumps({"version": VERSION, "files": [{"path": r["path"], "ai": r["ai"], "findings": [
            f.to_dict() for f in r["findings"]]} for r in results], "errors": errors}, indent=2))
    elif a.sarif:
        print(json.dumps(to_sarif(results), indent=2))
    else:
        for r in results:
            if not r["ai"]:
                continue
            for f in r["findings"]:
                print("%-8s %s %s:%s job=%s step=%s" % (f.severity.upper(), f.rule, f.path, f.line or "?", f.job, f.step))
                print("         " + f.message)
        n_ai = sum(1 for r in results if r["ai"])
        counts = {s: sum(1 for f in allf if f.severity == s) for s in SEVERITIES}
        summary = ", ".join("%d %s" % (counts[s], s) for s in reversed(SEVERITIES) if counts[s]) or "none"
        print("%d workflow file(s), %d with AI agents; %d finding(s): %s" % (len(results), n_ai, len(allf), summary))
    if a.fail_on == "none":
        return 0
    thr = SEV_RANK["low"] if a.fail_on == "any" else SEV_RANK[a.fail_on]
    return 1 if any(SEV_RANK[f.severity] >= thr for f in allf) else 0


if __name__ == "__main__":
    sys.exit(main())
