#!/usr/bin/env python3
"""rulesguard - offline scanner for 'rules file backdoor' risks in AI-agent
instruction files (AGENTS.md, CLAUDE.md, .cursorrules, .mdc rules, ...).

Heuristic and string-based. Stdlib only. MIT licensed.
"""
import argparse
import base64
import binascii
import json
import os
import re
import sys
import unicodedata

__version__ = "0.1.0"

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "RG01": ("high", "Hidden/invisible Unicode (zero-width, bidi controls, Unicode TAG characters)",
             "Remove invisible characters; view the file with a hex dump or `cat -A` and re-type affected lines."),
    "RG02": ("high", "Instruction to conceal actions from the user",
             "Agent instructions should never ask to hide changes or skip confirmation. Delete the line."),
    "RG03": ("medium", "Instruction to insert scripts, remote URLs or specific dependencies",
             "Rules should not mandate injecting external scripts/packages. Pin dependencies in manifests reviewed by humans."),
    "RG04": ("high", "Instruction to weaken security controls",
             "Remove instructions that disable TLS verification, auth, tests, lint/CI checks, or use eval/chmod 777."),
    "RG05": ("critical", "Possible exfiltration of secrets/credentials",
             "Never instruct agents to read ~/.ssh, .env or credentials, or send env vars/secrets to URLs."),
    "RG06": ("high", "Auto-execute / pipe-to-shell instruction",
             "Do not instruct agents to run curl|sh or execute downloaded code automatically."),
    "RG07": ("high", "Override / jailbreak phrasing",
             "Instruction files should not try to override prior/system instructions. Delete the phrasing."),
    "RG08": ("medium", "Fake role / turn delimiter",
             "Remove chat-template tokens and fake 'System:'/'Assistant:' turns from instruction files."),
    "RG09": ("low", "Encoded blob (base64/hex); escalated if it decodes to instruction-like text",
             "Avoid opaque encoded content in rules files; keep instructions human-readable."),
    "RG10": ("medium", "Hidden HTML comment containing instructions",
             "Rendered markdown hides HTML comments from reviewers. Move guidance into visible text or delete it."),
    "RG11": ("low", "Over-broad .mdc rule scope (alwaysApply: true with risky content, or globs '**/*')",
             "Scope Cursor rules narrowly with specific globs; avoid alwaysApply for rules with commands or URLs."),
    "RG12": ("high", "Remote include: fetch and follow instructions from a URL",
             "Instructions should be vendored and reviewed locally, not fetched at runtime from remote URLs."),
    "RG13": ("high", "Markdown image/link URL with data placeholders (exfiltration beacon)",
             "Remove images/links whose URLs embed placeholders like {secret}, $API_KEY or {{data}}."),
    "RG14": ("high", "Instruction to bypass agent permission/approval prompts",
             "Do not instruct agents to auto-approve, use --dangerously-skip-permissions, or YOLO modes."),
}

DISCOVER_NAMES = {"AGENTS.md", "CLAUDE.md", "CLAUDE.local.md", "GEMINI.md", ".cursorrules",
                  ".windsurfrules", ".clinerules", "SKILL.md", "copilot-instructions.md"}
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "env", ".env", "__pycache__", ".tox",
             ".mypy_cache", "site-packages", "dist", "build", ".hg", ".svn"}


def is_rules_file(rel):
    parts = rel.replace(os.sep, "/").split("/")
    name = parts[-1]
    parent = parts[-2] if len(parts) > 1 else ""
    gparent = parts[-3] if len(parts) > 2 else ""
    if name == "copilot-instructions.md":
        return parent == ".github"
    if name in DISCOVER_NAMES:
        return True
    if name.endswith(".mdc") and parent == "rules" and gparent == ".cursor":
        return True
    if name.endswith(".instructions.md") and parent == "instructions" and gparent == ".github":
        return True
    if ".clinerules" in parts[:-1]:
        return True
    if any(p.startswith("rules") for p in parts[:-1]) and ".roo" in parts[:-1]:
        return True
    return False


def discover(root):
    found = []
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if d not in SKIP_DIRS and not d.startswith("venv"))
        for fn in sorted(fns):
            full = os.path.join(dp, fn)
            rel = os.path.relpath(full, root)
            if is_rules_file(rel):
                found.append(full)
    return found


# ---------------------------------------------------------------- helpers
ZW = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x2061, 0x2062, 0x2063, 0x2064, 0x00AD}
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}


def visible(s):
    out = []
    for ch in s:
        cp = ord(ch)
        if cp in ZW or cp in BIDI or 0xE0000 <= cp <= 0xE007F or (unicodedata.category(ch) == "Cf"):
            out.append("<U+%04X>" % cp)
        else:
            out.append(ch)
    return "".join(out)


SECRETISH = re.compile(r"(?i)((?:key|token|secret|password|passwd|pwd)\s*[=:]\s*)(\S{4,})|\b((?=[A-Za-z_\-]*\d)(?=[\d_\-]*[A-Za-z])[A-Za-z0-9_\-]{24,})\b")


def mask(s, maxlen=160):
    s = visible(s.strip())

    def rep(m):
        if m.group(1):
            v = m.group(2)
            return m.group(1) + v[:2] + "***"
        v = m.group(3)
        return v[:4] + "..." + v[-2:] + "(masked)"
    s = SECRETISH.sub(rep, s)
    if len(s) > maxlen:
        s = s[:maxlen - 3] + "..."
    return s


def P(p):
    return re.compile(p, re.I)


CONCEAL = [P(r"\b(do\s*n[o']?t|never|without)\s+(mention|tell|inform|notify|telling|informing|notifying|mentioning|alert(ing)?|showing|show|reveal(ing)?|disclos(e|ing)|log(ging)?)\b[^.\n]{0,40}\b(user|human|developer|reviewer|anyone|them|it|this|these|change|changes)\b"),
           P(r"\bsilently\b"), P(r"\bwithout\s+(asking|confirmation|confirming|approval|permission|prompting|notice)\b"),
           P(r"\b(hide|conceal|omit)\b[^.\n]{0,30}\b(from|in)\b[^.\n]{0,20}\b(user|summary|output|response|diff|commit message|reviewer)s?\b"),
           P(r"\bkeep\s+(this|it|these)\s+(secret|hidden|confidential)\b"),
           P(r"\b(don'?t|do not|never)\s+(add|include|write)\b[^.\n]{0,30}\b(to the summary|in (the )?(summary|response|output|commit message))")]
INJECT = [P(r"<script[^>]+src\s*=\s*[\"']?https?://"),
          P(r"\b(add|insert|include|inject|append|import|load)\b[^.\n]{0,60}\b(script|snippet|tag|iframe|beacon|tracker|pixel)\b[^\n]{0,80}https?://"),
          P(r"\b(always|must)\b[^.\n]{0,40}\b(add|install|use|include)\b[^.\n]{0,30}\b(npm|pip|package|dependency|library|module|gem|crate)\b"),
          P(r"\b(npm|yarn|pnpm)\s+(i|install|add)\s+[^\s]+|pip3?\s+install\s+(--extra-index-url|--index-url|-i)\s+https?://"),
          P(r"\b(add|insert)\b[^.\n]{0,40}https?://[^\s)]+\.js\b")]
WEAKEN = [P(r"verify\s*=\s*False|rejectUnauthorized\s*:?\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=?\s*['\"]?0|InsecureSkipVerify\s*:?\s*true|--insecure\b|curl\s+-k\b|CURLOPT_SSL_VERIFYPEER|ssl\._create_unverified_context|strict-ssl\s*(=|\s)\s*false"),
          P(r"\b(disable|turn off|skip|bypass|remove)\b[^.\n]{0,30}\b(tls|ssl|certificate)\s*(verification|validation|checks?)?"),
          P(r"\b(use|prefer|call)\b[^.\n]{0,20}\beval\s*\(|\bnew Function\s*\(|\bexec\s*\(\s*(input|request|user)"),
          P(r"\b(skip|bypass|disable|remove|turn off)\b[^.\n]{0,30}\b(auth(entication|orization)?|login checks?|csrf|access control|permission checks?|input validation|sanitiz\w+)"),
          P(r"\b(skip|disable|bypass|remove|delete|turn off|comment out)\b[^.\n]{0,30}\b(tests?|linters?|lint(ing)?|ci|pre-commit|hooks?|security scans?|checks?|code review)\b"),
          P(r"--no-verify\b|eslint-disable(?!-next-line\s+\S+\s+--)|#\s*nosec|//\s*@ts-ignore"),
          P(r"\bchmod\s+(-R\s+)?(0?777|a\+rwx|o\+w)\b"),
          P(r"^(?!.*\b(never|don'?t|do not|avoid|no)\b).*\b(hard-?code|commit)\b[^.\n]{0,30}\b(password|secret|api key|credentials?|token)s?\b"),
          P(r"\bdisable\b[^.\n]{0,20}\b(firewall|selinux|apparmor|sandbox|cors|csp)\b")]
EXFIL = [P(r"(~|\$HOME|/home/\w+|/root)/\.(ssh|aws|gnupg|kube|docker|netrc|npmrc|pypirc|git-credentials|config/gh)\b"),
         P(r"\b(read|cat|open|copy|upload|send|include|collect|grab)\b[^.\n]{0,40}(\.env\b|id_rsa|id_ed25519|credentials\.json|\.npmrc|\.pypirc|\.netrc|secrets?\.(ya?ml|json))"),
         P(r"\b(send|post|upload|transmit|forward|report|exfiltrate|beacon|ship)\b[^\n]{0,60}\b(env(ironment)?\s*(var(iable)?s?)?|secrets?|api[_ ]?keys?|tokens?|credentials?|passwords?|private keys?|cookies)\b[^\n]{0,60}(https?://|webhook|endpoint|server|url)"),
         P(r"(curl|wget|fetch|requests\.(get|post)|Invoke-WebRequest)[^\n]{0,80}(\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASS|ENV)|printenv|os\.environ|process\.env|\$\(env\)|@?\.env\b)"),
         P(r"\b(printenv|env)\s*\|\s*(curl|nc|wget)|\bos\.environ\b[^\n]{0,40}(post|send|requests)")]
AUTOEXEC = [P(r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^\n|]{0,120}\|\s*(sudo\s+)?(ba|z|da)?sh\b|\|\s*(sudo\s+)?(python3?|node|bash|sh|iex|Invoke-Expression)\b(\s|$)"),
            P(r"\b(bash|sh)\s+(-c\s+)?[\"']?\$\((curl|wget)|\bsource\s+<\((curl|wget)|\beval\s+[\"']?\$\((curl|wget)"),
            P(r"\b(automatically|immediately|always)\s+(run|execute|exec)\b[^.\n]{0,60}\b(script|command|binary|installer|code|it)\b"),
            P(r"\b(download|fetch)\b[^.\n]{0,40}\band\s+(run|execute)\b"),
            P(r"\bpowershell\b[^\n]{0,40}-(enc|encodedcommand)\b")]
OVERRIDE = [P(r"\b(ignore|disregard|forget|override)\b[^.\n]{0,20}\b(all\s+)?(previous|prior|above|earlier|preceding|other|system|safety|original)\b[^.\n]{0,20}\b(instructions?|rules?|prompts?|guidelines?|directives?|policies)\b"),
            P(r"\byou are now\b|\bfrom now on,? you (are|will|must)\b|\bact as (an? )?(unrestricted|unfiltered|jailbroken)"),
            P(r"\b(system|admin|developer|god|debug)\s+(override|mode enabled|mode activated)\b|\bDAN mode\b|\bjailbreak\b"),
            P(r"\b(these|this) (instructions?|rules?) (take|takes|have) (precedence|priority) over\b[^.\n]{0,40}\b(system|user|safety|all)\b"),
            P(r"\bnew (system )?instructions?:")]
DELIMS = [re.compile(r"<\|(im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id|end_header_id)\|>"),
          re.compile(r"\[/?INST\]|<<\/?SYS>>|</?(system|system_prompt|assistant|user_turn|tool_result|function_results)>", re.I),
          re.compile(r"^\s*(#+\s*)?(System|SYSTEM|Assistant|ASSISTANT|Human|HUMAN)\s*:\s*\S", re.M),
          re.compile(r"\b(BEGIN|END) (SYSTEM|ADMIN) (PROMPT|MESSAGE|INSTRUCTIONS)\b", re.I)]
REMOTE = [P(r"\b(fetch|download|load|retrieve|read|get|pull|curl)\b[^.\n]{0,60}https?://\S+[^.\n]{0,80}\b(follow|obey|apply|execute|use|treat)\b[^.\n]{0,40}\b(instructions?|rules?|directives?|as (your )?(rules|instructions|system prompt)|it|them|contents?)\b"),
          P(r"\b(follow|obey|apply)\b[^.\n]{0,40}\b(instructions?|rules?|directives?)\b[^.\n]{0,30}\b(at|from|in|hosted at)\b[^.\n]{0,10}https?://"),
          P(r"^\s*@?(include|import)\s*[:(]?\s*https?://", )]
MDEXFIL = re.compile(r"!?\[[^\]]*\]\((https?://[^)\s]*(\{\{?[^}]*\}\}?|\$\{?[A-Za-z_]+\}?|<[A-Z_]+>|%[A-Z_]+%|\[(DATA|SECRET|TOKEN|KEY)[^\]]*\])[^)\s]*)\)", re.I)
MDEXFIL2 = re.compile(r"https?://[^\s)\"']*[?&][a-z_]*(data|q|secret|token|key|d|payload|env|c)=(\{\{?[^}]*\}\}?|\$\{?[A-Za-z_]+\}?|<[A-Za-z_ ]+>|%[A-Z_]+%)", re.I)
PERM = [P(r"--dangerously-skip-permissions|--dangerously-bypass-approvals|--yolo\b|\byolo mode\b|bypassPermissions"),
        P(r"\b(auto-?approve|automatically approve|approve all|accept all)\b[^.\n]{0,30}\b(commands?|tool calls?|edits?|actions?|requests?|everything|prompts?)\b"),
        P(r"\b(never|don'?t|do not)\s+(ask|wait)\b[^.\n]{0,20}\b(for )?(permission|approval|confirmation)\b")]
INSTR_WORDS = re.compile(r"(?i)\b(ignore|instruction|always|never|must|do not|don't|execute|run|send|curl|http|tell|user|secret|token|password|system|assistant|silently|delete|install|override)\b")
B64 = re.compile(r"(?<![A-Za-z0-9+/=_\-])([A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])")
HEX = re.compile(r"(?<![0-9A-Fa-f])((?:[0-9A-Fa-f]{2}){24,})(?![0-9A-Fa-f])|((?:\\x[0-9A-Fa-f]{2}){12,})")
HTMLC = re.compile(r"<!--(.*?)-->", re.S)
URL = re.compile(r"https?://", re.I)


def decode_tags(s):
    out = []
    for ch in s:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))
    return "".join(out)


class Finding(dict):
    pass


def scan_text(text, path, disabled=()):
    findings = []
    lines = text.split("\n")
    is_mdc = path.endswith(".mdc")

    def add(rule, line, snippet, msg=None, sev=None):
        if rule in disabled:
            return
        rsev, desc, fix = RULES[rule]
        findings.append(Finding(rule=rule, severity=sev or rsev, path=path, line=line,
                                message=msg or desc, snippet=mask(snippet), fix=fix))

    # RG01 hidden unicode (per line)
    for i, ln in enumerate(lines, 1):
        tags = decode_tags(ln)
        zws = [c for c in ln if ord(c) in ZW and not (i == 1 and ln.startswith("\ufeff") and c == "\ufeff" and ln.count("\ufeff") == 1)]
        bidi = [c for c in ln if ord(c) in BIDI]
        if tags:
            add("RG01", i, ln, "Unicode TAG characters hide text; decoded: %r" % mask(tags, 120), "critical")
        if bidi:
            add("RG01", i, ln, "%d bidi control character(s) can reorder displayed text" % len(bidi))
        if zws:
            add("RG01", i, ln, "%d zero-width/invisible character(s)" % len(zws))
    # normalized view for pattern rules: strip invisibles, append decoded tags
    norm_lines = []
    for ln in lines:
        tags = decode_tags(ln)
        clean = "".join(c for c in ln if not (ord(c) in ZW or ord(c) in BIDI or 0xE0000 <= ord(c) <= 0xE007F))
        norm_lines.append(clean + ((" " + tags) if tags else ""))

    # frontmatter for .mdc
    fm_end = 0
    fm = {}
    if norm_lines and norm_lines[0].strip() == "---":
        for j in range(1, min(len(norm_lines), 60)):
            if norm_lines[j].strip() == "---":
                fm_end = j + 1
                break
            m = re.match(r"\s*([A-Za-z_]+)\s*:\s*(.*)$", norm_lines[j])
            if m:
                fm[m.group(1).lower()] = (j + 1, m.group(2).strip())

    line_rules = [("RG02", CONCEAL), ("RG03", INJECT), ("RG04", WEAKEN), ("RG05", EXFIL),
                  ("RG06", AUTOEXEC), ("RG07", OVERRIDE), ("RG08", DELIMS), ("RG12", REMOTE), ("RG14", PERM)]
    risky_lines = set()
    for i, ln in enumerate(norm_lines, 1):
        for rule, pats in line_rules:
            for p in pats:
                if p.search(ln):
                    add(rule, i, ln)
                    risky_lines.add(i)
                    break
        if MDEXFIL.search(ln) or MDEXFIL2.search(ln):
            add("RG13", i, ln)
            risky_lines.add(i)
        # RG09 blobs
        for m in B64.finditer(ln):
            blob = m.group(1)
            if re.fullmatch(r"[A-Za-z]+", blob) or re.fullmatch(r"[0-9a-fA-F]+", blob):
                continue
            try:
                dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if sum(c.isprintable() or c in "\n\t" for c in dec) < 0.9 * len(dec):
                continue
            if INSTR_WORDS.search(dec):
                add("RG09", i, ln, "base64 decodes to instruction-like text: %r" % mask(dec, 100), "high")
            else:
                add("RG09", i, ln, "base64-like blob decodes to text: %r" % mask(dec, 60))
            risky_lines.add(i)
        for m in HEX.finditer(ln):
            h = m.group(1) or m.group(2).replace("\\x", "")
            try:
                dec = bytes.fromhex(h).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if not all(c.isprintable() or c in "\n\t" for c in dec):
                continue
            sev = "high" if INSTR_WORDS.search(dec) else None
            add("RG09", i, ln, "hex blob decodes to text: %r" % mask(dec, 100), sev)
            risky_lines.add(i)

    # RG10 hidden HTML comments
    ntext = "\n".join(norm_lines)
    for m in HTMLC.finditer(ntext):
        body = m.group(1)
        if not body.strip():
            continue
        line = ntext.count("\n", 0, m.start()) + 1
        risky = any(p.search(body) for _, pats in line_rules for p in pats) or URL.search(body)
        if risky:
            add("RG10", line, "<!--" + body + "-->", "HTML comment (invisible when rendered) contains risky instructions", "high")
        elif INSTR_WORDS.search(body) and len(body.split()) >= 4:
            add("RG10", line, "<!--" + body + "-->")
        risky_lines.add(line)

    # RG11 mdc scope
    if is_mdc and fm:
        aa = fm.get("alwaysapply")
        gl = fm.get("globs")
        body_risky = any(r > fm_end for r in risky_lines)
        if aa and aa[1].lower().strip("'\"") == "true" and body_risky:
            add("RG11", aa[0], "alwaysApply: " + aa[1], "alwaysApply: true on a rule that contains risky content (applies to every request)", "medium")
        if gl and re.search(r"(^|[\s,\[\"'])\*\*(/\*(\.\*)?)?($|[\s,\]\"'])", gl[1]):
            add("RG11", gl[0], "globs: " + gl[1], "globs matches every file (%s)" % gl[1],
                "medium" if body_risky else "low")
    findings.sort(key=lambda f: (f["line"], f["rule"]))
    return findings


def grade(findings):
    c = {s: 0 for s in SEVERITIES}
    for f in findings:
        c[f["severity"]] += 1
    if c["critical"] or c["high"] >= 3:
        return "F"
    if c["high"]:
        return "D"
    if c["medium"]:
        return "C"
    if c["low"]:
        return "B"
    return "A"


def scan_paths(paths, disabled=()):
    results, errors = [], []
    for p in paths:
        if os.path.isdir(p):
            files = discover(p)
        elif os.path.isfile(p):
            files = [p]
        else:
            errors.append("path not found: %s" % p)
            continue
        for f in files:
            try:
                with open(f, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError as e:
                errors.append("cannot read %s: %s" % (f, e))
                continue
            fnd = scan_text(text, f, disabled)
            results.append({"path": f, "grade": grade(fnd), "findings": fnd})
    return results, errors


def to_sarif(results):
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules = [{"id": k, "name": k, "shortDescription": {"text": v[1]}, "help": {"text": v[2]},
              "defaultConfiguration": {"level": level[v[0]]}, "properties": {"severity": v[0]}}
             for k, v in sorted(RULES.items())]
    res = []
    for r in results:
        for f in r["findings"]:
            res.append({"ruleId": f["rule"], "level": level[f["severity"]],
                        "message": {"text": "%s: %s" % (f["message"], f["snippet"])},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["path"].replace(os.sep, "/")},
                                                            "region": {"startLine": f["line"]}}}],
                        "properties": {"severity": f["severity"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "rulesguard", "version": __version__,
                                          "informationUri": "https://example.invalid/rulesguard", "rules": rules}},
                      "results": res}]}


def render_text(results):
    out = []
    for r in results:
        out.append("%s  [grade %s]  %d finding(s)" % (r["path"], r["grade"], len(r["findings"])))
        for f in r["findings"]:
            out.append("  %-4s L%-4d %-8s %s" % (f["rule"], f["line"], f["severity"].upper(), f["message"]))
            out.append("              > %s" % f["snippet"])
            out.append("              fix: %s" % f["fix"])
    tot = sum(len(r["findings"]) for r in results)
    out.append("")
    out.append("Scanned %d file(s); %d finding(s)." % (len(results), tot))
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="rulesguard", description="Scan AI-agent instruction/rules files for backdoor-style risks (heuristic).")
    ap.add_argument("paths", nargs="*", default=["."])
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true")
    fmt.add_argument("--sarif", action="store_true")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="info")
    ap.add_argument("--fail-on", choices=["high", "medium", "low", "any", "none"], default="high")
    ap.add_argument("--disable", action="append", default=[], help="rule id(s) to disable, e.g. RG09 or RG09,RG11")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    if a.list_rules:
        for k, v in sorted(RULES.items()):
            print("%s  %-8s %s\n      fix: %s" % (k, v[0], v[1], v[2]))
        return 0
    disabled = {d.strip().upper() for x in a.disable for d in x.split(",") if d.strip()}
    bad = disabled - set(RULES)
    if bad:
        print("rulesguard: unknown rule id(s): %s" % ", ".join(sorted(bad)), file=sys.stderr)
        return 2
    results, errors = scan_paths(a.paths, disabled)
    mn = SEV_RANK[a.min_severity]
    for r in results:
        r["findings"] = [f for f in r["findings"] if SEV_RANK[f["severity"]] >= mn]
    for e in errors:
        print("rulesguard: error: " + e, file=sys.stderr)
    if a.json:
        print(json.dumps({"tool": "rulesguard", "version": __version__, "results": results, "errors": errors}, indent=2))
    elif a.sarif:
        print(json.dumps(to_sarif(results), indent=2))
    else:
        print(render_text(results))
    if errors:
        return 2
    th = {"high": SEV_RANK["high"], "medium": SEV_RANK["medium"], "low": SEV_RANK["low"], "any": 0, "none": None}[a.fail_on]
    if th is None:
        return 0
    if any(SEV_RANK[f["severity"]] >= th for r in results for f in r["findings"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
