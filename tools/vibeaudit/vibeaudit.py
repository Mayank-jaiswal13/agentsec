#!/usr/bin/env python3
# vibeaudit: ignore-file
"""vibeaudit - heuristic security-smell scanner for code (Python / JS / TS / shell).

Flags patterns that show up frequently in AI-generated ("vibe-coded") code:
eval on dynamic input, shell injection, disabled TLS verification, SQL built
with string formatting, unsafe deserialization, weak password hashing,
insecure randomness, hardcoded secrets, debug servers, permissive CORS,
unverified JWTs, HTML injection sinks, and placeholder auth stubs.

This is a heuristic pattern scanner, NOT a SAST replacement. It cannot tell
whether code was written by an AI, and it has false positives and negatives.

Standard library only. Python 3.8+.
"""
import argparse
import ast
import fnmatch
import json
import os
import re
import sys

__version__ = "0.1.0"

SEV_RANK = {"low": 1, "medium": 2, "high": 3}
SARIF_LEVEL = {"low": "note", "medium": "warning", "high": "error"}
SARIF_SCORE = {"low": "3.0", "medium": "5.5", "high": "8.0"}


class Rule:
    __slots__ = ("id", "severity", "cwe", "title", "fix")

    def __init__(self, rid, severity, cwe, title, fix):
        self.id, self.severity, self.cwe, self.title, self.fix = rid, severity, cwe, title, fix


RULES = {r.id: r for r in [
    Rule("VA01", "high", 95, "Dynamic code execution (eval/exec/new Function) on non-literal input",
         "Never evaluate untrusted data. Use json / ast.literal_eval / JSON.parse, a dispatch table, or a real parser."),
    Rule("VA02", "high", 78, "Shell command built from dynamic input (shell=True / os.system / eval)",
         "Pass an argument list without a shell (subprocess.run([...], shell=False)); use shlex.quote only as a last resort."),
    Rule("VA03", "high", 78, "child_process exec/execSync with an interpolated or non-literal command",
         "Use execFile/spawn with an argument array and no shell; validate inputs against an allow-list."),
    Rule("VA04", "high", 295, "TLS certificate verification disabled",
         "Keep verification on. Fix the trust store or pass a CA bundle (verify='/path/ca.pem', ca: [...]) instead."),
    Rule("VA05", "high", 89, "SQL query built with string formatting / concatenation / template literal",
         "Use parameterized queries (cursor.execute(sql, params), db.query(sql, [values]), ORM bind parameters)."),
    Rule("VA06", "high", 502, "Unsafe deserialization (pickle/marshal/yaml.load without SafeLoader/...)",
         "Use json or yaml.safe_load; only unpickle data you created and authenticated."),
    Rule("VA07", "medium", 916, "Weak or fast hash used for passwords (md5/sha1/unsalted sha2)",
         "Use a password KDF: argon2, bcrypt, scrypt, or hashlib.pbkdf2_hmac with a per-user salt."),
    Rule("VA08", "medium", 338, "Non-cryptographic randomness used for a token/secret/password",
         "Use secrets.token_urlsafe()/secrets.choice() in Python or crypto.randomBytes()/crypto.randomUUID() in Node."),
    Rule("VA09", "high", 798, "Hardcoded secret / credential literal",
         "Load secrets from environment variables or a secret manager; rotate any secret that was committed."),
    Rule("VA10", "medium", 489, "Debug mode enabled / dev server exposed",
         "Never run with debug=True outside local dev; use a production WSGI server and bind to 127.0.0.1 in dev."),
    Rule("VA11", "high", 942, "CORS allows any (or reflected) origin together with credentials",
         "Use an explicit allow-list of trusted origins when credentials are allowed."),
    Rule("VA12", "high", 347, "JWT decoded without signature verification / 'none' algorithm allowed",
         "Verify signatures with a pinned algorithm list (jwt.decode(t, key, algorithms=['HS256']) / jwt.verify)."),
    Rule("VA13", "medium", 79, "HTML/template injection sink fed with non-literal data",
         "Use textContent / framework escaping; sanitize with a vetted library (e.g. DOMPurify) if HTML is required."),
    Rule("VA14", "medium", 287, "Placeholder or bypassed authentication / security check",
         "Implement the check (or fail closed) before shipping; remove 'return True' stubs and bypass flags."),
    Rule("VA15", "low", 1188, "Deferred-hardening comment ('in production, use ...', 'for demo purposes ...')",
         "Do the production hardening now, or track it explicitly; insecure defaults tend to ship."),
    Rule("VA16", "medium", 390, "Exception swallowed around a security check (fail-open)",
         "Catch specific exceptions and fail closed (deny / re-raise / log) when a security check errors."),
    Rule("VA17", "medium", 494, "Remote script piped straight into a shell (curl | sh)",
         "Download, verify a checksum/signature, then execute; or use a package manager."),
]}

LANG_BY_EXT = {
    ".py": "py", ".pyw": "py",
    ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".tsx": "js", ".mts": "js", ".cts": "js",
    ".sh": "sh", ".bash": "sh", ".zsh": "sh",
}
DEFAULT_EXCLUDE_DIRS = {
    "node_modules", ".git", ".hg", ".svn", "venv", ".venv", "env", ".env", "virtualenv", "__pycache__",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages", "dist", "build",
    ".next", ".nuxt", "coverage", "bower_components", ".idea", ".vscode",
}
DEFAULT_EXCLUDE_GLOBS = ["*.min.js", "*.bundle.js"]
MAX_LINE = 2000

# ---------------------------------------------------------------- helpers

SQLKW = re.compile(r"(?i)\b(select\b.*\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+table|"
                   r"where\s+\w+\s*(=|like\b|in\b)|order\s+by)")
SECRET_CTX = re.compile(r"(?i)(token|secret|passw|pwd|api_?key|apikey|nonce|salt|otp|session|csrf|reset|"
                        r"auth|invite|verification|credential)")
PASSWORD_CTX = re.compile(r"(?i)(passw|pwd|passwd)")
SANITIZE_CTX = re.compile(r"(?i)(dompurify|sanitiz|purify|escape)")
LITERAL_ARG = re.compile(r"""\s*(?:[rbuRBU]{0,2}(['"])(?:\\.|(?!\1).)*\1|`[^`$]*`)\s*(?:[,);}\]]|$)""")
PLACEHOLDER = re.compile(
    r"(?i)^(?:x+|\*+|\.+|-+|_+|none|null|nil|undefined|true|false|changeme|change[_-]?(?:me|this|it)|"
    r"replace[_-]?me|todo|tbd|redacted|secret|password|passwd|pass|pwd|example|sample|dummy|fake|test|"
    r"placeholder|default|empty|hidden|masked|<[^>]*>|\$\{.*\}|\{\{.*\}\}|\{.*\}|%\(.*\)s|%s|\$\w+|"
    r".*(?:your[_-]?(?:api|secret|token|key|password|own)|example|placeholder|xxxx|dummy|changeme|"
    r"replace[_-]?me|insert[_-]?here|goes[_-]?here|<.*>).*)$")
NAME_SKIP = re.compile(r"(?i)(tokeniz|_(name|field|label|hint|prompt|placeholder|url|uri|path|file|env|var|"
                       r"header|type|length|len|min|max|regex|pattern|policy|column|col|param|input|key_name|"
                       r"message|msg|text|title|template|format|selector|id)$|^(is|has|min|max|show|use)_)")


def first_arg_literal(rest):
    """True if `rest` (text after an opening paren / '=') starts with a plain literal."""
    return bool(LITERAL_ARG.match(rest))


def split_comment(line, lang):
    """Split a line into (code, comment). Quote-aware, single-line only."""
    s = line.lstrip()
    if lang == "js" and (s.startswith("*") or s.startswith("/*")):
        return "", line
    q = None
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if q:
            if c == "\\":
                i += 2
                continue
            if c == q:
                q = None
        elif c in "\"'" or (c == "`" and lang == "js"):
            q = c
        elif c == "#" and lang in ("py", "sh"):
            if lang == "py" or i == 0 or line[i - 1].isspace():
                return line[:i], line[i:]
        elif c == "/" and lang == "js" and line.startswith("//", i):
            return line[:i], line[i:]
        i += 1
    return line, ""


class Finding:
    __slots__ = ("rule", "severity", "path", "line", "col", "message", "cwe", "fix", "snippet")

    def __init__(self, rule, path, line, col, snippet, severity=None, message=None, cwe=None):
        r = RULES[rule]
        self.rule, self.path, self.line, self.col = rule, path, line, col
        self.severity = severity or r.severity
        self.message = message or r.title
        self.cwe = cwe or r.cwe
        self.fix = r.fix
        self.snippet = snippet.strip()[:200]

    def to_dict(self):
        return {"rule": self.rule, "severity": self.severity, "path": self.path, "line": self.line,
                "column": self.col, "message": self.message, "cwe": "CWE-%d" % self.cwe,
                "fix": self.fix, "snippet": self.snippet}


# ---------------------------------------------------------------- line patterns
# Each spec: rule, langs, regex, target ('code'|'raw'|'comment'), optional sev/msg/cwe/cond,
# fallback=True means "for Python, only used when the AST could not be parsed".

def _not_literal(m, line, code, ctx):
    return not first_arg_literal(code[m.end():])


def _not_literal_unsanitized(m, line, code, ctx):
    return not first_arg_literal(code[m.end():]) and not SANITIZE_CTX.search(line)


def _sql_kw(m, line, code, ctx):
    return bool(SQLKW.search(code))


def _secret_ctx(m, line, code, ctx):
    return bool(SECRET_CTX.search(ctx))


def _password_ctx(m, line, code, ctx):
    return bool(PASSWORD_CTX.search(ctx))


def _no_jwt(m, line, code, ctx):
    return "jwt" not in line.lower()


def _secret_value(m, line, code, ctx):
    name, value = m.group(1), m.group(3)
    if NAME_SKIP.search(name.strip("\"'")):
        return False
    if len(value) < 4 or any(ch.isspace() for ch in value):
        return False
    if PLACEHOLDER.match(value) or value.lower() == name.lower().strip("\"'"):
        return False
    if re.fullmatch(r"[A-Z][A-Z0-9_]+", value) or value.startswith(("/", "http://", "https://")):
        return False
    if len(set(value)) <= 2:
        return False
    return True


def _not_example_token(m, line, code, ctx):
    tok = m.group(0)
    body = re.sub(r"^(?:sk-(?:proj-|live-|ant-)?|sk_live_|ghp_|github_pat_|AKIA|xox[baprs]-|AIza)", "", tok)
    return "EXAMPLE" not in tok.upper() and len(set(body.lower())) > 3


def _flask_cors(m, line, code, ctx):
    o = re.search(r"origins\s*=\s*(\S)", code)
    return o is None or bool(re.search(r"origins\s*=\s*['\"]\*['\"]", code))


def _dangerously(m, line, code, ctx):
    rest = code[m.end():]
    return not first_arg_literal(rest) and not SANITIZE_CTX.search(line)


ALL = {"py", "js", "sh"}
PY, JS, SH = {"py"}, {"js"}, {"sh"}

SPECS = [
    # VA01 eval / exec
    dict(rule="VA01", langs=PY, rx=r"(?<![\w.])(?:eval|exec)\s*\(", cond=_not_literal, fallback=True),
    dict(rule="VA01", langs=JS, rx=r"(?<![\w.$])eval\s*\(", cond=_not_literal),
    dict(rule="VA01", langs=JS, rx=r"\bnew\s+Function\s*\(", cond=_not_literal),
    dict(rule="VA01", langs=JS, rx=r"\bvm\.run\w*\s*\(", cond=_not_literal),
    # VA02 shell injection
    dict(rule="VA02", langs=PY, rx=r"\bos\.(?:system|popen)\s*\(", cond=_not_literal, fallback=True),
    dict(rule="VA02", langs=PY, rx=r"\bsubprocess\.\w+\s*\(.*\bshell\s*=\s*True", fallback=True),
    dict(rule="VA02", langs=SH, rx=r"(?:^|[;&|]\s*)eval\s+\S*\$", sev="medium",
         msg="Shell 'eval' on an expanded variable"),
    # VA03 child_process
    dict(rule="VA03", langs=JS, rx=r"(?:\bchild_process\.|\bcp\.|(?<![\w.$]))(?:exec|execSync)\s*\(",
         cond=_not_literal),
    dict(rule="VA03", langs=JS, rx=r"\bspawn(?:Sync)?\s*\(.*\bshell\s*:\s*true", sev="medium",
         msg="spawn() with shell:true - arguments are interpreted by a shell"),
    # VA04 TLS
    dict(rule="VA04", langs=PY, rx=r"\bverify\s*=\s*False\b", cond=_no_jwt,
         msg="TLS certificate verification disabled (verify=False)"),
    dict(rule="VA04", langs=PY, rx=r"\bssl\._create_unverified_context\b|\bssl\.CERT_NONE\b|\bcheck_hostname\s*=\s*False\b"),
    dict(rule="VA04", langs=PY, rx=r"\burllib3\.disable_warnings\s*\(", sev="low",
         msg="urllib3 warnings disabled - usually hides verify=False"),
    dict(rule="VA04", langs=JS, rx=r"\brejectUnauthorized\s*:\s*false\b|\bstrictSSL\s*:\s*false\b"),
    dict(rule="VA04", langs=ALL, rx=r"NODE_TLS_REJECT_UNAUTHORIZED['\"]?\]?\s*=\s*['\"]?0\b|\bGIT_SSL_NO_VERIFY=['\"]?(?:1|true)\b|\bPYTHONHTTPSVERIFY=['\"]?0\b"),
    dict(rule="VA04", langs=SH, rx=r"\bcurl\b.*\s(?:-[A-Za-z]*k[A-Za-z]*|--insecure)(?=\s|$)|\bwget\b.*--no-check-certificate"),
    # VA05 SQL
    dict(rule="VA05", langs=PY, rx=r"\.(?:execute|executemany|executescript)\s*\(\s*(?:[rR]?[fF][rR]?['\"]|['\"][^'\"]*['\"]\s*(?:%|\+|\.format))",
         fallback=True),
    dict(rule="VA05", langs=JS, rx=r"\.(?:query|execute|raw|run|all|get|exec|prepare|each|unsafe|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*(?:`[^`]*\$\{|(['\"])[^'\"]*\1\s*\+)",
         cond=_sql_kw),
    dict(rule="VA05", langs=JS, rx=r"(?:const|let|var)\s+\w+\s*=\s*(?:`[^`]*\$\{|(['\"])[^'\"]*\1\s*\+)", cond=_sql_kw,
         sev="medium", msg="SQL string built with a template literal / concatenation (check where it is executed)"),
    dict(rule="VA05", langs=JS, rx=r"\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(", sev="medium",
         msg="Prisma *RawUnsafe query - make sure no user input is interpolated"),
    # VA06 deserialization
    dict(rule="VA06", langs=PY, rx=r"\b(?:c?[Pp]ickle|_pickle|dill|marshal)\.loads?\s*\(|\bshelve\.open\s*\(|\bjsonpickle\.decode\s*\(",
         sev="medium", fallback=True, msg="Unsafe deserialization (pickle/marshal/dill/shelve) - only safe on trusted data"),
    dict(rule="VA06", langs=PY, rx=r"\byaml\.(?:load|load_all)\s*\((?!.*Loader\s*=\s*(?:yaml\.)?C?(?:Safe|Base)Loader)", fallback=True,
         msg="yaml.load without SafeLoader can construct arbitrary objects"),
    dict(rule="VA06", langs=PY, rx=r"\byaml\.unsafe_load(?:_all)?\s*\(", fallback=True),
    dict(rule="VA06", langs=JS, rx=r"\bunserialize\s*\(", msg="node-serialize style unserialize() can execute code"),
    # VA07 weak password hash
    dict(rule="VA07", langs=PY, rx=r"\bhashlib\.(?:md5|sha1)\s*\(|\bhashlib\.new\s*\(\s*['\"](?:md5|sha1)['\"]", cond=_password_ctx),
    dict(rule="VA07", langs=JS, rx=r"\bcreateHash\s*\(\s*['\"](?:md5|sha1)['\"]|(?<![\w.$])(?:md5|sha1)\s*\(", cond=_password_ctx),
    dict(rule="VA07", langs=PY, rx=r"\bhashlib\.sha(?:224|256|384|512)\s*\(\s*\w*(?:passw|pwd)", sev="low",
         msg="Fast unsalted SHA-2 hash of a password"),
    dict(rule="VA07", langs=JS, rx=r"\bcreateHash\s*\(\s*['\"]sha(?:256|512)['\"]\s*\)\s*\.update\s*\(\s*\w*(?:passw|pwd)", sev="low",
         msg="Fast unsalted SHA-2 hash of a password"),
    # VA08 insecure randomness
    dict(rule="VA08", langs=PY, rx=r"\brandom\.(?:random|randint|randrange|choice|choices|getrandbits|sample|shuffle)\s*\(", cond=_secret_ctx),
    dict(rule="VA08", langs=JS, rx=r"\bMath\.random\s*\(", cond=_secret_ctx),
    # VA09 hardcoded secrets
    dict(rule="VA09", langs=ALL,
         rx=r"(?i)(?<![\w.])([\"']?[\w-]*?(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|token|private[_-]?key|client[_-]?secret|credentials?)[\w-]*[\"']?)\]?\s*[:=]\s*[bu]?([\"'])([^\"'\n]+)\2",
         cond=_secret_value),
    dict(rule="VA09", langs=ALL, rx=r"(?i)[\"']authorization[\"']\s*:\s*[\"'](?:bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{12,}[\"']",
         msg="Hardcoded Authorization header credential"),
    dict(rule="VA09", langs=ALL,
         rx=r"\b(?:sk-(?:proj-|live-|ant-)?[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b",
         cond=_not_example_token, msg="Hardcoded API key with a known provider format"),
    dict(rule="VA09", langs=ALL, rx=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", target="raw",
         msg="Private key embedded in source"),
    # VA10 debug
    dict(rule="VA10", langs=PY, rx=r"\.run\s*\(.*\bdebug\s*=\s*True.*0\.0\.0\.0|\.run\s*\(.*0\.0\.0\.0.*\bdebug\s*=\s*True",
         sev="high", msg="Debug server bound to all interfaces (debug=True, host='0.0.0.0') - remote code execution via debugger"),
    dict(rule="VA10", langs=PY, rx=r"\.run\s*\(.*\bdebug\s*=\s*True", msg="App run with debug=True"),
    dict(rule="VA10", langs=PY, rx=r"^\s*DEBUG\s*=\s*True\b", sev="low", msg="DEBUG = True setting"),
    # VA11 CORS (line-level; multi-line cases handled in file checks)
    dict(rule="VA11", langs=PY, rx=r"\bCORS\s*\(.*\bsupports_credentials\s*=\s*True", cond=_flask_cors,
         msg="flask-cors with supports_credentials=True and wildcard/default origins"),
    # VA12 JWT
    dict(rule="VA12", langs=PY, rx=r"\bjwt\.decode\s*\(.*\bverify\s*=\s*False"),
    dict(rule="VA12", langs=ALL, rx=r"[\"']verify_signature[\"']\s*:\s*False"),
    dict(rule="VA12", langs=ALL, rx=r"(?i)\balgorithms\s*[=:]\s*\[[^\]]*[\"']none[\"']", msg="JWT 'none' algorithm accepted"),
    dict(rule="VA12", langs=JS, rx=r"\bjwt\.decode\s*\(", sev="medium",
         msg="jsonwebtoken jwt.decode() does NOT verify the signature; use jwt.verify()"),
    dict(rule="VA12", langs=JS, rx=r"\bignoreExpiration\s*:\s*true\b", sev="low", msg="JWT expiration check disabled"),
    # VA13 HTML sinks
    dict(rule="VA13", langs=JS, rx=r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)", cond=_not_literal_unsanitized),
    dict(rule="VA13", langs=JS, rx=r"\bdocument\.write(?:ln)?\s*\(", cond=_not_literal_unsanitized),
    dict(rule="VA13", langs=JS, rx=r"\.insertAdjacentHTML\s*\(\s*['\"]\w+['\"]\s*,", cond=_not_literal_unsanitized),
    dict(rule="VA13", langs=JS, rx=r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:", cond=_dangerously),
    dict(rule="VA13", langs=PY, rx=r"\b(?:Markup|mark_safe)\s*\(", cond=_not_literal),
    dict(rule="VA13", langs=PY, rx=r"\brender_template_string\s*\(", cond=_not_literal, sev="high", cwe=1336,
         msg="render_template_string with a non-literal template (server-side template injection)"),
    # VA14 auth placeholders
    dict(rule="VA14", langs=ALL, target="comment",
         rx=r"(?i)\b(?:TODO|FIXME|XXX|HACK)\b.{0,60}?\b(?:authenticat\w*|authoriz\w*|auth\b|login|permissions?|"
            r"access control|csrf|sanitiz\w*|input validation|validate (?:the )?(?:input|token|signature|user)|"
            r"rate.?limit\w*|verify (?:the )?(?:token|signature|password|user)|security check)",
         msg="TODO left in place of an authentication/authorization/validation check"),
    dict(rule="VA14", langs=ALL, target="raw", sev="high",
         rx=r"(?i)\breturn\s+true\b\s*;?\s*(?:#|//).*\b(?:bypass\w*|skip\w*|todo|for now|placeholder|temporar\w*|stub|always allow|testing)\b",
         msg="Security check stubbed out with 'return True'"),
    dict(rule="VA14", langs=ALL, target="comment",
         rx=r"(?i)(?:#|//|/\*)\s*(?:bypass|skip|disable)\w*\s+(?:the\s+)?(?:auth\w*|verification|signature check|permission checks?|csrf)",
         msg="Comment indicates an authentication/verification bypass"),
    # VA15 deferred hardening
    dict(rule="VA15", langs=ALL, target="comment",
         rx=r"(?i)\bin (?:a )?(?:real|prod\w*)(?:\s+(?:app|application|environment|system|code|settings?|deployment|use))?\s*,?\s*(?:you\s+)?(?:should|would|must|need to|use|replace|make sure|add|implement|store|load|switch|move|change|enable|set)\b"),
    dict(rule="VA15", langs=ALL, target="comment",
         rx=r"(?i)\bfor (?:the )?(?:demo|demonstration|simplicity|testing|now|brevity|this example)(?: purposes)?\b.{0,40}\b(?:skip\w*|disabl\w*|bypass\w*|hardcod\w*|allow\w*|trust\w*|without|ignor\w*|no)\b"),
    dict(rule="VA15", langs=ALL, target="comment", rx=r"(?i)\bnot (?:secure|safe for production|production[- ]ready)\b"),
    # VA17 curl | sh
    dict(rule="VA17", langs=ALL, rx=r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"),
]
for _s in SPECS:
    _s["rx"] = re.compile(_s["rx"])
    _s.setdefault("target", "code")

# ---------------------------------------------------------------- file-level (multi-line) checks

CORS_JS = re.compile(r"\bcors\s*\(\s*\{(.*?)\}\s*\)", re.S)
ACAO = re.compile(r"(?i)access-control-allow-origin['\"]\s*[,:\]=]\s*\)?\s*(?:=\s*)?(?:['\"]\*['\"]|req(?:uest)?\.headers?(?:\.origin\b|\[['\"]origin['\"]\]|\.get\(\s*['\"]origin['\"]))")
ACAC = re.compile(r"(?i)access-control-allow-credentials['\"]\s*[,:\]=]\s*\)?\s*(?:=\s*)?['\"]?true")
FASTAPI_ORIGINS = re.compile(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]")
FASTAPI_CREDS = re.compile(r"allow_credentials\s*=\s*True")
JS_AUTH_STUB = re.compile(
    r"(?:function\s+|(?:const|let|var)\s+|^\s*(?:async\s+)?)(?P<name>\w*(?:[Aa]uth\w*|[Ll]ogin|[Vv]erify\w*|[Vv]alidate\w*|[Pp]ermission\w*|isAdmin|hasRole|canAccess)\w*)"
    r"\s*(?:=\s*(?:async\s*)?)?\([^)]*\)\s*(?::\s*[\w<>\[\]|]+\s*)?(?:=>\s*)?\{\s*(?:(?://[^\n]*|/\*.*?\*/)\s*)*return\s+true\s*;?\s*\}",
    re.M | re.S)


def _line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def file_checks(text, lang, path, lines):
    out = []
    if lang == "js":
        for m in CORS_JS.finditer(text):
            inner = m.group(1)
            if re.search(r"\borigin\s*:\s*(?:['\"]\*['\"]|true\b)", inner) and re.search(r"\bcredentials\s*:\s*true\b", inner):
                ln = _line_of(text, m.start())
                out.append(Finding("VA11", path, ln, 1, lines[ln - 1],
                                   message="cors() with origin '*'/true (reflect any) and credentials: true"))
        for m in JS_AUTH_STUB.finditer(text):
            ln = _line_of(text, m.start("name"))
            out.append(Finding("VA14", path, ln, 1, lines[ln - 1], severity="high",
                               message="Auth/permission function '%s' always returns true" % m.group("name")))
    if lang in ("py", "js"):
        mo = ACAO.search(text)
        if mo and ACAC.search(text):
            ln = _line_of(text, mo.start())
            out.append(Finding("VA11", path, ln, 1, lines[ln - 1],
                               message="Access-Control-Allow-Origin '*' or reflected Origin combined with Allow-Credentials: true"))
    if lang == "py":
        mo = FASTAPI_ORIGINS.search(text)
        if mo and FASTAPI_CREDS.search(text):
            ln = _line_of(text, mo.start())
            out.append(Finding("VA11", path, ln, 1, lines[ln - 1],
                               message="CORSMiddleware allow_origins=['*'] with allow_credentials=True"))
    return out

# ---------------------------------------------------------------- Python AST checks

EXEC_ATTRS = {"execute", "executemany", "executescript", "mogrify"}
SQL_ATTRS = {"raw", "read_sql", "read_sql_query", "text", "extra"}
SUBPROC_FUNCS = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"}
SHELL_FUNCS = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput",
               "asyncio.create_subprocess_shell"}
DESER_FUNCS = {"pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "_pickle.load", "_pickle.loads",
               "dill.load", "dill.loads", "marshal.load", "marshal.loads", "shelve.open", "jsonpickle.decode",
               "pandas.read_pickle"}
AUTH_FUNC = re.compile(r"(?i)(auth|login|verify|validate|check_(password|token|perm|access|signature)|"
                       r"is_(admin|authori[sz]ed|authenticated|allowed|valid|superuser|staff)|has_(perm|access|role)|"
                       r"permission|can_access)")
SEC_BODY = re.compile(r"(?i)(auth|token|passw|verify|signature|permission|jwt|csrf|ssl|cert|login|hmac|decrypt|"
                      r"is_admin|role)")


def _const_str(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _str_parts(node):
    """Concatenate the literal string parts of an expression (for SQL keyword checks)."""
    parts = []
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            parts.append(n.value)
    return " ".join(parts)


def _dynamic_str(node):
    """True if node builds a string from non-literal pieces (f-string, %, +, .format)."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Mod) and (_const_str(node.left) or _dynamic_str(node.left)):
            return not isinstance(node.right, ast.Constant)
        if isinstance(node.op, ast.Add):
            l, r = node.left, node.right
            strish = _const_str(l) or _const_str(r) or _dynamic_str(l) or _dynamic_str(r)
            return strish and not (isinstance(l, ast.Constant) and isinstance(r, ast.Constant))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return _const_str(node.func.value) or _dynamic_str(node.func.value)
    return False


class PyAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path, self.lines, self.out = path, lines, []
        self.alias = {}
        self.sql_vars = {}  # name -> [lineno of dynamic SQL assignment]

    def add(self, rule, node, **kw):
        ln = getattr(node, "lineno", 1)
        snippet = self.lines[ln - 1] if 0 < ln <= len(self.lines) else ""
        self.out.append(Finding(rule, self.path, ln, getattr(node, "col_offset", 0) + 1, snippet, **kw))

    def dotted(self, node):
        if isinstance(node, ast.Name):
            return self.alias.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.dotted(node.value)
            return base + "." + node.attr if base else None
        return None

    def visit_Import(self, node):
        for a in node.names:
            self.alias[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            for a in node.names:
                self.alias[a.asname or a.name] = node.module + "." + a.name
        self.generic_visit(node)

    def _track_sql(self, target, value, lineno):
        if isinstance(target, ast.Name) and _dynamic_str(value) and SQLKW.search(_str_parts(value)):
            self.sql_vars.setdefault(target.id, []).append(lineno)

    def visit_Assign(self, node):
        for t in node.targets:
            self._track_sql(t, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        if isinstance(node.op, ast.Add) and isinstance(node.target, ast.Name):
            v = node.value
            if (_dynamic_str(v) or not isinstance(v, ast.Constant)) and node.target.id in self.sql_vars:
                self.sql_vars[node.target.id].append(node.lineno)
            elif _dynamic_str(v) and SQLKW.search(_str_parts(v)):
                self.sql_vars.setdefault(node.target.id, []).append(node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = self.dotted(node.func) or ""
        arg0 = node.args[0] if node.args else None
        kws = {k.arg: k.value for k in node.keywords if k.arg}
        # VA01
        if name in ("eval", "exec") and arg0 is not None and not isinstance(arg0, ast.Constant):
            self.add("VA01", node, message="%s() called on a non-literal expression" % name)
        # VA02
        shell_true = isinstance(kws.get("shell"), ast.Constant) and kws["shell"].value is True
        if name in SUBPROC_FUNCS and shell_true:
            if arg0 is not None and _dynamic_str(arg0):
                self.add("VA02", node, message="%s(shell=True) with a formatted/concatenated command" % name)
            elif arg0 is not None and not isinstance(arg0, ast.Constant):
                self.add("VA02", node, message="%s(shell=True) with a non-literal command" % name)
            else:
                self.add("VA02", node, severity="low", message="%s(shell=True) with a constant command; prefer an argument list" % name)
        if name in SHELL_FUNCS and arg0 is not None and not isinstance(arg0, ast.Constant):
            sev = "high" if _dynamic_str(arg0) else "medium"
            self.add("VA02", node, severity=sev, message="%s() with a non-literal command string" % name)
        # VA05
        attr = node.func.attr if isinstance(node.func, ast.Attribute) else (node.func.id if isinstance(node.func, ast.Name) else "")
        if arg0 is not None and (attr in EXEC_ATTRS or attr in SQL_ATTRS):
            if _dynamic_str(arg0) and (attr in EXEC_ATTRS or SQLKW.search(_str_parts(arg0))):
                self.add("VA05", node, message="SQL passed to .%s() is built with string formatting/concatenation" % attr)
            elif isinstance(arg0, ast.Name) and arg0.id in self.sql_vars:
                prior = [l for l in self.sql_vars[arg0.id] if l <= node.lineno]
                if prior:
                    self.add("VA05", node, message="SQL variable '%s' (built with formatting at line %d) passed to .%s()"
                             % (arg0.id, prior[-1], attr))
        # VA06
        if name in DESER_FUNCS:
            self.add("VA06", node, severity="medium",
                     message="%s() deserializes arbitrary objects - only safe on trusted, authenticated data" % name)
        if name in ("yaml.load", "yaml.load_all"):
            loader = kws.get("Loader") or (node.args[1] if len(node.args) > 1 else None)
            ld = (self.dotted(loader) or "") if loader is not None else ""
            if not re.search(r"(Safe|Base)Loader$", ld):
                self.add("VA06", node, message="%s() without SafeLoader can construct arbitrary Python objects" % name)
        if name in ("yaml.unsafe_load", "yaml.unsafe_load_all"):
            self.add("VA06", node, message="%s() can construct arbitrary Python objects" % name)
        self.generic_visit(node)

    def _func(self, node):
        if AUTH_FUNC.search(node.name):
            body = [s for s in node.body
                    if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)) and not isinstance(s, ast.Pass)]
            if len(body) == 1 and isinstance(body[0], ast.Return) and isinstance(body[0].value, ast.Constant) \
                    and body[0].value.value is True:
                self.add("VA14", node, severity="high",
                         message="Auth/permission function '%s' unconditionally returns True" % node.name)
        self.generic_visit(node)

    visit_FunctionDef = _func
    visit_AsyncFunctionDef = _func

    def visit_Try(self, node):
        try:
            body_src = "\n".join(ast.unparse(s) for s in node.body) if hasattr(ast, "unparse") else ""
        except Exception:
            body_src = ""
        if SEC_BODY.search(body_src):
            for h in node.handlers:
                broad = h.type is None or (isinstance(h.type, ast.Name) and h.type.id in ("Exception", "BaseException"))
                if not broad:
                    continue
                stmts = h.body
                swallow = all(isinstance(s, (ast.Pass, ast.Continue)) or
                              (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)) for s in stmts)
                fail_open = len(stmts) == 1 and isinstance(stmts[0], ast.Return) and \
                    isinstance(stmts[0].value, ast.Constant) and stmts[0].value.value is True
                if fail_open:
                    self.add("VA16", h, severity="high",
                             message="Broad except returns True around a security check (fails open)")
                elif swallow:
                    self.add("VA16", h, message="Broad except: pass around a security-relevant block")
        self.generic_visit(node)

    visit_TryStar = visit_Try


# ---------------------------------------------------------------- suppression

SUPPRESS = re.compile(r"vibeaudit:\s*ignore(?!-file)(?:-next-line)?\b([^\n]*)")
SUPPRESS_FILE = re.compile(r"vibeaudit:\s*ignore-file\b")


def suppressions(lines, lang):
    """Return {lineno: set(rule ids) or None(=all)}."""
    sup = {}

    def merge(ln, ids):
        if ln in sup and sup[ln] is None:
            return
        if ids is None:
            sup[ln] = None
        else:
            sup.setdefault(ln, set()).update(ids)

    for i, raw in enumerate(lines, 1):
        if "vibeaudit" not in raw:
            continue
        code, comment = split_comment(raw, lang)
        m = SUPPRESS.search(comment) or SUPPRESS.search(raw)
        if not m:
            continue
        ids = set(re.findall(r"VA\d+", m.group(1).upper())) or None
        merge(i, ids)
        if not code.strip():
            merge(i + 1, ids)
    return sup

# ---------------------------------------------------------------- scanning


def detect_lang(path, text=None):
    ext = os.path.splitext(path)[1].lower()
    if ext in LANG_BY_EXT:
        return LANG_BY_EXT[ext]
    if text is not None and text.startswith("#!"):
        first = text.split("\n", 1)[0]
        if "python" in first:
            return "py"
        if "node" in first or "deno" in first or "bun" in first:
            return "js"
        if re.search(r"\b(ba|z|da)?sh\b", first):
            return "sh"
    return None


def scan_text(text, lang, path="<string>"):
    """Scan source text; returns a list of Finding (deduped, suppression applied, sorted)."""
    if SUPPRESS_FILE.search(text[:4096]):
        return []
    lines = text.splitlines()
    findings = []
    ast_ok = False
    if lang == "py":
        try:
            tree = ast.parse(text)
            an = PyAnalyzer(path, lines)
            an.visit(tree)
            findings.extend(an.out)
            ast_ok = True
        except (SyntaxError, ValueError, RecursionError):
            ast_ok = False
    for i, raw in enumerate(lines, 1):
        if len(raw) > MAX_LINE or not raw.strip():
            continue
        code, comment = split_comment(raw, lang)
        ctx = "\n".join(lines[max(0, i - 4):i])
        for s in SPECS:
            if lang not in s["langs"]:
                continue
            if s.get("fallback") and lang == "py" and ast_ok:
                continue
            target = code if s["target"] == "code" else (comment if s["target"] == "comment" else raw)
            if not target:
                continue
            m = s["rx"].search(target)
            if not m:
                continue
            cond = s.get("cond")
            if cond and not cond(m, raw, target, ctx):
                continue
            col = m.start() + 1 + (len(code) if s["target"] == "comment" else 0)
            findings.append(Finding(s["rule"], path, i, col, raw, severity=s.get("sev"),
                                    message=s.get("msg"), cwe=s.get("cwe")))
    findings.extend(file_checks(text, lang, path, lines))
    sup = suppressions(lines, lang)
    best = {}
    for f in findings:
        if f.line in sup and (sup[f.line] is None or f.rule in sup[f.line]):
            continue
        key = (f.line, f.rule)
        if key not in best or SEV_RANK[f.severity] > SEV_RANK[best[key].severity]:
            best[key] = f
    return sorted(best.values(), key=lambda f: (f.line, f.col, f.rule))


def _excluded(rel, name, globs):
    for g in globs:
        if fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(name, g) or fnmatch.fnmatch(rel, g.rstrip("/") + "/*"):
            return True
    return False


def collect_files(paths, excludes, include_shell=False, use_default_excludes=True):
    """Yield (display_path, lang) for each scannable file. Raises FileNotFoundError for missing paths."""
    globs = list(excludes) + (DEFAULT_EXCLUDE_GLOBS if use_default_excludes else [])
    out = []
    for p in paths:
        if not os.path.exists(p):
            raise FileNotFoundError(p)
        if os.path.isfile(p):
            out.append(p)
            continue
        for root, dirs, files in os.walk(p):
            keep = []
            for d in sorted(dirs):
                full = os.path.join(root, d)
                rel = os.path.relpath(full, p).replace(os.sep, "/")
                if use_default_excludes and (d in DEFAULT_EXCLUDE_DIRS or os.path.exists(os.path.join(full, "pyvenv.cfg"))):
                    continue
                if _excluded(rel, d, globs):
                    continue
                keep.append(d)
            dirs[:] = keep
            for fn in sorted(files):
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, p).replace(os.sep, "/")
                if _excluded(rel, fn, globs):
                    continue
                lang = detect_lang(fn)
                if lang is None or (lang == "sh" and not include_shell):
                    continue
                out.append(full)
    return out


def read_source(path, max_bytes):
    if os.path.getsize(path) > max_bytes:
        return None
    with open(path, "rb") as fh:
        data = fh.read()
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def scan_paths(paths, excludes=(), include_shell=False, max_bytes=2_000_000, use_default_excludes=True):
    files = collect_files(paths, excludes, include_shell, use_default_excludes)
    findings, scanned, errors = [], 0, []
    for f in files:
        try:
            text = read_source(f, max_bytes)
        except OSError as e:
            errors.append("%s: %s" % (f, e))
            continue
        if text is None:
            continue
        lang = detect_lang(f, text)
        if lang is None:
            continue
        scanned += 1
        findings.extend(scan_text(text, lang, f.replace(os.sep, "/")))
    return findings, scanned, errors

# ---------------------------------------------------------------- output


def summary(findings):
    s = {"total": len(findings), "high": 0, "medium": 0, "low": 0}
    for f in findings:
        s[f.severity] += 1
    return s


def render_text(findings, scanned):
    out = []
    for f in findings:
        out.append("%s:%d:%d: %s %s %s (CWE-%d)" % (f.path, f.line, f.col, f.severity.upper(), f.rule, f.message, f.cwe))
        out.append("    > " + f.snippet)
        out.append("    fix: " + f.fix)
    s = summary(findings)
    if findings:
        out.append("")
    out.append("vibeaudit: %d finding(s) (%d high, %d medium, %d low) in %d file(s) scanned."
               % (s["total"], s["high"], s["medium"], s["low"], scanned))
    out.append("Heuristic pattern scan only - review each finding; absence of findings is not proof of safety.")
    return "\n".join(out)


def render_json(findings, scanned):
    return json.dumps({"tool": "vibeaudit", "version": __version__, "files_scanned": scanned,
                       "summary": summary(findings), "findings": [f.to_dict() for f in findings]}, indent=2)


def render_sarif(findings):
    rule_ids = sorted(RULES)
    index = {r: i for i, r in enumerate(rule_ids)}
    rules = []
    for rid in rule_ids:
        r = RULES[rid]
        rules.append({
            "id": rid, "name": rid,
            "shortDescription": {"text": r.title},
            "help": {"text": r.fix},
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
            "properties": {"tags": ["security", "heuristic", "external/cwe/cwe-%d" % r.cwe],
                           "security-severity": SARIF_SCORE[r.severity]},
        })
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule, "ruleIndex": index[f.rule], "level": SARIF_LEVEL[f.severity],
            "message": {"text": "%s (CWE-%d). Fix: %s" % (f.message, f.cwe, f.fix)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.path.lstrip("./") if f.path.startswith("./") else f.path},
                "region": {"startLine": f.line, "startColumn": f.col, "snippet": {"text": f.snippet}}}}],
            "properties": {"severity": f.severity, "cwe": "CWE-%d" % f.cwe},
        })
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "vibeaudit", "version": __version__, "rules": rules}},
                     "results": results}]}
    return json.dumps(doc, indent=2)


def list_rules():
    out = ["ID    SEV     CWE       DESCRIPTION"]
    for rid in sorted(RULES):
        r = RULES[rid]
        out.append("%-5s %-7s %-9s %s" % (rid, r.severity, "CWE-%d" % r.cwe, r.title))
    return "\n".join(out)


def _rule_list(s):
    return {x.strip().upper() for x in s.split(",") if x.strip()} if s else set()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vibeaudit",
                                 description="Heuristic security-smell scanner for Python/JS/TS (and shell) code. "
                                             "Not a SAST replacement.")
    ap.add_argument("paths", nargs="*", help="files or directories to scan")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 output")
    ap.add_argument("--min-severity", choices=["low", "medium", "high"], default="low")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="exclude files/dirs matching glob (repeatable), e.g. 'tests/*' or '*.spec.ts'")
    ap.add_argument("--no-default-excludes", action="store_true",
                    help="also scan node_modules, .git, venvs, dist, build, *.min.js ...")
    ap.add_argument("--shell", action="store_true", help="also scan .sh/.bash/.zsh files found in directories")
    ap.add_argument("--select", metavar="IDS", help="only report these rule IDs (comma-separated)")
    ap.add_argument("--ignore", metavar="IDS", help="never report these rule IDs (comma-separated)")
    ap.add_argument("--max-bytes", type=int, default=2_000_000, help="skip files larger than this (default 2MB)")
    ap.add_argument("--exit-zero", action="store_true", help="exit 0 even when findings are reported")
    ap.add_argument("--list-rules", action="store_true", help="list rules and exit")
    ap.add_argument("--version", action="version", version="vibeaudit " + __version__)
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return 0 if e.code == 0 else 2
    if args.list_rules:
        print(list_rules())
        return 0
    if not args.paths:
        print("vibeaudit: error: no paths given (try: vibeaudit.py .)", file=sys.stderr)
        return 2
    if args.json and args.sarif:
        print("vibeaudit: error: choose one of --json / --sarif", file=sys.stderr)
        return 2
    select, ignore = _rule_list(args.select), _rule_list(args.ignore)
    bad = (select | ignore) - set(RULES)
    if bad:
        print("vibeaudit: error: unknown rule id(s): %s" % ", ".join(sorted(bad)), file=sys.stderr)
        return 2
    try:
        findings, scanned, errors = scan_paths(args.paths, args.exclude, args.shell, args.max_bytes,
                                               not args.no_default_excludes)
    except FileNotFoundError as e:
        print("vibeaudit: error: path not found: %s" % e, file=sys.stderr)
        return 2
    for err in errors:
        print("vibeaudit: warning: " + err, file=sys.stderr)
    floor = SEV_RANK[args.min_severity]
    findings = [f for f in findings if SEV_RANK[f.severity] >= floor
                and (not select or f.rule in select) and f.rule not in ignore]
    if args.json:
        print(render_json(findings, scanned))
    elif args.sarif:
        print(render_sarif(findings))
    else:
        print(render_text(findings, scanned))
    if errors and not findings:
        return 2
    return 1 if findings and not args.exit_zero else 0


if __name__ == "__main__":
    sys.exit(main())
