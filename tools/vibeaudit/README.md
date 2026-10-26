# vibeaudit

An offline, standard-library-only Python 3 CLI that scans Python, JavaScript and TypeScript
(and optionally shell) source for **security smells that show up a lot in AI-generated
("vibe-coded") code**: `eval` on user input, `shell=True` with f-strings, `verify=False`,
SQL built with f-strings or template literals, `pickle`/`yaml.load`, md5 password hashes,
`Math.random()` tokens, hardcoded keys, `app.run(debug=True, host="0.0.0.0")`, CORS `*` with
credentials, unverified JWTs, `innerHTML`/`dangerouslySetInnerHTML`, and the classic LLM
placeholders such as `# TODO: add authentication` and `return True  # bypass for now`.

> **Honesty note.** vibeaudit is a **heuristic pattern scanner, not a SAST replacement.**
> It uses regular expressions on single lines, a few multi-line regexes, and (for Python) cheap
> AST checks. It does not do data-flow or taint analysis, so it cannot tell whether a value is
> really attacker-controlled. It **cannot tell whether code was written by an AI**. The rules
> are just patterns often seen in LLM output, and humans write them too. Expect **false positives
> and false negatives**. A clean run does not mean the code is secure. Use it as a quick
> first-pass review aid next to real tools (Semgrep, CodeQL, Bandit, ESLint security plugins)
> and human review.

## What it does

- Walks files and directories. `.py`, `.js/.jsx/.mjs/.cjs`, `.ts/.tsx/.mts/.cts` are scanned
  by default. `.sh/.bash/.zsh` are scanned inside directories with `--shell`, or whenever you
  name them explicitly. Extensionless files with a python/node/sh shebang work when named.
- Skips `node_modules`, `.git`, `venv`/`.venv`/any dir containing `pyvenv.cfg`, `__pycache__`,
  `dist`, `build`, `.next`, `coverage`, `*.min.js` and similar by default
  (`--no-default-excludes` turns this off). Skips binary files, files over 2 MB, and lines over 2000 chars.
- Python: AST checks for eval/exec, subprocess/os.system (including import aliases), SQL passed to
  `.execute()` (including a variable built with formatting earlier in the file), pickle/marshal/yaml,
  auth functions whose whole body is `return True`, and broad `except: pass` / `except: return True`
  around security-relevant code. If a file does not parse (for example Python 2), regex fallbacks are used.
- Comment-aware: code rules ignore `#` / `//` comments (quote-aware, so `"https://..."` is fine).
  Comment rules (TODO-auth, "in production, use ...") only look at comments.
- Hardcoded-secret rule skips obvious placeholders (`""`, `your-api-key-here`, `<PASSWORD>`,
  `${TOKEN}`, `changeme`, `xxxx`, values with spaces, env-var names, `*_label`/`*_name`/`*_url` names, ...).
- Every finding has a rule ID, severity (low/medium/high), message, CWE id, fix hint, and file:line:col.
- Outputs human text, `--json`, or `--sarif` (SARIF 2.1.0, with `security-severity` for code-scanning UIs).

## Rules

```
ID    SEV     CWE       DESCRIPTION
VA01  high    CWE-95    Dynamic code execution (eval/exec/new Function) on non-literal input
VA02  high    CWE-78    Shell command built from dynamic input (shell=True / os.system / eval)
VA03  high    CWE-78    child_process exec/execSync with an interpolated or non-literal command
VA04  high    CWE-295   TLS certificate verification disabled
VA05  high    CWE-89    SQL query built with string formatting / concatenation / template literal
VA06  high    CWE-502   Unsafe deserialization (pickle/marshal/yaml.load without SafeLoader/...)
VA07  medium  CWE-916   Weak or fast hash used for passwords (md5/sha1/unsalted sha2)
VA08  medium  CWE-338   Non-cryptographic randomness used for a token/secret/password
VA09  high    CWE-798   Hardcoded secret / credential literal
VA10  medium  CWE-489   Debug mode enabled / dev server exposed
VA11  high    CWE-942   CORS allows any (or reflected) origin together with credentials
VA12  high    CWE-347   JWT decoded without signature verification / 'none' algorithm allowed
VA13  medium  CWE-79    HTML/template injection sink fed with non-literal data
VA14  medium  CWE-287   Placeholder or bypassed authentication / security check
VA15  low     CWE-1188  Deferred-hardening comment ('in production, use ...', 'for demo purposes ...')
VA16  medium  CWE-390   Exception swallowed around a security check (fail-open)
VA17  medium  CWE-494   Remote script piped straight into a shell (curl | sh)
```

Some findings carry a different severity than their rule's default. For example, `shell=True` with a
constant command is *low*, `debug=True` with `host="0.0.0.0"` is *high*, an auth stub that always
returns True is *high*, and `pickle.loads` is *medium*.

## Install

Requires Python 3.8+ (3.9+ recommended, since the VA16 body check uses `ast.unparse`). No dependencies.

```bash
cp vibeaudit.py ~/bin/vibeaudit && chmod +x ~/bin/vibeaudit   # or just: python3 vibeaudit.py ...
```

## Usage

```bash
python3 vibeaudit.py .                           # scan the current project
python3 vibeaudit.py src app.py --shell          # include shell scripts found in dirs
python3 vibeaudit.py . --min-severity medium     # hide low findings
python3 vibeaudit.py . --json > findings.json
python3 vibeaudit.py . --sarif > vibeaudit.sarif
python3 vibeaudit.py . --exclude 'tests/*' --exclude '*.spec.ts'
python3 vibeaudit.py . --select VA05,VA09        # only some rules
python3 vibeaudit.py . --ignore VA15             # drop a noisy rule
python3 vibeaudit.py --list-rules
```

**Exit codes:** `0` no findings (at or above `--min-severity`), `1` findings reported, `2` error
(bad arguments, path not found). `--exit-zero` always exits 0 when the scan succeeds.

### Inline suppression

```python
x = eval(expr)            # vibeaudit: ignore VA01      (this line, only VA01)
requests.get(u, verify=False)  # vibeaudit: ignore      (this line, all rules)
# vibeaudit: ignore VA04,VA09                           (a comment-only line also covers the next line)
el.innerHTML = trusted;   // vibeaudit: ignore VA13     (JS/TS use //)
# vibeaudit: ignore-file                                (in the first 4 KB: skip the whole file)
```

## Example output (real run on the bundled samples)

```
$ python3 vibeaudit.py examples/vulnerable_app.py --select VA02,VA05,VA14
examples/vulnerable_app.py:25:5: HIGH VA05 SQL passed to .execute() is built with string formatting/concatenation (CWE-89)
    > cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    fix: Use parameterized queries (cursor.execute(sql, params), db.query(sql, [values]), ORM bind parameters).
examples/vulnerable_app.py:31:12: HIGH VA05 SQL variable 'sql' (built with formatting at line 30) passed to .execute() (CWE-89)
    > return sqlite3.connect("app.db").execute(sql).fetchall()
    fix: Use parameterized queries (cursor.execute(sql, params), db.query(sql, [values]), ORM bind parameters).
examples/vulnerable_app.py:35:12: HIGH VA02 subprocess.check_output(shell=True) with a formatted/concatenated command (CWE-78)
    > return subprocess.check_output(f"ping -c 1 {host}", shell=True)
    fix: Pass an argument list without a shell (subprocess.run([...], shell=False)); use shlex.quote only as a last resort.
examples/vulnerable_app.py:39:5: HIGH VA02 os.system() with a non-literal command string (CWE-78)
    > os.system("tar czf /tmp/backup.tgz " + path)
    fix: Pass an argument list without a shell (subprocess.run([...], shell=False)); use shlex.quote only as a last resort.
examples/vulnerable_app.py:70:1: HIGH VA14 Auth/permission function 'is_admin' unconditionally returns True (CWE-287)
    > def is_admin(user):
    fix: Implement the check (or fail closed) before shipping; remove 'return True' stubs and bypass flags.
examples/vulnerable_app.py:71:7: MEDIUM VA14 TODO left in place of an authentication/authorization/validation check (CWE-287)
    > # TODO: add authentication and role checks
    fix: Implement the check (or fail closed) before shipping; remove 'return True' stubs and bypass flags.

vibeaudit: 6 finding(s) (5 high, 1 medium, 0 low) in 1 file(s) scanned.
Heuristic pattern scan only - review each finding; absence of findings is not proof of safety.
$ echo $?
1
```

The full sample set (`python3 vibeaudit.py examples --shell`) triggers all 17 rules:

```
vibeaudit: 38 finding(s) (24 high, 13 medium, 1 low) in 5 file(s) scanned.
Heuristic pattern scan only - review each finding; absence of findings is not proof of safety.
```

The safe counterparts produce nothing:

```
$ python3 vibeaudit.py examples/clean_app.py examples/clean_app.ts
vibeaudit: 0 finding(s) (0 high, 0 medium, 0 low) in 2 file(s) scanned.
Heuristic pattern scan only - review each finding; absence of findings is not proof of safety.
```

## Files

- `vibeaudit.py`: the scanner (single file, stdlib only). `scan_text(text, lang)` and `scan_paths(paths)` can be imported.
- `examples/vulnerable_app.py`, `examples/vulnerable_app.ts`, `examples/deploy.sh`: deliberately insecure samples with **fake** credentials.
- `examples/clean_app.py`, `examples/clean_app.ts`: safe equivalents that should produce no findings.
- `tests/test_vibeaudit.py`: unittest suite (`python3 -m unittest discover -s tests -v`).

## Known limitations

- No taint tracking: `eval(CONSTANT_FROM_CONFIG)` is flagged and `eval` reached through a wrapper is not.
- Line-based JS/TS matching: calls split across lines, or strings built in one place and used far away, can be missed.
- Context heuristics (VA07/VA08 look for words like *password*/*token* in the line and the 3 lines before it) can misfire either way.
- Test fixtures for secret scanners and similar tools will (correctly but unhelpfully) trigger VA09. Use `--exclude` or suppressions.

## License

MIT. See the [LICENSE](../../LICENSE) at the repository root.
