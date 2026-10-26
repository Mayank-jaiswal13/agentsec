# slopcheck

Offline, stdlib-only Python 3 CLI that flags **hallucinated-package / slopsquatting risk** in the
dependency lists and imports that AI coding assistants produce.

AI assistants sometimes invent plausible package names (`langchain-utils-pro`,
`python-openai-helper`) or make typos (`reqeusts`). Attackers can register those names
("slopsquatting") and wait for someone to install them. slopcheck gives you a quick,
offline first pass so you know **which names to go verify by hand**.

## What it can and cannot do (read this)

- It **does not contact PyPI, npm, or any network service**. It **cannot tell whether a package
  actually exists, who owns it, or whether it is malicious.**
- It compares names against `slopcheck_known.json`, a **hand-picked, possibly outdated snapshot**
  of a few hundred well-known PyPI and npm names (~295 PyPI, ~196 npm). It is **not** the registry.
- Not being in the snapshot does not mean a package is fake; being in it does not mean it is safe
  (popular packages get compromised too).
- False positives and false negatives are expected. Treat every finding as
  "verify this on pypi.org / npmjs.com yourself (owner, release history, downloads, source repo)".

## Inputs

| Input | How it is read |
|---|---|
| `requirements*.txt` | PEP 508-ish lines, extras, markers, `-e`, `git+`/URL, `name @ url`; skips `-r`/`-c`/index options |
| `pyproject.toml` | PEP 621 `dependencies` / `optional-dependencies`, `dependency-groups`, Poetry `dependencies`/`dev-dependencies`/groups (tomllib on 3.11+, tiny fallback otherwise) |
| `package.json` | `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies` |
| `*.py` | `ast` imports; stdlib skipped via `sys.stdlib_module_names`; relative imports and local modules skipped; common import→dist mapping (`yaml`→PyYAML, `cv2`→opencv-python, `sklearn`→scikit-learn, `PIL`→Pillow, `bs4`→beautifulsoup4, ...) |
| `*.js/.jsx/.mjs/.cjs/.ts/.tsx` | regex for `import`/`export from`/`require()`/`import()`; skips relative paths, `node:` and Node builtins |
| directories | recursive scan; skips `.git`, `node_modules`, venvs, `dist`, `build`, dot-dirs |

## Rules

| ID | Severity | Meaning |
|---|---|---|
| SC01 | info | Not in snapshot or allowlist: unverified, check the registry yourself |
| SC02 | high | Near-miss of a well-known name: Damerau-Levenshtein ≤1 (names ≤6 chars) or ≤2, separator confusion (`pythondateutil`), npm case confusion (`React`) |
| SC03 | medium | Hallucination shape: popular base + generic affixes (`-utils`, `-helper`, `-sdk`, `-api`, `-py`, `python-`, `-js`, `-pro`, ...) where the combination is unknown |
| SC04 | medium | Ecosystem confusion: npm-only name in Python deps (`axios` in requirements.txt) or vice versa |
| SC05 | low | Unpinned / loose version (`pandas`, `>=1.0`, `*`, `latest`) |
| SC06 | medium | Direct URL / VCS / git dependency bypasses the registry |
| SC07 | low | Imported but not declared (only when manifests **and** sources of that ecosystem are scanned) |
| SC08 | low | Declared but never imported (dev deps and common tools like pytest/black are skipped) |

## Install

No dependencies. Copy `slopcheck.py` and `slopcheck_known.json` next to each other, or run in place:

```
python3 slopcheck.py --version
```

## Usage

```
python3 slopcheck.py [PATHS ...]            # files or directories, default "."
  --allow FILE          allowlist, one name per line (# comments ok; repeatable)
  --known FILE          use another snapshot JSON ({"pypi": [...], "npm": [...]})
  --json | --sarif      JSON or SARIF 2.1.0 output (default: text table)
  --min-severity LEVEL  info|low|medium|high (default info)
  --fail-on LEVEL       high|medium|low|any|none (default high) -> exit 1
  --no-usage            skip SC07/SC08
  --list-rules
```

Exit codes: `0` ok, `1` findings at/above `--fail-on`, `2` errors (missing file, bad JSON/TOML, syntax error, bad allowlist).

Suppress a single line with an inline comment `# slopcheck: ignore` (requirements, pyproject, Python)
or `// slopcheck: ignore` (JS/TS). For package.json, list names under
`"slopcheck": {"ignore": ["name"]}`. For your private/internal packages, use `--allow`.

## Example output (real run)

```
$ python3 slopcheck.py examples/risky/requirements.txt --no-usage
SEV     RULE  ECO   NAME                  LOCATION                           MESSAGE
HIGH    SC02  pypi  reqeusts              examples/risky/requirements.txt:2  'reqeusts' is a near-miss of well-known 'requests' (edit distance 1); possible typo or slopsquat
HIGH    SC02  pypi  beautifulsoup         examples/risky/requirements.txt:7  'beautifulsoup' is a near-miss of well-known 'beautifulsoup4' (edit distance 1); possible typo or slopsquat
MEDIUM  SC03  pypi  langchain-utils-pro   examples/risky/requirements.txt:4  'langchain-utils-pro' = popular 'langchain' + generic affix(es) pro/utils; a common shape of AI-hallucinated names
MEDIUM  SC03  pypi  python-openai-helper  examples/risky/requirements.txt:5  'python-openai-helper' = popular 'openai' + generic affix(es) helper/python; a common shape of AI-hallucinated names
MEDIUM  SC04  pypi  axios                 examples/risky/requirements.txt:8  'axios' is a well-known npm package but not a known pypi one; likely wrong ecosystem
MEDIUM  SC06  pypi  somepkg               examples/risky/requirements.txt:9  direct URL/VCS dependency (git+https://github.com/example/somepkg.git#egg=somepkg) bypasses the registry; pin a commit hash and review the source
LOW     SC05  pypi  numpy                 examples/risky/requirements.txt:3  loose version '>=1.26' (no upper bound or exact pin)
LOW     SC05  pypi  python-openai-helper  examples/risky/requirements.txt:5  no version pin; an attacker-registered or changed release would be picked up automatically
LOW     SC05  pypi  pandas                examples/risky/requirements.txt:6  no version pin; an attacker-registered or changed release would be picked up automatically
LOW     SC05  pypi  beautifulsoup         examples/risky/requirements.txt:7  no version pin; an attacker-registered or changed release would be picked up automatically
INFO    SC01  pypi  somepkg               examples/risky/requirements.txt:9  'somepkg' is not in the bundled snapshot or allowlist: unverified, check the registry yourself

11 finding(s): 2 high, 4 medium, 4 low, 1 info  (1 file(s) scanned)
note: snapshot-based offline heuristics; cannot confirm a package exists or is safe. Verify flagged names on pypi.org / npmjs.com yourself.
$ echo $?
1
```

The full `examples/risky/` directory (requirements.txt + package.json + app.py + index.js, all
**fake** names, do not install) produces 41 findings (7 high) and exits 1; `examples/clean/`
produces no findings and exits 0.

CI example:

```
python3 slopcheck.py . --sarif --fail-on high > slopcheck.sarif
```

## Tests

```
python3 -m unittest
```

## License

MIT. See the [LICENSE](../../LICENSE) at the repository root.
