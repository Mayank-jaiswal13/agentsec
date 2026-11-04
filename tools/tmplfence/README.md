# tmplfence

Offline **prompt-template injection** scanner for LLM apps.

Many agent and chatbot codebases build prompts with Jinja2, Mustache/Handlebars,
or Python f-strings / `.format` / `%`. When a **user-controlled** placeholder is
interpolated into a **system / developer** (privileged) section, the end user
(or a retrieved document) can inject instructions that look like policy. tmplfence
reviews template files and prompt-construction code for that class of bug.

Standard library only. It never connects to a network and never renders templates.

## How it differs from siblings

| Tool | Surface |
|---|---|
| **tmplfence** | Prompt *templates* and Python prompt construction (Jinja2 / Mustache / f-string) |
| promptleak | Leakage of system prompts *out* of a run (transcripts) |
| canarytrap | Live canary payloads against a running agent |
| ragsieve | Pre-ingestion *RAG corpora* (poisoned docs) |
| rulesguard | Agent *instruction files* (AGENTS.md, SKILL.md, …) |
| outfence | Model *output* before it is rendered |

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| TM01 | critical | User-controlled variable interpolated into a system/developer prompt |
| TM02 | high | Unescaped / raw rendering of a user-ish variable (`\|safe`, `{{{ }}}`, autoescape off) |
| TM03 | high | User-ish variable adjacent to role delimiters (`<\|system\|>`, `SYSTEM:`, …) |
| TM04 | high | Dangerous Jinja2 construct in a prompt template (`{%`, `\|attr`, `__class__`, …) |
| TM05 | high | Python f-string / `.format` / `%` / concat of user data into a system prompt |
| TM06 | medium | System instructions and user placeholders share one undifferentiated template |
| TM07 | medium | Dynamic `include` / `extends` / Mustache partial with a variable path |
| TM08 | medium | Triple-mustache or `\|safe`/`\|raw` on any placeholder in a prompt template |
| TM09 | low | Broad catch-all placeholder (`input` / `query` / `message` / `text`) in a privileged section |
| TM10 | info | Inventory of templates and placeholders scanned (disable in CI with `--disable TM10`) |

**User-ish** names include `user_input`, `user_message`, `query`, `ticket`,
`document`, `customer_message`, and similar. **Privileged** context is inferred
from `role: system|developer`, system-ish variable / file names
(`system_prompt.j2`, `system_prompt = …`), or system-role markers in the template
head.

## Usage

```
python3 tmplfence.py template.j2 [more.py dir/ -]
  --disable RULE ...  skip rule ids (e.g. TM10 TM09)
  --json              machine-readable output
  --min-severity S    hide findings below S (default info)
  --fail-on S         exit 1 if any finding >= S (default high; any, none)
  --list-rules
```

Exit codes: `0` clean (below `--fail-on`), `1` findings, `2` usage / no readable
input. TM10 inventory alone does not fail the default `--fail-on high` gate.

Accepted shapes: `.j2` / `.jinja` / `.jinja2` / `.mustache` / `.hbs` / `.tpl` /
`.prompt` / `.txt` / `.md` templates, chat-template JSON/JSONL (`role`+`content`,
`system_prompt` fields), Python source that assigns `system_prompt` /
`system_message` / `developer_prompt` via f-strings / `.format` / `%` / concat,
directories, and stdin (`-`).

## Example

```sh
python3 tmplfence.py examples/system_prompt.j2 --disable TM10
```

Flags TM01 on `{{ user_input }}` and `{{ ticket }}` inside a system-style
template (exit 1).

```sh
python3 tmplfence.py examples/build_prompts.py --disable TM10
```

Flags TM05/TM01 where an f-string and string concatenation put `user_input` into
`system_prompt` / `system_message`.

`examples/clean_system.j2` and `examples/clean_chat.json` are clean under
`--fail-on high` (exit 0) — user content stays in the user role. See also
`system_raw.mustache` (TM02), `dangerous_jinja.j2` (TM04/TM07),
`role_adjacent.tpl` (TM03), and `chat_templates.json`.

## Known limits

- Name heuristics. A benign variable called `query` in a system template is
  flagged (TM09/TM01); an attacker-controlled field named `crm_note` may be
  missed unless it matches a user-ish pattern — review snippets.
- Templates are not executed. Runtime-only composition (string builders, non-AST
  Python, other languages) is invisible.
- Jinja2 detection is regex-based, not a full Jinja parser; unusual spacing or
  custom delimiters can evade TM04.
- A clean tmplfence result does not mean the surrounding agent is safe against
  prompt injection once messages are assembled.
