# modelpin

Offline **model-ID pin / drift checker** for AI agent transcripts.

Floating aliases (`gpt-4o`, `claude-3-5-sonnet-latest`), silent mid-run model
switches, unexpected provider routing (OpenAI → Bedrock) and accidental
downgrades change behaviour and invalidate evals. modelpin reads a small JSON
policy (or CLI flags), extracts the model IDs that actually appear in saved
transcripts, and reports findings with turn attribution.

Standard library only. It never runs an agent and never contacts the network.

## How it differs from siblings

| Tool | Surface |
|---|---|
| **modelpin** | *Observed* transcript model IDs vs an allowlist / exact pin (CI gate) |
| aibom | Repo inventory that *notes* floating aliases in source (AB03) |
| runledger | Token / dollar cost broken down by model (not a pin gate) |
| toolpin | MCP *tool definition* lockfile and rug-pull drift |
| rundiff | Behavioral tool-call diff between two runs |

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| MD01 | high | Observed model is not in the allowlist / policy |
| MD02 | high | Floating / unversioned alias (not a dated snapshot) |
| MD03 | high | Mid-run model switch (multiple distinct models in one transcript) |
| MD04 | high | Provider drift vs policy expected providers |
| MD05 | medium | Exact pinned model mismatch |
| MD06 | medium | Missing / empty model field on a model-bearing record |
| MD07 | low | Soft-deprecated or retired model family |
| MD08 | high | Suspected capability downgrade vs pinned tier |
| MD09 | info | Inventory of models observed |

## Policy

```json
{
  "allowed": ["gpt-4o-2024-08-06", "claude-3-5-sonnet-20241022"],
  "providers": ["openai", "anthropic"],
  "pinned": "gpt-4o-2024-08-06",
  "forbid_aliases": true,
  "forbid_switch": true,
  "forbid_downgrade": true
}
```

`allowed` entries may end with `*` (prefix match). `pinned` is an exact match
and also drives MD08 tier comparison. Write a starter with
`python3 modelpin.py --init modelpin.policy.json`.

## Usage

```
python3 modelpin.py transcript.json [more.jsonl dir/ -]
  -p / --policy FILE    JSON policy (allowed/providers/pinned/forbid_*)
  --allow MODEL ...     extra allowed ids / prefix* globs
  --pinned MODEL        exact model that must be used
  --providers LIST      comma-separated expected providers
  --allow-aliases       do not flag floating aliases
  --allow-switch        allow multiple models in one transcript
  --no-downgrade-check  disable MD08
  --disable RULE ...    skip rule ids
  --json                machine-readable output
  --min-severity S      hide findings below S (default info)
  --fail-on S           exit 1 if any finding >= S (default high; any, none)
  --list-rules
  --init [FILE]         write starter policy (default modelpin.policy.json)
```

Exit codes: `0` clean (below `--fail-on`), `1` findings, `2` usage / no readable input.

Accepted shapes: OpenAI chat completions / transcripts with a top-level
`model`, Anthropic message objects, generic JSON/JSONL records with
`model` / `model_name` / `modelId` (also nested under `response` /
`request` / `params`), directories, stdin (`-`).

## Example

```sh
python3 modelpin.py examples/risky_switch.jsonl -p examples/policy_strict.json
```

Flags MD02 on `gpt-4o-mini`, MD03 on the mid-run switch, MD05/MD08 against the
pin, MD07 on `gpt-3.5-turbo`, and MD01 for anything outside the allowlist
(exit 1). `examples/clean_openai.json` with the same policy stays clean aside
from the MD09 inventory (use `--min-severity low` or `--disable MD09` in CI).

See also `risky_aliases.json`, `risky_provider.json`, `risky_missing.json` and
`clean_anthropic.json`. All model IDs and payloads are synthetic.

## Known limits

- Heuristic transcript parsing. A custom logger that stores the model under an
  unusual key may be missed; prefer a top-level `model` field.
- Floating-alias detection is a curated list plus `-latest` / undated family
  heuristics. New provider aliases may need a list update.
- Provider inference from the model string is best-effort (prefix / pattern).
  Explicit `provider/model` forms are preferred.
- Capability tiers for MD08 are coarse (opus/sonnet/haiku-style). They are a
  tripwire, not a benchmark.
- It analyzes what was saved. It cannot stop a live router from switching
  models; enforce the pin in the client or gateway and use modelpin in CI.
