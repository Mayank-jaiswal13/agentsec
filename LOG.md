# agentsec publish log

- 2026-11-03 18:10 ET — Added #30 shellfence (tools/shellfence/): offline dangerous-shell-command auditor for agent transcripts; rules SF01–SF12; 42 tests. Kit now 30 tools / 1352 tests.
- 2026-11-03 20:11 ET — Added #31 schemafence (tools/schemafence/): offline tool-schema privilege auditor for agent/MCP tool defs; rules SK01–SK10; 43 tests. Kit now 31 tools / 1395 tests.
- 2026-11-04 08:07 ET — Added #32 memfence (tools/memfence/): offline persistent agent-memory / store poisoning scanner; rules MF01–MF10; 45 tests. Kit now 32 tools / 1440 tests.
- 2026-11-04 10:06 ET — Added #33 tmplfence (tools/tmplfence/): offline prompt-template injection scanner for Jinja2/Mustache/f-string LLM prompt templates; rules TM01–TM10; 42 tests. Kit now 33 tools / 1482 tests.
- 2026-11-04 12:12 ET — Added #34 piiguard (tools/piiguard/): offline PII / sensitive-personal-data scanner for agent transcripts (emails, phones, SSN, Luhn cards, gov IDs, bank/IBAN, DOB, address, MRN/NPI) with masked reports and --redact; rules PG01–PG10; 53 tests. Kit now 34 tools / 1535 tests.
- 2026-11-04 14:09 ET — Added #35 secretflow (tools/secretflow/): offline data-flow secret-propagation detector for agent transcripts (secret from tool result → later tool args, especially outbound/shell); rules FL01–FL10; 37 tests. Kit now 35 tools / 1572 tests.
