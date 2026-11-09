# Contributing

Thanks for helping. Please also read the [Code of Conduct](CODE_OF_CONDUCT.md).
A few ground rules keep the kit easy to use and audit:

- **Standard library only.** Each tool is a single Python file that runs on Python 3.10+
  with no third-party dependencies. Please don't add any.
- **Tests required.** Every change to a detector needs a test in `tools/<name>/tests/`
  (or `tools/toolpoison/test_toolpoison.py`). Run everything with:

  ```sh
  python3 run_tests.py          # or: make test
  python3 run_tests.py slopcheck  # a single tool
  ```

  A suite that runs zero tests counts as a failure, locally and in CI.
- **Fake secrets only.** Fixtures must be obviously fake (include `FAKE` or `EXAMPLE`).
  If a detector needs a value with a provider's exact shape, build it at runtime by string
  concatenation (see `tools/tracesweep/tests/`) so secret scanners don't flag the repo.
- **Be honest about limits.** If a rule is heuristic, say so in the tool's README and
  prefer reporting "unknown/unmapped" over guessing.
- Keep CLI exit codes consistent: `0` clean, `1` findings at/above the fail threshold,
  `2` usage or input errors.

Open an issue before large changes (new tools, new output formats) so we can agree on scope.
Issues labeled [good first issue](https://github.com/dunkleschitz/agentsec/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
are written to be small and self-contained.

## Pull requests

- One change per PR when you can (a rule, a format, or a docs fix).
- In the PR description, say how you ran the tests (`python3 run_tests.py` or a single tool).
- Do not force-push to `main`, rewrite published history, or add real credentials,
  tokens, private keys or personal data — including in screenshots.
