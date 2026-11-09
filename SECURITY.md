# Security policy

agentsec is a set of offline, heuristic security scanners. Two kinds of reports are welcome:

1. **Vulnerabilities in the tools themselves**: for example, a crafted input file that makes a
   scanner execute code, write outside its intended paths, hang indefinitely, or leak an
   unmasked secret in its output.
2. **Detection bypasses**: an input that should clearly be flagged but is not, or a common
   benign pattern that is reliably flagged by mistake.

## How to report

- For a vulnerability in the tools, please use GitHub's **private vulnerability reporting**
  ([Report a vulnerability](https://github.com/dunkleschitz/agentsec/security/advisories/new)
  under the repository's *Security* tab) rather than a public issue.
- Detection bypasses and false positives can be filed as normal public issues, unless the
  bypass is something you believe is being actively exploited.

Please include the tool name, Python version, a minimal input that reproduces the problem
(with **fake** secrets only), the command you ran, and the output you expected.

Never include real credentials, tokens, private keys or personal data in a report.

## Scope and expectations

The detectors are pattern- and heuristic-based. They are not a replacement for a sandbox,
SAST, or a secret manager, and a clean result is not proof that something is safe.
This is a volunteer-maintained project with no guaranteed response time; we aim to
acknowledge reports within a reasonable period.
