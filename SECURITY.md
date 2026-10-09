# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ Active |
| Older branches | ❌ Not supported |

## Reporting a Vulnerability

If you discover a security vulnerability in **BetAker**, please **do NOT open a public GitHub Issue**.

Instead, report it privately via one of the following channels:

- **GitHub Private Security Advisory** (preferred): Go to [Security → Report a vulnerability](../../security/advisories/new) on this repository.
- **Email**: [jack.vhknguyen@gmail.com](mailto:jack.vhknguyen@gmail.com) — include `[SECURITY]` in the subject line.

### What to include in your report

Please provide as much of the following as possible:
- A description of the vulnerability and its potential impact.
- Steps to reproduce the issue (code snippet, command, or test case).
- Affected file(s) and line number(s).
- Any suggested fix or mitigation (optional but appreciated).

## Response Timeline

| Stage | Time |
|-------|------|
| Acknowledgement | Within **48 hours** |
| Initial assessment | Within **5 business days** |
| Fix & patch release | Within **14 days** (critical: ≤ 7 days) |
| Public disclosure | After patch is released and users have had time to update |

## Scope

This policy covers vulnerabilities in the **BetAker** source code itself, including:

- `tools/scanner.py`, `tools/sca.py`, `tools/patcher.py`, `tools/terminal.py`
- `agent/core.py`, `llm/providers.py`, `llm/client.py`
- `main.py`, `config.py`

**Out of scope:**
- Vulnerabilities in third-party dependencies (report those to their respective upstream projects)
- Issues that require physical access to the machine running BetAker

## Responsible Disclosure

We follow a **Responsible Disclosure** policy. We ask that you:
1. Give us reasonable time to investigate and fix before public disclosure.
2. Avoid exploiting the vulnerability beyond what is necessary to demonstrate it.
3. Not disclose the vulnerability publicly until a coordinated disclosure date is agreed upon.

We credit all responsible disclosures in our release notes.

Thank you for helping keep BetAker secure. 🛡️
