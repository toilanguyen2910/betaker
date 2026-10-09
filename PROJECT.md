# Project: BetHacker — Interactive Security Code Auditor & Automated Patching CLI

## Architecture
BetHacker is a production-grade, defensive Security Code Auditor and Automated Patching CLI in Python.
The system is structured into five core decoupled subsystems:
1. **SAST & SCA Engine (`tools/scanner.py`, `tools/sca.py`, `tools/advisories.py`)**:
   - SAST: Hybrid pattern and lexical/AST inspection for Python, JavaScript/TypeScript, Go, and PHP detecting OWASP Top 10 vulnerabilities (SQLi, CMDi, Path Traversal, Insecure Deserialization, Hardcoded Secrets) with exact line numbers, code snippets, and severity ratings.
   - SCA: Dependency manifest auditing (`requirements.txt`, `package.json`) using zero-dependency SemVer/PEP 440 comparison against an offline CVE advisory database.
2. **LLM Root Cause & Patch Engine (`llm/client.py`, `llm/providers.py`, `agent/prompts.py`, `agent/core.py`)**:
   - Provider abstraction (`BaseLLMProvider`) supporting DeepSeek, Google Gemini, OpenAI, and a guaranteed zero-crash `OfflineMockProvider` for keyless/testing environments.
   - Defensive prompt engineering and structured JSON outputs extracting root cause explanation, CVSS/severity rating, and clean logic-preserving patch code.
3. **Safe Patching & Rollback Engine (`tools/patcher.py`)**:
   - Unified diff generation using standard ASCII headers (`a/file`, `b/file`).
   - Interactive confirmation prompt (`Confirm.ask`, overrideable via `auto_approve=True`).
   - Atomic file updates (`tempfile`, `os.fsync`, `os.replace`) to prevent file corruption.
   - Automatic `.bak` creation and byte-verified rollback restoring files to identical pre-patch state.
4. **Interactive Rich CLI & Reporting (`main.py`, `tools/reporter.py`)**:
   - Defensive auditor terminal persona with Rich color-coded severity tables, syntax highlighting, and progress status.
   - Commands: `/audit [path]`, `/deps [path]`, `/rollback [file]`, `/report [format] [output]`, `/help`, `/clear`, `/exit`.
   - Headless CLI arguments (`--audit`, `--deps`, `--rollback`, `--report`, `--auto-approve`, `--json`) for automation.
5. **E2E & 4-Tier Automated Test Suite (`tests/`, `pytest`)**:
   - Comprehensive test suite covering Tiers 1-4 with 100% pass rate, followed by Tier 5 adversarial hardening.

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | SAST Polyglot Rules | Detect SQLi, CMDi, Path Traversal, Deserialization, Secrets across Python, JS/TS, Go, PHP with line numbers & snippets | M1 | ORIGINAL_REQUEST §R1 |
| 2 | False Positive Reduction | Filter out safe parameterized SQL, constants, non-vulnerable usages | M1 | ORIGINAL_REQUEST §R1 |
| 3 | Dependency Manifest SCA | Parse requirements.txt (PEP 508/440) and package.json with SemVer comparison against offline CVE advisories | M1 | ORIGINAL_REQUEST §R1 |
| 4 | Multi-Provider LLM Engine | Provider abstractions for DeepSeek, Gemini, OpenAI | M2 | ORIGINAL_REQUEST §R2 |
| 5 | Offline Mock LLM Provider | Deterministic zero-crash offline fallback generating root cause, severity & clean patch | M2 | ORIGINAL_REQUEST §R2 |
| 6 | Defensive Prompt & Agent | Restructure prompt persona for defensive code auditing and structured JSON patch output | M2 | ORIGINAL_REQUEST §R2 |
| 7 | Git-Compatible Unified Diff | Generate clean unified diffs with ASCII headers avoiding Windows CP1252 charmap encoding errors | M3 | ORIGINAL_REQUEST §R3 |
| 8 | Safe Atomic Patching & Backup | Automatic .bak backup creation and atomic file swap (tempfile + os.replace) | M3 | ORIGINAL_REQUEST §R3 |
| 9 | Byte-Verified Rollback | Restore .bak backup identically and verify byte-for-byte matching | M3 | ORIGINAL_REQUEST §R3 |
| 10 | Interactive Rich Terminal CLI | Interactive REPL with color-coded severity tables and Rich panels | M4 | ORIGINAL_REQUEST §R4 |
| 11 | CLI Commands Handler | Implement /audit, /deps, /rollback, /report, /help, /clear, /exit | M4 | ORIGINAL_REQUEST §R4 |
| 12 | Headless Automation Flags | Support CLI flags (--audit, --deps, --rollback, --report, --auto-approve) | M4 | ORIGINAL_REQUEST §R4 |
| 13 | Multi-Format Reporting | Export security audit reports to JSON and Markdown/HTML | M4 | ORIGINAL_REQUEST §R4 |
| 14 | E2E 4-Tier Test Suite | Tiers 1-4 opaque-box and unit tests covering all features with 100% pytest pass rate | M5 & TestTrack | ORIGINAL_REQUEST §R4 |
| 15 | Tier 5 Adversarial Hardening | White-box adversarial testing, edge cases, mutation/stress testing | M5 | Project Pattern |

---

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | SAST & SCA Engine | Implement polyglot SAST rules (Py, JS/TS, Go, PHP) and dependency SCA (`tools/scanner.py`, `tools/sca.py`, `tools/advisories.py`) | none | IN_PROGRESS |
| M2 | LLM Analysis & Patch Engine | Implement provider abstraction, DeepSeek/Gemini/OpenAI + OfflineMockProvider, structured prompts (`llm/`, `agent/`) | M1 | PLANNED |
| M3 | Safe Patching & Rollback | Implement unified diffs, atomic patching, .bak backups, and byte-verified rollback (`tools/patcher.py`) | none | PLANNED |
| M4 | Interactive Rich CLI & Reporting | Implement Rich interactive REPL, /audit, /deps, /rollback, /report, headless flags, report generation (`main.py`, `tools/reporter.py`) | M1, M2, M3 | PLANNED |
| M5 | E2E Test Suite & Adversarial Hardening | Phase 1: 100% pass on E2E test suite (Tiers 1-4). Phase 2: Tier 5 adversarial hardening | M1, M2, M3, M4 | PLANNED |

---

## Interface Contracts

### SAST/SCA Engine (`tools/scanner.py`) ↔ CLI & Agent
- `scan_file(filepath: str | Path) -> list[VulnerabilityFinding]`
- `scan_directory(dirpath: str | Path, recursive: bool = True) -> list[VulnerabilityFinding]`
- `scan_dependencies(manifest_path: str | Path) -> list[DependencyFinding]`
- `VulnerabilityFinding`: dataclass / pydantic model with:
  `id: str, rule_id: str, title: str, severity: str (CRITICAL|HIGH|MEDIUM|LOW), file: str, line: int, snippet: str, description: str, language: str`
- `DependencyFinding`: dataclass / pydantic model with:
  `package: str, current_version: str, vulnerable_range: str, fixed_version: str, cve: str, severity: str, advisory: str`

### LLM Engine (`llm/client.py`) ↔ Agent & CLI
- `BaseLLMProvider.analyze_and_patch(vulnerability: VulnerabilityFinding, source_code: str) -> PatchResult`
- `PatchResult`:
  `root_cause: str, severity: str, explanation: str, patched_code: str, diff: str, confidence: float`
- `get_llm_client(provider_name: str | None = None) -> BaseLLMProvider` (returns configured provider or `OfflineMockProvider` fallback if keys missing)

### Patching Engine (`tools/patcher.py`) ↔ Agent & CLI
- `generate_diff(filepath: str | Path, original_content: str, patched_content: str) -> str`
- `create_backup(filepath: str | Path) -> Path`
- `apply_patch(filepath: str | Path, patched_content: str, auto_approve: bool = False) -> tuple[bool, str]`
- `rollback(filepath_or_backup: str | Path) -> tuple[bool, str]`
- `list_backups(directory: str | Path = ".") -> list[tuple[Path, Path]]`

### Reporting Engine (`tools/reporter.py`) ↔ CLI
- `export_report(findings: list, format: str = "json" | "markdown", output_path: str | Path | None = None) -> str`

---

## Code Layout
- `main.py` — Main CLI entrypoint, Rich REPL, command dispatcher, argument parser
- `config.py` — Environment settings, API keys, fallback defaults
- `requirements.txt` — Dependencies (`rich`, `python-dotenv`, `pydantic`, `pytest`, `openai`, `google-genai`)
- `tools/scanner.py` — SAST scanner for Python, JS/TS, Go, PHP
- `tools/sca.py` — SCA scanner for requirements.txt and package.json
- `tools/advisories.py` — Curated offline CVE database and SemVer matcher
- `tools/patcher.py` — Atomic patcher, diff generator, backup and rollback engine
- `tools/reporter.py` — Report generation (JSON, Markdown, Rich tables)
- `tools/file_ops.py` — File listing and safe I/O utilities
- `agent/core.py` — Auditor orchestration agent coordinating scan -> analyze -> patch -> verify
- `agent/prompts.py` — Defensive security auditor prompts and JSON schema
- `llm/client.py` — Multi-provider factory and client interface
- `llm/providers.py` — Concrete providers (DeepSeek, Gemini, OpenAI, OfflineMockProvider)
- `tests/` — Comprehensive test suite
  - `conftest.py` — Fixtures and vulnerable/safe code samples
  - `test_scanner_sast.py` — SAST tests across 4 languages
  - `test_scanner_sca.py` — SCA dependency parsing and SemVer tests
  - `test_patcher_rollback.py` — Patching, diff, .bak, and rollback tests
  - `test_llm_providers.py` — LLM providers and OfflineMockProvider tests
  - `test_cli_commands.py` — CLI commands, REPL, headless flags, and reporting tests
  - `test_e2e_scenarios.py` — End-to-end integration flows across real-world projects
