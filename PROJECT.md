# Project: BetAker — Security Auditing CLI Audit, Hardening & Polyglot SAST Expansion

## Architecture
BetAker is a defensive Security Code Auditor and Automated Patching CLI in Python.
The system is structured into five core decoupled subsystems:
1. **Polyglot SAST & Suppression Engine (`tools/scanner.py`)**:
   - Lexical scanner for Python, JavaScript/TypeScript, Go, and PHP detecting OWASP Top 10 vulnerabilities (SQLi, CMDi, Path Traversal, Secrets, Deserialization, SSRF, LFI, NoSQLi, Weak Crypto, XSS).
   - Comment-aware false positive suppression engine supporting `#nosec`, `//nosec`, `/* nosec */`, and `# bethacker:ignore`. Immune to string literal evasion.
   - Language-aware false positive filters (safe parameterization, Go `exec.Command` constant slices, JS `child_process.spawn` array args, DB `exec` disambiguation).
2. **SCA Dependency & Manifest Engine (`tools/sca.py`, `tools/advisories.py`)**:
   - Zero-dependency SemVer/PEP 440 comparison against an offline CVE database for `requirements.txt` and `package.json`.
   - Null-byte and corrupted manifest safety, returning graceful empty findings instead of uncaught exceptions.
3. **Safe File Operations & Atomic Patching (`tools/file_ops.py`, `tools/patcher.py`)**:
   - Strict workspace containment (`_resolve_safe_path` enforcing `relative_to(Config.WORKSPACE_DIR)`).
   - Atomic patching via `tempfile`, `os.replace`, and `os.fsync`.
   - Byte-verified rollback via SHA-256 hash checking and proper `.bak` extension stripping.
4. **Agent Orchestration, Offline Mock & CLI (`agent/core.py`, `llm/client.py`, `main.py`, `tools/terminal.py`)**:
   - Safe tool dispatching validating dictionary argument types.
   - Robust offline execution fallback (`OfflineMockProvider`) when LLM API keys are not configured.
   - Headless CLI flags (`--audit`, `--deps`, `--rollback`, `--report`, `--json`) and Rich interactive terminal REPL.
   - Platform-agnostic subprocess execution (`sys.executable`) with explicit UTF-8 decoding and timeout protection.
5. **Automated Verification Suite (`tests/`, `pytest`)**:
   - 4-Tier test suite covering features, boundaries, cross-language combinations, and real-world workloads.
   - 100% pytest pass rate on Windows and POSIX environments.
   - Adversarial Tier 5 coverage hardening.

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Platform-Agnostic Subprocess Invocation | Use `sys.executable` with quotation in subprocess timeout tests instead of hardcoded `python3` | M1 | ORIGINAL_REQUEST §R1 |
| 2 | Terminal Subprocess UTF-8 & Workspace Safety | Explicit UTF-8 decoding (`encoding="utf-8", errors="replace"`) and workspace directory auto-creation in `tools/terminal.py` | M1 | ORIGINAL_REQUEST §R1 |
| 3 | Strict Sandbox File Boundary Confinement | Enforce `relative_to(Config.WORKSPACE_DIR)` in `tools/file_ops.py:_resolve_safe_path` to block directory traversal escapes | M2 | ORIGINAL_REQUEST §R2 |
| 4 | Null-Byte & Malformed Input Exception Safety | Prevent unhandled `ValueError` crashes in `scanner.py`, `sca.py`, `file_ops.py` on null bytes, binary files, or missing directories | M2 | ORIGINAL_REQUEST §R2 |
| 5 | Atomic Patching & Byte-Verified Rollback | Atomic write (`tempfile` + `os.replace` + `os.fsync`), `.bak` suffix normalization, SHA-256 verification on rollback in `tools/patcher.py` | M2 | ORIGINAL_REQUEST §R2 |
| 6 | Agent & CLI Robustness & Keyless Fallback | Non-dict JSON validation in `agent/core.py`, `OfflineMockProvider` fallback in `llm/client.py`, and headless CLI flags in `main.py` | M2 | ORIGINAL_REQUEST §R2 |
| 7 | Suppression Engine Hardening & Evasion Immunity | Parse suppression directives exclusively from comments outside quotes; support `#nosec`, `//nosec`, `/* nosec */` with flexible whitespace | M3 | ORIGINAL_REQUEST §R3 |
| 8 | False-Positive Filtering & Disambiguation | Add FP filters for Go `exec.Command` and JS `child_process.spawn` array usages; disambiguate DB `exec(...)` from `SEC-DESER-005` | M3 | ORIGINAL_REQUEST §R3 |
| 9 | Polyglot SSRF Detection Rule | Implement `SEC-SSRF-007` covering Python (`requests`, `urllib`), JS (`axios`, `fetch`), Go (`http.Get`), PHP (`curl_exec`) | M3 | ORIGINAL_REQUEST §R3 |
| 10 | PHP File Inclusion Rule | Implement `SEC-LFI-008` covering PHP dynamic `include`, `require`, `include_once`, `require_once` | M3 | ORIGINAL_REQUEST §R3 |
| 11 | NoSQLi & Weak Cryptography Rules | Implement `SEC-NOSQLI-009` (NoSQLi), `SEC-CRYPTO-010` (Weak Crypto: MD5, SHA1, DES), and `SEC-XSS-011` (XSS) | M3 | ORIGINAL_REQUEST §R3 |
| 12 | Scanner Parsing & Regex Robustness | Handle nested parentheses `((...))`, multiline backslashes, keyword arguments (`query=`, `sql=`), and f-string variable interpolation | M3 | ORIGINAL_REQUEST §R3 |
| 13 | Automated Regression & Verification Tests | Comprehensive unit and integration test suite for all fixes and new rules; 100% pass on pytest across Windows & POSIX | M4 | ORIGINAL_REQUEST §R4 |
| 14 | Tier 5 Adversarial Coverage Hardening | White-box adversarial probing, stress tests, and mutation coverage verification | M4 | Project Pattern |

---

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Cross-Platform Test Reliability & Subprocess Hardening | Platform-agnostic `sys.executable` execution in tests and UTF-8 / workspace safety in `tools/terminal.py` | none | IN_PROGRESS |
| M2 | Codebase Self-Audit & Security Hardening | Sandbox path traversal confinement, atomic patching, rollback fix, null-byte safety, agent validation, offline CLI fallback | M1 | PLANNED |
| M3 | Polyglot SAST Rule Expansion & Suppression Engine | Suppression evasion fix, FP filters for Go/JS, new OWASP rules (SSRF, LFI, NoSQLi, Crypto, XSS), parsing robustness | M1 | PLANNED |
| M4 | Final Milestone: 100% E2E Test Suite Pass & Adversarial Hardening | Phase 1: Pass 100% of E2E tests (Tiers 1-4). Phase 2: Tier 5 adversarial coverage hardening | M1, M2, M3, E2E-Testing-Track | PLANNED |

---

## Interface Contracts

### Subprocess & Terminal Execution (`tools/terminal.py`)
- `execute_command(command: str, timeout: int = 30) -> tuple[int, str, str]`
  - Returns `(returncode, stdout, stderr)`.
  - On timeout: return `(-2, "", "Error: Command timed out...")`.
  - On execution error: return `(-3, "", "Execution error: ...")`.
  - Encoding: explicit UTF-8 with `errors="replace"`.
  - Workspace: auto-creates `Config.WORKSPACE_DIR` if missing.

### File Operations & Sandbox Confinement (`tools/file_ops.py`)
- `_resolve_safe_path(filepath: str | Path) -> Path`
  - Rejects null bytes (`\x00`) with `ValueError` caught and handled cleanly.
  - Resolves path and strictly validates `resolved.relative_to(Config.WORKSPACE_DIR.resolve())`.
  - Raises `PermissionError` if path escapes workspace sandbox.
- `read_file(filepath: str | Path) -> str`
- `write_file(filepath: str | Path, content: str) -> bool`
- `append_file(filepath: str | Path, content: str) -> bool`
- `list_directory(dirpath: str | Path = ".") -> list[str]`

### Atomic Patching & Rollback (`tools/patcher.py`)
- `apply_patch(filepath: str | Path, patched_content: str, auto_approve: bool = False) -> tuple[bool, str]`
  - Atomic write via temporary file, `os.replace`, and `os.fsync`.
  - Automatic `.bak` creation with SHA-256 hash tracking.
- `rollback_backup(filepath_or_backup: str | Path) -> tuple[bool, str]`
  - Accepts either original path or `.bak` path (strips `.bak` properly).
  - Verifies restored file SHA-256 against pre-patch hash.
- `rollback(filepath_or_backup: str | Path) -> tuple[bool, str]` (alias)
- `list_backups(directory: str | Path = ".") -> list[tuple[Path, Path]]`

### Polyglot SAST Scanner (`tools/scanner.py`)
- `scan_file(filepath: str | Path) -> list[VulnerabilityFinding]`
  - Gracefully handles null bytes and missing/binary files (returns `[]` without unhandled exceptions).
- `scan_directory(dirpath: str | Path, recursive: bool = True) -> list[VulnerabilityFinding]`
  - Returns `[]` if directory does not exist or has null bytes.
- `is_suppressed_by_directive(line_str: str, file_content: str | None = None, line_num: int = 1) -> bool`
  - Checks suppression comments outside string literals.
  - Supports `#nosec`, `//nosec`, `/* nosec */`, and `# bethacker:ignore`.
- Rules catalog:
  - `SEC-SQLI-001`, `SEC-CMDI-002`, `SEC-TRAV-003`, `SEC-SECR-004`, `SEC-DESER-005`, `SEC-MISC-006`
  - `SEC-SSRF-007` (SSRF), `SEC-LFI-008` (PHP LFI), `SEC-NOSQLI-009` (NoSQLi), `SEC-CRYPTO-010` (Weak Crypto), `SEC-XSS-011` (XSS)

### SCA Engine (`tools/sca.py`)
- `scan_dependencies(manifest_path: str | Path) -> list[DependencyFinding]`
  - Rejects null bytes and binary content gracefully.
- `scan_all_manifests(dirpath: str | Path = ".") -> list[DependencyFinding]`

### LLM Client & Offline Fallback (`llm/client.py`)
- `get_llm_client(provider_name: str | None = None) -> BaseLLMProvider`
  - If API key is missing or invalid, falls back to `OfflineMockProvider` instead of raising unhandled `ValueError` or exiting.

### Agent & CLI (`agent/core.py`, `main.py`)
- `BetAkerAgent.dispatch_tool(tool_name: str, args: dict) -> tuple[str, bool]`
  - Validates `isinstance(args, dict)` to prevent uncaught `AttributeError`.
- `main.py`:
  - Headless flags: `--audit [path]`, `--deps [path]`, `--rollback [path]`, `--report [format] [out]`, `--json`.
  - Decoupled from online LLM requirement for offline auditing commands.

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
- `tools/file_ops.py` — Safe file I/O utilities and sandbox containment
- `tools/terminal.py` — Platform-agnostic command execution and guardrails
- `agent/core.py` — Auditor orchestration agent coordinating scan -> analyze -> patch -> verify
- `agent/prompts.py` — Defensive security auditor prompts and JSON schema
- `llm/client.py` — Multi-provider factory and client interface
- `llm/providers.py` — Concrete providers (DeepSeek, Gemini, OpenAI, OfflineMockProvider)
- `tests/` — Comprehensive test suite
  - `conftest.py` — Fixtures and vulnerable/safe code samples
  - `test_tier1_features.py` — Core feature tests
  - `test_tier2_boundaries.py` — Edge case and boundary tests
  - `test_tier5_adversarial_sast.py` — Adversarial SAST probes
  - `test_tier5_adversarial_sca.py` — Adversarial SCA probes
  - `test_sca_stress.py` — Dependency stress tests
