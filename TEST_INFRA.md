# E2E Test Infra: BetHacker

## Test Philosophy
- **Opaque-box & Requirement-driven**: Derived directly from `ORIGINAL_REQUEST.md` and user-facing CLI/API contracts, independent of internal implementation details.
- **Methodology**: Systematic 4-Tier test hierarchy:
  - Tier 1: Feature Coverage (Category-Partition Testing, >=5 test cases per feature).
  - Tier 2: Boundary & Corner Cases (Boundary Value Analysis, extremes, malformed inputs, unicode, CRLF, dotfiles).
  - Tier 3: Cross-Feature Combinations (Pairwise integration of scan -> patch -> backup -> verify -> rollback -> re-verify).
  - Tier 4: Real-World Application Scenarios (Multi-file projects across Python, JS/TS, Go, PHP with vulnerable vs safe code).
  - Tier 5: Adversarial Coverage Hardening (White-box edge cases and mutation testing).

---

## Feature Inventory
| # | Feature | Source (requirement) | Tier 1 | Tier 2 | Tier 3 |
|---|---------|---------------------|:------:|:------:|:------:|
| 1 | SAST Polyglot Rules (Py, JS/TS, Go, PHP) | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ |
| 2 | False Positive Reduction (Safe Code) | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ |
| 3 | Dependency Manifest SCA (reqs.txt, package.json) | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ |
| 4 | Multi-Provider LLM Integration | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ |
| 5 | Offline Mock LLM Provider | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ |
| 6 | Root Cause Analysis & Severity Rating | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ |
| 7 | Git-Compatible Unified Diff Generation | ORIGINAL_REQUEST §R3 | 5 | 5 | ✓ |
| 8 | Safe Atomic Patching & .bak Backup | ORIGINAL_REQUEST §R3 | 5 | 5 | ✓ |
| 9 | Byte-Verified Rollback Restoration | ORIGINAL_REQUEST §R3 | 5 | 5 | ✓ |
| 10 | Interactive Rich Terminal CLI & REPL | ORIGINAL_REQUEST §R4 | 5 | 5 | ✓ |
| 11 | CLI Commands (/audit, /deps, /rollback, /report) | ORIGINAL_REQUEST §R4 | 5 | 5 | ✓ |
| 12 | Headless Flags & Automation Support | ORIGINAL_REQUEST §R4 | 5 | 5 | ✓ |

---

## Test Architecture
- **Runner**: `python3 -m pytest tests/ -v`
- **Pass/Fail Semantics**: All test suites must execute with 0 failures, 0 errors, 100% pass rate.
- **Execution Environment**:
  - Deterministic & offline (no external network or live LLM API calls needed; uses `OfflineMockProvider` or mocked HTTP).
  - Isolated test directory execution using pytest's `tmp_path`.
  - Non-interactive execution using `--auto-approve` / `auto_approve=True`.
- **Directory Layout**:
  - `tests/`
    - `conftest.py` — Shared fixtures, temporary project generators, vulnerable/safe polyglot snippets
    - `test_tier1_features.py` — Tier 1 unit and feature tests across SAST, SCA, diff, patch, rollback, CLI
    - `test_tier2_boundaries.py` — Tier 2 edge cases, empty files, dotfiles, CRLF, corrupt backups, malformed JSON
    - `test_tier3_combinations.py` — Tier 3 cross-feature workflows (Scan -> Patch -> Rollback lifecycle)
    - `test_tier4_scenarios.py` — Tier 4 realistic multi-language application workloads (Flask, Express, Go REST, PHP app)

---

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | Python Flask Web Application with SQLi, Command Injection, and outdated requirements.txt | SAST, SCA, Diff, Patch, Backup, Rollback | High |
| 2 | Node.js Express API with Path Traversal, Hardcoded JWT secret, and vulnerable package.json | SAST, SCA, Diff, Patch, Backup, Rollback | High |
| 3 | Go Microservice with Command Injection (`exec.Command`) and SQL Injection (`fmt.Sprintf`) | SAST, Diff, Patch, Backup, Rollback | Medium |
| 4 | PHP E-commerce Script with SQLi (`$db->query`), Command Injection (`system`), and Insecure Deserialization (`unserialize`) | SAST, Diff, Patch, Backup, Rollback | High |
| 5 | Polyglot Monorepo with Safe Patterns verifying zero false positives | SAST Polyglot, False Positive Filtering | Medium |

---

## Coverage Thresholds
- Tier 1: >=60 test cases across 12 features
- Tier 2: >=60 test cases across boundaries and edge cases
- Tier 3: >=12 cross-feature integration test cases
- Tier 4: >=5 comprehensive real-world application test cases
- **Total Minimum Test Count: >=137 test cases** with 100% pass rate
