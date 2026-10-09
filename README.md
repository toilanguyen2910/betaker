# 🛡️ BetAker

> **AI-Powered Security Code Auditor & Automated Patching CLI Tool**  
> An autonomous command-line security assistant for static code vulnerability analysis (SAST), dependency security auditing (SCA), root-cause analysis, and verified safe patch generation.

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests Passing](https://img.shields.io/badge/tests-221%20passed-brightgreen.svg)]()
[![Security: OWASP Top 10](https://img.shields.io/badge/security-OWASP%20Top%2010-red.svg)](https://owasp.org/www-project-top-ten/)

---

## 🌟 Key Features

* 🔍 **Polyglot SAST Engine (Zero External Dependencies)**
  * Scans source code across **Python, JavaScript/TypeScript, Go, and PHP** for **OWASP Top 10** vulnerabilities:
    * **SQL Injection (SQLi)**: Parameter concatenation, raw f-strings, unescaped string formatting.
    * **Command Injection (CMDi)**: Shell executions (`subprocess(shell=True)`, `os.system`, `child_process.exec`, `exec.Command("sh", "-c")`, `passthru`).
    * **Path Traversal / LFI**: Unsanitized user inputs passed to file reading/opening routines.
    * **Insecure Deserialization**: `pickle.loads`, `yaml.load(Loader=Loader)`, `unserialize($_POST)`.
    * **Hardcoded Secrets & API Keys**: High-entropy token detection, AWS keys, JWT tokens, private keys, API secrets with test-token exclusion.
    * **Server-Side Request Forgery (SSRF) & Cross-Site Scripting (XSS)**.
* 📦 **Offline Software Composition Analysis (SCA)**
  * Audits dependency manifest files (`requirements.txt`, `package.json`) against an embedded curated CVE advisory database.
  * Robust SemVer & PEP 440 version specifier engine handling complex ranges (`^`, `~`, `~=`, wildcards, prerelease tags).
* 🤖 **Multi-Provider AI Root Cause Analysis & Auto-Patcher**
  * Pluggable LLM backends: **DeepSeek** (`deepseek-chat`), **Google Gemini** (`gemini-2.5-flash`), **OpenAI** (`gpt-4o`), and **OpenRouter**.
  * Performs deep technical root-cause analysis and outputs clean, production-ready replacement code preserving existing business logic.
* 🛡️ **Safe Patching & Rollback Architecture**
  * Displays interactive **Unified Diffs** before writing changes.
  * Automatically creates timestamped `.bak` backups before modifying files.
  * Instant `/rollback <filepath>` command to revert files to original pristine state.
* 💻 **Interactive Rich Terminal CLI**
  * Color-coded severity indicators (**CRITICAL**, **HIGH**, **MEDIUM**, **LOW**).
  * Built-in command suite: `/audit`, `/deps`, `/rollback`, `/report`, `/files`, `/clear`, `/help`, `/exit`.
* ✅ **Comprehensive Automated Verification**
  * **221 automated tests** covering end-to-end flows, adversarial edge cases, syntax boundary probes, and sandbox containment.

---

## 🏗️ System Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                       BetAker CLI                           │
│     (Rich Terminal Interface & Interactive Command Loop)    │
└──────────────┬───────────────────────────────┬──────────────┘
               │                               │
       /audit  │                               │ /deps
               ▼                               ▼
  ┌─────────────────────────┐     ┌─────────────────────────┐
  │   Polyglot SAST Engine  │     │    Offline SCA Engine   │
  │ (Python, JS/TS, Go, PHP)│     │(requirements, pkg.json) │
  └────────────┬────────────┘     └────────────┬────────────┘
               │                               │
               └───────────────┬───────────────┘
                               │ Vulnerability Findings
                               ▼
  ┌─────────────────────────────────────────────────────────┐
  │            BetAker AI Agent (ReAct Loop)                │
  │   - Multi-Provider Adapter: DeepSeek, Gemini, OpenAI    │
  │   - Root Cause Analysis & Secure Patch Synthesis        │
  └────────────────────────────┬────────────────────────────┘
                               │ Generated Patch
                               ▼
  ┌─────────────────────────────────────────────────────────┐
  │                 Safe Patch Engine                       │
  │   - Unified Diff Generator                              │
  │   - .bak Backup Creator & /rollback Recovery            │
  └─────────────────────────────────────────────────────────┘
```

---

## 🚀 Quickstart & Installation

### 1. Prerequisites
* Python 3.10 or higher
* Git

### 2. Clone Repository
```bash
git clone https://github.com/toilanguyen2910/betaker.git
cd betaker
```

### 3. Setup Virtual Environment & Install Dependencies
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Linux/macOS:
source .venv/bin/activate
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Install required packages
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Copy `.env.example` to `.env` and configure your preferred LLM provider:

```bash
cp .env.example .env
```

Edit `.env`:
```env
# Choose provider: deepseek, gemini, openai, or openrouter
LLM_PROVIDER=deepseek
LLM_MODEL=deepseek-chat
DEEPSEEK_API_KEY=your_deepseek_api_key_here

# Security Settings
REQUIRE_APPROVAL=true
COMMAND_TIMEOUT_SECONDS=60
WORKSPACE_DIR=./workspace
```

### 5. Launch BetAker
```bash
python main.py
```

---

## 📖 CLI Command Reference

| Command | Description |
|---|---|
| `/audit <file_or_dir>` | Perform static security audit (SAST) on a file or entire directory |
| `/deps` | Scan dependency manifests (`requirements.txt`, `package.json`) for known CVEs |
| `/rollback <filepath>` | Revert file to original state using its `.bak` backup |
| `/report` | Export a Markdown security audit report to the workspace |
| `/files` | List all files tracked in the workspace sandbox |
| `/clear` | Clear conversation context and reset session memory |
| `/help` | Display command reference and system guide |
| `/exit` | Gracefully quit the application |

You can also type any security query or paste code directly into the prompt to request AI explanations and automated patches.

---

## 🧪 Running the Test Suite

BetAker comes with an automated test suite verifying SAST accuracy, SCA range evaluation, patch application, and edge cases:

```bash
python -m pytest tests/ -v
```

All **221 tests** execute in seconds without external network dependencies.

---

## 👥 Authors & Credits

* **Author:** [jack.vhknguyen@gmail.com](mailto:jack.vhknguyen@gmail.com)
* **GitHub:** [@toilanguyen2910](https://github.com/toilanguyen2910)
* **Repository:** [https://github.com/toilanguyen2910/betaker](https://github.com/toilanguyen2910/betaker)

Contributions, bug reports, and feature requests are welcome!

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
