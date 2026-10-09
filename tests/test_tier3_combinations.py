"""Tier 3: Cross-Feature Integration Test Suite.

Exercises end-to-end multi-step workflows (scan -> diff -> patch -> backup -> rollback -> re-verify)
across all supported languages (Python, JavaScript/TypeScript, Go, PHP) and subsystems (SAST, SCA, Diff, Patcher, Agent).
Derives test assertions strictly from user requirements and interface contracts.
"""

import json
from pathlib import Path
import pytest

from config import Config
from tools.scanner import (
    scan_file,
    scan_directory,
    scan_all,
    VulnerabilityFinding,
)
from tools.sca import (
    scan_dependencies,
    DependencyFinding,
)
from tools.patcher import (
    create_backup,
    rollback_backup,
    generate_diff,
    apply_patch,
)
from tools.file_ops import (
    read_file,
    write_file,
    append_file,
    list_workspace_files,
)
from agent.core import BetHackerAgent


# ==============================================================================
# 1. PYTHON END-TO-END WORKFLOWS
# ==============================================================================

class TestTier3PythonLifecycle:
    """End-to-end lifecycle verification for Python security vulnerabilities."""

    def test_tier3_python_sqli_patch_and_rollback_lifecycle(self, tmp_path):
        """Workflow: Detect SQLi -> Unified Diff -> Atomic Patch & .bak -> Verify Clean -> Rollback -> Re-verify."""
        target = tmp_path / "user_dao.py"
        vulnerable_code = (
            "import sqlite3\n\n"
            "def get_user_by_id(cursor, user_id):\n"
            '    cursor.execute(f"SELECT * FROM accounts WHERE id = {user_id}")\n'
            "    return cursor.fetchone()\n"
        )
        target.write_text(vulnerable_code, encoding="utf-8")

        # Step 1: Scan detects vulnerability
        findings = scan_file(target)
        assert len(findings) == 1
        assert findings[0]["vuln_id"] == "SEC-SQLI-001"
        assert findings[0]["severity"] == "CRITICAL"

        # Step 2: Generate unified diff
        patched_code = (
            "import sqlite3\n\n"
            "def get_user_by_id(cursor, user_id):\n"
            '    cursor.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))\n'
            "    return cursor.fetchone()\n"
        )
        diff = generate_diff(vulnerable_code, patched_code, target.name)
        assert "-    cursor.execute(f\"SELECT * FROM accounts WHERE id = {user_id}\")" in diff
        assert "+    cursor.execute(\"SELECT * FROM accounts WHERE id = %s\", (user_id,))" in diff

        # Step 3: Apply patch atomically with backup
        success, msg, applied_diff = apply_patch(str(target), patched_code)
        assert success is True
        assert "Đã vá thành công" in msg
        bak_file = target.with_suffix(".py.bak")
        assert bak_file.exists()
        assert bak_file.read_text(encoding="utf-8") == vulnerable_code
        assert target.read_text(encoding="utf-8") == patched_code

        # Step 4: Verify patched file is clean
        post_patch_findings = scan_file(target)
        assert len(post_patch_findings) == 0

        # Step 5: Rollback from backup
        rb_success, rb_msg = rollback_backup(target)
        assert rb_success is True
        assert "Đã khôi phục thành công" in rb_msg
        assert target.read_text(encoding="utf-8") == vulnerable_code

        # Step 6: Re-verify vulnerability restored
        re_findings = scan_file(target)
        assert len(re_findings) == 1
        assert re_findings[0]["vuln_id"] == "SEC-SQLI-001"

    def test_tier3_python_cmdi_patch_and_rollback_lifecycle(self, tmp_path):
        """Workflow: Detect CMDi -> Unified Diff -> Patch to safe subprocess list -> Verify Clean -> Rollback."""
        target = tmp_path / "diagnostics.py"
        vulnerable_code = (
            "import os\n\n"
            "def ping_host(host):\n"
            '    os.system(f"ping -c 1 {host}")\n'
        )
        target.write_text(vulnerable_code, encoding="utf-8")

        # Step 1: Detect CMDi
        findings = scan_file(target)
        assert len(findings) == 1
        assert findings[0]["vuln_id"] == "SEC-CMDI-002"
        assert findings[0]["severity"] == "CRITICAL"

        # Step 2: Patch to parameterized list invocation
        patched_code = (
            "import subprocess\n\n"
            "def ping_host(host):\n"
            '    subprocess.run(["ping", "-c", "1", host], check=True)\n'
        )
        success, msg, diff = apply_patch(str(target), patched_code)
        assert success is True
        assert target.with_suffix(".py.bak").exists()

        # Step 3: Verify clean (subprocess list without shell=True should not trigger CMDi)
        clean_findings = scan_file(target)
        assert len(clean_findings) == 0

        # Step 4: Rollback & Re-verify
        rollback_backup(target)
        assert scan_file(target)[0]["vuln_id"] == "SEC-CMDI-002"

    def test_tier3_python_path_traversal_patch_and_rollback_lifecycle(self, tmp_path):
        """Workflow: Detect Path Traversal -> Patch to safe static open -> Verify Clean -> Rollback."""
        target = tmp_path / "file_viewer.py"
        vulnerable_code = (
            "from flask import request\n\n"
            "def read_user_doc():\n"
            '    with open(request.args.get("file"), "r") as f:\n'
            "        return f.read()\n"
        )
        target.write_text(vulnerable_code, encoding="utf-8")

        # Step 1: Scan
        findings = scan_file(target)
        assert len(findings) == 1
        assert findings[0]["vuln_id"] == "SEC-TRAV-003"
        assert findings[0]["severity"] == "HIGH"

        # Step 2: Patch with safe static path and validation
        patched_code = (
            "from pathlib import Path\n\n"
            "def read_user_doc():\n"
            '    with open("safe_static_file.txt", "r") as f:\n'
            "        return f.read()\n"
        )
        apply_patch(str(target), patched_code)

        # Step 3: Verify clean
        assert len(scan_file(target)) == 0

        # Step 4: Rollback
        rollback_backup(target)
        assert scan_file(target)[0]["vuln_id"] == "SEC-TRAV-003"

    def test_tier3_python_secrets_and_debug_lifecycle(self, tmp_path):
        """Workflow: Detect Secrets & Debug -> Multi-vulnerability remediation -> Verify -> Rollback."""
        target = tmp_path / "config.py"
        vulnerable_code = (
            'api_key = "AIzaSyD-1234567890abcdef"\n'
            'secret_key = "super_secret_jwt_token_12345678"\n'
            "DEBUG = True\n"
        )
        target.write_text(vulnerable_code, encoding="utf-8")

        # Step 1: Scan finds secrets and debug
        findings = scan_file(target)
        vuln_ids = {f["vuln_id"] for f in findings}
        assert "SEC-SECR-004" in vuln_ids
        assert "SEC-MISC-006" in vuln_ids

        # Step 2: Patch to env vars and DEBUG=False
        patched_code = (
            'import os\n\n'
            'api_key = os.getenv("API_KEY")\n'
            'secret_key = os.getenv("SECRET_KEY")\n'
            "DEBUG = False\n"
        )
        apply_patch(str(target), patched_code)

        # Step 3: Verify completely clean
        assert len(scan_file(target)) == 0

        # Step 4: Rollback restores both
        rollback_backup(target)
        restored_ids = {f["vuln_id"] for f in scan_file(target)}
        assert "SEC-SECR-004" in restored_ids
        assert "SEC-MISC-006" in restored_ids

    def test_tier3_python_insecure_deserialization_lifecycle(self, tmp_path):
        """Workflow: Detect pickle/eval Deserialization -> Patch with json.loads -> Verify -> Rollback."""
        target = tmp_path / "cache_loader.py"
        vulnerable_code = (
            "import pickle\n\n"
            "def load_cached_session(raw_data):\n"
            "    user_obj = pickle.loads(raw_data)\n"
            "    return user_obj\n"
        )
        target.write_text(vulnerable_code, encoding="utf-8")

        # Step 1: Detect
        findings = scan_file(target)
        assert len(findings) == 1
        assert findings[0]["vuln_id"] == "SEC-DESER-005"

        # Step 2: Patch to json.loads
        patched_code = (
            "import json\n\n"
            "def load_cached_session(raw_data):\n"
            "    user_obj = json.loads(raw_data)\n"
            "    return user_obj\n"
        )
        apply_patch(str(target), patched_code)

        # Step 3: Verify clean
        assert len(scan_file(target)) == 0

        # Step 4: Rollback
        rollback_backup(target)
        assert scan_file(target)[0]["vuln_id"] == "SEC-DESER-005"


# ==============================================================================
# 2. JAVASCRIPT / TYPESCRIPT END-TO-END WORKFLOWS
# ==============================================================================

class TestTier3JavaScriptLifecycle:
    """End-to-end lifecycle verification for JavaScript/TypeScript vulnerabilities."""

    def test_tier3_javascript_sqli_patch_and_rollback_lifecycle(self, tmp_path):
        """Workflow: Detect JS string concatenation SQLi -> Patch with parameterized query -> Verify -> Rollback."""
        target = tmp_path / "userService.js"
        vulnerable_code = (
            "const db = require('./db');\n\n"
            "function getUser(userId) {\n"
            '    return db.query("SELECT * FROM users WHERE id = " + userId + ";");\n'
            "}\n"
        )
        target.write_text(vulnerable_code, encoding="utf-8")

        # Step 1: Scan
        findings = scan_file(target)
        assert len(findings) >= 1
        assert all(f["vuln_id"] == "SEC-SQLI-001" for f in findings)

        # Step 2: Patch to parameterized query
        patched_code = (
            "const db = require('./db');\n\n"
            "function getUser(userId) {\n"
            '    return db.query("SELECT * FROM users WHERE id = $1", [userId]);\n'
            "}\n"
        )
        apply_patch(str(target), patched_code)

        # Step 3: Verify clean
        assert len(scan_file(target)) == 0

        # Step 4: Rollback
        rollback_backup(target)
        re_findings = scan_file(target)
        assert len(re_findings) >= 1
        assert all(f["vuln_id"] == "SEC-SQLI-001" for f in re_findings)

    def test_tier3_javascript_eval_patch_and_rollback_lifecycle(self, tmp_path):
        """Workflow: Detect JS eval execution -> Patch to JSON.parse -> Verify -> Rollback."""
        target = tmp_path / "parser.js"
        vulnerable_code = (
            "function parsePayload(userInput) {\n"
            '    return eval("processData(" + userInput + ")");\n'
            "}\n"
        )
        target.write_text(vulnerable_code, encoding="utf-8")

        # Step 1: Detect eval
        findings = scan_file(target)
        assert len(findings) >= 1
        assert all(f["vuln_id"] == "SEC-DESER-005" for f in findings)

        # Step 2: Patch with JSON.parse
        patched_code = (
            "function parsePayload(userInput) {\n"
            "    const data = JSON.parse(userInput);\n"
            "    return data;\n"
            "}\n"
        )
        apply_patch(str(target), patched_code)

        # Step 3: Verify clean
        assert len(scan_file(target)) == 0

        # Step 4: Rollback
        rollback_backup(target)
        re_findings = scan_file(target)
        assert len(re_findings) >= 1
        assert all(f["vuln_id"] == "SEC-DESER-005" for f in re_findings)

    def test_tier3_javascript_secret_and_suppression_lifecycle(self, tmp_path):
        """Workflow: Detect JS secret -> Patch via inline // nosec suppression directive -> Verify -> Rollback."""
        target = tmp_path / "jwtConfig.js"
        vulnerable_code = (
            'const secret_key = "super_secret_jwt_token_12345678";\n'
            "module.exports = { secret_key };\n"
        )
        target.write_text(vulnerable_code, encoding="utf-8")

        # Step 1: Detect secret
        findings = scan_file(target)
        assert len(findings) == 1
        assert findings[0]["vuln_id"] == "SEC-SECR-004"

        # Step 2: Apply suppression comment // nosec
        suppressed_code = (
            'const secret_key = "super_secret_jwt_token_12345678"; // nosec\n'
            "module.exports = { secret_key };\n"
        )
        apply_patch(str(target), suppressed_code)

        # Step 3: Verify suppression engine ignores line
        assert len(scan_file(target)) == 0

        # Step 4: Rollback restores detection
        rollback_backup(target)
        assert scan_file(target)[0]["vuln_id"] == "SEC-SECR-004"


# ==============================================================================
# 3. GO END-TO-END WORKFLOWS
# ==============================================================================

class TestTier3GoLifecycle:
    """End-to-end lifecycle verification for Go vulnerabilities."""

    def test_tier3_go_sqli_patch_and_rollback_lifecycle(self, tmp_path):
        """Workflow: Detect Go raw SQL concatenation -> Patch with parameterized db.Query -> Verify -> Rollback."""
        target = tmp_path / "repository.go"
        vulnerable_code = (
            "package repository\n\n"
            "func GetRecord(recordKey string) {\n"
            '    raw("SELECT * FROM records WHERE key = " + recordKey + "")\n'
            "}\n"
        )
        target.write_text(vulnerable_code, encoding="utf-8")

        # Step 1: Detect Go SQLi
        findings = scan_file(target)
        assert len(findings) >= 1
        assert all(f["vuln_id"] == "SEC-SQLI-001" for f in findings)

        # Step 2: Patch to parameterized query
        patched_code = (
            "package repository\n\n"
            "func GetRecord(recordKey string) {\n"
            '    db.Query("SELECT * FROM records WHERE key = ?", recordKey)\n'
            "}\n"
        )
        apply_patch(str(target), patched_code)

        # Step 3: Verify clean
        assert len(scan_file(target)) == 0

        # Step 4: Rollback
        rollback_backup(target)
        re_findings = scan_file(target)
        assert len(re_findings) >= 1
        assert all(f["vuln_id"] == "SEC-SQLI-001" for f in re_findings)

    def test_tier3_go_secret_patch_and_rollback_lifecycle(self, tmp_path):
        """Workflow: Detect Go hardcoded API Key -> Patch with os.Getenv -> Verify -> Rollback."""
        target = tmp_path / "credentials.go"
        vulnerable_code = (
            "package config\n\n"
            'var api_key = "AIzaSyD-1234567890abcdef"\n'
        )
        target.write_text(vulnerable_code, encoding="utf-8")

        # Step 1: Detect secret
        findings = scan_file(target)
        assert len(findings) == 1
        assert findings[0]["vuln_id"] == "SEC-SECR-004"

        # Step 2: Patch to os.Getenv
        patched_code = (
            "package config\n"
            'import "os"\n\n'
            'var apiKey = os.Getenv("API_KEY")\n'
        )
        apply_patch(str(target), patched_code)

        # Step 3: Verify clean
        assert len(scan_file(target)) == 0

        # Step 4: Rollback
        rollback_backup(target)
        assert scan_file(target)[0]["vuln_id"] == "SEC-SECR-004"


# ==============================================================================
# 4. PHP END-TO-END WORKFLOWS
# ==============================================================================

class TestTier3PHPLifecycle:
    """End-to-end lifecycle verification for PHP vulnerabilities."""

    def test_tier3_php_sqli_patch_and_rollback_lifecycle(self, tmp_path):
        """Workflow: Detect PHP query concatenation -> Patch to PDO prepare -> Verify -> Rollback."""
        target = tmp_path / "orders.php"
        vulnerable_code = (
            "<?php\n"
            "function getOrders($userId) {\n"
            '    global $db;\n'
            '    return db.query("SELECT * FROM users WHERE id = " + $userId + ";");\n'
            "}\n"
        )
        target.write_text(vulnerable_code, encoding="utf-8")

        # Step 1: Detect SQLi
        findings = scan_file(target)
        assert len(findings) == 1
        assert findings[0]["vuln_id"] == "SEC-SQLI-001"

        # Step 2: Patch to PDO prepared statement
        patched_code = (
            "<?php\n"
            "function getOrders($userId) {\n"
            '    global $pdo;\n'
            '    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");\n'
            '    $stmt->execute([":id" => $userId]);\n'
            "    return $stmt->fetchAll();\n"
            "}\n"
        )
        apply_patch(str(target), patched_code)

        # Step 3: Verify clean
        assert len(scan_file(target)) == 0

        # Step 4: Rollback
        rollback_backup(target)
        assert scan_file(target)[0]["vuln_id"] == "SEC-SQLI-001"

    def test_tier3_php_deserialization_patch_and_rollback_lifecycle(self, tmp_path):
        """Workflow: Detect PHP eval/unserialize -> Patch to safe json_decode -> Verify -> Rollback."""
        target = tmp_path / "webhook.php"
        vulnerable_code = (
            "<?php\n"
            "function handleWebhook($untrusted_code) {\n"
            "    eval($untrusted_code);\n"
            "}\n"
        )
        target.write_text(vulnerable_code, encoding="utf-8")

        # Step 1: Detect eval
        findings = scan_file(target)
        assert len(findings) >= 1
        assert all(f["vuln_id"] == "SEC-DESER-005" for f in findings)

        # Step 2: Patch to json_decode
        patched_code = (
            "<?php\n"
            "function handleWebhook($untrusted_code) {\n"
            "    $data = json_decode($untrusted_code, true);\n"
            "    return $data;\n"
            "}\n"
        )
        apply_patch(str(target), patched_code)

        # Step 3: Verify clean
        assert len(scan_file(target)) == 0

        # Step 4: Rollback
        rollback_backup(target)
        re_findings = scan_file(target)
        assert len(re_findings) >= 1
        assert all(f["vuln_id"] == "SEC-DESER-005" for f in re_findings)


# ==============================================================================
# 5. CROSS-FEATURE DIRECTORY BATCH & COMBINED LIFECYCLES
# ==============================================================================

class TestTier3CrossFeatureDirectoryAndManifestLifecycle:
    """Complex multi-file, polyglot, and combined SAST+SCA workflows."""

    def test_tier3_polyglot_multitarget_directory_batch_lifecycle(self, tmp_path):
        """Workflow: Batch directory containing Python, JS, Go, and PHP -> Detect all -> Patch all -> Rollback all."""
        # Create multi-language repository structure
        py_file = tmp_path / "app.py"
        js_file = tmp_path / "client.js"
        go_file = tmp_path / "server.go"
        php_file = tmp_path / "portal.php"

        py_file.write_text('os.system(f"ping {host}")\n', encoding="utf-8")
        js_file.write_text('db.query("SELECT * FROM users WHERE id = " + userId + ";");\n', encoding="utf-8")
        go_file.write_text('private_key = "pk_live_12345678901234567890"\n', encoding="utf-8")
        php_file.write_text('eval($untrusted_code);\n', encoding="utf-8")

        # Step 1: Scan entire directory
        dir_findings = scan_directory(tmp_path)
        detected_rule_ids = {f["vuln_id"] for f in dir_findings if isinstance(f, VulnerabilityFinding)}
        assert "SEC-CMDI-002" in detected_rule_ids
        assert "SEC-SQLI-001" in detected_rule_ids
        assert "SEC-SECR-004" in detected_rule_ids
        assert "SEC-DESER-005" in detected_rule_ids
        assert len(detected_rule_ids) == 4

        # Step 2: Patch each file
        apply_patch(str(py_file), 'subprocess.run(["ping", host])\n')
        apply_patch(str(js_file), 'db.query("SELECT * FROM users WHERE id = $1", [userId]);\n')
        apply_patch(str(go_file), 'private_key := os.Getenv("PRIVATE_KEY")\n')
        apply_patch(str(php_file), '$data = json_decode($payload, true);\n')

        # Step 3: Scan directory after all patches
        clean_dir_findings = [f for f in scan_directory(tmp_path) if isinstance(f, VulnerabilityFinding)]
        assert len(clean_dir_findings) == 0

        # Step 4: Rollback all files
        for f in (py_file, js_file, go_file, php_file):
            success, _ = rollback_backup(f)
            assert success is True

        # Step 5: Directory scan after rollback detects all 4 flaws again
        restored_findings = [f for f in scan_directory(tmp_path) if isinstance(f, VulnerabilityFinding)]
        restored_rule_ids = {f["vuln_id"] for f in restored_findings}
        assert len(restored_rule_ids) == 4
        assert {"SEC-CMDI-002", "SEC-SQLI-001", "SEC-SECR-004", "SEC-DESER-005"}.issubset(restored_rule_ids)

    def test_tier3_combined_sast_and_sca_project_lifecycle(self, tmp_path):
        """Workflow: Project root with code vulnerability and vulnerable manifest -> scan_all -> patch both -> rollback both."""
        code_file = tmp_path / "main.py"
        manifest_file = tmp_path / "requirements.txt"

        code_file.write_text('cursor.execute(f"SELECT * FROM accounts WHERE id = {uid}")\n', encoding="utf-8")
        manifest_file.write_text('requests==2.25.0\nflask==1.0.1\n', encoding="utf-8")

        # Step 1: scan_all evaluates both SAST and SCA
        sast_findings, sca_findings = scan_all(tmp_path)
        assert len(sast_findings) >= 1
        assert sast_findings[0]["vuln_id"] == "SEC-SQLI-001"

        assert len(sca_findings) >= 2
        vuln_pkgs = {f["package"] for f in sca_findings}
        assert "requests" in vuln_pkgs
        assert "flask" in vuln_pkgs

        # Step 2: Patch both code and manifest
        patched_code = 'cursor.execute("SELECT * FROM accounts WHERE id = %s", (uid,))\n'
        patched_manifest = 'requests==2.31.0\nflask==3.0.0\n'

        apply_patch(str(code_file), patched_code)
        apply_patch(str(manifest_file), patched_manifest)

        # Step 3: scan_all reports zero findings across both SAST & SCA
        clean_sast, clean_sca = scan_all(tmp_path)
        assert len(clean_sast) == 0
        assert len(clean_sca) == 0

        # Step 4: Rollback both files
        rb_code_success, _ = rollback_backup(code_file)
        rb_manifest_success, _ = rollback_backup(manifest_file)
        assert rb_code_success is True
        assert rb_manifest_success is True

        # Step 5: Re-verify both findings return
        re_sast, re_sca = scan_all(tmp_path)
        assert len(re_sast) >= 1
        assert len(re_sca) >= 2

    def test_tier3_patch_idempotence_and_rollback_integrity(self, tmp_path):
        """Workflow: Identical patch is a no-op, preserves existing backup, and handles missing backup gracefully."""
        target = tmp_path / "service.py"
        initial_content = 'api_key = "AIzaSyD-1234567890abcdef"\n'
        target.write_text(initial_content, encoding="utf-8")

        # Step 1: Apply initial patch
        first_patch = 'api_key = os.getenv("API_KEY")\n'
        success, msg, diff = apply_patch(str(target), first_patch)
        assert success is True
        bak_file = target.with_suffix(".py.bak")
        assert bak_file.exists()
        assert bak_file.read_text(encoding="utf-8") == initial_content

        # Step 2: Re-apply the same patch content (idempotency check)
        success_idem, msg_idem, diff_idem = apply_patch(str(target), first_patch)
        assert success_idem is True
        assert "không có thay đổi" in msg_idem
        # Crucial: Backup should still contain the original unpatched content
        assert bak_file.read_text(encoding="utf-8") == initial_content

        # Step 3: Rollback
        rb_ok, rb_msg = rollback_backup(target)
        assert rb_ok is True
        assert target.read_text(encoding="utf-8") == initial_content

        # Step 4: Attempt rollback on a file with NO backup
        no_bak_file = tmp_path / "standalone.py"
        no_bak_file.write_text("print('clean')\n", encoding="utf-8")
        fail_ok, fail_msg = rollback_backup(no_bak_file)
        assert fail_ok is False
        assert "Không tìm thấy file sao lưu" in fail_msg

    def test_tier3_partial_remediation_and_selective_rollback(self, tmp_path):
        """Workflow: File with 2 vulnerabilities -> Patch only 1 -> Scan reports exactly the 1 remaining -> Rollback restores both."""
        target = tmp_path / "multi_vuln.py"
        original_code = (
            'import os\n\n'
            'def handler(cmd, uid):\n'
            '    os.system(f"echo {cmd}")\n'  # SEC-CMDI-002
            '    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'  # SEC-SQLI-001
        )
        target.write_text(original_code, encoding="utf-8")

        # Step 1: Detect both
        initial_findings = scan_file(target)
        assert len(initial_findings) == 2
        rule_ids = {f["vuln_id"] for f in initial_findings}
        assert rule_ids == {"SEC-CMDI-002", "SEC-SQLI-001"}

        # Step 2: Partially patch (fix CMDi only, leave SQLi)
        partially_patched = (
            'import subprocess\n\n'
            'def handler(cmd, uid):\n'
            '    subprocess.run(["echo", cmd])\n'
            '    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
        )
        apply_patch(str(target), partially_patched)

        # Step 3: Scan reports only the remaining SQLi
        mid_findings = scan_file(target)
        assert len(mid_findings) == 1
        assert mid_findings[0]["vuln_id"] == "SEC-SQLI-001"

        # Step 4: Rollback restores both
        rollback_backup(target)
        restored_findings = scan_file(target)
        assert len(restored_findings) == 2
        restored_ids = {f["vuln_id"] for f in restored_findings}
        assert restored_ids == {"SEC-CMDI-002", "SEC-SQLI-001"}
