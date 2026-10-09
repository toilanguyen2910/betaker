"""Tier 4: Real-World Application Scenarios Test Suite.

Evaluates full system behavior on realistic, multi-file applications across Python,
JavaScript/TypeScript, Go, PHP, and polyglot monorepos. Tests end-to-end auditing,
atomic patch application, backup verification, and rollback restoration.
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
    scan_all_manifests,
    DependencyFinding,
)
from tools.patcher import (
    apply_patch,
    rollback_backup,
    generate_diff,
)


# ==============================================================================
# Scenario 1: Python Flask Web Application
# ==============================================================================

class TestScenario1FlaskWebApplication:
    """Scenario 1: Realistic Python Flask Web Application with SQLi, CMDi, Path Traversal, Secrets & Vulnerable Dependencies."""

    def test_scenario1_flask_web_app_full_lifecycle(self, tmp_path):
        app_dir = tmp_path / "flask_app"
        app_dir.mkdir(parents=True, exist_ok=True)

        # 1. Create Flask main entrypoint
        app_file = app_dir / "app.py"
        app_code = (
            "from flask import Flask, request\n"
            "import os\n\n"
            "app = Flask(__name__)\n"
            "DEBUG = True\n\n"
            '@app.route("/ping")\n'
            "def ping():\n"
            '    host = request.args.get("host")\n'
            '    os.system(f"ping -c 1 {host}")\n'
            '    return "pong"\n\n'
            '@app.route("/view")\n'
            "def view_file():\n"
            '    with open(request.args.get("file"), "r") as f:\n'
            '        return f.read()\n'
        )
        app_file.write_text(app_code, encoding="utf-8")

        # 2. Create database module
        db_file = app_dir / "database.py"
        db_code = (
            "import sqlite3\n\n"
            "def get_user(user_id):\n"
            '    conn = sqlite3.connect("users.db")\n'
            "    cursor = conn.cursor()\n"
            '    cursor.execute(f"SELECT * FROM accounts WHERE id = {user_id}")\n'
            "    return cursor.fetchone()\n"
        )
        db_file.write_text(db_code, encoding="utf-8")

        # 3. Create settings module with secrets
        config_file = app_dir / "config.py"
        config_code = (
            'secret_key = "super_secret_jwt_token_12345678"\n'
            'api_key = "AIzaSyD-1234567890abcdef"\n'
        )
        config_file.write_text(config_code, encoding="utf-8")

        # 4. Create requirements.txt with vulnerable packages
        req_file = app_dir / "requirements.txt"
        req_code = (
            "flask==1.0.1\n"
            "requests==2.25.0\n"
            "urllib3==1.26.4\n"
        )
        req_file.write_text(req_code, encoding="utf-8")

        # ----------------------------------------------------------------------
        # Phase 1: Comprehensive Initial Audit
        # ----------------------------------------------------------------------
        sast_findings, sca_findings = scan_all(app_dir)

        # Assert SAST findings across files
        sast_rule_ids = {f["vuln_id"] for f in sast_findings}
        assert "SEC-MISC-006" in sast_rule_ids  # DEBUG = True
        assert "SEC-CMDI-002" in sast_rule_ids  # os.system
        assert "SEC-TRAV-003" in sast_rule_ids  # open(request.args.get)
        assert "SEC-SQLI-001" in sast_rule_ids  # cursor.execute f-string
        assert "SEC-SECR-004" in sast_rule_ids  # secret_key / api_key

        # Assert SCA findings for dependencies
        sca_packages = {f["package"] for f in sca_findings}
        assert "flask" in sca_packages
        assert "requests" in sca_packages
        assert "urllib3" in sca_packages

        # ----------------------------------------------------------------------
        # Phase 2: Apply Hardened Patches Across All Files
        # ----------------------------------------------------------------------
        patched_app_code = (
            "from flask import Flask, request\n"
            "import subprocess\n"
            "from pathlib import Path\n\n"
            "app = Flask(__name__)\n"
            "DEBUG = False\n\n"
            '@app.route("/ping")\n'
            "def ping():\n"
            '    host = request.args.get("host")\n'
            '    subprocess.run(["ping", "-c", "1", host], check=True)\n'
            '    return "pong"\n\n'
            '@app.route("/view")\n'
            "def view_file():\n"
            '    with open("safe_static_file.txt", "r", encoding="utf-8") as f:\n'
            '        return f.read()\n'
        )
        patched_db_code = (
            "import sqlite3\n\n"
            "def get_user(user_id):\n"
            '    conn = sqlite3.connect("users.db")\n'
            "    cursor = conn.cursor()\n"
            '    cursor.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))\n'
            "    return cursor.fetchone()\n"
        )
        patched_config_code = (
            "import os\n\n"
            'secret_key = os.getenv("SECRET_KEY")\n'
            'api_key = os.getenv("API_KEY")\n'
        )
        patched_req_code = (
            "flask==3.0.0\n"
            "requests==2.31.0\n"
            "urllib3==2.1.0\n"
        )

        ok1, _, diff1 = apply_patch(str(app_file), patched_app_code)
        ok2, _, diff2 = apply_patch(str(db_file), patched_db_code)
        ok3, _, diff3 = apply_patch(str(config_file), patched_config_code)
        ok4, _, diff4 = apply_patch(str(req_file), patched_req_code)

        assert ok1 and ok2 and ok3 and ok4
        assert "+DEBUG = False" in diff1
        assert "+    cursor.execute(\"SELECT * FROM accounts WHERE id = %s\", (user_id,))" in diff2
        assert '+secret_key = os.getenv("SECRET_KEY")' in diff3

        # ----------------------------------------------------------------------
        # Phase 3: Post-Patch Verification (Must be 100% clean)
        # ----------------------------------------------------------------------
        clean_sast, clean_sca = scan_all(app_dir)
        assert len(clean_sast) == 0, f"Expected 0 SAST findings, got: {[f['rule_id'] for f in clean_sast]}"
        assert len(clean_sca) == 0, f"Expected 0 SCA findings, got: {[f['package'] for f in clean_sca]}"

        # ----------------------------------------------------------------------
        # Phase 4: Full System Rollback Restoration
        # ----------------------------------------------------------------------
        for f in (app_file, db_file, config_file, req_file):
            rb_ok, rb_msg = rollback_backup(f)
            assert rb_ok is True

        # Verify file contents restored identically
        assert app_file.read_text(encoding="utf-8") == app_code
        assert db_file.read_text(encoding="utf-8") == db_code
        assert config_file.read_text(encoding="utf-8") == config_code
        assert req_file.read_text(encoding="utf-8") == req_code

        # ----------------------------------------------------------------------
        # Phase 5: Re-verification After Rollback
        # ----------------------------------------------------------------------
        re_sast, re_sca = scan_all(app_dir)
        assert len(re_sast) >= 4
        assert len(re_sca) >= 3


# ==============================================================================
# Scenario 2: Node.js Express API
# ==============================================================================

class TestScenario2ExpressAPI:
    """Scenario 2: Node.js Express REST API with CMDi, Path Traversal, Secrets, Insecure Deserialization & Outdated package.json."""

    def test_scenario2_express_api_full_lifecycle(self, tmp_path):
        api_dir = tmp_path / "express_api"
        api_dir.mkdir(parents=True, exist_ok=True)
        routes_dir = api_dir / "routes"
        routes_dir.mkdir(parents=True, exist_ok=True)

        # 1. server.js (CMDi and Path Traversal)
        server_file = api_dir / "server.js"
        server_code = (
            "const express = require('express');\n"
            "const child_process = require('child_process');\n"
            "const fs = require('fs');\n\n"
            "const app = express();\n\n"
            "app.get('/diag', (req, res) => {\n"
            '    child_process.exec("ping " + req.query.host);\n'
            '    res.send("ok");\n'
            "});\n\n"
            "app.get('/file', (req, res) => {\n"
            "    fs.readFile(req.query.path, (err, data) => res.send(data));\n"
            "});\n"
        )
        server_file.write_text(server_code, encoding="utf-8")

        # 2. routes/auth.js (Secret and eval)
        auth_file = routes_dir / "auth.js"
        auth_code = (
            'const secret_key = "super_secret_jwt_token_12345678";\n\n'
            "function processAuth(untrustedInput) {\n"
            '    return eval("processPayload(" + untrustedInput + ")");\n'
            "}\n\n"
            "module.exports = { secret_key, processAuth };\n"
        )
        auth_file.write_text(auth_code, encoding="utf-8")

        # 3. routes/users.js (SQLi)
        users_file = routes_dir / "users.js"
        users_code = (
            "const db = require('../db');\n\n"
            "function findUser(userId) {\n"
            '    return db.query("SELECT * FROM users WHERE id = " + userId + ";");\n'
            "}\n\n"
            "module.exports = { findUser };\n"
        )
        users_file.write_text(users_code, encoding="utf-8")

        # 4. package.json with vulnerable dependencies
        package_file = api_dir / "package.json"
        package_code = json.dumps({
            "name": "express-api",
            "version": "1.0.0",
            "dependencies": {
                "express": "4.18.2",
                "lodash": "4.17.15",
                "jsonwebtoken": "8.5.1"
            }
        }, indent=2)
        package_file.write_text(package_code, encoding="utf-8")

        # ----------------------------------------------------------------------
        # Phase 1: Audit Detection
        # ----------------------------------------------------------------------
        sast_findings, sca_findings = scan_all(api_dir)

        sast_rules = {f["vuln_id"] for f in sast_findings}
        assert "SEC-CMDI-002" in sast_rules
        assert "SEC-TRAV-003" in sast_rules
        assert "SEC-SECR-004" in sast_rules
        assert "SEC-DESER-005" in sast_rules
        assert "SEC-SQLI-001" in sast_rules

        sca_pkgs = {f["package"] for f in sca_findings}
        assert "express" in sca_pkgs
        assert "lodash" in sca_pkgs
        assert "jsonwebtoken" in sca_pkgs

        # ----------------------------------------------------------------------
        # Phase 2: Patch
        # ----------------------------------------------------------------------
        patched_server = (
            "const express = require('express');\n"
            "const path = require('path');\n\n"
            "const app = express();\n\n"
            "app.get('/diag', (req, res) => {\n"
            '    res.send("diagnostics disabled");\n'
            "});\n\n"
            "app.get('/file', (req, res) => {\n"
            '    res.sendFile(path.join(__dirname, "public", "safe_doc.txt"));\n'
            "});\n"
        )
        patched_auth = (
            'const secret_key = process.env.SECRET_KEY;\n\n'
            "function processAuth(untrustedInput) {\n"
            "    return JSON.parse(untrustedInput);\n"
            "}\n\n"
            "module.exports = { secret_key, processAuth };\n"
        )
        patched_users = (
            "const db = require('../db');\n\n"
            "function findUser(userId) {\n"
            '    return db.query("SELECT * FROM users WHERE id = $1", [userId]);\n'
            "}\n\n"
            "module.exports = { findUser };\n"
        )
        patched_package = json.dumps({
            "name": "express-api",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.19.2",
                "lodash": "^4.17.21",
                "jsonwebtoken": "^9.0.0"
            }
        }, indent=2)

        apply_patch(str(server_file), patched_server)
        apply_patch(str(auth_file), patched_auth)
        apply_patch(str(users_file), patched_users)
        apply_patch(str(package_file), patched_package)

        # ----------------------------------------------------------------------
        # Phase 3: Post-Patch Verification (Clean)
        # ----------------------------------------------------------------------
        clean_sast, clean_sca = scan_all(api_dir)
        assert len(clean_sast) == 0
        assert len(clean_sca) == 0

        # ----------------------------------------------------------------------
        # Phase 4: Rollback & Re-verification
        # ----------------------------------------------------------------------
        for f in (server_file, auth_file, users_file, package_file):
            ok, _ = rollback_backup(f)
            assert ok is True

        re_sast, re_sca = scan_all(api_dir)
        assert len(re_sast) >= 4
        assert len(re_sca) >= 3


# ==============================================================================
# Scenario 3: Go REST Microservice
# ==============================================================================

class TestScenario3GoMicroservice:
    """Scenario 3: Go REST Microservice with Command Execution, Path Traversal, SQLi, and Insecure Config."""

    def test_scenario3_go_microservice_full_lifecycle(self, tmp_path):
        go_dir = tmp_path / "go_microservice"
        go_dir.mkdir(parents=True, exist_ok=True)
        subdirs = [go_dir / "handlers", go_dir / "repository", go_dir / "config"]
        for d in subdirs:
            d.mkdir(parents=True, exist_ok=True)

        # 1. main.go (Path Traversal)
        main_file = go_dir / "main.go"
        main_code = (
            "package main\n\n"
            'import "os"\n\n'
            "func serveDoc(filePath string) ([]byte, error) {\n"
            "    return os.ReadFile(filePath)\n"
            "}\n"
        )
        main_file.write_text(main_code, encoding="utf-8")

        # 2. handlers/worker.go (Command Injection)
        worker_file = go_dir / "handlers" / "worker.go"
        worker_code = (
            "package handlers\n\n"
            'import "os/exec"\n\n'
            "func ExecTask(cmd string) {\n"
            '    exec.Command("sh", "-c", cmd)\n'
            "}\n"
        )
        worker_file.write_text(worker_code, encoding="utf-8")

        # 3. repository/items.go (SQL Injection)
        repo_file = go_dir / "repository" / "items.go"
        repo_code = (
            "package repository\n\n"
            "func GetItem(itemId string) {\n"
            '    db.query("SELECT * FROM items WHERE id = " + itemId + ";")\n'
            "}\n"
        )
        repo_file.write_text(repo_code, encoding="utf-8")

        # 4. config/settings.go (Secret and Debug)
        settings_file = go_dir / "config" / "settings.go"
        settings_code = (
            "package config\n\n"
            'var api_key = "AIzaSyD-1234567890abcdef"\n'
            "const DEBUG = True\n"
        )
        settings_file.write_text(settings_code, encoding="utf-8")

        # ----------------------------------------------------------------------
        # Phase 1: Audit Detection
        # ----------------------------------------------------------------------
        findings = [f for f in scan_directory(go_dir) if isinstance(f, VulnerabilityFinding)]
        detected_rules = {f["vuln_id"] for f in findings}
        assert "SEC-CMDI-002" in detected_rules
        assert "SEC-SQLI-001" in detected_rules
        assert "SEC-SECR-004" in detected_rules
        assert "SEC-MISC-006" in detected_rules

        # ----------------------------------------------------------------------
        # Phase 2: Patch
        # ----------------------------------------------------------------------
        patched_main = (
            "package main\n\n"
            "func serveDoc() ([]byte, error) {\n"
            '    return []byte("safe static document content"), nil\n'
            "}\n"
        )
        patched_worker = (
            "package handlers\n\n"
            "func ExecTask(cmd string) {\n"
            '    // Safe stub - external execution removed\n'
            "}\n"
        )
        patched_repo = (
            "package repository\n\n"
            "func GetItem(itemId string) {\n"
            '    db.Query("SELECT * FROM items WHERE id = ?", itemId)\n'
            "}\n"
        )
        patched_settings = (
            "package config\n\n"
            'import "os"\n\n'
            'var apiKey = os.Getenv("API_KEY")\n'
            "const DEBUG = False\n"
        )

        apply_patch(str(main_file), patched_main)
        apply_patch(str(worker_file), patched_worker)
        apply_patch(str(repo_file), patched_repo)
        apply_patch(str(settings_file), patched_settings)

        # ----------------------------------------------------------------------
        # Phase 3: Post-Patch Verification (Clean)
        # ----------------------------------------------------------------------
        clean_findings = [f for f in scan_directory(go_dir) if isinstance(f, VulnerabilityFinding)]
        assert len(clean_findings) == 0

        # ----------------------------------------------------------------------
        # Phase 4: Rollback & Re-verification
        # ----------------------------------------------------------------------
        for f in (main_file, worker_file, repo_file, settings_file):
            ok, _ = rollback_backup(f)
            assert ok is True

        re_findings = [f for f in scan_directory(go_dir) if isinstance(f, VulnerabilityFinding)]
        re_rules = {f["vuln_id"] for f in re_findings}
        assert "SEC-CMDI-002" in re_rules
        assert "SEC-SQLI-001" in re_rules
        assert "SEC-SECR-004" in re_rules
        assert "SEC-MISC-006" in re_rules


# ==============================================================================
# Scenario 4: PHP E-Commerce Web Application
# ==============================================================================

class TestScenario4PHPEcommerce:
    """Scenario 4: PHP E-Commerce Script with SQLi, Deserialization, Path Traversal, and Secrets."""

    def test_scenario4_php_ecommerce_full_lifecycle(self, tmp_path):
        php_dir = tmp_path / "php_ecommerce"
        php_dir.mkdir(parents=True, exist_ok=True)
        (php_dir / "models").mkdir(parents=True, exist_ok=True)
        (php_dir / "config").mkdir(parents=True, exist_ok=True)

        # 1. index.php (Path Traversal)
        index_file = php_dir / "index.php"
        index_code = (
            "<?php\n"
            '$filename = $_GET["doc"];\n'
            'read_file(f"/var/www/uploads/{filename}");\n'
        )
        index_file.write_text(index_code, encoding="utf-8")

        # 2. cart.php (Deserialization / eval)
        cart_file = php_dir / "cart.php"
        cart_code = (
            "<?php\n"
            "$user_payload = $_POST['data'];\n"
            "eval($user_payload);\n"
        )
        cart_file.write_text(cart_code, encoding="utf-8")

        # 3. models/User.php (SQL Injection)
        user_file = php_dir / "models" / "User.php"
        user_code = (
            "<?php\n"
            "class User {\n"
            "    public static function findById($userId) {\n"
            '        global $db;\n'
            '        return db.query("SELECT * FROM users WHERE id = " + $userId + ";");\n'
            "    }\n"
            "}\n"
        )
        user_file.write_text(user_code, encoding="utf-8")

        # 4. config/keys.php (Secrets)
        keys_file = php_dir / "config" / "keys.php"
        keys_code = (
            "<?php\n"
            '$secret_key = "super_secret_jwt_token_12345678";\n'
            '$api_key = "AIzaSyD-1234567890abcdef";\n'
        )
        keys_file.write_text(keys_code, encoding="utf-8")

        # ----------------------------------------------------------------------
        # Phase 1: Audit Detection
        # ----------------------------------------------------------------------
        findings = [f for f in scan_directory(php_dir) if isinstance(f, VulnerabilityFinding)]
        rules = {f["vuln_id"] for f in findings}
        assert "SEC-TRAV-003" in rules
        assert "SEC-DESER-005" in rules
        assert "SEC-SQLI-001" in rules
        assert "SEC-SECR-004" in rules

        # ----------------------------------------------------------------------
        # Phase 2: Patch
        # ----------------------------------------------------------------------
        patched_index = (
            "<?php\n"
            'read_file("/var/www/uploads/static_catalog.pdf");\n'
        )
        patched_cart = (
            "<?php\n"
            "$user_payload = $_POST['data'];\n"
            "$data = json_decode($user_payload, true);\n"
        )
        patched_user = (
            "<?php\n"
            "class User {\n"
            "    public static function findById($userId) {\n"
            '        global $pdo;\n'
            '        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");\n'
            '        $stmt->execute([":id" => $userId]);\n'
            "        return $stmt->fetch();\n"
            "    }\n"
            "}\n"
        )
        patched_keys = (
            "<?php\n"
            '$secret_key = getenv("SECRET_KEY");\n'
            '$api_key = getenv("API_KEY");\n'
        )

        apply_patch(str(index_file), patched_index)
        apply_patch(str(cart_file), patched_cart)
        apply_patch(str(user_file), patched_user)
        apply_patch(str(keys_file), patched_keys)

        # ----------------------------------------------------------------------
        # Phase 3: Post-Patch Verification (Clean)
        # ----------------------------------------------------------------------
        clean_findings = [f for f in scan_directory(php_dir) if isinstance(f, VulnerabilityFinding)]
        assert len(clean_findings) == 0

        # ----------------------------------------------------------------------
        # Phase 4: Rollback & Re-verification
        # ----------------------------------------------------------------------
        for f in (index_file, cart_file, user_file, keys_file):
            ok, _ = rollback_backup(f)
            assert ok is True

        re_findings = [f for f in scan_directory(php_dir) if isinstance(f, VulnerabilityFinding)]
        re_rules = {f["vuln_id"] for f in re_findings}
        assert "SEC-TRAV-003" in re_rules
        assert "SEC-DESER-005" in re_rules
        assert "SEC-SQLI-001" in re_rules
        assert "SEC-SECR-004" in re_rules


# ==============================================================================
# Scenario 5: Polyglot Monorepo with Safe Patterns (False Positive Immunity)
# ==============================================================================

class TestScenario5PolyglotSafeMonorepo:
    """Scenario 5: Multi-language monorepo using safe patterns verifying ZERO false positives across all scanners."""

    def test_scenario5_polyglot_safe_monorepo_zero_false_positives(self, tmp_path):
        monorepo = tmp_path / "monorepo"
        monorepo.mkdir(parents=True, exist_ok=True)

        # Python service
        py_dir = monorepo / "services" / "py_auth"
        py_dir.mkdir(parents=True, exist_ok=True)
        (py_dir / "handler.py").write_text(
            'import os\n'
            'import subprocess\n'
            'import yaml\n\n'
            'DEBUG = False\n'
            'api_key = os.getenv("API_KEY")\n'
            'secret_key = os.environ.get("SECRET_KEY")\n'
            '# os.system(f"echo {insecure}")\n'
            '# cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
            'def run_cmd(target):\n'
            '    return subprocess.run(["ping", "-c", "1", target], check=True)\n'
            'def load_cfg(data):\n'
            '    return yaml.safe_load(data)\n'
            'def query_user(cursor, uid):\n'
            '    return cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))\n',
            encoding="utf-8"
        )
        (py_dir / "requirements.txt").write_text(
            "requests==2.31.0\n"
            "urllib3==2.1.0\n"
            "flask==3.0.0\n",
            encoding="utf-8"
        )

        # Node.js service
        js_dir = monorepo / "services" / "js_api"
        js_dir.mkdir(parents=True, exist_ok=True)
        (js_dir / "index.js").write_text(
            'const apiKey = process.env.API_KEY;\n'
            'const debug = false;\n'
            '// db.query("SELECT * FROM users WHERE id = " + userId + ";");\n'
            '// eval("untrustedCode();");\n'
            'function fetchUser(db, userId) {\n'
            '    return db.query("SELECT * FROM users WHERE id = $1", [userId]);\n'
            '}\n'
            'function parse(data) {\n'
            '    return JSON.parse(data);\n'
            '}\n',
            encoding="utf-8"
        )
        (js_dir / "package.json").write_text(
            json.dumps({
                "name": "js-api",
                "version": "1.0.0",
                "dependencies": {
                    "axios": "^1.7.4",
                    "express": "^4.19.2",
                    "lodash": "^4.17.21"
                }
            }, indent=2),
            encoding="utf-8"
        )

        # Go service
        go_dir = monorepo / "services" / "go_core"
        go_dir.mkdir(parents=True, exist_ok=True)
        (go_dir / "main.go").write_text(
            'package main\n\n'
            'import "os"\n\n'
            'var apiKey = os.Getenv("API_KEY")\n'
            'const DEBUG = false\n'
            '// raw("SELECT * FROM records WHERE key = " + recordKey + "")\n'
            'func QueryUser(db Database, id string) {\n'
            '    db.Query("SELECT * FROM users WHERE id = ?", id)\n'
            '}\n',
            encoding="utf-8"
        )

        # PHP service
        php_dir = monorepo / "services" / "php_store"
        php_dir.mkdir(parents=True, exist_ok=True)
        (php_dir / "store.php").write_text(
            '<?php\n'
            '$apiKey = getenv("API_KEY");\n'
            '// db.query("SELECT * FROM users WHERE id = " + $userId + ";");\n'
            '// eval($untrusted_code);\n'
            'function getOrders($pdo, $id) {\n'
            '    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");\n'
            '    $stmt->execute([":id" => $id]);\n'
            '    return $stmt->fetchAll();\n'
            '}\n'
            'function parseInput($raw) {\n'
            '    return json_decode($raw, true);\n'
            '}\n',
            encoding="utf-8"
        )

        # ----------------------------------------------------------------------
        # Full Monorepo Scan: Zero SAST Findings and Zero SCA Findings
        # ----------------------------------------------------------------------
        sast_findings, sca_findings = scan_all(monorepo)
        assert len(sast_findings) == 0, f"False positives detected: {[f['rule_id'] for f in sast_findings]}"
        assert len(sca_findings) == 0, f"Unexpected SCA findings: {[f['package'] for f in sca_findings]}"


# ==============================================================================
# Scenario 6: CLI Headless Audit & Markdown Report Lifecycle
# ==============================================================================

class TestScenario6CLIReportLifecycle:
    """Scenario 6: End-to-End CLI Headless Audit & Markdown Report Generation."""

    def test_scenario6_cli_report_generation_lifecycle(self, tmp_path, monkeypatch):
        workspace = tmp_path / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(Config, "WORKSPACE_DIR", workspace)
        monkeypatch.chdir(workspace)

        # Create a sample project in the workspace
        sample_file = workspace / "service.py"
        sample_file.write_text(
            'import os\n'
            'DEBUG = True\n'
            'api_key = "AIzaSyD-1234567890abcdef"\n'
            'os.system(f"ping {host}")\n',
            encoding="utf-8"
        )
        sample_req = workspace / "requirements.txt"
        sample_req.write_text("requests==2.25.0\n", encoding="utf-8")

        # Import main and execute handle_report
        import main
        main.handle_report()

        # Find the generated markdown report file
        report_files = list(workspace.glob("security_report_*.md"))
        assert len(report_files) == 1, f"Expected 1 report file, found: {report_files}"
        report_content = report_files[0].read_text(encoding="utf-8")

        # Assert report structure conforms to interface contracts
        assert "# 🛡️ BetAker Security Audit Report" in report_content
        assert "## Summary" in report_content
        assert "## Static Code Analysis Findings" in report_content
        assert "## Dependency Audit Findings (SCA)" in report_content
        assert "requests (" in report_content and "2.25.0" in report_content
        assert "CVE-2023-32681" in report_content
        assert "SEC-MISC-006" in report_content or "Insecure Configuration" in report_content
        assert "SEC-SECR-004" in report_content or "Hardcoded Secret" in report_content
        assert "SEC-CMDI-002" in report_content or "Command Injection" in report_content
