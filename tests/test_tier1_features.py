import os
import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from config import Config
from tools.scanner import (
    scan_file_for_vulnerabilities,
    scan_directory,
    scan_dependencies,
    VULN_PATTERNS,
    KNOWN_VULNERABLE_PACKAGES,
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
from tools.terminal import (
    is_dangerous_command,
    execute_command,
)
from agent.core import BetHackerAgent
from llm.client import LLMClient, TOOLS_SCHEMA
from tests.conftest import DummyMessage, DummyToolCall, DummyFunctionCall


# ==============================================================================
# Feature 1: SAST Polyglot Rules (Python, JS, Go, PHP)
# ==============================================================================

class TestSASTPolyglotRules:

    def test_sast_sqli_python_detection(self, tmp_path, vulnerable_python_samples):
        for snippet in vulnerable_python_samples["SEC-SQLI-001"]:
            test_file = tmp_path / "test_sqli.py"
            test_file.write_text(snippet, encoding="utf-8")
            findings = scan_file_for_vulnerabilities(test_file)
            assert len(findings) >= 1, f"Failed to detect SQLi for snippet: {snippet}"
            assert findings[0]["vuln_id"] == "SEC-SQLI-001"
            assert findings[0]["severity"] == "CRITICAL"
            assert findings[0]["category"] == "A03:2021 - Injection"

    def test_sast_cmdi_python_detection(self, tmp_path, vulnerable_python_samples):
        for snippet in vulnerable_python_samples["SEC-CMDI-002"]:
            test_file = tmp_path / "test_cmdi.py"
            test_file.write_text(snippet, encoding="utf-8")
            findings = scan_file_for_vulnerabilities(test_file)
            assert len(findings) >= 1, f"Failed to detect CMDi for snippet: {snippet}"
            assert findings[0]["vuln_id"] == "SEC-CMDI-002"
            assert findings[0]["severity"] == "CRITICAL"

    def test_sast_path_traversal_python_detection(self, tmp_path, vulnerable_python_samples):
        for snippet in vulnerable_python_samples["SEC-TRAV-003"]:
            test_file = tmp_path / "test_trav.py"
            test_file.write_text(snippet, encoding="utf-8")
            findings = scan_file_for_vulnerabilities(test_file)
            assert len(findings) >= 1, f"Failed to detect Path Traversal for: {snippet}"
            assert findings[0]["vuln_id"] == "SEC-TRAV-003"
            assert findings[0]["severity"] == "HIGH"

    def test_sast_secrets_python_detection(self, tmp_path, vulnerable_python_samples):
        for snippet in vulnerable_python_samples["SEC-SECR-004"]:
            test_file = tmp_path / "test_secret.py"
            test_file.write_text(snippet, encoding="utf-8")
            findings = scan_file_for_vulnerabilities(test_file)
            assert len(findings) >= 1, f"Failed to detect Secret for: {snippet}"
            assert findings[0]["vuln_id"] == "SEC-SECR-004"
            assert findings[0]["severity"] == "HIGH"

    def test_sast_deserialization_python_detection(self, tmp_path, vulnerable_python_samples):
        for snippet in vulnerable_python_samples["SEC-DESER-005"]:
            test_file = tmp_path / "test_deser.py"
            test_file.write_text(snippet, encoding="utf-8")
            findings = scan_file_for_vulnerabilities(test_file)
            assert len(findings) >= 1, f"Failed to detect Deserialization for: {snippet}"
            assert findings[0]["vuln_id"] == "SEC-DESER-005"
            assert findings[0]["severity"] == "CRITICAL"

    def test_sast_insecure_config_python_detection(self, tmp_path, vulnerable_python_samples):
        for snippet in vulnerable_python_samples["SEC-MISC-006"]:
            test_file = tmp_path / "test_misc.py"
            test_file.write_text(snippet, encoding="utf-8")
            findings = scan_file_for_vulnerabilities(test_file)
            assert len(findings) >= 1, f"Failed to detect Insecure Config for: {snippet}"
            assert findings[0]["vuln_id"] == "SEC-MISC-006"
            assert findings[0]["severity"] == "MEDIUM"

    def test_sast_js_detection(self, tmp_path, vulnerable_js_samples):
        for vuln_id, snippets in vulnerable_js_samples.items():
            for snippet in snippets:
                test_file = tmp_path / "test.js"
                test_file.write_text(snippet, encoding="utf-8")
                findings = scan_file_for_vulnerabilities(test_file)
                assert any(f["vuln_id"] == vuln_id for f in findings), f"JS failed to detect {vuln_id} for: {snippet}"

    def test_sast_go_detection(self, tmp_path, vulnerable_go_samples):
        for vuln_id, snippets in vulnerable_go_samples.items():
            for snippet in snippets:
                test_file = tmp_path / "test.go"
                test_file.write_text(snippet, encoding="utf-8")
                findings = scan_file_for_vulnerabilities(test_file)
                assert any(f["vuln_id"] == vuln_id for f in findings), f"Go failed to detect {vuln_id} for: {snippet}"

    def test_sast_php_detection(self, tmp_path, vulnerable_php_samples):
        for vuln_id, snippets in vulnerable_php_samples.items():
            for snippet in snippets:
                test_file = tmp_path / "test.php"
                test_file.write_text(snippet, encoding="utf-8")
                findings = scan_file_for_vulnerabilities(test_file)
                assert any(f["vuln_id"] == vuln_id for f in findings), f"PHP failed to detect {vuln_id} for: {snippet}"

    def test_sast_directory_polyglot_scan(self, tmp_path):
        (tmp_path / "app.py").write_text('os.system(f"echo {user}")', encoding="utf-8")
        (tmp_path / "server.js").write_text('db.query("SELECT * FROM u WHERE id = " + id + ";");', encoding="utf-8")
        (tmp_path / "service.go").write_text('raw("SELECT * FROM items WHERE id = " + id + "")', encoding="utf-8")
        (tmp_path / "index.php").write_text('eval($code);', encoding="utf-8")
        (tmp_path / "keys.env").write_text('api_key = "AIzaSyD-1234567890abcdef"', encoding="utf-8")

        findings = scan_directory(str(tmp_path))
        assert len(findings) == 5
        found_ids = {f["vuln_id"] for f in findings}
        assert "SEC-CMDI-002" in found_ids
        assert "SEC-SQLI-001" in found_ids
        assert "SEC-DESER-005" in found_ids
        assert "SEC-SECR-004" in found_ids


# ==============================================================================
# Feature 2: False Positive Reduction (Safe Code & Comments)
# ==============================================================================

class TestFalsePositiveReduction:

    def test_fp_safe_sql_queries_not_flagged(self, tmp_path):
        safe_sql = (
            'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
            'cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])\n'
            'db.execute("SELECT * FROM users WHERE status = :status", {"status": "active"})\n'
        )
        test_file = tmp_path / "safe_sql.py"
        test_file.write_text(safe_sql, encoding="utf-8")
        findings = scan_file_for_vulnerabilities(test_file)
        assert len(findings) == 0

    def test_fp_safe_subprocess_not_flagged(self, tmp_path):
        safe_subp = (
            'subprocess.run(["ls", "-la", "/tmp"], check=True)\n'
            'subprocess.Popen(["ping", "-c", "1", "127.0.0.1"])\n'
            'subprocess.call(["uptime"])\n'
        )
        test_file = tmp_path / "safe_subp.py"
        test_file.write_text(safe_subp, encoding="utf-8")
        findings = scan_file_for_vulnerabilities(test_file)
        assert len(findings) == 0

    def test_fp_safe_file_open_not_flagged(self, tmp_path):
        safe_open = (
            'with open("/var/log/app.log", "r", encoding="utf-8") as f:\n'
            '    data = f.read()\n'
            'open("config.json", "w")\n'
        )
        test_file = tmp_path / "safe_open.py"
        test_file.write_text(safe_open, encoding="utf-8")
        findings = scan_file_for_vulnerabilities(test_file)
        assert len(findings) == 0

    def test_fp_safe_secrets_env_not_flagged(self, tmp_path):
        safe_secrets = (
            'api_key = os.getenv("API_KEY")\n'
            'secret_key = os.environ.get("SECRET_KEY", "default")\n'
            'password = getpass.getpass()\n'
            'access_token = config.ACCESS_TOKEN\n'
        )
        test_file = tmp_path / "safe_sec.py"
        test_file.write_text(safe_secrets, encoding="utf-8")
        findings = scan_file_for_vulnerabilities(test_file)
        assert len(findings) == 0

    def test_fp_safe_deserialization_not_flagged(self, tmp_path):
        safe_deser = (
            'data = json.loads(user_input)\n'
            'config = yaml.safe_load(yaml_str)\n'
        )
        test_file = tmp_path / "safe_deser.py"
        test_file.write_text(safe_deser, encoding="utf-8")
        findings = scan_file_for_vulnerabilities(test_file)
        assert len(findings) == 0

    def test_fp_python_comments_ignored(self, tmp_path):
        commented = (
            '# cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
            '# os.system(f"rm -rf {path}")\n'
            '# api_key = "AIzaSyD-1234567890abcdef"\n'
        )
        test_file = tmp_path / "commented.py"
        test_file.write_text(commented, encoding="utf-8")
        findings = scan_file_for_vulnerabilities(test_file)
        assert len(findings) == 0

    def test_fp_c_style_comments_ignored(self, tmp_path):
        commented = (
            '// db.query("SELECT * FROM users WHERE id = " + userId + ";");\n'
            '// eval("process(" + input + ")");\n'
            '// secret_key = "super_secret_jwt_token_12345678";\n'
        )
        test_file = tmp_path / "commented.js"
        test_file.write_text(commented, encoding="utf-8")
        findings = scan_file_for_vulnerabilities(test_file)
        assert len(findings) == 0

    def test_fp_debug_false_not_flagged(self, tmp_path):
        safe_debug = (
            'DEBUG = False\n'
            'app.run(debug=False)\n'
            'app.run(host="127.0.0.1", port=8000, debug=False)\n'
        )
        test_file = tmp_path / "safe_debug.py"
        test_file.write_text(safe_debug, encoding="utf-8")
        findings = scan_file_for_vulnerabilities(test_file)
        assert len(findings) == 0


# ==============================================================================
# Feature 3: Dependency Manifest SCA
# ==============================================================================

class TestDependencyManifestSCA:

    def test_sca_detects_all_known_packages(self, tmp_path, vulnerable_manifest_content):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(vulnerable_manifest_content, encoding="utf-8")
        findings = scan_dependencies(req_file)
        detected_pkgs = {f["package"] for f in findings}
        for expected in ["requests", "urllib3", "flask", "django", "pyyaml", "pillow"]:
            assert expected in detected_pkgs
            finding = next(f for f in findings if f["package"] == expected)
            assert finding["severity"] == "HIGH"
            assert "CVE" in finding["description"]

    def test_sca_safe_manifest_zero_findings(self, tmp_path, safe_manifest_content):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(safe_manifest_content, encoding="utf-8")
        findings = scan_dependencies(req_file)
        assert len(findings) == 0

    def test_sca_manifest_with_comments_and_empty_lines(self, tmp_path):
        content = (
            "# Main requirements\n"
            "\n"
            "   # Indented comment\n"
            "requests==2.25.0\n"
            "\n"
            "click==8.1.7\n"
        )
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(content, encoding="utf-8")
        findings = scan_dependencies(req_file)
        assert len(findings) == 1
        assert findings[0]["package"] == "requests"

    def test_sca_version_prefix_matching(self, tmp_path):
        # pyyaml 5.1 is in KNOWN_VULNERABLE_PACKAGES, prefix match applies
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("pyyaml==5.1.2\n", encoding="utf-8")
        findings = scan_dependencies(req_file)
        assert len(findings) == 1
        assert findings[0]["package"] == "pyyaml"

    def test_sca_nonexistent_manifest_returns_empty(self, tmp_path):
        nonexistent = tmp_path / "does_not_exist_requirements.txt"
        findings = scan_dependencies(nonexistent)
        assert findings == []


# ==============================================================================
# Feature 4: Multi-Provider LLM Integration
# ==============================================================================

class TestMultiProviderLLMIntegration:

    def test_llm_client_missing_key_gemini(self, monkeypatch):
        monkeypatch.setattr(Config, "LLM_PROVIDER", "gemini")
        monkeypatch.setattr(Config, "GEMINI_API_KEY", "")
        with pytest.raises(ValueError, match="GEMINI_API_KEY"):
            LLMClient()

    def test_llm_client_missing_key_openai(self, monkeypatch):
        monkeypatch.setattr(Config, "LLM_PROVIDER", "openai")
        monkeypatch.setattr(Config, "OPENAI_API_KEY", "")
        with pytest.raises(ValueError, match="OPENAI_API_KEY"):
            LLMClient()

    def test_llm_client_missing_key_openrouter(self, monkeypatch):
        monkeypatch.setattr(Config, "LLM_PROVIDER", "openrouter")
        monkeypatch.setattr(Config, "OPENROUTER_API_KEY", "")
        with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
            LLMClient()

    def test_llm_client_missing_key_deepseek(self, monkeypatch):
        monkeypatch.setattr(Config, "LLM_PROVIDER", "deepseek")
        monkeypatch.setattr(Config, "DEEPSEEK_API_KEY", "")
        with pytest.raises(ValueError, match="DEEPSEEK_API_KEY"):
            LLMClient()

    def test_llm_client_unsupported_provider(self, monkeypatch):
        monkeypatch.setattr(Config, "LLM_PROVIDER", "unsupported_cloud")
        with pytest.raises(ValueError, match="không được hỗ trợ"):
            LLMClient()

    def test_tools_schema_definition(self):
        tool_names = {t["function"]["name"] for t in TOOLS_SCHEMA}
        expected = {"run_terminal_command", "read_file", "write_file", "list_files"}
        assert expected.issubset(tool_names)
        for t in TOOLS_SCHEMA:
            assert t["type"] == "function"
            assert "description" in t["function"]
            assert "parameters" in t["function"]


# ==============================================================================
# Feature 5: Offline Mock LLM Provider & Agent Responses
# ==============================================================================

class TestOfflineMockAgent:

    def test_agent_plain_text_response(self, monkeypatch):
        monkeypatch.setattr(Config, "LLM_PROVIDER", "openai")
        monkeypatch.setattr(Config, "OPENAI_API_KEY", "dummy_key")
        
        with patch("openai.OpenAI"):
            agent = BetHackerAgent()
            agent.client.chat_completion = MagicMock(return_value=DummyMessage(content="No vulnerabilities found."))
            res = agent.step("audit workspace")
            assert "No vulnerabilities found." in res
            assert len(agent.history) == 3  # system, user, assistant

    def test_agent_tool_dispatch_flow(self, monkeypatch, isolated_workspace):
        monkeypatch.setattr(Config, "LLM_PROVIDER", "openai")
        monkeypatch.setattr(Config, "OPENAI_API_KEY", "dummy_key")

        # Create a file in workspace
        (isolated_workspace / "target.py").write_text("print('hello')", encoding="utf-8")

        with patch("openai.OpenAI"):
            agent = BetHackerAgent()
            # Turn 1: request tool call read_file
            tool_call = DummyToolCall(
                id="call_1",
                function=DummyFunctionCall(name="read_file", arguments=json.dumps({"filepath": "target.py"}))
            )
            msg1 = DummyMessage(content="", tool_calls=[tool_call])
            # Turn 2: LLM provides analysis
            msg2 = DummyMessage(content="File analysis complete: safe.", tool_calls=None)

            agent.client.chat_completion = MagicMock(side_effect=[msg1, msg2])
            res = agent.step("check target.py")
            assert "File analysis complete: safe." in res
            # Check tool role recorded in history
            tool_entries = [h for h in agent.history if h.get("role") == "tool"]
            assert len(tool_entries) == 1
            assert "print('hello')" in tool_entries[0]["content"]

    def test_agent_max_turns_limit(self, monkeypatch):
        monkeypatch.setattr(Config, "LLM_PROVIDER", "openai")
        monkeypatch.setattr(Config, "OPENAI_API_KEY", "dummy_key")

        with patch("openai.OpenAI"):
            agent = BetHackerAgent()
            tool_call = DummyToolCall(
                id="call_loop",
                function=DummyFunctionCall(name="list_files", arguments="{}")
            )
            loop_msg = DummyMessage(content="", tool_calls=[tool_call])
            agent.client.chat_completion = MagicMock(return_value=loop_msg)
            res = agent.step("infinite loop")
            assert "Đã đạt giới hạn số lượt suy luận" in res

    def test_agent_custom_approval_callback(self, monkeypatch):
        monkeypatch.setattr(Config, "LLM_PROVIDER", "openai")
        monkeypatch.setattr(Config, "OPENAI_API_KEY", "dummy_key")
        monkeypatch.setattr(Config, "REQUIRE_APPROVAL", True)

        approval_mock = MagicMock(return_value=False)
        with patch("openai.OpenAI"):
            agent = BetHackerAgent(approval_callback=approval_mock)
            output = agent.dispatch_tool("run_terminal_command", {"command": "dir"})
            assert approval_mock.called
            assert "TỪ CHỐI" in output


# ==============================================================================
# Feature 6: Root Cause Analysis & Severity Rating
# ==============================================================================

class TestFindingDataStructure:

    def test_finding_structure_has_required_keys(self, tmp_path):
        sample = tmp_path / "sample.py"
        sample.write_text('DEBUG = True\n', encoding="utf-8")
        findings = scan_file_for_vulnerabilities(sample)
        assert len(findings) == 1
        finding = findings[0]
        required_keys = {"file", "line", "code_snippet", "vuln_id", "title", "severity", "category", "description"}
        assert required_keys.issubset(finding.keys())

    def test_finding_severities_valid(self):
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for pattern in VULN_PATTERNS:
            assert pattern["severity"] in valid_severities

    def test_finding_categories_align_with_owasp(self):
        for pattern in VULN_PATTERNS:
            assert "A0" in pattern["category"]
            assert "2021" in pattern["category"]

    def test_finding_exact_line_numbers(self, tmp_path):
        code = (
            "# Line 1: comment\n"
            "# Line 2: comment\n"
            "cursor.execute(f'SELECT {user}')\n"  # Line 3
            "# Line 4\n"
            "DEBUG = True\n"  # Line 5
        )
        sample = tmp_path / "lines.py"
        sample.write_text(code, encoding="utf-8")
        findings = scan_file_for_vulnerabilities(sample)
        assert len(findings) == 2
        assert findings[0]["line"] == 3
        assert findings[0]["vuln_id"] == "SEC-SQLI-001"
        assert findings[1]["line"] == 5
        assert findings[1]["vuln_id"] == "SEC-MISC-006"

    def test_finding_code_snippet_exact_match(self, tmp_path):
        raw_line = '   api_key = "AIzaSyD-1234567890abcdef"   '
        sample = tmp_path / "snippet.py"
        sample.write_text(raw_line + "\n", encoding="utf-8")
        findings = scan_file_for_vulnerabilities(sample)
        assert len(findings) == 1
        assert findings[0]["code_snippet"] == raw_line.strip()


# ==============================================================================
# Feature 7: Git-Compatible Unified Diff Generation
# ==============================================================================

class TestUnifiedDiffGeneration:

    def test_diff_generates_standard_headers(self):
        orig = "def run():\n    pass\n"
        patch = "def run():\n    return True\n"
        diff = generate_diff(orig, patch, "script.py")
        assert "a/script.py (Gốc)" in diff
        assert "b/script.py (Đã vá)" in diff

    def test_diff_contains_added_and_removed_lines(self):
        orig = 'os.system(f"ping {host}")\n'
        patch = 'subprocess.run(["ping", "-c", "1", host], check=True)\n'
        diff = generate_diff(orig, patch, "net.py")
        assert f"-{orig}" in diff
        assert f"+{patch}" in diff

    def test_diff_identical_content_is_empty(self):
        content = "print('identical')\n"
        diff = generate_diff(content, content, "same.py")
        assert diff == ""

    def test_diff_multiline_changes(self):
        orig = "line 1\nline 2\nline 3\n"
        patch = "line 1\nline modified 2\nline 3\n"
        diff = generate_diff(orig, patch, "multi.py")
        assert "@@" in diff
        assert "-line 2" in diff
        assert "+line modified 2" in diff

    def test_diff_crlf_normalization(self):
        orig = "line 1\r\nline 2\r\n"
        patch = "line 1\r\nline 2 fixed\r\n"
        diff = generate_diff(orig, patch, "crlf.py")
        assert "-line 2" in diff
        assert "+line 2 fixed" in diff


# ==============================================================================
# Feature 8: Safe Atomic Patching & .bak Backup
# ==============================================================================

class TestSafePatchingAndBackup:

    def test_create_backup_creates_bak_file(self, sample_patch_file):
        bak = create_backup(sample_patch_file)
        assert bak.exists()
        assert bak.name == "vulnerable_script.py.bak"
        assert bak.read_text(encoding="utf-8") == sample_patch_file.read_text(encoding="utf-8")

    def test_apply_patch_modifies_target_file(self, sample_patch_file):
        new_content = 'import subprocess\n\ndef run_cmd(param):\n    subprocess.run(["ping", param])\n'
        success, msg, diff = apply_patch(str(sample_patch_file), new_content)
        assert success is True
        assert "Đã vá thành công" in msg
        assert sample_patch_file.read_text(encoding="utf-8") == new_content

    def test_apply_patch_creates_backup_automatically(self, sample_patch_file):
        orig_content = sample_patch_file.read_text(encoding="utf-8")
        new_content = 'def patched():\n    pass\n'
        apply_patch(str(sample_patch_file), new_content)
        bak_file = sample_patch_file.with_suffix(".py.bak")
        assert bak_file.exists()
        assert bak_file.read_text(encoding="utf-8") == orig_content

    def test_apply_patch_nonexistent_file_fails(self, tmp_path):
        nonexistent = tmp_path / "none.py"
        success, msg, diff = apply_patch(str(nonexistent), "patched")
        assert success is False
        assert "không tồn tại" in msg
        assert diff is None

    def test_apply_patch_identical_content_no_op(self, sample_patch_file):
        orig = sample_patch_file.read_text(encoding="utf-8")
        success, msg, diff = apply_patch(str(sample_patch_file), orig)
        assert success is True
        assert "không có thay đổi" in msg
        assert diff == ""
        # Backup shouldn't be created on no-op
        bak = sample_patch_file.with_suffix(".py.bak")
        assert not bak.exists()

    def test_apply_patch_returns_valid_diff(self, sample_patch_file):
        new_content = 'print("new")\n'
        success, msg, diff = apply_patch(str(sample_patch_file), new_content)
        assert success is True
        assert diff is not None
        assert "--- a/vulnerable_script.py (Gốc)" in diff
        assert "+++ b/vulnerable_script.py (Đã vá)" in diff


# ==============================================================================
# Feature 9: Byte-Verified Rollback Restoration
# ==============================================================================

class TestByteVerifiedRollback:

    def test_rollback_restores_original_content(self, sample_patch_file):
        orig_content = sample_patch_file.read_text(encoding="utf-8")
        patched_content = 'print("injected patch")\n'
        apply_patch(str(sample_patch_file), patched_content)
        assert sample_patch_file.read_text(encoding="utf-8") == patched_content

        success, msg = rollback_backup(sample_patch_file)
        assert success is True
        assert "Đã khôi phục thành công" in msg
        assert sample_patch_file.read_text(encoding="utf-8") == orig_content

    def test_rollback_preserves_backup_file(self, sample_patch_file):
        apply_patch(str(sample_patch_file), 'print("patched")\n')
        bak = sample_patch_file.with_suffix(".py.bak")
        assert bak.exists()
        rollback_backup(sample_patch_file)
        # Bak file should still exist as safety net
        assert bak.exists()

    def test_rollback_missing_backup_fails(self, tmp_path):
        target = tmp_path / "no_bak.py"
        target.write_text("content", encoding="utf-8")
        success, msg = rollback_backup(target)
        assert success is False
        assert "Không tìm thấy file sao lưu" in msg

    def test_rollback_after_multi_step_patch(self, sample_patch_file):
        orig_content = sample_patch_file.read_text(encoding="utf-8")
        # Patch step 1
        apply_patch(str(sample_patch_file), "patch 1")
        # Rollback immediately
        rollback_backup(sample_patch_file)
        assert sample_patch_file.read_text(encoding="utf-8") == orig_content

    def test_rollback_with_nonexistent_target_restores_from_bak(self, tmp_path):
        target = tmp_path / "deleted.py"
        bak = tmp_path / "deleted.py.bak"
        bak.write_text("saved from bak", encoding="utf-8")
        success, msg = rollback_backup(target)
        assert success is True
        assert target.read_text(encoding="utf-8") == "saved from bak"


# ==============================================================================
# Feature 10: Interactive Rich Terminal CLI & REPL
# ==============================================================================

class TestTerminalCLIAndREPL:

    def test_main_help_function(self, capsys):
        from main import print_help
        print_help()
        # Verify Help function executes cleanly

    def test_banner_constant_is_valid(self):
        from main import BANNER
        assert "AI-Powered" in BANNER
        assert "Offensive Security" in BANNER

    def test_config_ensure_workspace(self, tmp_path, monkeypatch):
        test_ws = tmp_path / "dynamic_ws"
        monkeypatch.setattr(Config, "WORKSPACE_DIR", test_ws)
        assert not test_ws.exists()
        Config.ensure_workspace()
        assert test_ws.exists()
        assert test_ws.is_dir()

    def test_config_defaults(self):
        assert isinstance(Config.COMMAND_TIMEOUT, int)
        assert Config.COMMAND_TIMEOUT > 0
        assert isinstance(Config.REQUIRE_APPROVAL, bool)
        assert Config.WORKSPACE_DIR is not None

    def test_main_cli_importable(self):
        import main
        assert hasattr(main, "main")
        assert hasattr(main, "print_help")


# ==============================================================================
# Feature 11: CLI Commands & Tool Dispatching
# ==============================================================================

class TestCLIToolDispatching:

    def test_tool_dispatch_read_file(self, isolated_workspace):
        (isolated_workspace / "demo.txt").write_text("demo content", encoding="utf-8")
        content = read_file("demo.txt")
        assert content == "demo content"

    def test_tool_dispatch_read_file_nonexistent(self, isolated_workspace):
        content = read_file("nonexistent_file_123.txt")
        assert "Lỗi: Tệp tin không tồn tại" in content

    def test_tool_dispatch_write_file(self, isolated_workspace):
        msg = write_file("written.txt", "new file written")
        assert "Thành công" in msg
        assert (isolated_workspace / "written.txt").read_text(encoding="utf-8") == "new file written"

    def test_tool_dispatch_append_file(self, isolated_workspace):
        write_file("append_test.txt", "part1\n")
        msg = append_file("append_test.txt", "part2\n")
        assert "Thành công" in msg
        assert (isolated_workspace / "append_test.txt").read_text(encoding="utf-8") == "part1\npart2\n"

    def test_tool_dispatch_list_files_empty(self, isolated_workspace):
        files = list_workspace_files()
        assert files == []

    def test_tool_dispatch_list_files_with_content(self, isolated_workspace):
        (isolated_workspace / "a.py").write_text("a", encoding="utf-8")
        (isolated_workspace / "b.py").write_text("bb", encoding="utf-8")
        files = list_workspace_files()
        assert len(files) == 2
        names = {f["name"] for f in files}
        assert "a.py" in names
        assert "b.py" in names

    def test_agent_dispatch_unknown_tool(self, monkeypatch):
        monkeypatch.setattr(Config, "LLM_PROVIDER", "openai")
        monkeypatch.setattr(Config, "OPENAI_API_KEY", "dummy")
        with patch("openai.OpenAI"):
            agent = BetHackerAgent()
            res = agent.dispatch_tool("nonexistent_tool", {})
            assert "Lỗi: Không tìm thấy công cụ" in res


# ==============================================================================
# Feature 12: Terminal Execution & Dangerous Command Protection
# ==============================================================================

class TestTerminalCommandProtection:

    def test_dangerous_command_rm_rf(self):
        dangerous, reason = is_dangerous_command("rm -rf /")
        assert dangerous is True
        assert "nguy hiểm" in reason

    def test_dangerous_command_format_drive(self):
        dangerous, reason = is_dangerous_command("format C:")
        assert dangerous is True

    def test_dangerous_command_del_windows(self):
        dangerous, reason = is_dangerous_command("del /f /s /q c:\\")
        assert dangerous is True

    def test_dangerous_command_fork_bomb(self):
        dangerous, reason = is_dangerous_command(":(){ :|:& };:")
        assert dangerous is True

    def test_dangerous_command_shutdown(self):
        dangerous, reason = is_dangerous_command("shutdown -h now")
        assert dangerous is True

    def test_safe_commands_allowed(self):
        safe_cmds = [
            "python3 --version",
            "git status",
            "echo 'Hello World'",
            "pip list",
            "ls -la",
        ]
        for cmd in safe_cmds:
            dangerous, _ = is_dangerous_command(cmd)
            assert dangerous is False

    def test_execute_command_safe_echo(self, isolated_workspace):
        returncode, stdout, stderr = execute_command("echo test_safe_output")
        assert returncode == 0
        assert "test_safe_output" in stdout

    def test_execute_command_dangerous_blocked(self, isolated_workspace):
        returncode, stdout, stderr = execute_command("rm -rf /")
        assert returncode == -1
        assert "chặn bởi cơ chế bảo vệ" in stderr
