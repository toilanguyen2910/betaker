import os
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from config import Config
from tools.scanner import (
    scan_file_for_vulnerabilities,
    scan_directory,
    scan_dependencies,
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
    _resolve_safe_path,
)
from tools.terminal import (
    is_dangerous_command,
    execute_command,
)


# ==============================================================================
# Tier 2 Boundary Group 1: Empty Files, Blank Lines & Extremes
# ==============================================================================

class TestEmptyFilesAndExtremes:

    def test_scan_empty_python_file(self, tmp_path):
        empty_file = tmp_path / "empty.py"
        empty_file.write_text("", encoding="utf-8")
        assert scan_file_for_vulnerabilities(empty_file) == []

    def test_scan_empty_javascript_file(self, tmp_path):
        empty_file = tmp_path / "empty.js"
        empty_file.write_text("", encoding="utf-8")
        assert scan_file_for_vulnerabilities(empty_file) == []

    def test_scan_whitespace_only_file(self, tmp_path):
        ws_file = tmp_path / "whitespace.py"
        ws_file.write_text("   \n\t\t\n   \n", encoding="utf-8")
        assert scan_file_for_vulnerabilities(ws_file) == []

    def test_scan_single_newline_file(self, tmp_path):
        nl_file = tmp_path / "newline.py"
        nl_file.write_text("\n", encoding="utf-8")
        assert scan_file_for_vulnerabilities(nl_file) == []

    def test_scan_empty_requirements_file(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("", encoding="utf-8")
        assert scan_dependencies(req) == []

    def test_scan_file_nonexistent_path(self, tmp_path):
        nonexistent = tmp_path / "does_not_exist.py"
        assert scan_file_for_vulnerabilities(nonexistent) == []

    def test_scan_file_called_on_directory(self, tmp_path):
        sub = tmp_path / "a_subfolder"
        sub.mkdir()
        assert scan_file_for_vulnerabilities(sub) == []

    def test_diff_two_empty_files(self):
        assert generate_diff("", "", "empty.py") == ""

    def test_diff_from_empty_to_new_content(self):
        diff = generate_diff("", "def new():\n    pass\n", "created.py")
        assert "+def new():" in diff
        assert "a/created.py (Gốc)" in diff

    def test_diff_from_content_to_empty(self):
        diff = generate_diff("def deleted():\n    pass\n", "", "deleted.py")
        assert "-def deleted():" in diff
        assert "b/deleted.py (Đã vá)" in diff

    def test_patch_empty_file_to_new_content(self, tmp_path):
        target = tmp_path / "was_empty.py"
        target.write_text("", encoding="utf-8")
        success, msg, diff = apply_patch(str(target), "print('now full')\n")
        assert success is True
        assert target.read_text(encoding="utf-8") == "print('now full')\n"
        assert target.with_suffix(".py.bak").read_text(encoding="utf-8") == ""

    def test_patch_to_empty_content(self, tmp_path):
        target = tmp_path / "make_empty.py"
        target.write_text("original content", encoding="utf-8")
        success, msg, diff = apply_patch(str(target), "")
        assert success is True
        assert target.read_text(encoding="utf-8") == ""
        assert target.with_suffix(".py.bak").read_text(encoding="utf-8") == "original content"

    def test_patch_empty_to_empty_is_noop(self, tmp_path):
        target = tmp_path / "stay_empty.py"
        target.write_text("", encoding="utf-8")
        success, msg, diff = apply_patch(str(target), "")
        assert success is True
        assert "không có thay đổi" in msg
        assert diff == ""


# ==============================================================================
# Tier 2 Boundary Group 2: CRLF vs LF Line Endings & Whitespace
# ==============================================================================

class TestLineEndingsAndWhitespaceBoundaries:

    def test_sast_scan_crlf_dos_endings(self, tmp_path):
        crlf_content = 'import os\r\nos.system(f"ping {host}")\r\nDEBUG = True\r\n'
        test_file = tmp_path / "dos.py"
        test_file.write_bytes(crlf_content.encode("utf-8"))
        findings = scan_file_for_vulnerabilities(test_file)
        assert len(findings) == 2
        assert findings[0]["line"] == 2
        assert findings[0]["vuln_id"] == "SEC-CMDI-002"
        assert findings[1]["line"] == 3
        assert findings[1]["vuln_id"] == "SEC-MISC-006"

    def test_sast_scan_mixed_line_endings(self, tmp_path):
        mixed = 'DEBUG = True\ros.system(f"ls {dir}")\ncursor.execute(f"SELECT {id}")\r\n'
        test_file = tmp_path / "mixed.py"
        test_file.write_bytes(mixed.encode("utf-8"))
        findings = scan_file_for_vulnerabilities(test_file)
        # splitlines() handles \r, \n, \r\n cleanly
        assert len(findings) >= 2

    def test_diff_with_crlf_line_endings(self):
        orig = 'line1\r\nline2\r\n'
        patched = 'line1\r\nline2_modified\r\n'
        diff = generate_diff(orig, patched, "crlf.py")
        assert "line2" in diff
        assert "line2_modified" in diff

    def test_patch_and_rollback_preserves_crlf(self, tmp_path):
        orig_bytes = b'def func():\r\n    return 42\r\n'
        target = tmp_path / "target_crlf.py"
        target.write_bytes(orig_bytes)

        apply_patch(str(target), 'def func():\r\n    return 99\r\n')
        rollback_backup(target)
        assert target.read_bytes() == orig_bytes

    def test_scanner_handles_indented_vulnerable_code(self, tmp_path):
        indented = (
            "class Service:\n"
            "    def execute_query(self, user_id):\n"
            "        if True:\n"
            "            while True:\n"
            '                cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
            "                break\n"
        )
        test_file = tmp_path / "indented.py"
        test_file.write_text(indented, encoding="utf-8")
        findings = scan_file_for_vulnerabilities(test_file)
        assert len(findings) == 1
        assert findings[0]["line"] == 5
        assert findings[0]["vuln_id"] == "SEC-SQLI-001"


# ==============================================================================
# Tier 2 Boundary Group 3: Unicode, Non-ASCII & Special Characters
# ==============================================================================

class TestUnicodeAndSpecialCharacters:

    def test_sast_scan_utf8_bom(self, tmp_path):
        content_with_bom = b'\xef\xbb\xbfDEBUG = True\n'
        test_file = tmp_path / "bom.py"
        test_file.write_bytes(content_with_bom)
        findings = scan_file_for_vulnerabilities(test_file)
        assert len(findings) == 1
        assert findings[0]["vuln_id"] == "SEC-MISC-006"

    def test_sast_scan_vietnamese_comments_and_strings(self, tmp_path):
        code = (
            "# Kiểm tra lỗ hổng bảo mật nghiêm trọng trong hệ thống\n"
            'thong_bao = "Đang kết nối tới cơ sở dữ liệu..."\n'
            'cursor.execute(f"SELECT * FROM nguoi_dung WHERE ma_so = {ma}")\n'
        )
        test_file = tmp_path / "vn.py"
        test_file.write_text(code, encoding="utf-8")
        findings = scan_file_for_vulnerabilities(test_file)
        assert len(findings) == 1
        assert findings[0]["vuln_id"] == "SEC-SQLI-001"

    def test_sast_scan_emojis_in_source(self, tmp_path):
        code = (
            'log("🔥 Khởi động dịch vụ...")\n'
            'os.system(f"echo 🚀 {target}")\n'
        )
        test_file = tmp_path / "emoji.py"
        test_file.write_text(code, encoding="utf-8")
        findings = scan_file_for_vulnerabilities(test_file)
        assert len(findings) == 1
        assert findings[0]["vuln_id"] == "SEC-CMDI-002"

    def test_sast_scan_binary_file_graceful_handling(self, tmp_path):
        # A pseudo-binary file with non-utf8 byte sequence
        binary_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff\xfe\xfd\x00\x00\x00'
        bin_file = tmp_path / "image.py"
        bin_file.write_bytes(binary_data)
        # Should not raise UnicodeDecodeError due to errors='replace'
        findings = scan_file_for_vulnerabilities(bin_file)
        assert isinstance(findings, list)

    def test_secret_key_boundary_characters(self, tmp_path):
        # Hyphens and dots in secret
        code = 'api_key = "abc-123.XYZ_456789"\n'
        test_file = tmp_path / "secret_chars.py"
        test_file.write_text(code, encoding="utf-8")
        findings = scan_file_for_vulnerabilities(test_file)
        assert len(findings) == 1
        assert findings[0]["vuln_id"] == "SEC-SECR-004"

    def test_secret_key_length_boundary(self, tmp_path):
        # {12,} boundary: 11 characters should NOT match, 12 characters SHOULD match
        too_short = 'api_key = "12345678901"\n'  # 11 chars
        just_enough = 'api_key = "123456789012"\n'  # 12 chars
        f1 = tmp_path / "short.py"
        f1.write_text(too_short, encoding="utf-8")
        f2 = tmp_path / "enough.py"
        f2.write_text(just_enough, encoding="utf-8")

        assert len(scan_file_for_vulnerabilities(f1)) == 0
        assert len(scan_file_for_vulnerabilities(f2)) == 1


# ==============================================================================
# Tier 2 Boundary Group 4: Directory Structure & Hidden Files
# ==============================================================================

class TestDirectoryStructureAndExclusions:

    def test_scan_directory_ignores_dotfiles(self, tmp_path):
        (tmp_path / ".hidden_vuln.py").write_text('DEBUG = True\n', encoding="utf-8")
        findings = scan_directory(str(tmp_path))
        assert len(findings) == 0

    def test_scan_directory_ignores_dot_directories(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "hook.py").write_text('os.system(f"echo {cmd}")\n', encoding="utf-8")
        findings = scan_directory(str(tmp_path))
        assert len(findings) == 0

    def test_scan_directory_ignores_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules" / "some_pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text('eval("untrusted");\n', encoding="utf-8")
        findings = scan_directory(str(tmp_path))
        assert len(findings) == 0

    def test_scan_directory_ignores_venv(self, tmp_path):
        venv = tmp_path / "venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "site.py").write_text('DEBUG = True\n', encoding="utf-8")
        findings = scan_directory(str(tmp_path))
        assert len(findings) == 0

    def test_scan_directory_ignores_pycache(self, tmp_path):
        pycache = tmp_path / "__pycache__"
        pycache.mkdir()
        (pycache / "compiled.py").write_text('DEBUG = True\n', encoding="utf-8")
        findings = scan_directory(str(tmp_path))
        assert len(findings) == 0

    def test_scan_directory_deep_nesting(self, tmp_path):
        deep = tmp_path / "src" / "modules" / "sub" / "core"
        deep.mkdir(parents=True)
        (deep / "nested.py").write_text('DEBUG = True\n', encoding="utf-8")
        findings = scan_directory(str(tmp_path))
        assert len(findings) == 1
        assert findings[0]["vuln_id"] == "SEC-MISC-006"

    def test_scan_directory_ignores_unsupported_extensions(self, tmp_path):
        (tmp_path / "data.csv").write_text('DEBUG = True\n', encoding="utf-8")
        (tmp_path / "notes.txt").write_text('DEBUG = True\n', encoding="utf-8")
        (tmp_path / "image.png").write_text('DEBUG = True\n', encoding="utf-8")
        findings = scan_directory(str(tmp_path))
        assert len(findings) == 0

    def test_scan_nonexistent_directory(self, tmp_path):
        nonexistent = tmp_path / "does_not_exist_dir"
        findings = scan_directory(str(nonexistent))
        assert len(findings) == 1
        assert "error" in findings[0]
        assert "không tồn tại" in findings[0]["error"]


# ==============================================================================
# Tier 2 Boundary Group 5: Malformed Dependency Manifests
# ==============================================================================

class TestDependencyManifestBoundaries:

    def test_sca_unversioned_package(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests\nflask\n", encoding="utf-8")
        findings = scan_dependencies(req)
        # Unversioned packages cannot be matched against version list
        assert len(findings) == 0

    def test_sca_case_insensitive_package_name(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("REQUESTS==2.25.0\nFlask==1.0.1\n", encoding="utf-8")
        findings = scan_dependencies(req)
        assert len(findings) == 2
        pkgs = {f["package"] for f in findings}
        assert pkgs == {"requests", "flask"}

    def test_sca_complex_whitespace(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("   requests   ==   2.25.0   \n", encoding="utf-8")
        findings = scan_dependencies(req)
        assert len(findings) == 1
        assert findings[0]["package"] == "requests"

    def test_sca_operators_boundary(self, tmp_path):
        # Splitting regex [=<>~]+ handles >=, <=, ~=, ==
        req = tmp_path / "requirements.txt"
        req.write_text("urllib3>=1.26.4\nflask~=1.0.1\n", encoding="utf-8")
        findings = scan_dependencies(req)
        assert len(findings) == 2

    def test_sca_unknown_package_with_vulnerable_version(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("my_custom_internal_pkg==2.25.0\n", encoding="utf-8")
        findings = scan_dependencies(req)
        assert len(findings) == 0

    def test_sca_only_comments(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("# requests==2.25.0\n# urllib3==1.26.4\n", encoding="utf-8")
        findings = scan_dependencies(req)
        assert len(findings) == 0

    def test_sca_malformed_lines_handled_gracefully(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("====\n>>><<<\n--extra-index-url https://example.com\n", encoding="utf-8")
        findings = scan_dependencies(req)
        assert isinstance(findings, list)


# ==============================================================================
# Tier 2 Boundary Group 6: Patch & Backup Boundary Conditions
# ==============================================================================

class TestPatchAndBackupBoundaries:

    def test_double_patch_overwrites_target(self, sample_patch_file):
        apply_patch(str(sample_patch_file), "version 2")
        assert sample_patch_file.read_text(encoding="utf-8") == "version 2"
        apply_patch(str(sample_patch_file), "version 3")
        assert sample_patch_file.read_text(encoding="utf-8") == "version 3"

    def test_double_rollback(self, sample_patch_file):
        orig = sample_patch_file.read_text(encoding="utf-8")
        apply_patch(str(sample_patch_file), "patched")
        # First rollback
        s1, m1 = rollback_backup(sample_patch_file)
        assert s1 is True
        assert sample_patch_file.read_text(encoding="utf-8") == orig
        # Second rollback: .bak still exists, should succeed idempotently
        s2, m2 = rollback_backup(sample_patch_file)
        assert s2 is True
        assert sample_patch_file.read_text(encoding="utf-8") == orig

    def test_rollback_corrupted_backup_path(self, tmp_path):
        target = tmp_path / "corrupted_target.py"
        target.write_text("curr", encoding="utf-8")
        # Backup path is a directory instead of file
        bak = tmp_path / "corrupted_target.py.bak"
        bak.mkdir()
        success, msg = rollback_backup(target)
        # shutil.copy2 will fail copying dir as file
        assert success is False
        assert "Lỗi khi khôi phục" in msg

    def test_patch_filename_with_multiple_dots(self, tmp_path):
        multi_dot = tmp_path / "my.app.config.v1.py"
        multi_dot.write_text("old", encoding="utf-8")
        success, msg, diff = apply_patch(str(multi_dot), "new")
        assert success is True
        bak = tmp_path / "my.app.config.v1.py.bak"
        assert bak.exists()
        assert bak.read_text(encoding="utf-8") == "old"

    def test_patch_filename_with_spaces(self, tmp_path):
        spaced = tmp_path / "my test script file.py"
        spaced.write_text("space old", encoding="utf-8")
        success, msg, diff = apply_patch(str(spaced), "space new")
        assert success is True
        assert spaced.read_text(encoding="utf-8") == "space new"

    def test_large_file_patching(self, tmp_path):
        large_lines = [f"line_{i} = {i}\n" for i in range(2000)]
        target = tmp_path / "large.py"
        target.write_text("".join(large_lines), encoding="utf-8")

        large_lines[1000] = "line_1000 = 'modified'\n"
        patched_content = "".join(large_lines)

        success, msg, diff = apply_patch(str(target), patched_content)
        assert success is True
        assert "line_1000 = 'modified'" in target.read_text(encoding="utf-8")
        assert target.with_suffix(".py.bak").exists()


# ==============================================================================
# Tier 2 Boundary Group 7: Dangerous Command & Terminal Boundaries
# ==============================================================================

class TestDangerousCommandBoundaries:

    def test_case_insensitive_dangerous_command(self):
        dangerous, reason = is_dangerous_command("RM -RF /")
        assert dangerous is True
        dangerous2, _ = is_dangerous_command("FORMAT C:")
        assert dangerous2 is True
        dangerous3, _ = is_dangerous_command("DEL /F /S /Q C:\\")
        assert dangerous3 is True

    def test_dangerous_patterns_mkfs_and_dd(self):
        d1, _ = is_dangerous_command("mkfs /dev/sda1")
        assert d1 is True
        d2, _ = is_dangerous_command("dd if=/dev/zero of=/dev/sda")
        assert d2 is True

    def test_dangerous_pattern_reboot(self):
        d, _ = is_dangerous_command("sudo reboot")
        assert d is True

    def test_safe_command_with_rm_word_in_string(self):
        # A file named 'rm_helper.py' shouldn't trigger 'rm -rf /'
        safe, _ = is_dangerous_command("python3 rm_helper.py")
        assert safe is False

    def test_safe_command_format_string(self):
        # Word 'format' without drive letter like 'c:'
        safe, _ = is_dangerous_command("black --check --format github")
        assert safe is False

    def test_empty_command(self):
        safe, reason = is_dangerous_command("")
        assert safe is False

    def test_whitespace_only_command(self):
        safe, reason = is_dangerous_command("   \t   ")
        assert safe is False

    def test_execute_command_timeout(self, isolated_workspace):
        # Run a command with 1 second timeout
        cmd = f'"{sys.executable}" -c "import time; time.sleep(5)"'
        returncode, stdout, stderr = execute_command(cmd, timeout=1)
        assert returncode == -2
        assert "vượt quá thời gian" in stderr

    def test_execute_command_utf8_non_ascii(self, isolated_workspace):
        # Verify Vietnamese text and emoji are returned without decoding crashes or mojibake
        cmd = f'"{sys.executable}" -c "import sys; sys.stdout.buffer.write(\'Ti\\u1ebfng Vi\\u1ec7t c\\u00f3 d\\u1ea5u v\\u00e0 emoji \\U0001f680\\n\'.encode(\'utf-8\'))"'
        returncode, stdout, stderr = execute_command(cmd)
        assert returncode == 0
        assert "Tiếng Việt có dấu và emoji" in stdout
        assert "🚀" in stdout

    def test_execute_command_auto_creates_missing_workspace(self, tmp_path, monkeypatch):
        # Verify missing workspace directory is auto-created
        missing_ws = tmp_path / "missing_auto_create_workspace"
        assert not missing_ws.exists()
        monkeypatch.setattr(Config, "WORKSPACE_DIR", missing_ws)

        cmd = f'"{sys.executable}" -c "print(\'workspace_created\')"'
        returncode, stdout, stderr = execute_command(cmd)
        assert returncode == 0
        assert "workspace_created" in stdout
        assert missing_ws.exists()
        assert missing_ws.is_dir()

    def test_dangerous_command_case_variations(self):
        for cmd in ["SHUTDOWN", "rEbOoT", "FOrMaT d:"]:
            dangerous, reason = is_dangerous_command(cmd)
            assert dangerous is True


# ==============================================================================
# Tier 2 Boundary Group 8: File Operations Boundaries
# ==============================================================================

class TestFileOperationsBoundaries:

    def test_read_file_max_lines_limit(self, isolated_workspace):
        content = "\n".join([f"line_{i}" for i in range(50)]) + "\n"
        (isolated_workspace / "multiline.txt").write_text(content, encoding="utf-8")
        read_result = read_file("multiline.txt", max_lines=5)
        lines = read_result.splitlines()
        assert len(lines) == 5
        assert lines[0] == "line_0"
        assert lines[-1] == "line_4"

    def test_read_file_on_directory(self, isolated_workspace):
        sub_dir = isolated_workspace / "sub_folder"
        sub_dir.mkdir()
        result = read_file("sub_folder")
        assert "không phải là một tệp tin thông thường" in result

    def test_write_file_deep_directory_creation(self, isolated_workspace):
        deep_path = "nested/deep/directory/output.log"
        result = write_file(deep_path, "deep content")
        assert "Thành công" in result
        created_file = isolated_workspace / "nested" / "deep" / "directory" / "output.log"
        assert created_file.exists()
        assert created_file.read_text(encoding="utf-8") == "deep content"

    def test_append_file_creates_new_if_missing(self, isolated_workspace):
        missing_target = "new_append.txt"
        result = append_file(missing_target, "first entry\n")
        assert "Thành công" in result
        target = isolated_workspace / missing_target
        assert target.exists()
        assert target.read_text(encoding="utf-8") == "first entry\n"

    def test_resolve_safe_path_relative(self, isolated_workspace):
        p = _resolve_safe_path("rel_file.py")
        assert p == (isolated_workspace / "rel_file.py").resolve()

    def test_resolve_safe_path_absolute(self, isolated_workspace):
        abs_target = (isolated_workspace / "abs.py").resolve()
        p = _resolve_safe_path(str(abs_target))
        assert p == abs_target

    def test_list_workspace_files_nested(self, isolated_workspace):
        (isolated_workspace / "root.py").write_text("root", encoding="utf-8")
        sub = isolated_workspace / "sub"
        sub.mkdir()
        (sub / "nested.py").write_text("nested", encoding="utf-8")

        files = list_workspace_files()
        assert len(files) == 2
        file_names = {f["name"] for f in files}
        assert "root.py" in file_names
        assert "sub/nested.py" in file_names

    def test_read_file_beyond_file_length(self, isolated_workspace):
        (isolated_workspace / "short.txt").write_text("line1\nline2\n", encoding="utf-8")
        res = read_file("short.txt", max_lines=1000)
        assert res == "line1\nline2\n"

    def test_write_file_empty_content(self, isolated_workspace):
        res = write_file("empty.txt", "")
        assert "Thành công" in res
        assert (isolated_workspace / "empty.txt").read_text(encoding="utf-8") == ""
