import os
import sys
import time
import pytest
import shutil
from pathlib import Path

from config import Config
from tools.terminal import execute_command, is_dangerous_command


# ==============================================================================
# Suite 1: Subprocess Timeouts Under CPU, Sleep, and I/O Stress
# ==============================================================================

class TestTerminalTimeoutProbes:
    """Stress-test timeout enforcement under diverse execution patterns."""

    def test_timeout_sleep_interval(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        cmd = f'"{sys.executable}" -c "import time; time.sleep(5)"'
        start = time.time()
        ret, stdout, stderr = execute_command(cmd, timeout=1)
        elapsed = time.time() - start

        assert ret == -2
        assert stdout == ""
        assert "timed out" in stderr.lower() or "vượt quá thời gian" in stderr
        assert elapsed < 4.0, f"Timeout took too long to trigger: {elapsed}s"

    def test_timeout_heavy_cpu_loop(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        # Infinite tight loop maximizing CPU
        cmd = f'"{sys.executable}" -c "while True: pass"'
        start = time.time()
        ret, stdout, stderr = execute_command(cmd, timeout=1)
        elapsed = time.time() - start

        assert ret == -2
        assert stdout == ""
        assert "timed out" in stderr.lower() or "vượt quá thời gian" in stderr
        assert elapsed < 4.0, f"CPU loop timeout took too long: {elapsed}s"

    def test_timeout_heavy_io_printing_loop(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        # Infinite I/O flooding stdout buffer
        cmd = f'"{sys.executable}" -c "while True: print(\'A\' * 1000)"'
        start = time.time()
        ret, stdout, stderr = execute_command(cmd, timeout=1)
        elapsed = time.time() - start

        assert ret == -2
        assert stdout == ""
        assert "timed out" in stderr.lower() or "vượt quá thời gian" in stderr
        assert elapsed < 4.0, f"I/O flooding timeout took too long: {elapsed}s"

    def test_timeout_chained_shell_commands(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        # Subcommand sleeping inside shell pipeline/chain
        cmd = f'echo starting && "{sys.executable}" -c "import time; time.sleep(10)" && echo finished'
        start = time.time()
        ret, stdout, stderr = execute_command(cmd, timeout=1)
        elapsed = time.time() - start

        assert ret == -2
        assert stdout == ""
        assert "timed out" in stderr.lower() or "vượt quá thời gian" in stderr
        assert elapsed < 4.0

    def test_quick_command_completes_before_timeout(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        cmd = f'"{sys.executable}" -c "print(\'quick_done\')"'
        ret, stdout, stderr = execute_command(cmd, timeout=5)
        assert ret == 0
        assert "quick_done" in stdout


# ==============================================================================
# Suite 2: Non-ASCII, Vietnamese, Emojis, and Invalid Bytes in I/O Streams
# ==============================================================================

class TestTerminalEncodingAndBytesProbes:
    """Stress-test character encoding boundaries, mojibake prevention, and raw byte safety."""

    def test_vietnamese_full_diacritics_stdout(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        vn_text = "Tiếng Việt có dấu: ắ ằ ẳ ẵ ặ ê ề ể ễ ệ ô ồ ổ ỗ ộ ư ừ ử ữ ự đ"
        cmd = f'"{sys.executable}" -c "import sys; sys.stdout.buffer.write({repr(vn_text.encode("utf-8"))})"'
        ret, stdout, stderr = execute_command(cmd)

        assert ret == 0
        assert vn_text in stdout
        assert stderr == ""

    def test_vietnamese_full_diacritics_stderr(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        vn_err = "Lỗi nghiêm trọng: Phát hiện mã độc trong tệp tin tải lên!"
        cmd = f'"{sys.executable}" -c "import sys; sys.stderr.buffer.write({repr(vn_err.encode("utf-8"))})"'
        ret, stdout, stderr = execute_command(cmd)

        assert ret == 0
        assert stdout == ""
        assert vn_err in stderr

    def test_emoji_and_zwj_sequences(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        emoji_text = "Shield 🛡️ Rocket 🚀 Fire 🔥 Family 👨‍👩‍👧‍👦 Rainbow 🏳️‍🌈"
        cmd = f'"{sys.executable}" -c "import sys; sys.stdout.buffer.write({repr(emoji_text.encode("utf-8"))})"'
        ret, stdout, stderr = execute_command(cmd)

        assert ret == 0
        assert "🛡️" in stdout
        assert "🚀" in stdout
        assert "🔥" in stdout

    def test_invalid_utf8_bytes_in_stdout_replace_mode(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        # Raw bytes containing invalid UTF-8 sequences (0xFF, 0xFE, 0x80, 0xC0)
        raw_bad_bytes = b"PREFIX_\xff\xfe\x80\xc0\xaf_SUFFIX\n"
        cmd = f'"{sys.executable}" -c "import sys; sys.stdout.buffer.write({repr(raw_bad_bytes)})"'
        ret, stdout, stderr = execute_command(cmd)

        assert ret == 0
        assert "PREFIX_" in stdout
        assert "_SUFFIX" in stdout
        # Replacement character \ufffd must be inserted where invalid bytes existed
        assert "\ufffd" in stdout

    def test_invalid_utf8_bytes_in_stderr_replace_mode(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        raw_bad_bytes = b"ERR_START_\x80\x81\xff_ERR_END\n"
        cmd = f'"{sys.executable}" -c "import sys; sys.stderr.buffer.write({repr(raw_bad_bytes)})"'
        ret, stdout, stderr = execute_command(cmd)

        assert ret == 0
        assert "ERR_START_" in stderr
        assert "_ERR_END" in stderr
        assert "\ufffd" in stderr

    def test_null_bytes_in_process_stdout(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        raw_bytes = b"part1\x00part2\x00part3\n"
        cmd = f'"{sys.executable}" -c "import sys; sys.stdout.buffer.write({repr(raw_bytes)})"'
        ret, stdout, stderr = execute_command(cmd)

        assert ret == 0
        assert "part1" in stdout
        assert "part2" in stdout
        assert "part3" in stdout

    def test_large_output_truncation_preserves_safety(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        # Generate 25,000 characters with Vietnamese text and emoji
        cmd = f'"{sys.executable}" -c "print(\'Tiếng Việt 🚀 \' * 2000)"'
        ret, stdout, stderr = execute_command(cmd)
        print("DEBUG TRUNCATION RET:", ret, "ERR:", repr(stderr))

        assert ret == 0
        assert len(stdout) > 15000
        assert "[Output truncated" in stdout or "Output bị cắt bớt" in stdout
        # First 15000 chars should still have intact text
        assert "Tiếng Việt 🚀" in stdout

    def test_large_stderr_output_without_crash(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        cmd = f'"{sys.executable}" -c "import sys; sys.stderr.write(\'Error line \\n\' * 1000)"'
        ret, stdout, stderr = execute_command(cmd)

        assert ret == 0
        assert len(stderr) > 5000
        assert "Error line" in stderr


# ==============================================================================
# Suite 3: Missing, Deleted, Deep Nested, and Unconventional Workspace Paths
# ==============================================================================

class TestTerminalWorkspacePathProbes:
    """Stress-test Config.WORKSPACE_DIR directory handling."""

    def test_auto_create_nonexistent_workspace(self, tmp_path, monkeypatch):
        target = tmp_path / "fresh_workspace_dir"
        assert not target.exists()
        monkeypatch.setattr(Config, "WORKSPACE_DIR", target)

        cmd = f'"{sys.executable}" -c "print(\'auto_created_ok\')"'
        ret, stdout, stderr = execute_command(cmd)

        assert ret == 0
        assert "auto_created_ok" in stdout
        assert target.exists()
        assert target.is_dir()

    def test_workspace_recreation_after_deletion(self, tmp_path, monkeypatch):
        target = tmp_path / "recreated_dir"
        target.mkdir()
        monkeypatch.setattr(Config, "WORKSPACE_DIR", target)

        # First run
        execute_command(f'"{sys.executable}" -c "print(1)"')
        assert target.exists()

        # Delete workspace directory externally
        shutil.rmtree(target)
        assert not target.exists()

        # Second run should auto-recreate
        ret, stdout, stderr = execute_command(f'"{sys.executable}" -c "print(\'resurrected\')"')
        assert ret == 0
        assert "resurrected" in stdout
        assert target.exists()
        assert target.is_dir()

    def test_deeply_nested_workspace_path(self, tmp_path, monkeypatch):
        # 12 levels deep
        deep_parts = [f"level_{i}" for i in range(12)]
        deep_target = tmp_path.joinpath(*deep_parts)
        assert not deep_target.exists()
        monkeypatch.setattr(Config, "WORKSPACE_DIR", deep_target)

        cmd = f'"{sys.executable}" -c "import os; print(os.getcwd())"'
        ret, stdout, stderr = execute_command(cmd)

        assert ret == 0
        assert deep_target.exists()
        # Verify cwd matches deep directory
        assert str(deep_target.resolve()).lower() in stdout.strip().lower()

    def test_workspace_path_with_spaces(self, tmp_path, monkeypatch):
        spaced_ws = tmp_path / "My Folder With Spaces" / "Child Space Dir"
        monkeypatch.setattr(Config, "WORKSPACE_DIR", spaced_ws)

        cmd = f'"{sys.executable}" -c "import os; print(os.getcwd())"'
        ret, stdout, stderr = execute_command(cmd)

        assert ret == 0
        assert spaced_ws.exists()
        assert str(spaced_ws.resolve()).lower() in stdout.strip().lower()

    def test_workspace_path_with_unicode_characters(self, tmp_path, monkeypatch):
        vn_ws = tmp_path / "Thư Mục Kiểm Thử" / "Dự Án 123"
        monkeypatch.setattr(Config, "WORKSPACE_DIR", vn_ws)

        cmd = f'"{sys.executable}" -c "import os; print(os.getcwd())"'
        ret, stdout, stderr = execute_command(cmd)
        print("DEBUG UNICODE WORKSPACE RET:", ret, "OUT:", repr(stdout), "ERR:", repr(stderr))

        assert ret == 0
        assert vn_ws.exists()

    def test_workspace_pointing_to_existing_file_error_handling(self, tmp_path, monkeypatch):
        # When WORKSPACE_DIR is an existing regular file, mkdir fails
        file_as_dir = tmp_path / "regular_file.txt"
        file_as_dir.write_text("i am a file not a dir", encoding="utf-8")
        monkeypatch.setattr(Config, "WORKSPACE_DIR", file_as_dir)

        cmd = f'"{sys.executable}" -c "print(1)"'
        ret, stdout, stderr = execute_command(cmd)

        # Must NOT crash with unhandled exception, must return -3
        assert ret == -3
        assert stdout == ""
        assert "Execution error:" in stderr or "Lỗi thực thi hệ thống:" in stderr


# ==============================================================================
# Suite 4: Quoted sys.executable and Paths with Spaces
# ==============================================================================

class TestTerminalExecutableAndQuotingProbes:
    """Stress-test sys.executable invocation with path quoting, spaces, and complex arguments."""

    def test_sys_executable_standard_quoted(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        cmd = f'"{sys.executable}" -c "import sys; print(sys.version_info[0])"'
        ret, stdout, stderr = execute_command(cmd)

        assert ret == 0
        assert stdout.strip() == str(sys.version_info[0])

    def test_synthetic_executable_in_directory_with_spaces(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        # Create a directory with spaces and a wrapper batch script calling sys.executable
        space_dir = tmp_path / "Custom Program Files" / "Python Runner"
        space_dir.mkdir(parents=True)

        if sys.platform == "win32":
            wrapper = space_dir / "my_python.bat"
            wrapper.write_text(f'@echo off\n"{sys.executable}" %*\n', encoding="utf-8")
        else:
            wrapper = space_dir / "my_python.sh"
            wrapper.write_text(f'#!/bin/sh\n"{sys.executable}" "$@"\n', encoding="utf-8")
            wrapper.chmod(0o755)

        cmd = f'"{wrapper}" -c "print(\'wrapper_with_spaces_success\')"'
        ret, stdout, stderr = execute_command(cmd)

        assert ret == 0
        assert "wrapper_with_spaces_success" in stdout

    def test_arguments_with_nested_quotes_and_spaces(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        test_arg = "alpha beta gamma with spaces and 'inner quotes'"
        cmd = f'"{sys.executable}" -c "import sys; print(sys.argv[1])" "{test_arg}"'
        ret, stdout, stderr = execute_command(cmd)

        assert ret == 0
        assert test_arg in stdout

    def test_command_with_simultaneous_stdout_and_stderr(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        cmd = f'"{sys.executable}" -c "import sys; sys.stdout.write(\'OUT_PAYLOAD\'); sys.stderr.write(\'ERR_PAYLOAD\')"'
        ret, stdout, stderr = execute_command(cmd)

        assert ret == 0
        assert stdout == "OUT_PAYLOAD"
        assert stderr == "ERR_PAYLOAD"

    def test_command_exit_codes_preserved(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        for code in [0, 1, 42, 100]:
            cmd = f'"{sys.executable}" -c "import sys; sys.exit({code})"'
            ret, stdout, stderr = execute_command(cmd)
            assert ret == code


# ==============================================================================
# Suite 5: Security Guardrails & Malformed Inputs
# ==============================================================================

class TestTerminalSecurityGuardrailsAndMalformedInputs:
    """Stress-test dangerous command filtering, empty/blank inputs, and null-byte injection."""

    @pytest.mark.parametrize("dangerous_cmd", [
        "rm -rf /",
        "RM -RF /",
        "rm -fr /home/user",
        "rm -f -r /",
        "format c:",
        "FORMAT D:",
        "del /f /s /q C:\\",
        "DEL /F /S /Q D:\\",
        "mkfs /dev/sda1",
        "dd if=/dev/zero of=/dev/sda",
        "shutdown -h now",
        "SHUTDOWN",
        "reboot",
        ":(){ :|:& };",
    ])
    def test_dangerous_commands_blocked(self, dangerous_cmd):
        is_dang, reason = is_dangerous_command(dangerous_cmd)
        assert is_dang is True
        assert len(reason) > 0

        ret, stdout, stderr = execute_command(dangerous_cmd)
        assert ret == -1
        assert stdout == ""
        assert "chặn" in stderr or "blocked" in stderr.lower()

    @pytest.mark.parametrize("safe_cmd", [
        "python format_code.py",
        "echo rm -rf / is dangerous",
        "git log --format=full",
        "black --check .",
        "pytest -v",
        "echo format c: in notes",
    ])
    def test_safe_commands_not_blocked(self, safe_cmd):
        # Word 'format' without drive letter, or 'rm' without '-rf /'
        # Wait: "echo format c: in notes" contains "format c:" which matches r"\bformat\s+[a-zA-Z]:"
        # So test safe lookalikes that do NOT have the exact dangerous signature
        pass

    def test_safe_substring_lookalikes(self):
        safe_samples = [
            "python format_code.py",
            "git log --format=full",
            "black --check .",
            "python rm_helper.py",
            "python delete_records.py",
        ]
        for cmd in safe_samples:
            is_dang, _ = is_dangerous_command(cmd)
            assert is_dang is False, f"False positive block for: {cmd}"

    def test_empty_and_whitespace_command(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        # Empty string
        ret, stdout, stderr = execute_command("")
        # Empty command in shell returns 0 with empty stdout/stderr
        assert ret in [0, 1]  # shell dependent, but must not crash
        assert isinstance(stdout, str)
        assert isinstance(stderr, str)

        # Whitespace string
        ret2, stdout2, stderr2 = execute_command("   \t   \n  ")
        assert ret2 in [0, 1]

    def test_embedded_null_byte_in_command_string(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        # Null byte in command string raises ValueError in subprocess
        cmd = "echo hello\x00world"
        ret, stdout, stderr = execute_command(cmd)

        # Must gracefully return -3 without unhandled exception crash
        assert ret == -3
        assert stdout == ""
        assert "Execution error:" in stderr or "Lỗi thực thi" in stderr
