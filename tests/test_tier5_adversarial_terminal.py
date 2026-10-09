"""
Tier 5 Adversarial Probes: Terminal Execution & Command Guardrails.
Probing tools/terminal.py for:
1. Command evasion vectors against is_dangerous_command.
2. Safe command pass-through and false positive edge cases.
3. Timeout boundary conditions (0.1s, 1s, 2s) and wall-clock latency.
4. Interface contract adherence: returncodes (-1, -2, -3, 0, non-zero exit codes).
"""

import sys
import time
import pytest
from pathlib import Path
from config import Config
from tools.terminal import execute_command, is_dangerous_command, DANGEROUS_PATTERNS


class TestDangerousCommandBlockAndEvasionVectors:
    """Test standard dangerous commands and identify evasion vectors."""

    @pytest.mark.parametrize("cmd", [
        # Canonical rm -rf patterns
        "rm -rf /",
        "rm -rf ~",
        "rm -rf /var",
        "rm -fr /",
        "rm -r /",
        "rm -f /",
        "RM -RF /",
        # Canonical Windows disk destruction
        "format c:",
        "FORMAT D:",
        "format z:",
        "del /f /s /q c:\\",
        "DEL /F /S /Q D:\\",
        "del /f /s /q C:\\windows",
        # System control & low-level destruction
        "shutdown",
        "shutdown -h now",
        "shutdown /s /t 0",
        "reboot",
        "mkfs",
        "mkfs /dev/sda1",
        "dd if=/dev/zero of=/dev/sda",
        ":(){ :|:& };:",
        ":() { :|:& };",
    ])
    def test_canonical_dangerous_commands_strictly_blocked(self, cmd):
        """Verify canonical dangerous commands are blocked by is_dangerous_command and execute_command."""
        is_dang, reason = is_dangerous_command(cmd)
        assert is_dang is True, f"Failed to detect dangerous command: {cmd}"
        assert len(reason) > 0

        ret, stdout, stderr = execute_command(cmd)
        assert ret == -1, f"Expected returncode -1 for blocked command, got {ret}"
        assert stdout == "", f"Expected empty stdout for blocked command, got {stdout}"
        assert "chặn bởi cơ chế bảo vệ" in stderr or "blocked" in stderr.lower()

    @pytest.mark.parametrize("evasion_cmd, description", [
        # Split flags: -r -f instead of -rf
        ("rm -r -f /", "Split flags -r -f bypasses regex requiring -rf or -fr"),
        ("rm -f -r /", "Split flags -f -r bypasses regex"),
        ("rm -rf --no-preserve-root /", "Intermediate flag before path bypasses regex"),
        ("rm -rf .", "Targeting relative current directory '.' bypasses regex"),
        ("rm -rf *", "Targeting glob wildcard '*' bypasses regex"),
        ('rm -rf "/"', "Quoting root path bypasses regex requiring immediate / or ~"),
        ("rm -rf '$HOME'", "Single quoting variable bypasses regex"),
        ("rm --recursive --force /", "GNU long options bypass regex"),
        # Format flag reordering
        ("format /q c:", "Reordered flag before drive letter bypasses format regex"),
        ("format /y c:", "Auto-confirm flag before drive bypasses regex"),
        ("format /fs:ntfs c:", "Filesystem flag before drive bypasses regex"),
        # Windows del flag reordering and alternative deletion utilities
        ("del /f /q /s c:\\", "Reordered del flags (/f /q /s instead of /f /s /q) bypasses regex"),
        ("del /s /f /q c:\\", "Reordered del flags (/s /f /q) bypasses regex"),
        ("del /q /s /f c:\\", "Reordered del flags (/q /s /f) bypasses regex"),
        ("del /f /s /q c:", "Missing trailing backslash bypasses regex"),
        ("del /f c:\\*.*", "Missing /s /q bypasses regex"),
        ("erase /f /s /q c:\\", "CMD built-in 'erase' synonym bypasses regex"),
        ("rd /s /q c:\\", "CMD built-in 'rd' directory removal bypasses regex"),
        ("rmdir /s /q c:\\", "CMD built-in 'rmdir' directory removal bypasses regex"),
        # dd parameter reordering
        ("dd of=/dev/sda if=/dev/zero", "Reordered dd flags (of= before if=) bypasses regex"),
        # Process fork bombs & alternative resource exhaustion
        ("bomb() { bomb | bomb & }; bomb", "Bash function rename bypasses fork bomb regex"),
        ('python -c "import os; [os.fork() for _ in iter(int, 1)]"', "Python fork bomb bypasses regex"),
    ])
    def test_evasion_vectors_demonstrated(self, evasion_cmd, description):
        """
        Adversarial proof: Demonstrate inputs that represent destructive actions
        but EVADE the regex patterns in is_dangerous_command.
        """
        is_dang, _ = is_dangerous_command(evasion_cmd)
        # We document these evasion vectors: is_dang is False even though command is destructive
        # This confirms that regex-based filtering is inherently vulnerable to syntactic evasion.
        # Note: We do NOT execute destructive commands with execute_command to preserve machine integrity!
        assert is_dang is False, f"Unexpectedly blocked: {evasion_cmd} ({description})"


class TestSafeCommandExecution:
    """Verify safe commands execute properly and return code 0 with captured output."""

    def test_safe_echo(self, isolated_workspace):
        ret, stdout, stderr = execute_command("echo hello_safe_adversarial")
        assert ret == 0
        assert "hello_safe_adversarial" in stdout
        assert stderr == ""

    def test_safe_python_command(self, isolated_workspace):
        cmd = f'"{sys.executable}" -c "print(1000 + 337)"'
        ret, stdout, stderr = execute_command(cmd)
        assert ret == 0
        assert "1337" in stdout.strip()
        assert stderr == ""

    def test_safe_dir_command(self, isolated_workspace):
        cmd = "dir" if sys.platform == "win32" else "ls -la"
        ret, stdout, stderr = execute_command(cmd)
        assert ret == 0
        assert len(stdout) > 0

    @pytest.mark.parametrize("safe_lookalike", [
        "python format_code.py",
        "git log --format=oneline",
        "black --check .",
        "python delete_records.py",
        "pytest -k 'test_format'",
    ])
    def test_safe_lookalikes_not_blocked(self, safe_lookalike):
        """Ensure legitimate developer tools containing partial keywords are not blocked."""
        is_dang, _ = is_dangerous_command(safe_lookalike)
        assert is_dang is False, f"False positive block for: {safe_lookalike}"

    @pytest.mark.parametrize("false_positive_candidate", [
        'echo "format c:"',
        'echo "shutdown in progress"',
        'echo "rm -rf / is dangerous"',
    ])
    def test_false_positive_guardrail_behavior(self, false_positive_candidate):
        """
        Demonstrate that naive substring matching causes false positives on safe commands
        that merely mention dangerous patterns in arguments or echo statements.
        """
        is_dang, reason = is_dangerous_command(false_positive_candidate)
        # Because regexes don't parse shell grammar or quotes, these safe echoes ARE blocked.
        # This is an observed boundary limitation of tools/terminal.py.
        assert is_dang is True
        assert len(reason) > 0


class TestTimeoutBoundaryConditions:
    """Verify timeout boundary conditions (short timeouts: 0.1s, 1s, 2s)."""

    def test_timeout_boundary_short_0_1s(self, tmp_path, monkeypatch):
        """Test short 0.1s timeout boundary with a 0.6s sleep."""
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        cmd = f'"{sys.executable}" -c "import time; time.sleep(0.6)"'
        start = time.perf_counter()
        ret, stdout, stderr = execute_command(cmd, timeout=0.1)
        elapsed = time.perf_counter() - start

        # Verify contract adherence
        assert ret == -2
        assert stdout == ""
        assert "timed out after 0.1s" in stderr or "vượt quá thời gian cho phép (0.1 giây)" in stderr

    def test_timeout_boundary_1s(self, tmp_path, monkeypatch):
        """Test 1s timeout boundary with a 2s sleep."""
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        cmd = f'"{sys.executable}" -c "import time; time.sleep(2)"'
        start = time.perf_counter()
        ret, stdout, stderr = execute_command(cmd, timeout=1)
        elapsed = time.perf_counter() - start

        # Verify contract adherence
        assert ret == -2
        assert stdout == ""
        assert "timed out after 1s" in stderr or "vượt quá thời gian cho phép (1 giây)" in stderr

    def test_timeout_boundary_2s(self, tmp_path, monkeypatch):
        """Test 2s timeout boundary with a 3.5s sleep."""
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        cmd = f'"{sys.executable}" -c "import time; time.sleep(3.5)"'
        start = time.perf_counter()
        ret, stdout, stderr = execute_command(cmd, timeout=2)
        elapsed = time.perf_counter() - start

        # Verify contract adherence
        assert ret == -2
        assert stdout == ""
        assert "timed out after 2s" in stderr or "vượt quá thời gian cho phép (2 giây)" in stderr

    def test_command_completes_within_short_timeout(self, tmp_path, monkeypatch):
        """A command finishing well before timeout must succeed with returncode 0."""
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        cmd = f'"{sys.executable}" -c "import time; time.sleep(0.05); print(\'completed_in_time\')"'
        ret, stdout, stderr = execute_command(cmd, timeout=2)

        assert ret == 0
        assert "completed_in_time" in stdout
        assert stderr == ""


class TestReturnCodeContractAdherence:
    """
    Verify strict adherence to Interface Contracts for return codes:
    -1: Guardrail blocked command
    -2: Subprocess timeout expired
    -3: System execution error
     0: Clean execution success
    >0: Process non-zero exit code
    """

    def test_contract_returncode_minus_1_blocked(self):
        ret, stdout, stderr = execute_command("shutdown -s -t 0")
        assert ret == -1
        assert stdout == ""
        assert len(stderr) > 0
        assert "chặn bởi cơ chế bảo vệ" in stderr

    def test_contract_returncode_minus_2_timeout(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        cmd = f'"{sys.executable}" -c "import time; time.sleep(1)"'
        ret, stdout, stderr = execute_command(cmd, timeout=0.1)
        assert ret == -2
        assert stdout == ""
        assert "timed out after 0.1s" in stderr

    def test_contract_returncode_minus_3_execution_error_bad_workspace(self, tmp_path, monkeypatch):
        # Create a file at the target workspace path so mkdir(parents=True) fails with FileExistsError / NotADirectoryError
        bad_ws = tmp_path / "file_blocking_workspace"
        bad_ws.write_text("blocker", encoding="utf-8")
        monkeypatch.setattr(Config, "WORKSPACE_DIR", bad_ws)

        ret, stdout, stderr = execute_command("echo test")
        assert ret == -3
        assert stdout == ""
        assert "Execution error:" in stderr or "Lỗi thực thi hệ thống:" in stderr

    def test_contract_returncode_minus_3_execution_error_null_byte(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "WORKSPACE_DIR", tmp_path)
        ret, stdout, stderr = execute_command("echo hello\x00evil")
        assert ret == -3
        assert stdout == ""
        assert "Execution error:" in stderr

    def test_contract_returncode_zero_success(self, isolated_workspace):
        ret, stdout, stderr = execute_command("echo all_good")
        assert ret == 0
        assert "all_good" in stdout
        assert stderr == ""

    @pytest.mark.parametrize("exit_code", [1, 2, 7, 42, 127, 255])
    def test_contract_arbitrary_nonzero_exit_codes_preserved(self, exit_code, isolated_workspace):
        cmd = f'"{sys.executable}" -c "import sys; sys.exit({exit_code})"'
        ret, stdout, stderr = execute_command(cmd)
        assert ret == exit_code
