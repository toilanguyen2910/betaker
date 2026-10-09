import subprocess
import shlex
import re
from typing import Tuple
from config import Config

DANGEROUS_PATTERNS = [
    r"\brm\s+-(?:r|f|rf|fr)\s+[/~]",
    r"\bformat\s+[a-zA-Z]:",
    r"\bdel\s+/[fF]\s+/[sS]\s+/[qQ]\s+[a-zA-Z]:\\",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\bshutdown\b",
    r"\breboot\b",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;",  # Fork bomb
]

def is_dangerous_command(command: str) -> Tuple[bool, str]:
    """Check whether the command matches known destructive system patterns."""
    cmd_clean = command.strip().lower()
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, cmd_clean):
            return True, f"Command blocked by security guardrails / Lệnh bị chặn bởi cơ chế bảo vệ an toàn (chứa pattern nguy hiểm: '{pattern}')"
    return False, ""

def execute_command(command: str, timeout: int = None) -> Tuple[int, str, str]:
    """
    Execute a shell command with timeout enforcement and buffer truncation.
    Returns: (returncode, stdout, stderr)
    """
    if timeout is None:
        timeout = Config.COMMAND_TIMEOUT

    dangerous, reason = is_dangerous_command(command)
    if dangerous:
        return -1, "", reason

    try:
        # Run inside shell to support pipes and CLI utilities
        process = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=Config.WORKSPACE_DIR
        )
        stdout = process.stdout or ""
        stderr = process.stderr or ""
        
        # Truncate oversized output to avoid context overflow
        max_output_chars = 15000
        if len(stdout) > max_output_chars:
            stdout = stdout[:max_output_chars] + f"\n\n... [Output truncated / Output bị cắt bớt {len(stdout) - max_output_chars} characters because it was too long] ..."
            
        return process.returncode, stdout, stderr

    except subprocess.TimeoutExpired:
        return -2, "", f"Error: Command timed out after {timeout}s / Lỗi: Lệnh vượt quá thời gian cho phép ({timeout} giây) và đã bị ngắt tự động."
    except Exception as e:
        return -3, "", f"Execution error / Lỗi thực thi hệ thống: {str(e)}"
