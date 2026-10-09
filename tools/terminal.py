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
    """Kiểm tra xem lệnh có chứa mẫu nguy hiểm có thể phá hủy hệ điều hành hay không."""
    cmd_clean = command.strip().lower()
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, cmd_clean):
            return True, f"Lệnh bị chặn bởi cơ chế bảo vệ an toàn (chứa pattern nguy hiểm: '{pattern}')"
    return False, ""

def execute_command(command: str, timeout: int = None) -> Tuple[int, str, str]:
    """
    Thực thi một lệnh shell trên hệ thống, kèm theo cơ chế timeout và bắt lỗi.
    Trả về: (returncode, stdout, stderr)
    """
    if timeout is None:
        timeout = Config.COMMAND_TIMEOUT

    dangerous, reason = is_dangerous_command(command)
    if dangerous:
        return -1, "", reason

    try:
        # Chạy trong shell để hỗ trợ các cú pháp pipe, redirect hoặc công cụ CLI
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
        
        # Cắt tỉa output nếu quá dài để tránh tràn context token
        max_output_chars = 15000
        if len(stdout) > max_output_chars:
            stdout = stdout[:max_output_chars] + f"\n\n... [Output bị cắt bớt {len(stdout) - max_output_chars} ký tự vì quá dài] ..."
            
        return process.returncode, stdout, stderr

    except subprocess.TimeoutExpired:
        return -2, "", f"Lỗi: Lệnh vượt quá thời gian cho phép ({timeout} giây) và đã bị ngắt tự động."
    except Exception as e:
        return -3, "", f"Lỗi thực thi hệ thống: {str(e)}"
