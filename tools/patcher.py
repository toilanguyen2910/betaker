import os
import shutil
import difflib
import tempfile
from pathlib import Path
from typing import Tuple, Optional


def _safe_bak_path(filepath: Path) -> Path:
    """Return the .bak path for filepath, ensuring it stays in the same directory."""
    return filepath.parent.resolve() / (filepath.name + ".bak")


def create_backup(filepath: Path) -> Path:
    """Create a .bak backup copy of the target file prior to modification.

    Uses shutil.copy2 to preserve metadata. The .bak file is always co-located
    with the original file (no path traversal possible).
    """
    backup_path = _safe_bak_path(filepath)
    shutil.copy2(filepath, backup_path)
    return backup_path


def rollback_backup(filepath: Path) -> Tuple[bool, str]:
    """Restore target file from its .bak backup copy with byte-level verification."""
    backup_path = _safe_bak_path(filepath)
    if not backup_path.exists():
        return False, f"Backup file not found / Không tìm thấy file sao lưu {backup_path.name}"

    try:
        shutil.copy2(backup_path, filepath)

        # Byte-level verification: restored file must be identical to backup
        original_bytes = backup_path.read_bytes()
        restored_bytes = filepath.read_bytes()
        if original_bytes != restored_bytes:
            return False, (
                f"Verification FAILED / Xác minh THẤT BẠI: "
                f"{filepath.name} ({len(restored_bytes)} bytes) ≠ "
                f"{backup_path.name} ({len(original_bytes)} bytes) after restore."
            )

        return True, f"Successfully restored / Đã khôi phục thành công {filepath.name} from {backup_path.name}"
    except Exception as e:
        return False, f"Error restoring backup / Lỗi khi khôi phục: {str(e)}"


def generate_diff(original_content: str, patched_content: str, filename: str) -> str:
    """Generate Unified Diff between original and patched source code."""
    original_lines = original_content.splitlines(keepends=True)
    patched_lines = patched_content.splitlines(keepends=True)

    diff = difflib.unified_diff(
        original_lines,
        patched_lines,
        fromfile=f"a/{filename} (Gốc)",
        tofile=f"b/{filename} (Đã vá)",
        n=3
    )
    return "".join(diff)


def apply_patch(filepath_str: str, patched_content: str) -> Tuple[bool, str, Optional[str]]:
    """Apply patched code to target file safely using atomic write (tempfile + os.replace).

    Guarantees:
    - Automatic .bak backup created before any modification.
    - Atomic write: content written to a temp file in the same directory, then
      renamed over the original — prevents partial writes on crash.
    - Returns (success, status_message, diff_text).
    """
    filepath = Path(filepath_str).resolve()
    if not filepath.exists():
        return False, f"Target file does not exist / Tệp tin không tồn tại: {filepath}", None

    try:
        original_content = filepath.read_text(encoding="utf-8", errors="replace")

        # If content is identical, skip modification
        if original_content == patched_content:
            return True, "File content is identical; no changes made / Nội dung tệp tin không có thay đổi.", ""

        # Create safety backup before any write
        backup_file = create_backup(filepath)

        # Compute Unified Diff
        diff_text = generate_diff(original_content, patched_content, filepath.name)

        # Atomic write: write to temp file in same dir, then os.replace
        dir_path = filepath.parent
        fd, tmp_path = tempfile.mkstemp(dir=dir_path, prefix=".betaker_patch_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_f:
                tmp_f.write(patched_content)
                tmp_f.flush()
                os.fsync(tmp_f.fileno())
            os.replace(tmp_path, filepath)
        except Exception:
            # Clean up temp file on failure
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        return True, f"Successfully patched / Đã vá thành công {filepath.name} (Backup: {backup_file.name})", diff_text

    except Exception as e:
        return False, f"Error applying patch / Lỗi khi áp dụng bản vá: {str(e)}", None
