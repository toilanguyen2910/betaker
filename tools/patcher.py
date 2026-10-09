import shutil
import difflib
from pathlib import Path
from typing import Tuple, Optional

def create_backup(filepath: Path) -> Path:
    """Create a .bak backup copy of the target file prior to modification."""
    backup_path = filepath.with_suffix(filepath.suffix + ".bak")
    shutil.copy2(filepath, backup_path)
    return backup_path

def rollback_backup(filepath: Path) -> Tuple[bool, str]:
    """Restore target file from its .bak backup copy."""
    backup_path = filepath.with_suffix(filepath.suffix + ".bak")
    if not backup_path.exists():
        return False, f"Backup file not found / Không tìm thấy file sao lưu {backup_path.name}"

    try:
        shutil.copy2(backup_path, filepath)
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
    """
    Apply patched code to target file safely with automatic backup and diff generation.
    Returns: (success, status_message, diff_text)
    """
    filepath = Path(filepath_str).resolve()
    if not filepath.exists():
        return False, f"Target file does not exist / Tệp tin không tồn tại: {filepath}", None

    try:
        original_content = filepath.read_text(encoding="utf-8", errors="replace")
        
        # If content is identical, skip modification
        if original_content == patched_content:
            return True, "File content is identical; no changes made / Nội dung tệp tin không có thay đổi.", ""

        # Create safety backup
        backup_file = create_backup(filepath)

        # Compute Unified Diff
        diff_text = generate_diff(original_content, patched_content, filepath.name)

        # Atomically / safely write new content
        filepath.write_text(patched_content, encoding="utf-8")

        return True, f"Successfully patched / Đã vá thành công {filepath.name} (Backup: {backup_file.name})", diff_text

    except Exception as e:
        return False, f"Error applying patch / Lỗi khi áp dụng bản vá: {str(e)}", None
