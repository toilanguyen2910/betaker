import shutil
import difflib
from pathlib import Path
from typing import Tuple, Optional

def create_backup(filepath: Path) -> Path:
    """Tạo một bản sao lưu .bak của tệp tin trước khi sửa đổi."""
    backup_path = filepath.with_suffix(filepath.suffix + ".bak")
    shutil.copy2(filepath, backup_path)
    return backup_path

def rollback_backup(filepath: Path) -> Tuple[bool, str]:
    """Khôi phục tệp tin từ bản sao lưu .bak."""
    backup_path = filepath.with_suffix(filepath.suffix + ".bak")
    if not backup_path.exists():
        return False, f"Không tìm thấy file sao lưu {backup_path.name}"

    try:
        shutil.copy2(backup_path, filepath)
        return True, f"Đã khôi phục thành công {filepath.name} từ {backup_path.name}"
    except Exception as e:
        return False, f"Lỗi khi khôi phục: {str(e)}"

def generate_diff(original_content: str, patched_content: str, filename: str) -> str:
    """Sinh ra chuỗi so sánh khác biệt (Unified Diff) giữa code cũ và code mới."""
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
    Áp dụng nội dung code mới vào tệp tin.
    Trả về: (thành_công, thông_báo, chuỗi_diff)
    """
    filepath = Path(filepath_str).resolve()
    if not filepath.exists():
        return False, f"Tệp tin không tồn tại: {filepath}", None

    try:
        original_content = filepath.read_text(encoding="utf-8", errors="replace")
        
        # Nếu nội dung giống hệt nhau thì không cần sửa
        if original_content == patched_content:
            return True, "Nội dung tệp tin không có thay đổi.", ""

        # Tạo bản sao lưu dự phòng
        backup_file = create_backup(filepath)

        # Tính toán Diff
        diff_text = generate_diff(original_content, patched_content, filepath.name)

        # Ghi đè nội dung mới an toàn
        filepath.write_text(patched_content, encoding="utf-8")

        return True, f"Đã vá thành công {filepath.name} (Bản lưu dự phòng: {backup_file.name})", diff_text

    except Exception as e:
        return False, f"Lỗi khi áp dụng bản vá: {str(e)}", None
