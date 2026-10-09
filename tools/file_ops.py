import os
from pathlib import Path
from typing import List, Dict, Any
from config import Config

def _resolve_safe_path(filepath: str) -> Path:
    """Đảm bảo đường dẫn nằm trong hoặc liên quan đến workspace."""
    path = Path(filepath)
    if not path.is_absolute():
        path = (Config.WORKSPACE_DIR / path).resolve()
    return path

def read_file(filepath: str, max_lines: int = 500) -> str:
    """Đọc nội dung một tệp tin."""
    target = _resolve_safe_path(filepath)
    if not target.exists():
        return f"Lỗi: Tệp tin không tồn tại tại {target}"
    if not target.is_file():
        return f"Lỗi: {target} không phải là một tệp tin thông thường."

    try:
        with open(target, "r", encoding="utf-8", errors="replace") as f:
            lines = [f.readline() for _ in range(max_lines)]
            content = "".join(lines)
            return content
    except Exception as e:
        return f"Lỗi khi đọc file: {str(e)}"

def write_file(filepath: str, content: str) -> str:
    """Ghi đè nội dung vào một tệp tin trong workspace."""
    target = _resolve_safe_path(filepath)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            f.write(content)
        return f"Thành công: Đã ghi {len(content)} ký tự vào {target.name}"
    except Exception as e:
        return f"Lỗi khi ghi file: {str(e)}"

def append_file(filepath: str, content: str) -> str:
    """Ghi nối tiếp nội dung vào cuối tệp tin."""
    target = _resolve_safe_path(filepath)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "a", encoding="utf-8") as f:
            f.write(content)
        return f"Thành công: Đã nối {len(content)} ký tự vào {target.name}"
    except Exception as e:
        return f"Lỗi khi nối file: {str(e)}"

def list_workspace_files() -> List[Dict[str, Any]]:
    """Liệt kê danh sách các tệp tin hiện có trong thư mục workspace."""
    results = []
    if not Config.WORKSPACE_DIR.exists():
        return results

    for item in Config.WORKSPACE_DIR.rglob("*"):
        if item.is_file():
            results.append({
                "name": item.relative_to(Config.WORKSPACE_DIR).as_posix(),
                "size_bytes": item.stat().st_size
            })
    return results
