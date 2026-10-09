import os
from pathlib import Path
from typing import List, Dict, Any
from config import Config

def _resolve_safe_path(filepath: str) -> Path:
    """Resolve target path, confining absolute paths to within the current working tree.

    Relative paths are anchored to WORKSPACE_DIR. Absolute paths outside the
    workspace are re-anchored to WORKSPACE_DIR to prevent path traversal.
    """
    path = Path(filepath)
    if not path.is_absolute():
        path = (Config.WORKSPACE_DIR / path).resolve()
    else:
        # Confine absolute paths: reject traversal outside workspace
        try:
            path.resolve().relative_to(Config.WORKSPACE_DIR.resolve())
        except ValueError:
            # Attacker-supplied absolute path escapes workspace → re-anchor
            path = (Config.WORKSPACE_DIR / path.name).resolve()
    return path

def read_file(filepath: str, max_lines: int = 500) -> str:
    """Read content of a target file up to max_lines."""
    target = _resolve_safe_path(filepath)
    if not target.exists():
        return f"Error: File does not exist / Lỗi: Tệp tin không tồn tại tại {target}"
    if not target.is_file():
        return f"Error: Target is not a regular file / Lỗi: {target} không phải là một tệp tin thông thường."

    try:
        with open(target, "r", encoding="utf-8", errors="replace") as f:
            lines = [f.readline() for _ in range(max_lines)]
            content = "".join(lines)
            return content
    except Exception as e:
        return f"Error reading file: {str(e)}"

def write_file(filepath: str, content: str) -> str:
    """Safely write content to a file in workspace directory."""
    target = _resolve_safe_path(filepath)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            f.write(content)
        return f"Success / Thành công: Written {len(content)} characters to {target.name}"
    except Exception as e:
        return f"Error writing file: {str(e)}"

def append_file(filepath: str, content: str) -> str:
    """Append content to an existing or new file in workspace directory."""
    target = _resolve_safe_path(filepath)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "a", encoding="utf-8") as f:
            f.write(content)
        return f"Success / Thành công: Appended {len(content)} characters to {target.name}"
    except Exception as e:
        return f"Error appending file: {str(e)}"

def list_workspace_files() -> List[Dict[str, Any]]:
    """List all files currently tracked in the workspace sandbox."""
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
