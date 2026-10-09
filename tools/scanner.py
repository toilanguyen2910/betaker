"""BetHacker Security Code Auditor — SAST & SCA Scanning Engine.

Provides polyglot static application security testing (SAST) across Python,
JavaScript/TypeScript, Go, and PHP, alongside software composition analysis (SCA).
Zero external dependencies: uses only Python standard library.
"""

from dataclasses import dataclass, asdict, field
import fnmatch
import hashlib
import math
import os
from pathlib import Path
import re
from typing import Any, Dict, Generator, List, Optional, Set, Tuple, Union

from tools.sca import (
    DependencyFinding,
    KNOWN_VULNERABLE_PACKAGES,
    scan_dependencies as sca_scan_dependencies,
    scan_all_manifests,
)


# ============================================================================
# 1. DATA MODELS
# ============================================================================

@dataclass
class VulnerabilityFinding:
    """Represents a static security vulnerability detected in source code.

    Strictly satisfies PROJECT.md interface contract:
    id, rule_id, title, severity, file, line, snippet, description, language.
    Provides dict-like mapping access for backward compatibility with existing test suites.
    """
    id: str
    rule_id: str
    title: str
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    file: str
    line: int
    snippet: str
    description: str
    language: str
    cwe: str = ""
    category: str = ""
    end_line: Optional[int] = None
    remediation: str = ""
    confidence: str = "HIGH"

    def __post_init__(self) -> None:
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        self.severity = self.severity.strip().upper()
        if self.severity not in valid_severities:
            self.severity = "MEDIUM"

        valid_confidence = {"HIGH", "MEDIUM", "LOW"}
        self.confidence = self.confidence.strip().upper()
        if self.confidence not in valid_confidence:
            self.confidence = "HIGH"

        if self.line < 1:
            self.line = 1
        if self.end_line is not None and self.end_line < self.line:
            self.end_line = self.line

        try:
            self.file = Path(self.file).as_posix()
        except Exception:
            pass

        if not self.id:
            raw_sig = f"{self.rule_id}:{self.file}:{self.line}:{self.snippet[:40]}"
            digest = hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()[:10]
            self.id = f"{self.rule_id}-{digest}"

    @property
    def vuln_id(self) -> str:
        """Alias for rule_id to satisfy test suite assertions."""
        return self.rule_id

    @property
    def code_snippet(self) -> str:
        """Alias for snippet to satisfy test suite assertions."""
        return self.snippet

    def to_dict(self) -> Dict[str, Any]:
        """Converts finding into clean JSON-serializable dictionary."""
        data = asdict(self)
        data["vuln_id"] = self.rule_id
        data["code_snippet"] = self.snippet
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VulnerabilityFinding":
        """Constructs a VulnerabilityFinding instance safely from a dictionary."""
        return cls(
            id=data.get("id", ""),
            rule_id=data.get("rule_id", data.get("vuln_id", "SEC-GENERIC-000")),
            title=data.get("title", "Unknown Vulnerability"),
            severity=data.get("severity", "MEDIUM"),
            file=data.get("file", ""),
            line=int(data.get("line", 1)),
            snippet=data.get("snippet", data.get("code_snippet", "")),
            description=data.get("description", ""),
            language=data.get("language", "unknown"),
            cwe=data.get("cwe", ""),
            category=data.get("category", ""),
            end_line=data.get("end_line"),
            remediation=data.get("remediation", ""),
            confidence=data.get("confidence", "HIGH"),
        )

    def severity_rank(self) -> int:
        """Returns numeric rank for sorting (lower number = higher severity)."""
        ranks = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return ranks.get(self.severity, 4)

    # -----------------------------------------------------------------------
    # Dict-like Mapping Protocol for Backward Compatibility
    # -----------------------------------------------------------------------
    def __getitem__(self, key: str) -> Any:
        if key == "vuln_id":
            return self.rule_id
        if key == "code_snippet":
            return self.snippet
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:
        if key == "vuln_id":
            self.rule_id = value
        elif key == "code_snippet":
            self.snippet = value
        elif hasattr(self, key):
            setattr(self, key, value)
        else:
            raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        if key in ("vuln_id", "code_snippet"):
            return True
        return hasattr(self, str(key))

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def keys(self) -> List[str]:
        base_keys = list(self.__dataclass_fields__.keys())
        for alias in ("vuln_id", "code_snippet"):
            if alias not in base_keys:
                base_keys.append(alias)
        return base_keys

    def items(self) -> List[Tuple[str, Any]]:
        return [(k, self[k]) for k in self.keys()]

    def values(self) -> List[Any]:
        return [self[k] for k in self.keys()]

    def __hash__(self) -> int:
        return hash((self.rule_id, self.file, self.line))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VulnerabilityFinding):
            return False
        return (self.rule_id, self.file, self.line) == (other.rule_id, other.file, other.line)


@dataclass
class ScanSummary:
    """Summary metrics of a completed SAST/SCA scan."""
    total_files_scanned: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    scanned_languages: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================================
# 2. CONFIGURATION & CONSTANTS
# ============================================================================

CHUNK_SIZE: int = 4096
MAX_FILE_SIZE_BYTES: int = 2_000_000  # 2 MB limit

DEFAULT_IGNORED_DIRS: Set[str] = {
    ".git", ".svn", ".hg", ".bzr",
    "venv", ".venv", "env", ".env", "virtualenv", "ENV", ".tox", ".nox",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".hypothesis", ".eggs", "build", "dist",
    "node_modules", "bower_components", ".yarn", ".pnpm-store",
    ".next", ".nuxt", ".svelte-kit", ".turbo",
    "bin", "pkg", "obj", "target", ".gradle",
    ".idea", ".vscode", ".vs", ".settings", ".fleet",
    ".agents", "workspace", ".gemini",
    ".bak", "temp", "tmp", ".tmp",
}

DEFAULT_IGNORED_PATTERNS: Tuple[str, ...] = (
    "*.min.js", "*.min.css", "*.bundle.js", "*.bundle.min.js",
    "*.chunk.js", "*.map", "*.sourcemap",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock", "go.sum",
    "*.bak", "*.backup", "*~", "*.swp", "*.swo", "*.tmp",
    "*.pyc", "*.pyo", "*.pyd", "*.class", "*.o", "*.obj", "*.exe", "*.dll", "*.so", "*.dylib",
    "*.wasm", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg", "*.webp",
    "*.pdf", "*.zip", "*.tar", "*.gz", "*.7z", "*.rar",
    "*.woff", "*.woff2", "*.ttf", "*.eot",
    "*.log", "*.sqlite", "*.sqlite3", "*.db",
)

SUPPORTED_EXTENSIONS: Dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".go": "go",
    ".php": "php",
    ".phtml": "php",
    ".php3": "php",
    ".php4": "php",
    ".php5": "php",
    ".php7": "php",
    ".phps": "php",
    ".env": "config",
}

CONFIG_SECRET_FILENAMES: Set[str] = {
    ".env", ".env.local", ".env.development", ".env.production",
    ".env.staging", ".env.test", ".env.example",
}


# ============================================================================
# 3. RULE CATALOG (OWASP Top 10 Aligned)
# ============================================================================

VULN_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "SEC-SQLI-001",
        "title": "SQL Injection (Cộng/Nối chuỗi SQL không an toàn)",
        "severity": "CRITICAL",
        "category": "A03:2021 - Injection",
        "cwe": "CWE-89",
        "pattern": r"""(?i)(?:cursor\s*\.\s*execute|execute|raw|db\s*\.\s*(?:query(?:row)?|exec)|\$pdo\s*->\s*query|mysqli_query)\s*\(\s*(?:[a-zA-Z0-9_\$]+\s*,\s*)*(?:str\s*\(\s*)?(?:f["'].*?\{.*?\}|["'].*?%s.*?["']\s*%|(?:["'].*?["']\s*[\+\.]|[a-zA-Z0-9_\$]+\s*[\+\.]\s*["'])|`.*?\{.*?\}`|`.*?\$\{.*?\}`)""",
        "description": "Câu lệnh SQL được tạo bằng cách nối chuỗi trực tiếp từ biến đầu vào thay vì sử dụng tham số hóa (Parameterized Query / Prepared Statements).",
    },
    {
        "id": "SEC-CMDI-002",
        "title": "Command Injection (Thực thi lệnh Shell không lọc dữ liệu)",
        "severity": "CRITICAL",
        "category": "A03:2021 - Injection",
        "cwe": "CWE-78",
        "pattern": r"""(?x)
        (?:
            (?:os\.system|os\.popen)\s*\( |
            subprocess\.(?:call|Popen|run|check_output)\s*\(\s*(?:f["']|.*?shell\s*=\s*True) |
            exec\.Command(?:Context)?\s*\( |
            (?:system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\( |
            child_process\.(?:exec|execSync|spawn|spawnSync|execFile)\s*\(
        )
        """,
        "description": "Thực thi câu lệnh hệ điều hành với tùy chọn shell=True hoặc nối chuỗi trực tiếp, cho phép kẻ tấn công chèn ký tự điều khiển lệnh (&, |, ;).",
    },
    {
        "id": "SEC-TRAV-003",
        "title": "Path Traversal / LFI (Đọc/Ghi file không kiểm soát đường dẫn)",
        "severity": "HIGH",
        "category": "A01:2021 - Broken Access Control",
        "cwe": "CWE-22",
        "pattern": r"""(?x)
        (?:
            (?:open|send_file|send_from_directory|read_file)\s*\(\s*(?:request\.(?:args|form|values|GET|POST)|f["'].*?(?:path|filename|file)) |
            fs(?:\.promises)?\.(?:readFile|readFileSync|createReadStream|open)\s*\( |
            (?:os|ioutil)\.(?:ReadFile|Open|OpenFile)\s*\( |
            (?:file_get_contents|readfile|file_put_contents)\s*\(
        )
        """,
        "description": "Đường dẫn file được lấy trực tiếp từ người dùng mà không chuẩn hóa, có thể cho phép đọc trộm các file nhạy cảm trong hệ thống.",
    },
    {
        "id": "SEC-SECR-004",
        "title": "Hardcoded Secret / API Key (Lộ mật khẩu hoặc khóa bí mật trong mã nguồn)",
        "severity": "HIGH",
        "category": "A07:2021 - Identification and Authentication Failures",
        "cwe": "CWE-798",
        "pattern": r"""(?i)["']?(?:\$)??(?:api_?key|secret_?key|private_?key|aws_?secret|password|access_?token|auth_?token|client_?secret)["']?\s*(?::=|:|=)\s*["'][a-zA-Z0-9_\-\.\$\!\#/\+=]{12,}["']""",
        "description": "Mật khẩu, Token hoặc API Key được ghi cứng trực tiếp vào mã nguồn thay vì lưu trữ trong biến môi trường (.env).",
    },
    {
        "id": "SEC-DESER-005",
        "title": "Insecure Deserialization (Giải tuần tự hóa không an toàn)",
        "severity": "CRITICAL",
        "category": "A08:2021 - Software and Data Integrity Failures",
        "cwe": "CWE-502",
        "pattern": r"(?:pickle\.loads|yaml\.load\s*\(\s*.*?Loader\s*=\s*(?:yaml\.)?Loader|\beval\s*\(|\bexec\s*\(|unserialize\s*\()",
        "description": "Sử dụng pickle.loads, eval() hoặc yaml.load không an toàn trên dữ liệu không tin cậy có thể dẫn đến Thực thi Mã từ xa (RCE).",
    },
    {
        "id": "SEC-MISC-006",
        "title": "Insecure Configuration (Cấu hình DEBUG đang mở)",
        "severity": "MEDIUM",
        "category": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-489",
        "pattern": r"(?i)(?:DEBUG\s*=\s*True|app\.run\s*\(.*?debug\s*=\s*True)",
        "description": "Bật chế độ Debug trong môi trường chạy ứng dụng có thể làm lộ stack trace và thông tin nội bộ hệ thống.",
    },
    # -----------------------------------------------------------------------
    # New rules — R3 expansion
    # -----------------------------------------------------------------------
    {
        "id": "SEC-SSRF-007",
        "title": "Server-Side Request Forgery / SSRF (Giả mạo yêu cầu phía máy chủ)",
        "severity": "HIGH",
        "category": "A10:2021 - Server-Side Request Forgery",
        "cwe": "CWE-918",
        "pattern": r"""(?x)
        (?:
            requests\s*\.\s*(?:get|post|put|delete|head|patch|request)\s*\(\s*(?:request\.|req\.|url\s*=\s*(?:request\.|req\.)|f["'].*?\{) |
            urllib(?:\.request)?\s*\.\s*urlopen\s*\(\s*(?:request\.|req\.|url) |
            http\.(?:get|post)\s*\(\s*(?:req\.|request\.)
        )
        """,
        "description": "URL được lấy từ đầu vào người dùng và truyền trực tiếp vào hàm HTTP client, có thể cho phép kẻ tấn công thực hiện các yêu cầu đến mạng nội bộ hoặc dịch vụ Cloud metadata.",
        "remediation": "Dùng allowlist URL tĩnh hoặc kiểm tra scheme/host trước khi thực hiện yêu cầu HTTP.",
    },
    {
        "id": "SEC-XSS-008",
        "title": "Cross-Site Scripting / XSS (Chèn mã kịch bản độc hại phía client)",
        "severity": "HIGH",
        "category": "A03:2021 - Injection",
        "cwe": "CWE-79",
        "pattern": r"""(?x)
        (?:
            \.innerHTML\s*=\s*(?!["']) |
            \.outerHTML\s*=\s*(?!["']) |
            document\.write\s*\( |
            \$\s*\(\s*["'][^"']+["']\s*\)\s*\.html\s*\(\s*(?!["']) |
            Markup\s*\(\s*(?:request\.|req\.|user_input|f["'])
        )
        """,
        "description": "Nội dung người dùng được chèn trực tiếp vào DOM hoặc phản hồi HTML mà không được escape, cho phép tấn công XSS.",
        "remediation": "Sử dụng textContent thay innerHTML, hoặc dùng template engine tự động escape.",
    },
    {
        "id": "SEC-REDIR-009",
        "title": "Open Redirect (Chuyển hướng mở không kiểm soát)",
        "severity": "MEDIUM",
        "category": "A01:2021 - Broken Access Control",
        "cwe": "CWE-601",
        "pattern": r"""(?x)
        (?:
            redirect\s*\(\s*request\.(?:args|form|values|GET|POST)\s*\.\s*get\s*\( |
            return\s+redirect\s*\(\s*(?:request\.|req\.) |
            res\.redirect\s*\(\s*(?:req\.|request\.)
        )
        """,
        "description": "URL chuyển hướng được lấy trực tiếp từ tham số người dùng mà không xác thực, có thể bị lợi dụng để chuyển hướng nạn nhân đến trang độc hại.",
        "remediation": "Dùng allowlist URL nội bộ hoặc chỉ cho phép chuyển hướng đến các đường dẫn tương đối.",
    },
    {
        "id": "SEC-JWT-010",
        "title": "Hardcoded JWT / Token Secret (Lộ bí mật ký JWT trong mã nguồn)",
        "severity": "CRITICAL",
        "category": "A07:2021 - Identification and Authentication Failures",
        "cwe": "CWE-321",
        "pattern": r"""(?i)(?:jwt\.(?:encode|decode|sign)|sign\s*\(\s*payload)\s*\(.*?[,\(]\s*["'][A-Za-z0-9_\-\.]{20,}["']""",
        "description": "Khóa bí mật dùng để ký JWT được ghi cứng trực tiếp vào mã nguồn, cho phép bất kỳ ai có mã nguồn giả mạo token hợp lệ.",
        "remediation": "Đọc JWT secret từ biến môi trường hoặc secrets manager; sử dụng khóa bất đối xứng (RS256) thay HMAC.",
    },
    {
        "id": "SEC-MASS-011",
        "title": "Mass Assignment / Prototype Pollution (Gán thuộc tính hàng loạt không kiểm soát)",
        "severity": "HIGH",
        "category": "A08:2021 - Software and Data Integrity Failures",
        "cwe": "CWE-915",
        "pattern": r"""(?x)
        (?:
            Object\.assign\s*\(\s*(?:req\.(?:user|session|body)|user|session)\s*,\s*req\.body |
            \*\*request\.(?:json|form|get_json)\(\) |
            update\s*\(\s*\*\*request\.\w+\b
        )
        """,
        "description": "Thuộc tính từ request body được gán trực tiếp vào object/model mà không lọc trường, có thể cho phép kẻ tấn công ghi đè các trường đặc quyền như is_admin, role.",
        "remediation": "Dùng whitelist tường minh các trường được phép cập nhật; không dùng ** unpacking từ user input trực tiếp.",
    },
]



# ============================================================================
# 4. SAFE FILE READING & DIRECTORY TRAVERSAL
# ============================================================================

def is_binary_file(filepath: Union[Path, str], chunk_size: int = CHUNK_SIZE) -> bool:
    """Detects whether a file contains binary content."""
    path = Path(filepath)
    try:
        with open(path, "rb") as f:
            chunk = f.read(chunk_size)
            if not chunk:
                return False
            if b"\x00" in chunk:
                return True
            control_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
            non_printable = chunk.translate(None, control_chars)
            if len(non_printable) / len(chunk) > 0.10:
                return True
            return False
    except OSError:
        return True


def read_source_file_safe(
    filepath: Union[Path, str], max_size: int = MAX_FILE_SIZE_BYTES
) -> Optional[Tuple[str, List[str]]]:
    """Safely reads a source code file with multi-tier encoding fallback (utf-8-sig, cp1252, latin-1),
    line normalization (CRLF/CR -> LF), and size/binary safeguards.
    """
    path = Path(filepath)
    if not path.is_file():
        return None

    try:
        file_size = path.stat().st_size
        if file_size == 0:
            return ("", [])
        if file_size > max_size or is_binary_file(path):
            return None
    except OSError:
        return None

    encodings = ("utf-8-sig", "cp1252", "latin-1")
    content: Optional[str] = None

    for enc in encodings:
        try:
            with open(path, "r", encoding=enc) as f:
                content = f.read()
                break
        except (UnicodeDecodeError, UnicodeError):
            continue
        except OSError:
            return None

    if content is None:
        return None

    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    return normalized, normalized.splitlines()


def should_ignore_file(filename: str, extra_patterns: Optional[List[str]] = None) -> bool:
    """Checks whether a filename matches any default or custom ignore pattern."""
    patterns = DEFAULT_IGNORED_PATTERNS
    if extra_patterns:
        patterns = patterns + tuple(extra_patterns)
    for pattern in patterns:
        if fnmatch.fnmatch(filename.lower(), pattern.lower()):
            return True
    return False


def walk_source_files(
    root_dir: Union[str, Path],
    recursive: bool = True,
    extra_ignore_dirs: Optional[Set[str]] = None,
    extra_ignore_patterns: Optional[List[str]] = None,
    follow_symlinks: bool = False,
) -> Generator[Path, None, None]:
    """Yields all valid source code files under root_dir using top-down directory pruning."""
    root_path = Path(root_dir).resolve()
    if not root_path.exists():
        return

    if root_path.is_file():
        if not should_ignore_file(root_path.name, extra_ignore_patterns):
            yield root_path
        return

    ignored_dirs = set(DEFAULT_IGNORED_DIRS)
    if extra_ignore_dirs:
        ignored_dirs.update(extra_ignore_dirs)

    visited_inodes: Set[Tuple[int, int]] = set()

    for dirpath, dirnames, filenames in os.walk(root_path, topdown=True, followlinks=follow_symlinks):
        current_dir = Path(dirpath)

        if follow_symlinks:
            try:
                st = current_dir.stat()
                key = (st.st_dev, st.st_ino)
                if key in visited_inodes:
                    dirnames.clear()
                    continue
                visited_inodes.add(key)
            except OSError:
                dirnames.clear()
                continue

        # In-place directory pruning: Prevent descending into ignored directories
        dirnames[:] = [
            d for d in dirnames
            if d not in ignored_dirs and not d.startswith(".")
        ]

        for fname in filenames:
            # Ignore dotfiles unless it's a known environment file (.env, .env.local, etc.)
            if fname.startswith(".") and fname.lower() not in CONFIG_SECRET_FILENAMES:
                continue

            if should_ignore_file(fname, extra_ignore_patterns):
                continue

            file_path = current_dir / fname
            suffix = file_path.suffix.lower()

            if (
                suffix in SUPPORTED_EXTENSIONS
                or fname.lower() in CONFIG_SECRET_FILENAMES
                or fname.lower().endswith(".env")
                or fname.lower() in ("requirements.txt", "package.json")
            ):
                yield file_path

        if not recursive:
            break


def detect_language(filepath: Union[Path, str]) -> str:
    """Determines programming language or manifest type from file extension/name."""
    path = Path(filepath)
    name_lower = path.name.lower()
    if name_lower in CONFIG_SECRET_FILENAMES or name_lower.endswith(".env"):
        return "config"
    if name_lower == "requirements.txt":
        return "python_manifest"
    if name_lower == "package.json":
        return "npm_manifest"
    return SUPPORTED_EXTENSIONS.get(path.suffix.lower(), "unknown")


# ============================================================================
# 5. FALSE POSITIVE FILTERS & HEURISTICS
# ============================================================================

def is_line_comment(line_str: str, language: str) -> bool:
    """Determines if a line is a comment in the given language."""
    stripped = line_str.strip()
    if not stripped:
        return True
    if stripped.startswith("#"):
        return True
    if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
        return True
    return False


def is_suppressed_by_directive(line_str: str) -> bool:
    """Checks for inline security scanner suppression directives.

    Handles both spaced and compact variants:
      # nosec, #nosec, // nosec, //nosec, # bethacker:ignore, //bethacker:ignore
    """
    lowered = line_str.lower()
    directives = (
        "# nosec", "#nosec",
        "// nosec", "//nosec",
        "# bethacker:ignore", "//bethacker:ignore",
        "# betaker:ignore", "//betaker:ignore",
    )
    return any(d in lowered for d in directives)


def strip_inline_comment(line: str, lang: str) -> str:
    """Strips trailing comments from a code line while preserving string literals and URLs."""
    in_single = False
    in_double = False
    in_backtick = False
    escape = False
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if escape:
            escape = False
            i += 1
            continue
        if c == "\\":
            escape = True
            i += 1
            continue
        if c == "'" and not in_double and not in_backtick:
            in_single = not in_single
            i += 1
            continue
        if c == '"' and not in_single and not in_backtick:
            in_double = not in_double
            i += 1
            continue
        if c == "`" and not in_single and not in_double:
            in_backtick = not in_backtick
            i += 1
            continue
        if not in_single and not in_double and not in_backtick:
            if (lang in ("python", "php", "config") or lang == "unknown") and c == "#":
                return line[:i].rstrip()
            if (lang in ("javascript", "typescript", "go", "php") or lang == "unknown") and line[i:i+2] == "//":
                return line[:i].rstrip()
            if (lang in ("javascript", "typescript", "go", "php") or lang == "unknown") and line[i:i+2] == "/*":
                end_idx = line.find("*/", i + 2)
                if end_idx != -1:
                    line = line[:i] + " " + line[end_idx+2:]
                    n = len(line)
                    continue
                else:
                    return line[:i].rstrip()
        i += 1
    return line


def is_false_positive_sql(line_str: str) -> bool:
    """Filters out safe parameterized SQL queries."""
    if re.search(r'cursor\.execute\s*\(\s*["\'].*?%s["\']\s*,\s*\(', line_str):
        return True
    if re.search(r'cursor\.execute\s*\(\s*["\'].*?\?["\']\s*,\s*\[', line_str):
        return True
    if re.search(r'db\.execute\s*\(\s*["\'].*?:[a-zA-Z0-9_]+["\']\s*,\s*\{', line_str):
        return True
    if re.search(r'(?i)db\.Query\s*\(\s*["\'].*?\?["\']\s*,\s*', line_str):
        return True
    if re.search(r'(?i)db\.query\s*\(\s*["\'].*?\$[0-9]+["\']\s*,\s*\[', line_str):
        return True
    if re.search(r'(?i)db\.query\s*\(\s*["\'].*?\?["\']\s*,\s*\[', line_str):
        return True
    if re.search(r'\$pdo->prepare\s*\(', line_str):
        return True
    return False


def is_false_positive_cmdi(line_str: str) -> bool:
    """Filters out safe subprocess invocations without shell=True."""
    if re.search(r'subprocess\.(?:run|Popen|call|check_output)\s*\(\s*\[', line_str):
        if "shell=True" not in line_str and "shell = True" not in line_str:
            return True
    return False


def is_false_positive_path_trav(line_str: str) -> bool:
    """Filters out safe static file open operations."""
    if re.search(r'(?:open|os\.(?:Open|ReadFile)|fs\.(?:readFile|readFileSync))\s*\(\s*["\'][a-zA-Z0-9_\-\./\\]+["\']\s*(?:,\s*["\'][^"\']+["\'])?\s*\)', line_str):
        if "request." not in line_str and "{" not in line_str and "+" not in line_str and "$_" not in line_str and "req." not in line_str:
            return True
    return False


def is_false_positive_secret(line_str: str) -> bool:
    """Filters out safe environment variable access and dummy secret strings."""
    safe_patterns = (
        "os.getenv(",
        "os.environ.get(",
        "os.environ[",
        "process.env.",
        "os.Getenv(",
        "getenv(",
        "getpass.getpass()",
        "config.ACCESS_TOKEN",
        "config.SECRET_KEY",
        "config.",
    )
    if any(p in line_str for p in safe_patterns):
        return True

    placeholders = ("your_api_key_here", "placeholder", "changeme", "dummy", "todo", "example", "xxxxxxxx")
    if any(p in line_str.lower() for p in placeholders):
        return True

    return False


def is_false_positive_deser(line_str: str) -> bool:
    """Filters out safe deserialization and eval-like methods."""
    if "json.loads" in line_str or "yaml.safe_load" in line_str or "ast.literal_eval" in line_str:
        return True
    return False


def is_false_positive_debug(line_str: str) -> bool:
    """Filters out safe debug configurations (DEBUG = False)."""
    if re.search(r'DEBUG\s*=\s*False', line_str, re.IGNORECASE):
        return True
    if re.search(r'debug\s*=\s*False', line_str, re.IGNORECASE):
        return True
    return False


def is_false_positive_ssrf(line_str: str) -> bool:
    """Filters out safe static HTTP calls (hardcoded URLs, test fixtures)."""
    # Static string URL not from user input
    if re.search(r'requests\.\w+\s*\(\s*["\'](https?://[^"\']+)["\']', line_str):
        return True
    # Localhost / test URLs
    if re.search(r'(localhost|127\.0\.0\.1|0\.0\.0\.0)', line_str):
        return True
    return False


def is_false_positive_xss(line_str: str) -> bool:
    """Filters out safe static innerHTML assignments."""
    # Assignment of a plain string literal
    if re.search(r'\.innerHTML\s*=\s*["\'][^"\']*["\']', line_str):
        return True
    # DOMPurify or escaping wrapper
    if any(s in line_str for s in ("DOMPurify", "sanitize(", "escapeHtml(", "htmlspecialchars")):
        return True
    return False


def is_false_positive_jwt(line_str: str) -> bool:
    """Filters out safe JWT calls reading secret from env vars."""
    if any(s in line_str for s in ("os.getenv", "os.environ", "process.env", "os.Getenv", "config.")):
        return True
    return False


def is_false_positive_mass(line_str: str) -> bool:
    """Filters out safe whitelisted field updates."""
    # If there's a schema/validator call nearby, trust it
    if any(s in line_str for s in ("schema.load(", "validate(", "Serializer(", "only=", "exclude=")):
        return True
    return False


# ============================================================================
# 6. SCANNING ENGINE
# ============================================================================

# Compiled regex for JavaScript bare exec/spawn CMDi detection
JS_CMDI_REGEX = re.compile(r"""(?:\bexec|\bexecSync|\bspawn|\bspawnSync)\s*\(""")


def scan_file(filepath: Union[str, Path]) -> List[VulnerabilityFinding]:
    """Scans a single source code file for static vulnerabilities across supported languages.

    Returns a list of strongly-typed VulnerabilityFinding instances.
    """
    path = Path(filepath).resolve()
    findings: List[VulnerabilityFinding] = []

    if not path.is_file():
        return findings

    lang = detect_language(path)
    if lang in ("python_manifest", "npm_manifest"):
        return findings

    read_result = read_source_file_safe(path)
    if read_result is None:
        return findings

    content, lines = read_result
    if not lines or not content.strip():
        return findings

    seen: Set[Tuple[str, int]] = set()

    # Pass 1: Line-by-line scanning with inline comment stripping
    for line_num, line in enumerate(lines, start=1):
        line_str = line.strip()
        if not line_str:
            continue

        if is_suppressed_by_directive(line_str):
            continue

        if is_line_comment(line_str, lang):
            continue

        code_to_match = strip_inline_comment(line_str, lang)
        if not code_to_match.strip():
            continue

        # Language-aware dispatch: bare exec(...) in JS/TS is Command Injection (SEC-CMDI-002)
        if lang in ("javascript", "typescript") and JS_CMDI_REGEX.search(code_to_match):
            key = ("SEC-CMDI-002", line_num)
            if key not in seen:
                seen.add(key)
                findings.append(VulnerabilityFinding(
                    id=f"SEC-CMDI-002-{line_num}",
                    rule_id="SEC-CMDI-002",
                    title="Command Injection (Thực thi lệnh Shell không lọc dữ liệu)",
                    severity="CRITICAL",
                    file=str(path),
                    line=line_num,
                    snippet=line_str,
                    description="Thực thi câu lệnh hệ điều hành với tùy chọn shell=True hoặc nối chuỗi trực tiếp, cho phép kẻ tấn công chèn ký tự điều khiển lệnh (&, |, ;).",
                    language=lang,
                    cwe="CWE-78",
                    category="A03:2021 - Injection",
                ))

        for rule in VULN_PATTERNS:
            rule_id = rule["id"]

            if rule_id == "SEC-SQLI-001" and is_false_positive_sql(code_to_match):
                continue
            if rule_id == "SEC-CMDI-002" and is_false_positive_cmdi(code_to_match):
                continue
            if rule_id == "SEC-TRAV-003" and is_false_positive_path_trav(code_to_match):
                continue
            if rule_id == "SEC-SECR-004" and is_false_positive_secret(code_to_match):
                continue
            if rule_id == "SEC-DESER-005" and is_false_positive_deser(code_to_match):
                continue
            if rule_id == "SEC-MISC-006" and is_false_positive_debug(code_to_match):
                continue
            if rule_id == "SEC-SSRF-007" and is_false_positive_ssrf(code_to_match):
                continue
            if rule_id == "SEC-XSS-008" and is_false_positive_xss(code_to_match):
                continue
            if rule_id == "SEC-JWT-010" and is_false_positive_jwt(code_to_match):
                continue
            if rule_id == "SEC-MASS-011" and is_false_positive_mass(code_to_match):
                continue

            if re.search(rule["pattern"], code_to_match):
                key = (rule_id, line_num)
                if key not in seen:
                    seen.add(key)
                    findings.append(VulnerabilityFinding(
                        id=f"{rule_id}-{line_num}",
                        rule_id=rule_id,
                        title=rule["title"],
                        severity=rule["severity"],
                        file=str(path),
                        line=line_num,
                        snippet=line_str,
                        description=rule["description"],
                        language=lang,
                        cwe=rule.get("cwe", ""),
                        category=rule.get("category", ""),
                    ))

    # Pass 2: Multiline statements lookahead (strictly activated on unclosed delimiters)
    for start_idx in range(len(lines)):
        start_line_str = lines[start_idx].strip()
        if not start_line_str or is_suppressed_by_directive(start_line_str) or is_line_comment(start_line_str, lang):
            continue

        clean_start = strip_inline_comment(start_line_str, lang)
        net_parens = clean_start.count("(") - clean_start.count(")")
        net_brackets = clean_start.count("[") - clean_start.count("]")
        net_braces = clean_start.count("{") - clean_start.count("}")
        is_continuation = clean_start.endswith("\\")

        # Crucial guard: Only look ahead when delimiters are unclosed or line ends with '\'
        if net_parens <= 0 and net_brackets <= 0 and net_braces <= 0 and not is_continuation:
            continue

        block_lines = [lines[start_idx]]
        curr_p = net_parens
        curr_b = net_brackets

        for lookahead in range(1, 10):
            if start_idx + lookahead >= len(lines):
                break
            nxt = lines[start_idx + lookahead]
            if is_suppressed_by_directive(nxt):
                block_lines = []
                break
            block_lines.append(nxt)
            nxt_clean = strip_inline_comment(nxt.strip(), lang)
            curr_p += nxt_clean.count("(") - nxt_clean.count(")")
            curr_b += nxt_clean.count("[") - nxt_clean.count("]")
            if curr_p <= 0 and curr_b <= 0:
                break

        if not block_lines:
            continue

        combined_stripped = [strip_inline_comment(l.strip(), lang) for l in block_lines]
        block_str = " ".join(combined_stripped).strip()
        start_line_num = start_idx + 1

        for rule in VULN_PATTERNS:
            rule_id = rule["id"]
            if (rule_id, start_line_num) in seen:
                continue
            if rule_id == "SEC-SQLI-001" and is_false_positive_sql(block_str):
                continue
            if rule_id == "SEC-CMDI-002" and is_false_positive_cmdi(block_str):
                continue
            if rule_id == "SEC-TRAV-003" and is_false_positive_path_trav(block_str):
                continue
            if rule_id == "SEC-SECR-004" and is_false_positive_secret(block_str):
                continue
            if rule_id == "SEC-DESER-005" and is_false_positive_deser(block_str):
                continue
            if rule_id == "SEC-MISC-006" and is_false_positive_debug(block_str):
                continue
            if rule_id == "SEC-SSRF-007" and is_false_positive_ssrf(block_str):
                continue
            if rule_id == "SEC-XSS-008" and is_false_positive_xss(block_str):
                continue
            if rule_id == "SEC-JWT-010" and is_false_positive_jwt(block_str):
                continue
            if rule_id == "SEC-MASS-011" and is_false_positive_mass(block_str):
                continue

            if re.search(rule["pattern"], block_str):
                seen.add((rule_id, start_line_num))
                findings.append(VulnerabilityFinding(
                    id=f"{rule_id}-{start_line_num}",
                    rule_id=rule_id,
                    title=rule["title"],
                    severity=rule["severity"],
                    file=str(path),
                    line=start_line_num,
                    snippet=start_line_str,
                    description=rule["description"],
                    language=lang,
                    cwe=rule.get("cwe", ""),
                    category=rule.get("category", ""),
                    end_line=start_idx + len(block_lines),
                ))

    # Sort findings by line number
    findings.sort(key=lambda f: f.line)
    return findings


# Backward compatibility alias
scan_file_for_vulnerabilities = scan_file


def scan_directory(
    dirpath: Union[str, Path],
    recursive: bool = True,
    extra_ignore_dirs: Optional[Set[str]] = None,
    extra_ignore_patterns: Optional[List[str]] = None,
) -> List[Any]:
    """Recursively scans a directory for source code vulnerabilities.

    Prunes ignored directories (.git, node_modules, venv), skips binaries,
    and returns a list of VulnerabilityFinding objects.
    """
    target_dir = Path(dirpath).resolve()
    if not target_dir.exists():
        return [{"error": f"Thư mục không tồn tại: {dirpath}"}]

    if target_dir.is_file():
        return scan_file(target_dir)

    all_findings: List[VulnerabilityFinding] = []
    seen: Set[Tuple[str, str, int]] = set()

    for file_path in walk_source_files(
        root_dir=target_dir,
        recursive=recursive,
        extra_ignore_dirs=extra_ignore_dirs,
        extra_ignore_patterns=extra_ignore_patterns,
    ):
        file_findings = scan_file(file_path)
        for f in file_findings:
            key = (f.rule_id, f.file, f.line)
            if key not in seen:
                seen.add(key)
                all_findings.append(f)

    # Sort globally by severity rank, then file path, then line number
    all_findings.sort(key=lambda f: (f.severity_rank(), f.file, f.line))
    return all_findings


def scan_dependencies(manifest_path: Union[str, Path]) -> List[DependencyFinding]:
    """Audits a dependency manifest file (requirements.txt or package.json)
    against the offline curated CVE database.
    Delegates to tools.sca.scan_dependencies.
    """
    return sca_scan_dependencies(manifest_path)


def scan_all(
    target_path: Union[str, Path], recursive: bool = True
) -> Tuple[List[VulnerabilityFinding], List[DependencyFinding]]:
    """Performs a complete audit (SAST code scan + SCA dependency scan) on target_path.

    Returns a tuple of (vulnerability_findings, dependency_findings).
    """
    target = Path(target_path).resolve()
    sast_findings: List[VulnerabilityFinding] = []

    if target.is_dir():
        raw_res = scan_directory(target, recursive=recursive)
        sast_findings = [f for f in raw_res if isinstance(f, VulnerabilityFinding)]
    elif target.is_file():
        sast_findings = scan_file(target)

    sca_findings: List[DependencyFinding] = []
    if target.is_dir():
        for manifest_name in ("requirements.txt", "package.json"):
            manifest_file = target / manifest_name
            if manifest_file.is_file():
                sca_findings.extend(scan_dependencies(manifest_file))
    elif target.name in ("requirements.txt", "package.json"):
        sca_findings.extend(scan_dependencies(target))

    return sast_findings, sca_findings
