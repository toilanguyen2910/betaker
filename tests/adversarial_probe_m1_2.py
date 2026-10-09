"""Second-Generation Adversarial Stress-Testing Suite for tools/scanner.py.
Author: Challenger M1_2_1
Milestone 1 Iteration 2

Executes empirical probes across Python, JS/TS, Go, and PHP to evaluate:
- Detection accuracy under deeply nested parentheses, brackets, and call wrappers
- Multiline formatting variations, line continuations, and lookahead window limits
- Mixed comments, inline suppression directives, and comment markers in string literals
- International characters and encodings (UTF-8 BOM, Vietnamese, CJK, CRLF, CP1252)
- Zero-length files, whitespace, giant lines, and binary boundaries
- Exact line numbers and snippet fidelity
- False positive resistance across polyglot safe constructs
- Evasion vectors: parenthesized arguments, backslash continuations, keyword arguments,
  and path traversal f-string variable restrictions
"""

import os
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Safe UTF-8 output on Windows console
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from tools.scanner import (
    scan_file,
    scan_directory,
    scan_all,
    VulnerabilityFinding,
    VULN_PATTERNS,
)


class AdversarialProbe:
    def __init__(self, name: str, category: str, is_bug_check: bool = False):
        self.name = name
        self.category = category
        self.is_bug_check = is_bug_check
        self.passed = False
        self.details = ""
        self.findings: List[VulnerabilityFinding] = []

    def __repr__(self):
        status = "PASS" if self.passed else "FAIL"
        return f"[{status}] {self.category} :: {self.name} - {self.details}"


# Prevent pytest from collecting this helper class
AdversarialProbe.__test__ = False


def probe(filename: str, content: str, encoding: str = "utf-8") -> List[VulnerabilityFinding]:
    with tempfile.TemporaryDirectory() as td:
        file_path = Path(td) / filename
        file_path.write_text(content, encoding=encoding)
        return scan_file(file_path)


# ==============================================================================
# Suite 1: Deeply Nested Parens, Brackets, and Call Wrappers
# ==============================================================================

def test_suite_deeply_nested_parens() -> List[AdversarialProbe]:
    results = []

    # 1.1 Python SQLi 1 level of nested paren
    f1 = probe("nest_sqli_1.py", 'cursor.execute((f"SELECT * FROM users WHERE id = {uid}"))\n')
    r1 = AdversarialProbe("Python SQLi with 1 nested paren wrapper '((f\"...\"))'", "Deep Nesting", is_bug_check=True)
    r1.findings = f1
    if len(f1) >= 1 and f1[0].rule_id == "SEC-SQLI-001":
        r1.passed = True
        r1.details = "Detected through 1 nested paren"
    else:
        r1.passed = False
        r1.details = f"BUG: Missed SQLi wrapped in parentheses '((f\"...\"))'! Findings: {f1}"
    results.append(r1)

    # 1.2 Python SQLi 5 levels of parens
    f2 = probe("nest_sqli_5.py", 'cursor.execute(((((f"SELECT * FROM users WHERE id = {uid}")))))\n')
    r2 = AdversarialProbe("Python SQLi with 5 nested paren wrappers", "Deep Nesting", is_bug_check=True)
    r2.findings = f2
    if len(f2) >= 1 and f2[0].rule_id == "SEC-SQLI-001":
        r2.passed = True
        r2.details = "Detected through 5 nested parens"
    else:
        r2.passed = False
        r2.details = f"BUG: Missed SQLi wrapped in 5 nested parens! Findings: {f2}"
    results.append(r2)

    # 1.3 Python CMDi 4 levels of parens
    f3 = probe("nest_cmdi_4.py", 'os.system((((f"ping {host}"))))\n')
    r3 = AdversarialProbe("Python CMDi with 4 nested paren wrappers", "Deep Nesting")
    r3.findings = f3
    if len(f3) >= 1 and f3[0].rule_id == "SEC-CMDI-002":
        r3.passed = True
        r3.details = "Detected through 4 nested parens"
    else:
        r3.passed = False
        r3.details = f"Failed to detect CMDi in nested parens: findings={f3}"
    results.append(r3)

    # 1.4 Python Path Traversal nested open
    f4 = probe("nest_trav.py", 'with open((f"/data/{filename}"), "r") as f: data = f.read()\n')
    r4 = AdversarialProbe("Python Path Traversal with nested open 'open((f\"...\"))'", "Deep Nesting", is_bug_check=True)
    r4.findings = f4
    if len(f4) >= 1 and f4[0].rule_id == "SEC-TRAV-003":
        r4.passed = True
        r4.details = "Detected nested path traversal"
    else:
        r4.passed = False
        r4.details = f"BUG: Missed path traversal wrapped in parens 'open((f\"...\"))'! Findings: {f4}"
    results.append(r4)

    # 1.5 Python Deserialization nested eval
    f5 = probe("nest_eval.py", 'res = eval((((user_input))))\n')
    r5 = AdversarialProbe("Python Deserialization nested eval", "Deep Nesting")
    r5.findings = f5
    if len(f5) >= 1 and f5[0].rule_id == "SEC-DESER-005":
        r5.passed = True
        r5.details = "Detected nested eval"
    else:
        r5.passed = False
        r5.details = f"Failed to detect nested eval: findings={f5}"
    results.append(r5)

    # 1.6 JS SQLi nested parens with concatenation
    f6 = probe("nest_js_sqli.js", 'db.query(("SELECT * FROM t WHERE id = " + userId));\n')
    r6 = AdversarialProbe("JavaScript SQLi nested parens 'db.query((\"...\" + id))'", "Deep Nesting", is_bug_check=True)
    r6.findings = f6
    if len(f6) >= 1 and f6[0].rule_id == "SEC-SQLI-001":
        r6.passed = True
        r6.details = "Detected nested JS SQLi"
    else:
        r6.passed = False
        r6.details = f"BUG: Missed JS SQLi wrapped in parens! Findings: {f6}"
    results.append(r6)

    return results


# ==============================================================================
# Suite 2: Multiline Formatting Variations & Line Continuations
# ==============================================================================

def test_suite_multiline_variations() -> List[AdversarialProbe]:
    results = []

    # 2.1 Multiline SQLi spanning 6 lines with intermediate comments
    content_sqli_6 = textwrap.dedent('''
        cursor.execute(
            # step 1: prepare query
            # step 2: format string
            f"SELECT * FROM accounts "
            f"WHERE id = {acc_id}"
        )
    ''').strip()
    f1 = probe("sqli_multiline_6.py", content_sqli_6)
    r1 = AdversarialProbe("Python SQLi multiline spanning 6 lines with comments", "Multiline Variations")
    r1.findings = f1
    if len(f1) >= 1 and f1[0].rule_id == "SEC-SQLI-001":
        r1.passed = True
        r1.details = f"Detected multiline SQLi (start line={f1[0].line}, end_line={f1[0].end_line})"
    else:
        r1.passed = False
        r1.details = f"Failed to detect multiline SQLi: findings={f1}"
    results.append(r1)

    # 2.2 Python SQLi with backslash line continuations
    content_backslash = (
        'cursor.execute( \\\n'
        '    "SELECT * FROM items WHERE id = " \\\n'
        '    + item_id \\\n'
        ')\n'
    )
    f2 = probe("sqli_backslash.py", content_backslash)
    r2 = AdversarialProbe("Python SQLi with backslash line continuations", "Multiline Variations", is_bug_check=True)
    r2.findings = f2
    if len(f2) >= 1 and f2[0].rule_id == "SEC-SQLI-001":
        r2.passed = True
        r2.details = "Detected backslash-continued SQLi"
    else:
        r2.passed = False
        r2.details = f"BUG: Missed backslash-continued SQLi (trailing '\\' retained in multiline joiner)! Findings: {f2}"
    results.append(r2)

    # 2.3 JS Multiline template literal with internal line breaks
    content_js_multi = textwrap.dedent('''
        db.query(
            `SELECT *
             FROM users
             WHERE id = ${
                userId
             }`
        );
    ''').strip()
    f3 = probe("sqli_js_multi.js", content_js_multi)
    r3 = AdversarialProbe("JavaScript multiline ES6 template literal SQLi", "Multiline Variations")
    r3.findings = f3
    if len(f3) >= 1 and f3[0].rule_id == "SEC-SQLI-001":
        r3.passed = True
        r3.details = "Detected multiline JS template SQLi"
    else:
        r3.passed = False
        r3.details = f"Failed to detect multiline JS template SQLi: findings={f3}"
    results.append(r3)

    # 2.4 Go Multiline db.Query with capital Q
    content_go_multi = textwrap.dedent('''
        rows, err := db.Query(
            "SELECT * FROM users WHERE id = " +
                userId,
        )
    ''').strip()
    f4 = probe("sqli_go_multi.go", content_go_multi)
    r4 = AdversarialProbe("Go multiline db.Query concatenation", "Multiline Variations")
    r4.findings = f4
    if len(f4) >= 1 and f4[0].rule_id == "SEC-SQLI-001":
        r4.passed = True
        r4.details = "Detected multiline Go SQLi"
    else:
        r4.passed = False
        r4.details = f"Failed to detect multiline Go SQLi: findings={f4}"
    results.append(r4)

    # 2.5 PHP Multiline PDO dot concatenation
    content_php_multi = textwrap.dedent('''
        $stmt = $pdo->query(
            "SELECT * FROM users WHERE id = " .
            $userId
        );
    ''').strip()
    f5 = probe("sqli_php_multi.php", content_php_multi)
    r5 = AdversarialProbe("PHP multiline $pdo->query dot concatenation", "Multiline Variations")
    r5.findings = f5
    if len(f5) >= 1 and f5[0].rule_id == "SEC-SQLI-001":
        r5.passed = True
        r5.details = "Detected multiline PHP SQLi"
    else:
        r5.passed = False
        r5.details = f"Failed to detect multiline PHP SQLi: findings={f5}"
    results.append(r5)

    # 2.6 Multiline CMDi subprocess.Popen with shell=True on 4th line
    content_cmdi_multi = textwrap.dedent('''
        proc = subprocess.Popen(
            f"cat {filepath}",
            stdout=subprocess.PIPE,
            shell=True
        )
    ''').strip()
    f6 = probe("cmdi_popen_multi.py", content_cmdi_multi)
    r6 = AdversarialProbe("Python multiline subprocess.Popen with shell=True on 4th line", "Multiline Variations")
    r6.findings = f6
    if len(f6) >= 1 and f6[0].rule_id == "SEC-CMDI-002":
        r6.passed = True
        r6.details = "Detected multiline subprocess.Popen CMDi"
    else:
        r6.passed = False
        r6.details = f"Failed to detect multiline CMDi: findings={f6}"
    results.append(r6)

    # 2.7 Multiline statement exceeding 10 lines (lookahead window limit = 10)
    # When query spans > 10 lines before arguments finish
    content_over_10 = (
        'cursor.execute(\n'
        + '\n'.join([f'    # line {i}: spacer' for i in range(12)]) + '\n'
        + '    f"SELECT * FROM users WHERE id = {uid}"\n'
        + ')\n'
    )
    f7 = probe("sqli_over_10.py", content_over_10)
    r7 = AdversarialProbe("Multiline statement exceeding 10-line lookahead window", "Multiline Variations", is_bug_check=True)
    r7.findings = f7
    if len(f7) >= 1 and f7[0].rule_id == "SEC-SQLI-001":
        r7.passed = True
        r7.details = "Detected SQLi despite >10 lines"
    else:
        r7.passed = False
        r7.details = f"BUG: Lookahead window hardcoded to range(1, 10), misses statements spanning >10 lines! Findings: {f7}"
    results.append(r7)

    return results


# ==============================================================================
# Suite 3: Mixed Comments, Directives, and String Literals with Comment Markers
# ==============================================================================

def test_suite_mixed_comments() -> List[AdversarialProbe]:
    results = []

    # 3.1 String literal containing '#' marker
    content_str_hash = 'cursor.execute(f"SELECT * FROM users WHERE tag = \'#trending\' AND id = {uid}")\n'
    f1 = probe("str_with_hash.py", content_str_hash)
    r1 = AdversarialProbe("String literal containing '#' symbol is not prematurely truncated", "Comments & Directives")
    r1.findings = f1
    if len(f1) >= 1 and f1[0].rule_id == "SEC-SQLI-001":
        r1.passed = True
        r1.details = "SQLi correctly detected despite '#' inside string literal"
    else:
        r1.passed = False
        r1.details = f"Failed to detect SQLi when string has '#': findings={f1}"
    results.append(r1)

    # 3.2 String literal containing '//' in JavaScript
    content_js_url = 'db.query("SELECT * FROM links WHERE url = \'https://" + userDomain + "\'");\n'
    f2 = probe("str_with_slash.js", content_js_url)
    r2 = AdversarialProbe("JS String literal containing 'https://' is not truncated as '//' comment", "Comments & Directives")
    r2.findings = f2
    if len(f2) >= 1 and f2[0].rule_id == "SEC-SQLI-001":
        r2.passed = True
        r2.details = "SQLi correctly detected despite '//' in URL string"
    else:
        r2.passed = False
        r2.details = f"Failed to detect SQLi when string has '//': findings={f2}"
    results.append(r2)

    # 3.3 Trailing C-style block comment on same line
    content_block_comment = 'const port = 8080; /* db.query("SELECT * FROM u WHERE id = " + id); */ const host = "localhost";\n'
    f3 = probe("c_comment.js", content_block_comment)
    r3 = AdversarialProbe("Vulnerable pattern inside inline /* ... */ block comment is ignored", "Comments & Directives")
    r3.findings = f3
    if len(f3) == 0:
        r3.passed = True
        r3.details = "Correctly ignored pattern inside /* ... */ block comment"
    else:
        r3.passed = False
        r3.details = f"False positive on block comment: findings={f3}"
    results.append(r3)

    # 3.4 Suppression directive // bethacker:ignore in Go
    content_go_ignore = 'cmd := exec.Command("sh", "-c", userInput) // bethacker:ignore\n'
    f4 = probe("go_ignore.go", content_go_ignore)
    r4 = AdversarialProbe("Suppression directive '// bethacker:ignore' in Go", "Comments & Directives")
    r4.findings = f4
    if len(f4) == 0:
        r4.passed = True
        r4.details = "Suppression directive respected in Go"
    else:
        r4.passed = False
        r4.details = f"Suppression failed: findings={f4}"
    results.append(r4)

    # 3.5 Suppression directive # nosec in Python
    content_py_nosec = 'os.system(f"echo {msg}")  # nosec\n'
    f5 = probe("py_nosec.py", content_py_nosec)
    r5 = AdversarialProbe("Suppression directive '# nosec' in Python", "Comments & Directives")
    r5.findings = f5
    if len(f5) == 0:
        r5.passed = True
        r5.details = "Suppression directive respected in Python"
    else:
        r5.passed = False
        r5.details = f"Suppression failed: findings={f5}"
    results.append(r5)

    # 3.6 Multiline block containing suppression directive on internal line
    content_multi_suppressed = textwrap.dedent('''
        cursor.execute(
            # nosec
            f"SELECT * FROM users WHERE id = {uid}"
        )
    ''').strip()
    f6 = probe("multi_suppressed.py", content_multi_suppressed)
    r6 = AdversarialProbe("Multiline call with suppression directive inside block", "Comments & Directives")
    r6.findings = f6
    if len(f6) == 0:
        r6.passed = True
        r6.details = "Multiline suppressed correctly"
    else:
        r6.passed = False
        r6.details = f"Suppression failed inside multiline block: findings={f6}"
    results.append(r6)

    return results


# ==============================================================================
# Suite 4: International Characters, Encodings & Unicode
# ==============================================================================

def test_suite_international_encodings() -> List[AdversarialProbe]:
    results = []

    # 4.1 UTF-8 with BOM (\ufeff)
    bom_content = '\ufeffcursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
    with tempfile.TemporaryDirectory() as td:
        tf = Path(td) / "bom_test.py"
        tf.write_bytes(bom_content.encode("utf-8-sig"))
        f1 = scan_file(tf)
        r1 = AdversarialProbe("UTF-8 with BOM file handling", "International & Encodings")
        r1.findings = f1
        if len(f1) >= 1 and f1[0].rule_id == "SEC-SQLI-001" and f1[0].line == 1:
            r1.passed = True
            r1.details = f"Detected SQLi on line 1 without BOM corruption"
        else:
            r1.passed = False
            r1.details = f"BOM caused scan failure: findings={f1}"
        results.append(r1)

    # 4.2 Vietnamese variable and table names
    content_vn = 'cursor.execute(f"SELECT * FROM người_dùng WHERE mã_số = {ma_so}")\n'
    f2 = probe("vn_test.py", content_vn)
    r2 = AdversarialProbe("Vietnamese identifiers (người_dùng, mã_số)", "International & Encodings")
    r2.findings = f2
    if len(f2) >= 1 and f2[0].rule_id == "SEC-SQLI-001":
        r2.passed = True
        r2.details = "SQLi detected with Vietnamese Unicode characters"
    else:
        r2.passed = False
        r2.details = f"Failed on Vietnamese characters: findings={f2}"
    results.append(r2)

    # 4.3 CJK (Chinese / Japanese / Korean) identifiers
    content_cjk = 'cursor.execute(f"SELECT * FROM 顧客 WHERE 名前 = \'{user_name}\'")\n'
    f3 = probe("cjk_test.py", content_cjk)
    r3 = AdversarialProbe("CJK identifiers (顧客, 名前)", "International & Encodings")
    r3.findings = f3
    if len(f3) >= 1 and f3[0].rule_id == "SEC-SQLI-001":
        r3.passed = True
        r3.details = "SQLi detected with CJK characters"
    else:
        r3.passed = False
        r3.details = f"Failed on CJK characters: findings={f3}"
    results.append(r3)

    # 4.4 Mixed Windows CRLF in multiline statement
    content_crlf = "cursor.execute(\r\n    f\"SELECT * FROM t WHERE id = {uid}\"\r\n)\r\n"
    with tempfile.TemporaryDirectory() as td:
        tf = Path(td) / "crlf_test.py"
        tf.write_bytes(content_crlf.encode("utf-8"))
        f4 = scan_file(tf)
        r4 = AdversarialProbe("Windows CRLF multiline statement line count normalization", "International & Encodings")
        r4.findings = f4
        if len(f4) >= 1 and f4[0].rule_id == "SEC-SQLI-001" and f4[0].line == 1:
            r4.passed = True
            r4.details = "Exact line 1 preserved under CRLF"
        else:
            r4.passed = False
            r4.details = f"CRLF normalization issue: findings={f4}"
        results.append(r4)

    # 4.5 CP1252 / Latin-1 encoded file with non-ASCII characters
    content_cp1252 = '# Copyright © 2026 Café Münch\ncursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
    with tempfile.TemporaryDirectory() as td:
        tf = Path(td) / "latin1_test.py"
        tf.write_bytes(content_cp1252.encode("latin-1"))
        f5 = scan_file(tf)
        r5 = AdversarialProbe("Latin-1 / CP1252 encoded file decoding fallback", "International & Encodings")
        r5.findings = f5
        if len(f5) >= 1 and f5[0].rule_id == "SEC-SQLI-001" and f5[0].line == 2:
            r5.passed = True
            r5.details = "Decoded Latin-1 successfully; SQLi flagged on line 2"
        else:
            r5.passed = False
            r5.details = f"Latin-1 fallback failed: findings={f5}"
        results.append(r5)

    return results


# ==============================================================================
# Suite 5: Boundaries, Zero-Length Files & Malformed Inputs
# ==============================================================================

def test_suite_boundary_inputs() -> List[AdversarialProbe]:
    results = []

    # 5.1 Zero-byte files for all supported languages
    for ext, lang in [(".py", "Python"), (".js", "JavaScript"), (".go", "Go"), (".php", "PHP"), (".env", "Config")]:
        f = probe(f"empty{ext}", "")
        r = AdversarialProbe(f"Zero-byte {lang} file ({ext}) handling", "Boundaries & Extremes")
        r.findings = f
        if len(f) == 0:
            r.passed = True
            r.details = "Clean zero findings, no crash"
        else:
            r.passed = False
            r.details = f"Unexpected findings on zero-byte file: {f}"
        results.append(r)

    # 5.2 Whitespace-only files
    ws_content = "   \n\t\t\n   \r\n  \n"
    f_ws = probe("whitespace_only.py", ws_content)
    r_ws = AdversarialProbe("Whitespace-only source file", "Boundaries & Extremes")
    r_ws.findings = f_ws
    if len(f_ws) == 0:
        r_ws.passed = True
        r_ws.details = "Clean zero findings, no crash"
    else:
        r_ws.passed = False
        r_ws.details = f"Unexpected findings on whitespace file: {f_ws}"
    results.append(r_ws)

    # 5.3 Massive single line (50,000 characters) with vulnerability
    long_prefix = "x = " + "1 + " * 10000 + "1; "
    vuln_call = 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
    giant_line = long_prefix + vuln_call
    f_giant = probe("giant_line.py", giant_line)
    r_giant = AdversarialProbe("Massive line (50,000+ chars) performance and detection", "Boundaries & Extremes")
    r_giant.findings = f_giant
    if len(f_giant) >= 1 and f_giant[0].rule_id == "SEC-SQLI-001" and f_giant[0].line == 1:
        r_giant.passed = True
        r_giant.details = "Detected SQLi on giant line without timeout or stack overflow"
    else:
        r_giant.passed = False
        r_giant.details = f"Giant line scan failed: findings={f_giant}"
    results.append(r_giant)

    # 5.4 Binary file with ELF header simulation
    with tempfile.TemporaryDirectory() as td:
        elf_path = Path(td) / "fake_binary.py"
        elf_path.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 200 + b'cursor.execute(f"SELECT * FROM users")')
        f_elf = scan_file(elf_path)
        r_elf = AdversarialProbe("Binary ELF-like file with embedded extension", "Boundaries & Extremes")
        r_elf.findings = f_elf
        if len(f_elf) == 0:
            r_elf.passed = True
            r_elf.details = "Binary file correctly rejected by null-byte / entropy check"
        else:
            r_elf.passed = False
            r_elf.details = f"Binary file not skipped: findings={f_elf}"
        results.append(r_elf)

    # 5.5 Non-existent file path
    f_none = scan_file("nonexistent_file_path_12345.py")
    r_none = AdversarialProbe("Non-existent file path handling", "Boundaries & Extremes")
    r_none.findings = f_none
    if len(f_none) == 0:
        r_none.passed = True
        r_none.details = "Gracefully returns empty list without exception"
    else:
        r_none.passed = False
        r_none.details = f"Unexpected result on non-existent file: {f_none}"
    results.append(r_none)

    return results


# ==============================================================================
# Suite 6: Line Number, Snippet & Multiline Span Precision
# ==============================================================================

def test_suite_line_and_snippet_precision() -> List[AdversarialProbe]:
    results = []

    # 6.1 Multi-vulnerability file with verified line indices
    lines_content = [
        "# Line 1: Header",                                              # line 1
        "import os",                                                      # line 2
        "import sqlite3",                                                 # line 3
        "",                                                               # line 4
        "def handle_user(req):",                                          # line 5
        '    user_id = req.args.get("id")',                               # line 6
        "    cursor.execute(",                                            # line 7 (SQLi start)
        '        f"SELECT * FROM users WHERE id = {user_id}"',            # line 8
        "    )",                                                          # line 9
        "",                                                               # line 10
        '    os.system(f"ping {user_id}")',                               # line 11 (CMDi)
        "",                                                               # line 12
        '    with open(f"/var/log/{req.args.get(\'filename\')}") as f:',  # line 13 (Path Trav)
        "        data = f.read()",                                        # line 14
        "",                                                               # line 15
        '    api_key = "AIzaSyD-1234567890abcdef"',                       # line 16 (Secret)
        "    return data",                                                # line 17
    ]
    content = "\n".join(lines_content) + "\n"

    with tempfile.TemporaryDirectory() as td:
        tf = Path(td) / "precision_multi.py"
        tf.write_text(content, encoding="utf-8")
        findings = scan_file(tf)

        r = AdversarialProbe("Multi-vulnerability exact line number and snippet matching", "Precision & Spans")
        r.findings = findings

        expected_map = {
            "SEC-SQLI-001": (7, "cursor.execute("),
            "SEC-CMDI-002": (11, 'os.system(f"ping {user_id}")'),
            "SEC-TRAV-003": (13, 'with open(f"/var/log/{req.args.get(\'filename\')}") as f:'),
            "SEC-SECR-004": (16, 'api_key = "AIzaSyD-1234567890abcdef"'),
        }

        mismatches = []
        found_rules = {f.rule_id: f for f in findings}

        for rule_id, (expected_line, expected_snip) in expected_map.items():
            if rule_id not in found_rules:
                mismatches.append(f"Missing {rule_id}")
                continue
            f = found_rules[rule_id]
            if f.line != expected_line:
                mismatches.append(f"{rule_id}: line {f.line} != expected {expected_line}")
            actual_line_in_file = lines_content[f.line - 1].strip()
            if f.snippet != actual_line_in_file:
                mismatches.append(f"{rule_id}: snippet '{f.snippet}' != file '{actual_line_in_file}'")

        if not mismatches and len(findings) == 4:
            r.passed = True
            r.details = "All 4 findings strictly matched exact line numbers and file snippets"
        else:
            r.passed = False
            r.details = f"Precision errors: {mismatches}"
        results.append(r)

    # 6.2 Consecutive vulnerable lines
    content_consec = textwrap.dedent('''
        import os
        # Line 2
        cursor.execute(f"SELECT * FROM u WHERE id = {uid}")
        os.system(f"echo {msg}")
        api_key = "AIzaSyD-1234567890abcdef"
    ''').strip()
    f_consec = probe("consec.py", content_consec)
    r_consec = AdversarialProbe("Consecutive lines with different vulnerabilities", "Precision & Spans")
    r_consec.findings = f_consec
    lines_found = [f.line for f in f_consec]
    if len(f_consec) == 3 and lines_found == [3, 4, 5]:
        r_consec.passed = True
        r_consec.details = f"Lines strictly match consecutive positions: {lines_found}"
    else:
        r_consec.passed = False
        r_consec.details = f"Consecutive line mismatch: lines={lines_found}, count={len(f_consec)}"
    results.append(r_consec)

    return results


# ==============================================================================
# Suite 7: False Positive Resistance across Polyglot Safe Constructs
# ==============================================================================

def test_suite_false_positive_resistance() -> List[AdversarialProbe]:
    results = []

    # 7.1 Python safe SQL queries
    safe_py_sql = [
        ('cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n', "Py %s tuple params"),
        ('cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])\n', "Py ? list params"),
        ('db.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})\n', "Py named dict params"),
    ]
    for code, name in safe_py_sql:
        f = probe("safe_sql.py", code)
        r = AdversarialProbe(f"Safe SQL: {name}", "False Positive Resistance")
        r.findings = f
        if len(f) == 0:
            r.passed = True
            r.details = "Zero findings (correct)"
        else:
            r.passed = False
            r.details = f"False positive: findings={f}"
        results.append(r)

    # 7.2 JS/TS safe SQL queries
    safe_js_sql = [
        ('db.query("SELECT * FROM users WHERE id = $1", [userId]);\n', "Postgres $1 params"),
        ('db.query("SELECT * FROM users WHERE id = ?", [userId]);\n', "MySQL ? params"),
    ]
    for code, name in safe_js_sql:
        f = probe("safe_js_sql.js", code)
        r = AdversarialProbe(f"Safe SQL: {name}", "False Positive Resistance")
        r.findings = f
        if len(f) == 0:
            r.passed = True
            r.details = "Zero findings (correct)"
        else:
            r.passed = False
            r.details = f"False positive: findings={f}"
        results.append(r)

    # 7.3 Go safe parameterized queries
    safe_go_sql = [
        ('db.Query("SELECT * FROM users WHERE id = ?", userId)\n', "Go Query ? param"),
        ('db.Exec("UPDATE users SET name = ? WHERE id = ?", name, id)\n', "Go Exec ? params"),
    ]
    for code, name in safe_go_sql:
        f = probe("safe_go_sql.go", code)
        r = AdversarialProbe(f"Safe SQL: {name}", "False Positive Resistance")
        r.findings = f
        if len(f) == 0:
            r.passed = True
            r.details = "Zero findings (correct)"
        else:
            r.passed = False
            r.details = f"False positive: findings={f}"
        results.append(r)

    # 7.4 PHP safe prepared statement
    code_php_safe = '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");\n$stmt->execute(["id" => $id]);\n'
    f_php = probe("safe_php_pdo.php", code_php_safe)
    r_php = AdversarialProbe("Safe SQL: PHP PDO prepared statement", "False Positive Resistance")
    r_php.findings = f_php
    if len(f_php) == 0:
        r_php.passed = True
        r_php.details = "Zero findings (correct)"
    else:
        r_php.passed = False
        r_php.details = f"False positive: findings={f_php}"
    results.append(r_php)

    # 7.5 Python safe subprocess invocations
    safe_subproc = [
        ('subprocess.run(["ping", "-c", "1", host], check=True)\n', "subprocess.run list args"),
        ('subprocess.Popen(["ls", "-la", target_dir], stdout=subprocess.PIPE)\n', "subprocess.Popen list args"),
        ('subprocess.call(["systemctl", "status", service])\n', "subprocess.call list args"),
        ('subprocess.check_output(["df", "-h"])\n', "subprocess.check_output list args"),
    ]
    for code, name in safe_subproc:
        f = probe("safe_subproc.py", code)
        r = AdversarialProbe(f"Safe Subprocess: {name}", "False Positive Resistance")
        r.findings = f
        if len(f) == 0:
            r.passed = True
            r.details = "Zero findings (correct)"
        else:
            r.passed = False
            r.details = f"False positive: findings={f}"
        results.append(r)

    # 7.6 Python safe file reading
    safe_files = [
        ('with open("config.json", "r") as f: data = f.read()\n', "open static string path"),
        ('content = Path("/var/log/app.log").read_text(encoding="utf-8")\n', "Pathlib read_text"),
    ]
    for code, name in safe_files:
        f = probe("safe_file.py", code)
        r = AdversarialProbe(f"Safe File Read: {name}", "False Positive Resistance")
        r.findings = f
        if len(f) == 0:
            r.passed = True
            r.details = "Zero findings (correct)"
        else:
            r.passed = False
            r.details = f"False positive: findings={f}"
        results.append(r)

    # 7.7 Safe environment variables and placeholder secrets
    safe_secrets = [
        ('api_key = os.getenv("API_KEY")\n', "os.getenv"),
        ('api_key = os.environ.get("API_KEY", "fallback")\n', "os.environ.get"),
        ('api_key = "your_api_key_here_12345"\n', "placeholder 'your_api_key_here'"),
        ('password = "changeme_dummy_pass_123"\n', "placeholder 'changeme'"),
        ('secret_key = config.SECRET_KEY\n', "config attribute reference"),
        ('const apiKey = process.env.API_KEY;\n', "Node process.env"),
        ('apiKey := os.Getenv("API_KEY")\n', "Go os.Getenv"),
        ('$apiKey = getenv("API_KEY");\n', "PHP getenv"),
    ]
    for code, name in safe_secrets:
        f = probe("safe_secret.py", code)
        r = AdversarialProbe(f"Safe Secret: {name}", "False Positive Resistance")
        r.findings = f
        if len(f) == 0:
            r.passed = True
            r.details = "Zero findings (correct)"
        else:
            r.passed = False
            r.details = f"False positive: findings={f}"
        results.append(r)

    # 7.8 Safe deserialization and parsing
    safe_deser = [
        ('data = json.loads(user_input)\n', "json.loads"),
        ('data = yaml.safe_load(user_input)\n', "yaml.safe_load"),
        ('data = ast.literal_eval(user_input)\n', "ast.literal_eval"),
    ]
    for code, name in safe_deser:
        f = probe("safe_deser.py", code)
        r = AdversarialProbe(f"Safe Deser: {name}", "False Positive Resistance")
        r.findings = f
        if len(f) == 0:
            r.passed = True
            r.details = "Zero findings (correct)"
        else:
            r.passed = False
            r.details = f"False positive: findings={f}"
        results.append(r)

    # 7.9 Safe configurations
    safe_configs = [
        ('DEBUG = False\n', "DEBUG = False"),
        ('debug = False\n', "debug = False"),
        ('app.run(host="127.0.0.1", port=5000, debug=False)\n', "Flask debug=False"),
    ]
    for code, name in safe_configs:
        f = probe("safe_config.py", code)
        r = AdversarialProbe(f"Safe Config: {name}", "False Positive Resistance")
        r.findings = f
        if len(f) == 0:
            r.passed = True
            r.details = "Zero findings (correct)"
        else:
            r.passed = False
            r.details = f"False positive: findings={f}"
        results.append(r)

    return results


# ==============================================================================
# Suite 8: Advanced Adversarial Evasion Probes (Identified Blind Spots)
# ==============================================================================

def test_suite_adversarial_evasion_vectors() -> List[AdversarialProbe]:
    results = []

    # 8.1 Keyword arguments in execute(): cursor.execute(query=f"...")
    f1 = probe("kw_query.py", 'cursor.execute(query=f"SELECT * FROM users WHERE id = {uid}")\n')
    r1 = AdversarialProbe("Keyword argument in execute call: cursor.execute(query=f\"...\")", "Evasion Vectors", is_bug_check=True)
    r1.findings = f1
    if len(f1) >= 1 and f1[0].rule_id == "SEC-SQLI-001":
        r1.passed = True
        r1.details = "Detected SQLi with keyword argument query="
    else:
        r1.passed = False
        r1.details = f"BUG: Missed SQLi with keyword argument 'query=f\"...\"'! Findings: {f1}"
    results.append(r1)

    # 8.2 Keyword arguments in execute(): cursor.execute(sql=f"...")
    f2 = probe("kw_sql.py", 'cursor.execute(sql=f"SELECT * FROM users WHERE id = {uid}")\n')
    r2 = AdversarialProbe("Keyword argument in execute call: cursor.execute(sql=f\"...\")", "Evasion Vectors", is_bug_check=True)
    r2.findings = f2
    if len(f2) >= 1 and f2[0].rule_id == "SEC-SQLI-001":
        r2.passed = True
        r2.details = "Detected SQLi with keyword argument sql="
    else:
        r2.passed = False
        r2.details = f"BUG: Missed SQLi with keyword argument 'sql=f\"...\"'! Findings: {f2}"
    results.append(r2)

    # 8.3 Path Traversal f-string with arbitrary variable name (not 'path', 'filename', 'file')
    f3 = probe("trav_userdoc.py", 'with open(f"/var/log/{user_doc}") as f: pass\n')
    r3 = AdversarialProbe("Path Traversal f-string with variable '{user_doc}'", "Evasion Vectors", is_bug_check=True)
    r3.findings = f3
    if len(f3) >= 1 and f3[0].rule_id == "SEC-TRAV-003":
        r3.passed = True
        r3.details = "Detected path traversal with user_doc variable"
    else:
        r3.passed = False
        r3.details = f"BUG: Missed path traversal! Regex naively requires 'path|filename|file' in f-string. Findings: {f3}"
    results.append(r3)

    # 8.4 Path Traversal f-string with request parameter
    f4 = probe("trav_reqlog.py", 'with open(f"/var/log/{req.args.get(\'log\')}") as f: pass\n')
    r4 = AdversarialProbe("Path Traversal f-string with '{req.args.get(\"log\")}'", "Evasion Vectors", is_bug_check=True)
    r4.findings = f4
    if len(f4) >= 1 and f4[0].rule_id == "SEC-TRAV-003":
        r4.passed = True
        r4.details = "Detected path traversal with req.args parameter"
    else:
        r4.passed = False
        r4.details = f"BUG: Missed path traversal with req.args! Findings: {f4}"
    results.append(r4)

    return results


# ==============================================================================
# Master Runner
# ==============================================================================

def run_all_m1_2_probes() -> Dict[str, Any]:
    suites = {
        "1. Deeply Nested Parens": test_suite_deeply_nested_parens(),
        "2. Multiline Variations": test_suite_multiline_variations(),
        "3. Mixed Comments & Directives": test_suite_mixed_comments(),
        "4. International & Encodings": test_suite_international_encodings(),
        "5. Boundaries & Extremes": test_suite_boundary_inputs(),
        "6. Line Numbers & Snippet Precision": test_suite_line_and_snippet_precision(),
        "7. False Positive Resistance (Safe Constructs)": test_suite_false_positive_resistance(),
        "8. Advanced Adversarial Evasion Probes": test_suite_adversarial_evasion_vectors(),
    }

    total = 0
    passed = 0
    failed = 0
    bugs_reproduced = []

    print("=" * 80)
    print("CHALLENGER M1_2_1 EMPIRICAL ADVERSARIAL STRESS TEST SUITE")
    print("Target: tools/scanner.py")
    print("=" * 80)

    for suite_name, tests in suites.items():
        print(f"\n--- Suite: {suite_name} ({len(tests)} probes) ---")
        for t in tests:
            total += 1
            if t.passed:
                passed += 1
                print(f"  [PASS] {t.name}: {t.details}")
            else:
                failed += 1
                bugs_reproduced.append(t)
                print(f"  [FAIL] {t.name}: {t.details}")

    print("\n" + "=" * 80)
    print(f"SUMMARY: Total Probes={total}, Passed={passed}, Failed/Bugs Found={failed}")
    print("=" * 80)

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "bugs": bugs_reproduced,
    }


if __name__ == "__main__":
    res = run_all_m1_2_probes()
    if res["failed"] > 0:
        print(f"\nREPRODUCED BUGS & LIMITATIONS ({len(res['bugs'])} items):")
        for b in res["bugs"]:
            print(f" - [{b.category}] {b.name}")
            print(f"   Reason: {b.details}")
        sys.exit(1)
    else:
        print(f"\nALL {res['total']} SECOND-GENERATION PROBES PASSED!")
        sys.exit(0)
