"""Second-Generation Adversarial Stress-Testing Suite for tools/scanner.py.
Author: Challenger M1_2_1
Milestone 1 Iteration 2

This suite challenges tools/scanner.py on advanced attack surfaces:
1. Deeply nested parentheses, brackets, and call wrappers (3-5 levels deep).
2. Multiline formatting variations, line continuations, and lookahead window boundaries.
3. Complex mixed comments: inline directives, C-style comments, comments inside multiline blocks.
4. International characters and encodings: UTF-8 with BOM, Vietnamese, CJK, Emoji, Latin-1/CP1252.
5. Boundary and edge-case inputs: zero-length files, whitespace-only, huge single lines, binary files.
6. Precise line numbers, snippet matches, and multi-line span tracking.
7. False positive resistance across Python, JavaScript/TypeScript, Go, and PHP safe constructs.
"""

import os
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Any, Dict, List

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tools.scanner import (
    scan_file,
    scan_directory,
    scan_all,
    VulnerabilityFinding,
    VULN_PATTERNS,
)


class AdversarialProbeResult:
    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category
        self.passed = False
        self.details = ""
        self.findings: List[VulnerabilityFinding] = []

    def __repr__(self):
        status = "PASS" if self.passed else "FAIL"
        return f"[{status}] {self.category} :: {self.name} - {self.details}"


# Prevent pytest from collecting helper class
AdversarialProbeResult.__test__ = False


def probe(filename: str, content: str, encoding: str = "utf-8") -> List[VulnerabilityFinding]:
    with tempfile.TemporaryDirectory() as td:
        file_path = Path(td) / filename
        file_path.write_text(content, encoding=encoding)
        return scan_file(file_path)


# ==============================================================================
# Suite 1: Deeply Nested Parens, Brackets, and Call Wrappers
# ==============================================================================

def test_suite_deeply_nested_parens() -> List[AdversarialProbeResult]:
    results = []

    # 1.1 Python SQLi 5 levels of parens
    f = probe("nest_sqli_5.py", 'cursor.execute(((((f"SELECT * FROM users WHERE id = {uid}")))))\n')
    r = AdversarialProbeResult("Python SQLi with 5 nested paren wrappers", "Deep Nesting")
    r.findings = f
    if len(f) >= 1 and f[0].rule_id == "SEC-SQLI-001":
        r.passed = True
        r.details = "Detected through 5 nested parens"
    else:
        r.passed = False
        r.details = f"Failed to detect SQLi in nested parens: findings={f}"
    results.append(r)

    # 1.2 Python CMDi 4 levels of parens
    f = probe("nest_cmdi_4.py", 'os.system((((f"ping {host}"))))\n')
    r = AdversarialProbeResult("Python CMDi with 4 nested paren wrappers", "Deep Nesting")
    r.findings = f
    if len(f) >= 1 and f[0].rule_id == "SEC-CMDI-002":
        r.passed = True
        r.details = "Detected through 4 nested parens"
    else:
        r.passed = False
        r.details = f"Failed to detect CMDi in nested parens: findings={f}"
    results.append(r)

    # 1.3 Python Path Traversal deeply nested open
    f = probe("nest_trav.py", 'with open(((((f"/data/{filename}")))), "r") as f: data = f.read()\n')
    r = AdversarialProbeResult("Python Path Traversal with deeply nested open", "Deep Nesting")
    r.findings = f
    if len(f) >= 1 and f[0].rule_id == "SEC-TRAV-003":
        r.passed = True
        r.details = "Detected nested path traversal"
    else:
        r.passed = False
        r.details = f"Failed to detect nested path traversal: findings={f}"
    results.append(r)

    # 1.4 Python Deserialization nested eval and pickle
    f = probe("nest_eval.py", 'res = eval((((user_input))))\n')
    r = AdversarialProbeResult("Python Deserialization nested eval", "Deep Nesting")
    r.findings = f
    if len(f) >= 1 and f[0].rule_id == "SEC-DESER-005":
        r.passed = True
        r.details = "Detected nested eval"
    else:
        r.passed = False
        r.details = f"Failed to detect nested eval: findings={f}"
    results.append(r)

    # 1.5 JS SQLi nested parens with string concatenation
    f = probe("nest_js_sqli.js", 'db.query((((("SELECT * FROM t WHERE id = " + userId)))));\n')
    r = AdversarialProbeResult("JavaScript SQLi nested parens with concatenation", "Deep Nesting")
    r.findings = f
    if len(f) >= 1 and f[0].rule_id == "SEC-SQLI-001":
        r.passed = True
        r.details = "Detected nested JS SQLi"
    else:
        r.passed = False
        r.details = f"Failed to detect nested JS SQLi: findings={f}"
    results.append(r)

    return results


# ==============================================================================
# Suite 2: Multiline Formatting Variations & Line Continuations
# ==============================================================================

def test_suite_multiline_variations() -> List[AdversarialProbeResult]:
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
    f = probe("sqli_multiline_6.py", content_sqli_6)
    r = AdversarialProbeResult("Python SQLi multiline spanning 6 lines with comments", "Multiline Variations")
    r.findings = f
    if len(f) >= 1 and f[0].rule_id == "SEC-SQLI-001":
        r.passed = True
        r.details = f"Detected multiline SQLi (start line={f[0].line}, end_line={f[0].end_line})"
    else:
        r.passed = False
        r.details = f"Failed to detect multiline SQLi spanning comments: findings={f}"
    results.append(r)

    # 2.2 Python SQLi with backslash line continuations
    content_backslash = (
        'cursor.execute( \\\n'
        '    "SELECT * FROM items WHERE id = " \\\n'
        '    + item_id \\\n'
        ')\n'
    )
    f = probe("sqli_backslash.py", content_backslash)
    r = AdversarialProbeResult("Python SQLi with backslash line continuations", "Multiline Variations")
    r.findings = f
    if len(f) >= 1 and f[0].rule_id == "SEC-SQLI-001":
        r.passed = True
        r.details = "Detected backslash-continued SQLi"
    else:
        r.passed = False
        r.details = f"Failed to detect backslash continued SQLi: findings={f}"
    results.append(r)

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
    f = probe("sqli_js_multi.js", content_js_multi)
    r = AdversarialProbeResult("JavaScript multiline ES6 template literal SQLi", "Multiline Variations")
    r.findings = f
    if len(f) >= 1 and f[0].rule_id == "SEC-SQLI-001":
        r.passed = True
        r.details = "Detected multiline JS template SQLi"
    else:
        r.passed = False
        r.details = f"Failed to detect multiline JS template SQLi: findings={f}"
    results.append(r)

    # 2.4 Go Multiline db.Query with capital Q
    content_go_multi = textwrap.dedent('''
        rows, err := db.Query(
            "SELECT * FROM users WHERE id = " +
                userId,
        )
    ''').strip()
    f = probe("sqli_go_multi.go", content_go_multi)
    r = AdversarialProbeResult("Go multiline db.Query concatenation", "Multiline Variations")
    r.findings = f
    if len(f) >= 1 and f[0].rule_id == "SEC-SQLI-001":
        r.passed = True
        r.details = "Detected multiline Go SQLi"
    else:
        r.passed = False
        r.details = f"Failed to detect multiline Go SQLi: findings={f}"
    results.append(r)

    # 2.5 PHP Multiline PDO dot concatenation
    content_php_multi = textwrap.dedent('''
        $stmt = $pdo->query(
            "SELECT * FROM users WHERE id = " .
            $userId
        );
    ''').strip()
    f = probe("sqli_php_multi.php", content_php_multi)
    r = AdversarialProbeResult("PHP multiline $pdo->query dot concatenation", "Multiline Variations")
    r.findings = f
    if len(f) >= 1 and f[0].rule_id == "SEC-SQLI-001":
        r.passed = True
        r.details = "Detected multiline PHP SQLi"
    else:
        r.passed = False
        r.details = f"Failed to detect multiline PHP SQLi: findings={f}"
    results.append(r)

    # 2.6 Multiline CMDi subprocess.Popen with shell=True on 4th line
    content_cmdi_multi = textwrap.dedent('''
        proc = subprocess.Popen(
            f"cat {filepath}",
            stdout=subprocess.PIPE,
            shell=True
        )
    ''').strip()
    f = probe("cmdi_popen_multi.py", content_cmdi_multi)
    r = AdversarialProbeResult("Python multiline subprocess.Popen with shell=True on 4th line", "Multiline Variations")
    r.findings = f
    if len(f) >= 1 and f[0].rule_id == "SEC-CMDI-002":
        r.passed = True
        r.details = "Detected multiline subprocess.Popen CMDi"
    else:
        r.passed = False
        r.details = f"Failed to detect multiline CMDi: findings={f}"
    results.append(r)

    return results


# ==============================================================================
# Suite 3: Mixed Comments, Directives, and String Literals with Comment Markers
# ==============================================================================

def test_suite_mixed_comments() -> List[AdversarialProbeResult]:
    results = []

    # 3.1 String literal containing '#' marker (must NOT be treated as comment)
    content_str_hash = 'cursor.execute(f"SELECT * FROM users WHERE tag = \'#trending\' AND id = {uid}")\n'
    f = probe("str_with_hash.py", content_str_hash)
    r = AdversarialProbeResult("String literal containing '#' symbol is not prematurely truncated", "Comments & Directives")
    r.findings = f
    if len(f) >= 1 and f[0].rule_id == "SEC-SQLI-001":
        r.passed = True
        r.details = "SQLi correctly detected despite '#' inside string literal"
    else:
        r.passed = False
        r.details = f"Failed to detect SQLi when string has '#': findings={f}"
    results.append(r)

    # 3.2 String literal containing '//' in JavaScript
    content_js_url = 'db.query("SELECT * FROM links WHERE url = \'https://" + userDomain + "\'");\n'
    f = probe("str_with_slash.js", content_js_url)
    r = AdversarialProbeResult("JS String literal containing 'https://' is not truncated as '//' comment", "Comments & Directives")
    r.findings = f
    if len(f) >= 1 and f[0].rule_id == "SEC-SQLI-001":
        r.passed = True
        r.details = "SQLi correctly detected despite '//' in URL string"
    else:
        r.passed = False
        r.details = f"Failed to detect SQLi when string has '//': findings={f}"
    results.append(r)

    # 3.3 Trailing C-style block comment on same line
    content_block_comment = 'const port = 8080; /* db.query("SELECT * FROM u WHERE id = " + id); */ const host = "localhost";\n'
    f = probe("c_comment.js", content_block_comment)
    r = AdversarialProbeResult("Vulnerable pattern inside inline /* ... */ block comment is ignored", "Comments & Directives")
    r.findings = f
    if len(f) == 0:
        r.passed = True
        r.details = "Correctly ignored pattern inside /* ... */ block comment"
    else:
        r.passed = False
        r.details = f"False positive on block comment: findings={f}"
    results.append(r)

    # 3.4 Suppression directive // bethacker:ignore in Go
    content_go_ignore = 'cmd := exec.Command("sh", "-c", userInput) // bethacker:ignore\n'
    f = probe("go_ignore.go", content_go_ignore)
    r = AdversarialProbeResult("Suppression directive '// bethacker:ignore' in Go", "Comments & Directives")
    r.findings = f
    if len(f) == 0:
        r.passed = True
        r.details = "Suppression directive respected in Go"
    else:
        r.passed = False
        r.details = f"Suppression failed: findings={f}"
    results.append(r)

    # 3.5 Suppression directive # nosec in Python
    content_py_nosec = 'os.system(f"echo {msg}")  # nosec\n'
    f = probe("py_nosec.py", content_py_nosec)
    r = AdversarialProbeResult("Suppression directive '# nosec' in Python", "Comments & Directives")
    r.findings = f
    if len(f) == 0:
        r.passed = True
        r.details = "Suppression directive respected in Python"
    else:
        r.passed = False
        r.details = f"Suppression failed: findings={f}"
    results.append(r)

    # 3.6 Multiline block containing suppression directive on internal line
    content_multi_suppressed = textwrap.dedent('''
        cursor.execute(
            # nosec
            f"SELECT * FROM users WHERE id = {uid}"
        )
    ''').strip()
    f = probe("multi_suppressed.py", content_multi_suppressed)
    r = AdversarialProbeResult("Multiline call with suppression directive inside block", "Comments & Directives")
    r.findings = f
    if len(f) == 0:
        r.passed = True
        r.details = "Multiline suppressed correctly"
    else:
        r.passed = False
        r.details = f"Suppression failed inside multiline block: findings={f}"
    results.append(r)

    return results


# ==============================================================================
# Suite 4: International Characters, Encodings & Unicode
# ==============================================================================

def test_suite_international_encodings() -> List[AdversarialProbeResult]:
    results = []

    # 4.1 UTF-8 with BOM (\ufeff)
    bom_content = '\ufeffcursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
    with tempfile.TemporaryDirectory() as td:
        tf = Path(td) / "bom_test.py"
        tf.write_bytes(bom_content.encode("utf-8-sig"))
        f = scan_file(tf)
        r = AdversarialProbeResult("UTF-8 with BOM file handling", "International & Encodings")
        r.findings = f
        if len(f) >= 1 and f[0].rule_id == "SEC-SQLI-001" and f[0].line == 1:
            r.passed = True
            r.details = f"Detected SQLi on line 1 without BOM corruption"
        else:
            r.passed = False
            r.details = f"BOM caused scan failure: findings={f}"
        results.append(r)

    # 4.2 Vietnamese variable and table names
    content_vn = 'cursor.execute(f"SELECT * FROM người_dùng WHERE mã_số = {ma_so}")\n'
    f = probe("vn_test.py", content_vn)
    r = AdversarialProbeResult("Vietnamese identifiers (người_dùng, mã_số)", "International & Encodings")
    r.findings = f
    if len(f) >= 1 and f[0].rule_id == "SEC-SQLI-001":
        r.passed = True
        r.details = "SQLi detected with Vietnamese Unicode characters"
    else:
        r.passed = False
        r.details = f"Failed on Vietnamese characters: findings={f}"
    results.append(r)

    # 4.3 CJK (Chinese / Japanese / Korean) identifiers
    content_cjk = 'cursor.execute(f"SELECT * FROM 顧客 WHERE 名前 = \'{user_name}\'")\n'
    f = probe("cjk_test.py", content_cjk)
    r = AdversarialProbeResult("CJK identifiers (顧客, 名前)", "International & Encodings")
    r.findings = f
    if len(f) >= 1 and f[0].rule_id == "SEC-SQLI-001":
        r.passed = True
        r.details = "SQLi detected with CJK characters"
    else:
        r.passed = False
        r.details = f"Failed on CJK characters: findings={f}"
    results.append(r)

    # 4.4 Mixed Windows CRLF in multiline statement
    content_crlf = "cursor.execute(\r\n    f\"SELECT * FROM t WHERE id = {uid}\"\r\n)\r\n"
    with tempfile.TemporaryDirectory() as td:
        tf = Path(td) / "crlf_test.py"
        tf.write_bytes(content_crlf.encode("utf-8"))
        f = scan_file(tf)
        r = AdversarialProbeResult("Windows CRLF multiline statement line count normalization", "International & Encodings")
        r.findings = f
        if len(f) >= 1 and f[0].rule_id == "SEC-SQLI-001" and f[0].line == 1:
            r.passed = True
            r.details = "Exact line 1 preserved under CRLF"
        else:
            r.passed = False
            r.details = f"CRLF normalization issue: findings={f}"
        results.append(r)

    # 4.5 CP1252 / Latin-1 encoded file with non-ASCII characters
    content_cp1252 = '# Copyright © 2026 Café Münch\ncursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
    with tempfile.TemporaryDirectory() as td:
        tf = Path(td) / "latin1_test.py"
        tf.write_bytes(content_cp1252.encode("latin-1"))
        f = scan_file(tf)
        r = AdversarialProbeResult("Latin-1 / CP1252 encoded file decoding fallback", "International & Encodings")
        r.findings = f
        if len(f) >= 1 and f[0].rule_id == "SEC-SQLI-001" and f[0].line == 2:
            r.passed = True
            r.details = "Decoded Latin-1 successfully; SQLi flagged on line 2"
        else:
            r.passed = False
            r.details = f"Latin-1 fallback failed: findings={f}"
        results.append(r)

    return results


# ==============================================================================
# Suite 5: Boundaries, Zero-Length Files & Malformed Inputs
# ==============================================================================

def test_suite_boundary_inputs() -> List[AdversarialProbeResult]:
    results = []

    # 5.1 Zero-byte files for all supported languages
    for ext, lang in [(".py", "Python"), (".js", "JavaScript"), (".go", "Go"), (".php", "PHP"), (".env", "Config")]:
        f = probe(f"empty{ext}", "")
        r = AdversarialProbeResult(f"Zero-byte {lang} file ({ext}) handling", "Boundaries & Extremes")
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
    r_ws = AdversarialProbeResult("Whitespace-only source file", "Boundaries & Extremes")
    r_ws.findings = f_ws
    if len_findings := len(f_ws) == 0:
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
    r_giant = AdversarialProbeResult("Massive line (50,000+ chars) performance and detection", "Boundaries & Extremes")
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
        r_elf = AdversarialProbeResult("Binary ELF-like file with embedded extension", "Boundaries & Extremes")
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
    r_none = AdversarialProbeResult("Non-existent file path handling", "Boundaries & Extremes")
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

def test_suite_line_and_snippet_precision() -> List[AdversarialProbeResult]:
    results = []

    content = textwrap.dedent('''
        # Line 1: Header
        import os
        import sqlite3

        def handle_user(req):
            user_id = req.args.get("id")
            # Line 8: Multiline SQLi
            cursor.execute(
                f"SELECT * FROM users WHERE id = {user_id}"
            )

            # Line 14: Single line CMDi
            os.system(f"ping {user_id}")

            # Line 17: Path traversal
            with open(f"/var/log/{req.args.get('log')}") as f:
                data = f.read()

            # Line 22: Hardcoded secret
            api_key = "AIzaSyD-1234567890abcdef"
            return data
    ''').strip()

    with tempfile.TemporaryDirectory() as td:
        tf = Path(td) / "precision_multi.py"
        tf.write_text(content, encoding="utf-8")
        lines = content.splitlines()
        findings = scan_file(tf)

        r = AdversarialProbeResult("Multi-vulnerability line number and snippet exactness", "Precision & Spans")
        r.findings = findings

        expected_findings = [
            ("SEC-SQLI-001", 9, "cursor.execute("),
            ("SEC-CMDI-002", 14, 'os.system(f"ping {user_id}")'),
            ("SEC-TRAV-003", 17, 'with open(f"/var/log/{req.args.get(\'log\')}") as f:'),
            ("SEC-SECR-004", 21, 'api_key = "AIzaSyD-1234567890abcdef"'),
        ]

        mismatches = []
        rule_map = {f.rule_id: f for f in findings}

        for exp_rule, exp_line, exp_snippet_sub in expected_findings:
            if exp_rule not in rule_map:
                mismatches.append(f"Missing rule {exp_rule}")
                continue
            actual = rule_map[exp_rule]
            if actual.line != exp_line:
                mismatches.append(f"{exp_rule}: line {actual.line} != expected {exp_line}")
            if exp_snippet_sub not in actual.snippet:
                mismatches.append(f"{exp_rule}: snippet '{actual.snippet}' does not contain '{exp_snippet_sub}'")

        if not mismatches and len(findings) == 4:
            r.passed = True
            r.details = "All 4 findings matched exact line numbers and code snippets"
        else:
            r.passed = False
            r.details = f"Mismatches: {mismatches}; Findings: {[f.rule_id for f in findings]}"
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
    r_consec = AdversarialProbeResult("Consecutive lines with different vulnerabilities", "Precision & Spans")
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

def test_suite_false_positive_resistance() -> List[AdversarialProbeResult]:
    results = []

    # 7.1 Python safe SQL queries
    safe_py_sql = [
        ('cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n', "Py %s tuple params"),
        ('cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])\n', "Py ? list params"),
        ('db.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})\n', "Py named dict params"),
    ]
    for code, name in safe_py_sql:
        f = probe("safe_sql.py", code)
        r = AdversarialProbeResult(f"Safe SQL: {name}", "False Positive Resistance")
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
        r = AdversarialProbeResult(f"Safe SQL: {name}", "False Positive Resistance")
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
        r = AdversarialProbeResult(f"Safe SQL: {name}", "False Positive Resistance")
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
    r_php = AdversarialProbeResult("Safe SQL: PHP PDO prepared statement", "False Positive Resistance")
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
        r = AdversarialProbeResult(f"Safe Subprocess: {name}", "False Positive Resistance")
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
        r = AdversarialProbeResult(f"Safe File Read: {name}", "False Positive Resistance")
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
        r = AdversarialProbeResult(f"Safe Secret: {name}", "False Positive Resistance")
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
        r = AdversarialProbeResult(f"Safe Deser: {name}", "False Positive Resistance")
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
        r = AdversarialProbeResult(f"Safe Config: {name}", "False Positive Resistance")
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
# Master Runner & Pytest Integration
# ==============================================================================

def collect_all_adversarial_probes() -> List[AdversarialProbeResult]:
    all_tests = []
    all_tests.extend(test_suite_deeply_nested_parens())
    all_tests.extend(test_suite_multiline_variations())
    all_tests.extend(test_suite_mixed_comments())
    all_tests.extend(test_suite_international_encodings())
    all_tests.extend(test_suite_boundary_inputs())
    all_tests.extend(test_suite_line_and_snippet_precision())
    all_tests.extend(test_suite_false_positive_resistance())
    return all_tests


ALL_M1_2_PROBES = collect_all_adversarial_probes()


def run_standalone_probes() -> Dict[str, Any]:
    print("=" * 80)
    print("SECOND-GENERATION ADVERSARIAL STRESS TEST SUITE (M1 Iteration 2)")
    print("Target: tools/scanner.py")
    print("=" * 80)

    suites = {
        "1. Deeply Nested Parens": test_suite_deeply_nested_parens(),
        "2. Multiline Variations": test_suite_multiline_variations(),
        "3. Mixed Comments & Directives": test_suite_mixed_comments(),
        "4. International & Encodings": test_suite_international_encodings(),
        "5. Boundaries & Extremes": test_suite_boundary_inputs(),
        "6. Precision & Spans": test_suite_line_and_snippet_precision(),
        "7. False Positive Resistance": test_suite_false_positive_resistance(),
    }

    total = 0
    passed = 0
    failed = 0
    failures = []

    for suite_name, tests in suites.items():
        print(f"\n--- Suite: {suite_name} ({len(tests)} tests) ---")
        for t in tests:
            total += 1
            if t.passed:
                passed += 1
                print(f"  [PASS] {t.name}: {t.details}")
            else:
                failed += 1
                failures.append(t)
                print(f"  [FAIL] {t.name}: {t.details}")

    print("\n" + "=" * 80)
    print(f"M1_2 ADVERSARIAL SUMMARY: Total={total}, Passed={passed}, Failed={failed}")
    print("=" * 80)

    return {"total": total, "passed": passed, "failed": failed, "failures": failures}


# Pytest parametrization adapter
try:
    import pytest

    @pytest.mark.parametrize("probe_item", ALL_M1_2_PROBES, ids=[f"{p.category}::{p.name}" for p in ALL_M1_2_PROBES])
    def test_m1_2_adversarial_probe(probe_item):
        assert probe_item.passed, f"[{probe_item.category}] {probe_item.name} FAILED: {probe_item.details}"
except ImportError:
    pass


if __name__ == "__main__":
    res = run_standalone_probes()
    if res["failed"] > 0:
        print(f"\nFAILURES ({len(res['failures'])}):")
        for f in res["failures"]:
            print(f" - [{f.category}] {f.name}: {f.details}")
        sys.exit(1)
    else:
        print(f"\nSUCCESS: All {res['total']} second-generation adversarial probes passed!")
        sys.exit(0)
