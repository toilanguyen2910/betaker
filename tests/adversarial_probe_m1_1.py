"""Adversarial Stress-Testing Harness for tools/scanner.py.
Author: Challenger M1_1
Executes empirical probes across Python, JS/TS, Go, and PHP to evaluate:
- Detection accuracy on polyglot OWASP Top 10 vulnerabilities
- Corner-case patterns (single concatenation, language-specific calls, template literals)
- Multiline statement handling
- False positive resistance (safe parameterized queries, safe constants, env vars)
- Line number and snippet accuracy
- Binary, encoding, and file-boundary robustness
- Unconventional formatting, multiple statements, nested calls, escaped quotes, inline comments
"""

import os
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Dict, List, Tuple, Any

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


class TestResult:
    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category
        self.passed = False
        self.details = ""
        self.findings_count = 0
        self.rule_ids: List[str] = []

    def __repr__(self):
        status = "PASS" if self.passed else "FAIL"
        return f"[{status}] {self.category} :: {self.name} - {self.details}"


def run_probe(filename: str, content: str) -> List[VulnerabilityFinding]:
    with tempfile.TemporaryDirectory() as td:
        file_path = Path(td) / filename
        file_path.write_text(content, encoding="utf-8")
        return scan_file(file_path)


def test_sqli_adversarial_suite() -> List[TestResult]:
    results = []

    # Case 1: Python SQLi - Single string concatenation (NO trailing +)
    content_single_concat = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'
    f1 = run_probe("sqli_single.py", content_single_concat)
    r1 = TestResult("Python SQLi single concatenation without trailing '+'", "SQLi")
    r1.findings_count = len(f1)
    r1.rule_ids = [f.rule_id for f in f1]
    if len(f1) >= 1 and f1[0].rule_id == "SEC-SQLI-001":
        r1.passed = True
        r1.details = "Detected single concatenation"
    else:
        r1.passed = False
        r1.details = f"MISSED: Pattern requires two '+' characters! Found {len(f1)} findings"
    results.append(r1)

    # Case 2: Python SQLi - Multiline cursor.execute
    content_multiline_sqli = textwrap.dedent('''
        cursor.execute(
            f"SELECT * FROM users WHERE id = {user_id}"
        )
    ''').strip()
    f2 = run_probe("sqli_multiline.py", content_multiline_sqli)
    r2 = TestResult("Python SQLi multiline cursor.execute call", "SQLi")
    r2.findings_count = len(f2)
    r2.rule_ids = [f.rule_id for f in f2]
    if len(f2) >= 1 and f2[0].rule_id == "SEC-SQLI-001":
        r2.passed = True
        r2.details = "Detected multiline SQLi"
    else:
        r2.passed = False
        r2.details = f"MISSED: Scanner operates line-by-line and misses calls spanning lines! Found {len(f2)} findings"
    results.append(r2)

    # Case 3: JavaScript SQLi - Template literal interpolation (ES6)
    content_js_template = 'db.query(`SELECT * FROM users WHERE id = ${userId}`);\n'
    f3 = run_probe("sqli_template.js", content_js_template)
    r3 = TestResult("JavaScript SQLi ES6 template literal interpolation", "SQLi")
    r3.findings_count = len(f3)
    r3.rule_ids = [f.rule_id for f in f3]
    if len(f3) >= 1 and f3[0].rule_id == "SEC-SQLI-001":
        r3.passed = True
        r3.details = "Detected ES6 template literal SQLi"
    else:
        r3.passed = False
        r3.details = f"MISSED: Regex does not account for backtick template strings (`... ${{...}}`)! Found {len(f3)} findings"
    results.append(r3)

    # Case 4: JavaScript SQLi - Single string concatenation
    content_js_single_concat = 'db.query("SELECT * FROM users WHERE id = " + userId);\n'
    f4 = run_probe("sqli_js_single.js", content_js_single_concat)
    r4 = TestResult("JavaScript SQLi single concatenation without trailing '+'", "SQLi")
    r4.findings_count = len(f4)
    r4.rule_ids = [f.rule_id for f in f4]
    if len(f4) >= 1 and f4[0].rule_id == "SEC-SQLI-001":
        r4.passed = True
        r4.details = "Detected single concatenation"
    else:
        r4.passed = False
        r4.details = f"MISSED: Pattern requires two '+' characters! Found {len(f4)} findings"
    results.append(r4)

    # Case 5: Go SQLi - db.Query with capital Q and concatenation
    content_go_sqli = 'db.Query("SELECT * FROM users WHERE id = " + userId)\n'
    f5 = run_probe("sqli_go.go", content_go_sqli)
    r5 = TestResult("Go SQLi db.Query with capital Q and concatenation", "SQLi")
    r5.findings_count = len(f5)
    r5.rule_ids = [f.rule_id for f in f5]
    if len(f5) >= 1 and f5[0].rule_id == "SEC-SQLI-001":
        r5.passed = True
        r5.details = "Detected Go SQLi"
    else:
        r5.passed = False
        r5.details = f"MISSED: Regex has lowercase 'db.query' without (?i) and requires 2 '+'! Found {len(f5)} findings"
    results.append(r5)

    # Case 6: Go SQLi - db.Exec with concatenation
    content_go_exec = 'db.Exec("DELETE FROM users WHERE id = " + userId)\n'
    f6 = run_probe("sqli_go_exec.go", content_go_exec)
    r6 = TestResult("Go SQLi db.Exec with concatenation", "SQLi")
    r6.findings_count = len(f6)
    r6.rule_ids = [f.rule_id for f in f6]
    if len(f6) >= 1 and f6[0].rule_id == "SEC-SQLI-001":
        r6.passed = True
        r6.details = "Detected Go db.Exec SQLi"
    else:
        r6.passed = False
        r6.details = f"MISSED: Regex only matches execute|cursor.execute|raw|db.query! Found {len(f6)} findings"
    results.append(r6)

    # Case 7: PHP SQLi - PDO query with dot string concatenation
    content_php_pdo = '$pdo->query("SELECT * FROM users WHERE id = " . $userId);\n'
    f7 = run_probe("sqli_pdo.php", content_php_pdo)
    r7 = TestResult("PHP SQLi $pdo->query with dot concatenation ('.')", "SQLi")
    r7.findings_count = len(f7)
    r7.rule_ids = [f.rule_id for f in f7]
    if len(f7) >= 1 and f7[0].rule_id == "SEC-SQLI-001":
        r7.passed = True
        r7.details = "Detected PHP PDO SQLi"
    else:
        r7.passed = False
        r7.details = f"MISSED: PHP string concatenation '.' not supported! Found {len(f7)} findings"
    results.append(r7)

    # Case 8: PHP SQLi - mysqli_query with dot concatenation
    content_php_mysqli = 'mysqli_query($conn, "SELECT * FROM users WHERE id = " . $userId);\n'
    f8 = run_probe("sqli_mysqli.php", content_php_mysqli)
    r8 = TestResult("PHP SQLi mysqli_query with dot concatenation", "SQLi")
    r8.findings_count = len(f8)
    r8.rule_ids = [f.rule_id for f in f8]
    if len(f8) >= 1 and f8[0].rule_id == "SEC-SQLI-001":
        r8.passed = True
        r8.details = "Detected PHP mysqli_query SQLi"
    else:
        r8.passed = False
        r8.details = f"MISSED: mysqli_query not in regex and '.' not in pattern! Found {len(f8)} findings"
    results.append(r8)

    # Case 9: Safe Go Parameterized Query - db.Query with '?'
    content_go_safe = 'db.Query("SELECT * FROM users WHERE id = ?", userId)\n'
    f9 = run_probe("safe_go.go", content_go_safe)
    r9 = TestResult("Safe Go Parameterized Query db.Query('...', userId)", "SQLi")
    r9.findings_count = len(f9)
    if len(f9) == 0:
        r9.passed = True
        r9.details = "Correctly not flagged"
    else:
        r9.passed = False
        r9.details = f"FALSE POSITIVE: Flagged safe Go query! Findings: {f9}"
    results.append(r9)

    # Case 10: Safe JS Parameterized Query - db.query with '?' (MySQL style)
    content_js_mysql_safe = 'db.query("SELECT * FROM users WHERE id = ?", [userId]);\n'
    f10 = run_probe("safe_js_mysql.js", content_js_mysql_safe)
    r10 = TestResult("Safe JS Parameterized Query db.query with '?' and array", "SQLi")
    r10.findings_count = len(f10)
    if len(f10) == 0:
        r10.passed = True
        r10.details = "Correctly not flagged"
    else:
        r10.passed = False
        r10.details = f"FALSE POSITIVE: Flagged safe JS query! Findings: {f10}"
    results.append(r10)

    # Case 11: Safe Static SQL Query Constant
    content_static_sql = 'cursor.execute("SELECT id, name FROM users WHERE status = \'ACTIVE\' ORDER BY id")\n'
    f11 = run_probe("safe_static_sql.py", content_static_sql)
    r11 = TestResult("Safe static SQL query string without dynamic parameters", "SQLi")
    r11.findings_count = len(f11)
    if len(f11) == 0:
        r11.passed = True
        r11.details = "Correctly not flagged"
    else:
        r11.passed = False
        r11.details = f"FALSE POSITIVE: Static SQL query constant was flagged! Findings: {f11}"
    results.append(r11)

    return results


def test_cmdi_adversarial_suite() -> List[TestResult]:
    results = []

    # Case 1: Python CMDi - Multiline subprocess.run
    content_py_cmdi_multiline = textwrap.dedent('''
        subprocess.run(
            f"ping {host}",
            shell=True
        )
    ''').strip()
    f1 = run_probe("cmdi_multiline.py", content_py_cmdi_multiline)
    r1 = TestResult("Python CMDi multiline subprocess.run with shell=True", "CMDi")
    r1.findings_count = len(f1)
    r1.rule_ids = [f.rule_id for f in f1]
    if len(f1) >= 1 and f1[0].rule_id == "SEC-CMDI-002":
        r1.passed = True
        r1.details = "Detected multiline CMDi"
    else:
        r1.passed = False
        r1.details = f"MISSED: Line-by-line regex fails when shell=True is on next line! Found {len(f1)} findings"
    results.append(r1)

    # Case 2: Node.js CMDi - child_process.exec(userInput)
    content_js_cmdi = 'const { exec } = require("child_process");\nexec(userInput, (err, stdout) => {});\n'
    f2 = run_probe("cmdi.js", content_js_cmdi)
    r2 = TestResult("Node.js CMDi child_process.exec(userInput)", "CMDi")
    r2.findings_count = len(f2)
    r2.rule_ids = [f.rule_id for f in f2]
    if any(f.rule_id == "SEC-CMDI-002" for f in f2):
        r2.passed = True
        r2.details = "Detected as CMDi"
    elif any(f.rule_id == "SEC-DESER-005" for f in f2):
        r2.passed = False
        r2.details = "MISCLASSIFIED: exec() flagged as Insecure Deserialization (SEC-DESER-005) instead of CMDi"
    else:
        r2.passed = False
        r2.details = f"MISSED: Node.js exec/spawn not detected as CMDi! Found {len(f2)} findings"
    results.append(r2)

    # Case 3: Go CMDi - exec.Command("sh", "-c", userInput)
    content_go_cmdi = 'cmd := exec.Command("sh", "-c", userInput)\ncmd.Run()\n'
    f3 = run_probe("cmdi.go", content_go_cmdi)
    r3 = TestResult("Go CMDi exec.Command('sh', '-c', userInput)", "CMDi")
    r3.findings_count = len(f3)
    r3.rule_ids = [f.rule_id for f in f3]
    if len(f3) >= 1 and f3[0].rule_id == "SEC-CMDI-002":
        r3.passed = True
        r3.details = "Detected Go CMDi"
    else:
        r3.passed = False
        r3.details = f"MISSED: Go exec.Command not in regex! Found {len(f3)} findings"
    results.append(r3)

    # Case 4: PHP CMDi - system($cmd) and shell_exec($cmd)
    content_php_cmdi = '<?php\nsystem($_GET["cmd"]);\n$out = shell_exec($userInput);\n?>\n'
    f4 = run_probe("cmdi.php", content_php_cmdi)
    r4 = TestResult("PHP CMDi system() and shell_exec()", "CMDi")
    r4.findings_count = len(f4)
    r4.rule_ids = [f.rule_id for f in f4]
    if any(f.rule_id == "SEC-CMDI-002" for f in f4):
        r4.passed = True
        r4.details = "Detected PHP CMDi"
    else:
        r4.passed = False
        r4.details = f"MISSED: PHP system/shell_exec/passthru/popen not in regex! Found {len(f4)} findings"
    results.append(r4)

    # Case 5: Safe Python multiline subprocess.run with argument list
    content_py_safe_multiline = textwrap.dedent('''
        subprocess.run(
            ["ping", "-c", "1", host],
            check=True
        )
    ''').strip()
    f5 = run_probe("safe_cmdi_multiline.py", content_py_safe_multiline)
    r5 = TestResult("Safe multiline subprocess.run with argument list", "CMDi")
    r5.findings_count = len(f5)
    if len(f5) == 0:
        r5.passed = True
        r5.details = "Correctly not flagged"
    else:
        r5.passed = False
        r5.details = f"FALSE POSITIVE: Flagged safe multiline subprocess! Findings: {f5}"
    results.append(r5)

    return results


def test_path_traversal_adversarial_suite() -> List[TestResult]:
    results = []

    # Case 1: Python Path Traversal - Multiline open
    content_py_trav_multiline = textwrap.dedent('''
        with open(
            request.args.get("file"),
            "r"
        ) as f:
            data = f.read()
    ''').strip()
    f1 = run_probe("trav_multiline.py", content_py_trav_multiline)
    r1 = TestResult("Python Path Traversal multiline open call", "Path Traversal")
    r1.findings_count = len(f1)
    r1.rule_ids = [f.rule_id for f in f1]
    if len(f1) >= 1 and f1[0].rule_id == "SEC-TRAV-003":
        r1.passed = True
        r1.details = "Detected multiline path traversal"
    else:
        r1.passed = False
        r1.details = f"MISSED: Regex expects open(request... on the same line! Found {len(f1)} findings"
    results.append(r1)

    # Case 2: Node.js Path Traversal - fs.readFile with req.query.file
    content_js_trav = 'fs.readFile(req.query.file, "utf8", (err, data) => {});\n'
    f2 = run_probe("trav.js", content_js_trav)
    r2 = TestResult("Node.js Path Traversal fs.readFile(req.query.file)", "Path Traversal")
    r2.findings_count = len(f2)
    r2.rule_ids = [f.rule_id for f in f2]
    if len(f2) >= 1 and f2[0].rule_id == "SEC-TRAV-003":
        r2.passed = True
        r2.details = "Detected Node.js path traversal"
    else:
        r2.passed = False
        r2.details = f"MISSED: fs.readFile / fs.readFileSync not in regex! Found {len(f2)} findings"
    results.append(r2)

    # Case 3: Go Path Traversal - os.ReadFile(userInput)
    content_go_trav = 'data, err := os.ReadFile(userInput)\n'
    f3 = run_probe("trav.go", content_go_trav)
    r3 = TestResult("Go Path Traversal os.ReadFile(userInput)", "Path Traversal")
    r3.findings_count = len(f3)
    r3.rule_ids = [f.rule_id for f in f3]
    if len(f3) >= 1 and f3[0].rule_id == "SEC-TRAV-003":
        r3.passed = True
        r3.details = "Detected Go path traversal"
    else:
        r3.passed = False
        r3.details = f"MISSED: Go os.ReadFile / os.Open not in regex! Found {len(f3)} findings"
    results.append(r3)

    # Case 4: PHP Path Traversal - file_get_contents($_GET['file'])
    content_php_trav = '$content = file_get_contents($_GET["file"]);\n'
    f4 = run_probe("trav.php", content_php_trav)
    r4 = TestResult("PHP Path Traversal file_get_contents($_GET['file'])", "Path Traversal")
    r4.findings_count = len(f4)
    r4.rule_ids = [f.rule_id for f in f4]
    if len(f4) >= 1 and f4[0].rule_id == "SEC-TRAV-003":
        r4.passed = True
        r4.details = "Detected PHP path traversal"
    else:
        r4.passed = False
        r4.details = f"MISSED: file_get_contents not in regex! Found {len(f4)} findings"
    results.append(r4)

    # Case 5: Safe Python Pathlib with literal constant
    content_safe_path = 'data = Path("config.json").read_text(encoding="utf-8")\n'
    f5 = run_probe("safe_path.py", content_safe_path)
    r5 = TestResult("Safe Pathlib read_text with static path", "Path Traversal")
    r5.findings_count = len(f5)
    if len(f5) == 0:
        r5.passed = True
        r5.details = "Correctly not flagged"
    else:
        r5.passed = False
        r5.details = f"FALSE POSITIVE: Flagged safe Pathlib read! Findings: {f5}"
    results.append(r5)

    return results


def test_secrets_adversarial_suite() -> List[TestResult]:
    results = []

    # Case 1: Go short variable declaration :=
    content_go_short_decl = 'apiKey := "AIzaSyD-1234567890abcdef"\n'
    f1 = run_probe("secret.go", content_go_short_decl)
    r1 = TestResult("Go hardcoded secret with short variable assignment ':='", "Secrets")
    r1.findings_count = len(f1)
    r1.rule_ids = [f.rule_id for f in f1]
    if len(f1) >= 1 and f1[0].rule_id == "SEC-SECR-004":
        r1.passed = True
        r1.details = "Detected Go secret with :="
    else:
        r1.passed = False
        r1.details = f"MISSED: Pattern requires '=' and fails on Go ':=' syntax! Found {len(f1)} findings"
    results.append(r1)

    # Case 2: JSON / Dictionary secret mapping
    content_json_dict = '{"api_key": "AIzaSyD-1234567890abcdef"}\n'
    f2 = run_probe("secret_dict.py", content_json_dict)
    r2 = TestResult("Dictionary / JSON secret mapping 'api_key': '...'", "Secrets")
    r2.findings_count = len(f2)
    r2.rule_ids = [f.rule_id for f in f2]
    if len(f2) >= 1 and f2[0].rule_id == "SEC-SECR-004":
        r2.passed = True
        r2.details = "Detected dictionary secret"
    else:
        r2.passed = False
        r2.details = f"MISSED: Pattern requires '=' not ':'! Found {len(f2)} findings"
    results.append(r2)

    # Case 3: Safe false positive - Unit test dummy password
    content_dummy_test = 'password = "dummy_test_password_12345"\n'
    f3 = run_probe("test_dummy.py", content_dummy_test)
    r3 = TestResult("Safe dummy test password containing 'dummy'", "Secrets")
    r3.findings_count = len(f3)
    if len(f3) == 0:
        r3.passed = True
        r3.details = "Correctly filtered by placeholder list"
    else:
        r3.passed = False
        r3.details = f"FALSE POSITIVE: 'dummy' not filtered! Findings: {f3}"
    results.append(r3)

    # Case 4: Non-placeholder test secret - 'test_password_value_123'
    content_test_secret = 'password = "test_password_value_123"\n'
    f4 = run_probe("test_pass.py", content_test_secret)
    r4 = TestResult("Password variable with test string (not in placeholder list)", "Secrets")
    r4.findings_count = len(f4)
    r4.passed = True
    r4.details = f"Flagged count: {len(f4)} (expected behavior for generic regex scanner)"
    results.append(r4)

    # Case 5: Safe env var with fallback - os.getenv
    content_env_fallback = 'api_key = os.getenv("API_KEY", "fallback_secret_value_123")\n'
    f5 = run_probe("safe_env.py", content_env_fallback)
    r5 = TestResult("Safe env var with fallback os.getenv()", "Secrets")
    r5.findings_count = len(f5)
    if len(f5) == 0:
        r5.passed = True
        r5.details = "Correctly filtered by is_false_positive_secret"
    else:
        r5.passed = False
        r5.details = f"FALSE POSITIVE: os.getenv not filtered! Findings: {f5}"
    results.append(r5)

    return results


def test_deserialization_adversarial_suite() -> List[TestResult]:
    results = []

    # Case 1: PHP Insecure Deserialization - unserialize($_POST['data'])
    content_php_deser = '$obj = unserialize($_POST["data"]);\n'
    f1 = run_probe("deser.php", content_php_deser)
    r1 = TestResult("PHP Insecure Deserialization unserialize($_POST['data'])", "Deserialization")
    r1.findings_count = len(f1)
    r1.rule_ids = [f.rule_id for f in f1]
    if len(f1) >= 1 and f1[0].rule_id == "SEC-DESER-005":
        r1.passed = True
        r1.details = "Detected PHP unserialize"
    else:
        r1.passed = False
        r1.details = f"MISSED: PHP unserialize() not in regex! Found {len(f1)} findings"
    results.append(r1)

    # Case 2: Multiline pickle.loads
    content_py_pickle_multiline = textwrap.dedent('''
        obj = pickle.loads(
            untrusted_network_data
        )
    ''').strip()
    f2 = run_probe("pickle_multiline.py", content_py_pickle_multiline)
    r2 = TestResult("Python pickle.loads across multiple lines", "Deserialization")
    r2.findings_count = len(f2)
    r2.rule_ids = [f.rule_id for f in f2]
    if len(f2) >= 1 and f2[0].rule_id == "SEC-DESER-005":
        r2.passed = True
        r2.details = "Detected because 'pickle.loads(' is on the first line"
    else:
        r2.passed = False
        r2.details = f"MISSED: pickle.loads multiline not detected! Found {len(f2)} findings"
    results.append(r2)

    # Case 3: Safe ast.literal_eval
    content_safe_ast = 'data = ast.literal_eval(payload_str)\n'
    f3 = run_probe("safe_ast.py", content_safe_ast)
    r3 = TestResult("Safe ast.literal_eval(payload_str)", "Deserialization")
    r3.findings_count = len(f3)
    if len(f3) == 0:
        r3.passed = True
        r3.details = "Correctly filtered by word boundary \\beval\\s*\\("
    else:
        r3.passed = False
        r3.details = f"FALSE POSITIVE: ast.literal_eval flagged! Findings: {f3}"
    results.append(r3)

    return results


def test_corner_cases_suite() -> List[TestResult]:
    results = []

    # Case 1: Unconventional whitespace formatting
    # cursor  .  execute  (  f"..."  )
    content_ws = 'cursor  .  execute  (  f"SELECT * FROM users WHERE id = {user_id}"  )\n'
    f1 = run_probe("ws_corner.py", content_ws)
    r1 = TestResult("Unconventional token spacing 'cursor  .  execute  ('", "Corner Cases")
    r1.findings_count = len(f1)
    # SEC-SQLI-001 pattern: cursor\.execute\s*\( requires no whitespace between cursor and . and execute
    if len(f1) >= 1 and f1[0].rule_id == "SEC-SQLI-001":
        r1.passed = True
        r1.details = "Detected spaced call"
    else:
        r1.passed = False
        r1.details = f"MISSED: Regex strictly requires 'cursor\\.execute' without spaces around dot! Found {len(f1)} findings"
    results.append(r1)

    # Case 2: Multiple statements on a single line
    content_multi_stmt = 'conn = get_db(); cursor.execute(f"SELECT * FROM users WHERE id = {user_id}"); conn.commit()\n'
    f2 = run_probe("multi_stmt.py", content_multi_stmt)
    r2 = TestResult("Multiple statements on a single line", "Corner Cases")
    r2.findings_count = len(f2)
    if len(f2) >= 1 and f2[0].rule_id == "SEC-SQLI-001":
        r2.passed = True
        r2.details = "Detected within multi-statement line"
    else:
        r2.passed = False
        r2.details = f"MISSED: Statement not matched! Found {len(f2)} findings"
    results.append(r2)

    # Case 3: Escaped quotes in query
    content_escaped_quotes = 'cursor.execute("SELECT * FROM users WHERE name = \\"" + user_name + "\\"")\n'
    f3 = run_probe("escaped_quotes.py", content_escaped_quotes)
    r3 = TestResult("Query containing escaped quotes '...\\\"' + var + '\\\"'", "Corner Cases")
    r3.findings_count = len(f3)
    if len(f3) >= 1 and f3[0].rule_id == "SEC-SQLI-001":
        r3.passed = True
        r3.details = "Detected query with escaped quotes"
    else:
        r3.passed = False
        r3.details = f"MISSED: Regex failed on escaped quotes string concatenation! Found {len(f3)} findings"
    results.append(r3)

    # Case 4: Nested function call in query argument: cursor.execute(str(f"..."))
    content_nested = 'cursor.execute(str(f"SELECT * FROM users WHERE id = {user_id}"))\n'
    f4 = run_probe("nested_call.py", content_nested)
    r4 = TestResult("Nested call wrapper 'cursor.execute(str(f\"...\"))'", "Corner Cases")
    r4.findings_count = len(f4)
    if len(f4) >= 1 and f4[0].rule_id == "SEC-SQLI-001":
        r4.passed = True
        r4.details = "Detected nested query call"
    else:
        r4.passed = False
        r4.details = f"MISSED: Regex expects f-string immediately following 'execute('! Found {len(f4)} findings"
    results.append(r4)

    # Case 5: Inline comment containing safe code after executable line
    # Should flag the executable vulnerability, but what if vulnerability is ONLY in the comment?
    content_inline_comment = 'x = 42  # cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
    f5 = run_probe("inline_comment.py", content_inline_comment)
    r5 = TestResult("Vulnerable pattern exclusively located in inline comment", "Corner Cases")
    r5.findings_count = len(f5)
    # is_line_comment only checks stripped.startswith('#')!
    # It does NOT strip trailing comments!
    if len(f5) == 0:
        r5.passed = True
        r5.details = "Correctly not flagged"
    else:
        r5.passed = False
        r5.details = f"FALSE POSITIVE: Code in trailing comment was flagged as vulnerability! Findings count: {len(f5)}, rules: {[f.rule_id for f in f5]}"
    results.append(r5)

    return results


def test_line_and_snippet_accuracy() -> List[TestResult]:
    results = []

    content = textwrap.dedent('''
        # Line 1: Comment
        # Line 2: Comment
        import os
        import sqlite3

        def get_user(user_id):
            conn = sqlite3.connect("db.sqlite")
            cursor = conn.cursor()
            # Line 10: Vulnerable SQL query
            cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
            return cursor.fetchone()

        def run_tool(cmd):
            # Line 16: Safe subprocess
            subprocess.run(["echo", cmd])
            # Line 18: Vulnerable command injection
            os.system(f"echo {cmd}")

        def get_file(req):
            # Line 22: Vulnerable path traversal
            return open(request.args.get("file"), "r").read()
    ''').strip()

    with tempfile.TemporaryDirectory() as td:
        tf = Path(td) / "precision_test.py"
        tf.write_text(content, encoding="utf-8")
        lines = content.splitlines()

        findings = scan_file(tf)
        r = TestResult("Line number and snippet accuracy check", "Precision")
        all_accurate = True
        mismatches = []

        for f in findings:
            expected_line_content = lines[f.line - 1].strip()
            if f.snippet != expected_line_content:
                all_accurate = False
                mismatches.append(f"Line {f.line}: snippet '{f.snippet}' != file '{expected_line_content}'")

        if all_accurate and len(findings) == 3:
            r.passed = True
            r.details = f"All {len(findings)} findings have exact line numbers and matching snippets"
        else:
            r.passed = False
            r.details = f"Mismatches: {mismatches}; Findings count: {len(findings)}"
        results.append(r)

    return results


def test_robustness_and_boundary_suite() -> List[TestResult]:
    results = []

    # 1. Empty file
    f_empty = run_probe("empty.py", "")
    r1 = TestResult("Empty source file handling", "Robustness")
    if len(f_empty) == 0:
        r1.passed = True
        r1.details = "Clean zero findings, no crash"
    else:
        r1.passed = False
        r1.details = f"Unexpected findings on empty file: {f_empty}"
    results.append(r1)

    # 2. Binary file with null bytes
    with tempfile.TemporaryDirectory() as td:
        bin_path = Path(td) / "test.bin"
        bin_path.write_bytes(b"\x00\x01\x02\x03\x04" * 100)
        f_bin = scan_file(bin_path)
        r2 = TestResult("Binary file with null bytes", "Robustness")
        if len(f_bin) == 0:
            r2.passed = True
            r2.details = "Clean zero findings, correctly skipped"
        else:
            r2.passed = False
            r2.details = f"Failed to skip binary file: {f_bin}"
        results.append(r2)

    # 3. Inline suppression comments
    content_suppression = textwrap.dedent('''
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # nosec
        os.system(f"ping {host}")  # bethacker:ignore
        eval(userInput)  // nosec
    ''').strip()
    f_sup = run_probe("suppressed.py", content_suppression)
    r3 = TestResult("Inline suppression directives (# nosec, // nosec, # bethacker:ignore)", "Robustness")
    if len(f_sup) == 0:
        r3.passed = True
        r3.details = "All suppressed vulnerabilities successfully ignored"
    else:
        r3.passed = False
        r3.details = f"Suppression failed: {len(f_sup)} findings remained ({[f.rule_id for f in f_sup]})"
    results.append(r3)

    return results


def run_all_stress_tests() -> Dict[str, Any]:
    suites = {
        "SQL Injection": test_sqli_adversarial_suite(),
        "Command Injection": test_cmdi_adversarial_suite(),
        "Path Traversal": test_path_traversal_adversarial_suite(),
        "Hardcoded Secrets": test_secrets_adversarial_suite(),
        "Insecure Deserialization": test_deserialization_adversarial_suite(),
        "Corner Cases & Formatting": test_corner_cases_suite(),
        "Line & Snippet Precision": test_line_and_snippet_accuracy(),
        "Robustness & Boundaries": test_robustness_and_boundary_suite(),
    }

    total_probes = 0
    passed_probes = 0
    failed_probes = 0
    failures = []

    print("=" * 80)
    print("EMPIRICAL ADVERSARIAL STRESS TEST SUITE: tools/scanner.py")
    print("=" * 80)

    for suite_name, tests in suites.items():
        print(f"\n--- Suite: {suite_name} ---")
        for t in tests:
            total_probes += 1
            if t.passed:
                passed_probes += 1
                print(f"  [PASS] {t.name}: {t.details}")
            else:
                failed_probes += 1
                failures.append(t)
                print(f"  [FAIL] {t.name}: {t.details}")

    print("\n" + "=" * 80)
    print(f"SUMMARY: Total={total_probes}, Passed={passed_probes}, Failed={failed_probes}")
    print("=" * 80)

    return {
        "total": total_probes,
        "passed": passed_probes,
        "failed": failed_probes,
        "failures": failures,
    }


if __name__ == "__main__":
    res = run_all_stress_tests()
    if res["failed"] > 0:
        print(f"\nFAILURE SUMMARY ({len(res['failures'])} failures):")
        for f in res["failures"]:
            print(f" - [{f.category}] {f.name}: {f.details}")
        sys.exit(1)
    else:
        print("\nALL STRESS PROBES PASSED!")
        sys.exit(0)
