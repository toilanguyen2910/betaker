import pytest
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional

from config import Config


@dataclass
class DummyFunctionCall:
    name: str
    arguments: str


@dataclass
class DummyToolCall:
    id: str
    type: str = "function"
    function: DummyFunctionCall = None


@dataclass
class DummyMessage:
    content: Optional[str]
    tool_calls: Optional[List[DummyToolCall]] = None


@pytest.fixture
def vulnerable_python_samples():
    return {
        "SEC-SQLI-001": [
            'cursor.execute(f"SELECT * FROM accounts WHERE id = {user_id}")',
            'execute("SELECT * FROM users WHERE name = \'%s\'" % user_name)',
            'db.query("SELECT * FROM items WHERE id = " + item_id + ";")',
            'raw(f"UPDATE users SET email=\'{email}\'")',
        ],
        "SEC-CMDI-002": [
            'os.system(f"ping -c 1 {host}")',
            'subprocess.run(user_cmd, shell=True)',
            'subprocess.Popen(f"cat {file_path}", shell=True)',
            'os.popen(f"ls -la {target_dir}")',
            'subprocess.call(f"echo {message}", shell=True)',
        ],
        "SEC-TRAV-003": [
            'open(request.args.get("file"), "r")',
            'open(request.form.get("doc"), "rb")',
            'send_file(f"/data/user_uploads/{filename}")',
            'read_file(request.POST.get("path"))',
        ],
        "SEC-SECR-004": [
            'api_key = "AIzaSyD-1234567890abcdef"',
            'secret_key = "super_secret_jwt_token_12345678"',
            'private_key = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASC"',
            'password = "SuperSecretAdminPassword2026"',
            'access_token = "ghp_0123456789abcdef0123456789"',
            'aws_secret = "wJalrXUtnFEMI_K7MDENG_bPxRfiCYEX"',
        ],
        "SEC-DESER-005": [
            'user_obj = pickle.loads(raw_data)',
            'config_obj = yaml.load(user_input, Loader=yaml.Loader)',
            'config_obj = yaml.load(user_input, Loader=Loader)',
            'res = eval(user_expression)',
            'exec(untrusted_code_string)',
        ],
        "SEC-MISC-006": [
            'DEBUG = True',
            'app.run(host="0.0.0.0", port=5000, debug=True)',
        ],
    }


@pytest.fixture
def vulnerable_js_samples():
    return {
        "SEC-SQLI-001": [
            'db.query("SELECT * FROM users WHERE id = " + userId + ";");',
            'db.query("SELECT * FROM accounts WHERE email = " + userEmail + "");',
        ],
        "SEC-SECR-004": [
            'api_key = "AIzaSyD-1234567890abcdef";',
            'secret_key = "super_secret_jwt_token_12345678";',
            'access_token = "ghp_0123456789abcdef0123456789";',
        ],
        "SEC-DESER-005": [
            'eval("processData(" + userInput + ")");',
            'exec("calc.exe");',
        ],
        "SEC-MISC-006": [
            'const DEBUG = True;',
        ],
    }


@pytest.fixture
def vulnerable_go_samples():
    return {
        "SEC-SQLI-001": [
            'db.query("SELECT * FROM items WHERE id = " + itemId + ";")',
            'raw("SELECT * FROM records WHERE key = " + recordKey + "")',
        ],
        "SEC-SECR-004": [
            'private_key = "pk_live_12345678901234567890"',
            'api_key = "AIzaSyD-1234567890abcdef"',
        ],
        "SEC-MISC-006": [
            'const DEBUG = True',
        ],
    }


@pytest.fixture
def vulnerable_php_samples():
    return {
        "SEC-SQLI-001": [
            'db.query("SELECT * FROM users WHERE id = " + $userId + ";");',
        ],
        "SEC-TRAV-003": [
            'read_file(f"/var/www/uploads/{filename}");',
        ],
        "SEC-SECR-004": [
            '$secret_key = "super_secret_jwt_token_12345678";',
            '$api_key = "AIzaSyD-1234567890abcdef";',
        ],
        "SEC-DESER-005": [
            'eval($untrusted_code);',
        ],
    }


@pytest.fixture
def safe_polyglot_samples():
    return {
        "python": [
            'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            'cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])',
            'subprocess.run(["ping", "-c", "1", host], check=True)',
            'subprocess.Popen(["ls", "-la", target_dir])',
            'with open(safe_filepath, "r", encoding="utf-8") as f:\n    content = f.read()',
            'api_key = os.getenv("API_KEY")',
            'secret_key = config.SECRET_KEY',
            'data = json.loads(user_payload)',
            'data = yaml.safe_load(payload)',
            'DEBUG = False',
            'app.run(host="0.0.0.0", port=5000, debug=False)',
        ],
        "comments": [
            '# cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            '# os.system(f"ping {host}")',
            '# api_key = "AIzaSyD-1234567890abcdef"',
            '// db.query("SELECT * FROM users WHERE id = " + userId + ";");',
            '// eval("untrustedCode()");',
            '// secret_key = "super_secret_jwt_token_12345678"',
        ],
        "js": [
            'db.query("SELECT * FROM users WHERE id = $1", [userId]);',
            'const apiKey = process.env.API_KEY;',
            'const debug = false;',
        ],
        "go": [
            'db.Query("SELECT * FROM users WHERE id = ?", userId)',
            'apiKey := os.Getenv("API_KEY")',
        ],
        "php": [
            '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");',
            '$apiKey = getenv("API_KEY");',
        ],
    }


@pytest.fixture
def vulnerable_manifest_content():
    return (
        "requests==2.25.0\n"
        "urllib3==1.26.4\n"
        "flask==1.0.1\n"
        "django==2.2\n"
        "pyyaml==5.1\n"
        "pillow==8.0.0\n"
    )


@pytest.fixture
def safe_manifest_content():
    return (
        "requests==2.31.0\n"
        "urllib3==2.1.0\n"
        "flask==3.0.0\n"
        "django==4.2.0\n"
        "pyyaml==6.0.1\n"
        "pillow==10.2.0\n"
        "rich>=13.7.0\n"
        "pytest>=8.0.0\n"
    )


@pytest.fixture
def isolated_workspace(tmp_path, monkeypatch):
    ws = tmp_path / "test_workspace"
    ws.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Config, "WORKSPACE_DIR", ws)
    return ws


@pytest.fixture
def sample_patch_file(tmp_path):
    target = tmp_path / "vulnerable_script.py"
    target.write_text(
        'import os\n\ndef run_cmd(param):\n    os.system(f"ping {param}")\n',
        encoding="utf-8"
    )
    return target
