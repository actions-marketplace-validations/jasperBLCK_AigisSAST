from pathlib import Path

import pytest

from aigis.scanner import scan_path

TG_TOKEN = "7312845567:" + "AA" + "H" * 33


def ids(tmp_path: Path, name: str, content: str) -> set[str]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return {f.rule.id for f in scan_path(tmp_path).findings}


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("tests/test_auth.py", 'client.post("/login", json={"password": "Str0ngPass!"})\n'),
        ("tests/conftest.py", 'API_KEY = "k-29dk3ls0d"\neval(code)\n'),
        ("src/auth.test.ts", 'const token = "abc123xyz789";\n'),
        ("pnpm-lock.yaml", "  js-tokens: 4.0.0\n  minipass: 7.1.2\n"),
        ("package.json", '{"dependencies": {"jsonwebtoken": "^9.0.2"}}\n'),
        (".github/workflows/ci.yml", "permissions:\n  id-token: write\nsecrets: inherit\n"),
        ("ci.yml", "run: github_token = os.environ.get('GITHUB_TOKEN')\n"),
        ("supabase/config.toml", 'openai_api_key = "env(OPENAI_API_KEY)"\n'),
        ("ml.py", 'tokenizer.pad_token = "<pad>"\nACCESS_TOKEN_EXPIRE_MINUTES = 30\n'),
        ("models.py", 'user.hashed_password = "bcrypt$2b$12$abcdef"\nm.password_hash = "x9f8e7d6"\n'),
        ("session.ts", 'const ACCESS_TOKEN_KEY = "access_token";\n'),
        ("src/locales/de/auth.json", '{"passwordLabel": "Passwort", "forgotPassword": "Vergessen?"}\n'),
        ("status.js", "const status = ok ? 'PASS' : 'FAIL';\n"),
        ("docs/deploy.md", "| `SSH_KEY` | `-----BEGIN RSA PRIVATE KEY-----...` |\n"),
        ("appsettings.json", '{"TelegramBotToken": "1111111111:AAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}\n'),
        ("ui.js", "list.innerHTML = '';\nbtn.innerHTML = '<span class=\"spin\"></span> Loading';\n"),
        ("log.ts", "log.info(`skipping eval (will retry)`);\n"),
        ("example.env", "OPENAI_API_KEY=\n"),
        ("hash.py", "import hashlib\ncache_key = hashlib.md5(content.encode()).hexdigest()\n"),
        ("db.py", 'con.execute(f"UPDATE t SET n = n + 1 WHERE id IN ({placeholders})", ids)\n'),
        ("compose.yml", "DATABASE_URL: postgresql://postgres:postgres@localhost:5432/app\n"),
        ("cfg.py", 'URL = "postgresql+asyncpg://myuser:Sup3rPass@db.example.com/mydb"\n'),
        ("env.py", 'current_api_key = "NOT_SET"\nBOT_TOKEN = "__BOT_TOKEN__"\n'),
        ("cfg.py", 'password_max_length_key = "USER_PASSWORD_MAX_LENGTH"\n'),
        ("term.ts", "const token = `@${label}-${id}`;\n"),
        ("frontend/test-auth-flow.js", 'const jwtToken = "eyJhbGciOiJIUzI1NiJ9.e30.abc";\n'),
        (
            "api.py",
            "from fastapi import FastAPI\napp = FastAPI()\n@app.post('/auth/login')\ndef login():\n    pass\n",
        ),
        (
            "api.py",
            "from fastapi import FastAPI, Request\napp = FastAPI()\n@app.post('/items')\n"
            "def create(request: Request):\n    verify_token(request.headers)\n",
        ),
    ],
)
def test_no_false_positive(tmp_path, name, content):
    assert ids(tmp_path, name, content) == set()


@pytest.mark.parametrize(
    ("name", "content", "rule"),
    [
        ("tests/test_bot.py", f'BOT_TOKEN = "{TG_TOKEN}"\n', "AIG001"),
        ("k8s/secret.yaml", "MYSQL_ROOT_PASSWORD: cm9vdHBhc3N3b3JkMTIz\n", "AIG002"),
        ("hash.py", "import hashlib\npw = hashlib.md5(password.encode()).hexdigest()\n", "AIG018"),
        ("ui.js", "el.innerHTML = `<b>${name}</b>`;\n", "AIG031"),
        ("compose.yml", "DATABASE_URL: postgresql://app:Xk92jdLq@db.prod.internal:5432/app\n", "AIG003"),
        ("key.py", "# -----BEGIN PRIVATE KEY-----\n# MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n", "AIG004"),
    ],
)
def test_still_detects(tmp_path, name, content, rule):
    assert rule in ids(tmp_path, name, content)
