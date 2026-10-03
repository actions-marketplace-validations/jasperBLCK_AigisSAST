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
        ("airbyte/unit_tests/resource/auth.json", '{"id_token": "eyfaKe93kd02kdkd"}\n'),
        ("codex-rs/core/src/mod_tests.rs", 'let github = "ghp_testToken' + "Q" * 27 + '";\n'),
        (
            "n8n/test/Crypto.node.test.ts",
            '"-----BEGIN RSA PRIVATE KEY-----\\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu"\n',
        ),
        (
            "lib.rs",
            'const TEST_RSA_KEY: &str = "-----BEGIN PRIVATE KEY-----\\n'
            'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7";\n',
        ),
        ("docs/guide.mdx", "LANGFLOW_DATABASE_URL=postgresql://app:Sup3rS3cret@db-proxy:5432/app\n"),
        (
            "deploy/docker-compose.yml",
            "MONGODB_URI: mongodb://myusername:mypassword@fastgpt-mongo:27017/db\n"
            "REDIS_URL: redis://default:minioadmin@fastgpt-redis:6379\n",
        ),
        ("docker-compose.yml", "DATABASE_URL: postgresql://superset:superset@db-light:5432/test\n"),
        ("manifest.yaml", "X-AppSecretToken: \"{{ config['app_secret_token'] }}\"\n"),
        ("starter.json", '{"api_key_param": "google_api_key"}\n'),
        ("provider.ts", "tokenSource = 'generated_token';\nconst API_KEY_CREATE = 'api_key:create';\n"),
        ("swatches.tsx", "{ token: 'border-subtle', note: 'dividers' },\n"),
        ("settings.py", 'HEADLESS_TOKEN_STRATEGY = "paperless.tokens.Strategy"\n'),
        ("q.py", 'from x import text\nt = text(f"{days} days")\n'),
        ("q.py", 'cursor.execute(f"SHOW INDEX FROM {self._config.schema_name}.{self._table_name}")\n'),
        ("q.py", 'cursor.execute(f"PRAGMA mmap_size={MMAP_SIZE}")\n'),
        ("h.py", "import hashlib\nv = hashlib.sha1(vary_string.encode()).hexdigest()[:8]\n"),
        ("h.py", "import hashlib\nh = hashlib.md5(x)  # noqa: S324\n"),
        ("r.py", "import random\napi_key = random.choice(self.API_KEYS)\n"),
        ("j.py", 'unverified_claims = jwt.decode(t, options={"verify_signature": False})\n'),
        (
            "api.py",
            'from fastapi import FastAPI\napp = FastAPI()\n@app.post("/files")\n'
            '@requires(["authenticated"])\ndef add(request):\n    pass\n',
        ),
        (
            "routes.py",
            'from fastapi import FastAPI\nrouter = UserAPIRouter()\n@router.delete("/{slug}")\n'
            "def delete_one(slug):\n    pass\n",
        ),
        ("ui.tsx", "<div dangerouslySetInnerHTML={{ __html: sanitizedContent }} />\n"),
        (
            "ui.ts",
            '// Check for dangerous patterns like eval("...")\n'
            'const f = new Function("specifier", "return import(specifier)");\n',
        ),
        ("types.ts", "  eval(script: string, options: Options): Promise<unknown>;\n"),
        (
            "a.ts",
            "const k = process.env.NEXT_PUBLIC_GOOGLE_API_KEY;\nconst p = import.meta.env.VITE_POSTHOG_API_KEY;\n",
        ),
        ("frontend/.env.production", "VITE_API_URL=https://api.example.org\n"),
        (".env.test", "SECRET_KEY=k29dk3ls0dfk\n"),
        ("polar/views.py", 'from x import text\ntext(f"Shared with {len(shared)} organizations")\n'),
        ("alembic/versions/0001_init.py", 'op.execute(sa.text(f"DROP TRIGGER IF EXISTS {name}"))\n'),
        (".github/workflows/ci.yml", "env:\n  POSTGRES_PASSWORD: k29dk3ls0dfk\n"),
        ("package.json", '{"dependencies": {"jsonwebtoken": "catalog:"}}\n'),
        ("types.ts", "export type ApiKeyOwnership = 'own' | 'all';\n"),
        ("brand.jsx", '{ name: "warning", token: "--warning", note: "Caution" },\n'),
        ("app/google-services.json", '"current_key": "AIza' + "SyB3k9dLq0sPz7xWm2nRt5vYc8hJf4gKe1a" + '"\n'),
        ("docs/models.mdx", "Authorization: Bearer sk-" + "aaaaaaaaaaaabbbbbbbbbbbbcccccccccc" + "\n"),
        ("worker.ts", "const MSG = 'Code generation with eval() is not allowed';\n"),
        ("sdk.gen.ts", "  get eval(): Eval {\n"),
        ("Button.stories.tsx", "<div dangerouslySetInnerHTML={{ __html: html }} />\n"),
        ("netbox/configuration_testing.py", "SECRET_KEY = 'abcdk3ls0dfk29dk3ls0dfk'\n"),
        ("source-okta/sample_files/config.json", '{"consumer_secret": "88b.k29dk3ls0dfk"}\n'),
        (".env.default", "SECRET_KEY=k29dk3ls0dfk\n"),
        (".env", "SECRET_KEY=changethis\n"),
        ("chain.py", 'import hashlib\nn = int(hashlib.md5(f"chain:{request_id}".encode()).hexdigest()[:15], 16)\n'),
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
        ("docker-compose.yml", "DATABASE_URL: postgresql://app:Xk29dLq0sP@db.prod.internal:5432/app\n", "AIG003"),
        ("q.py", 'cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")\n', "AIG010"),
        ("ui.ts", "const f = new Function(`${source}; return handle;`);\n", "AIG030"),
        ("a.ts", "const t = import.meta.env.VITE_GITHUB_ACCESS_TOKEN;\n", "AIG032"),
        ("r.py", "import random, string\napi_key = random.choice(string.ascii_letters)\n", "AIG019"),
        ("q.py", 'cur.execute(f"DELETE FROM items WHERE owner = {owner}")\n', "AIG010"),
        ("docs/js/table.js", "tbody.innerHTML = html;\n", "AIG031"),
        ("docker-compose.yml", "POSTGRES_PASSWORD: einvoice_pass\n", "AIG002"),
        ("q.py", 'conn.execute(text(f"EXPLAIN ANALYZE {query}"))\n', "AIG010"),
        ("q.py", 'db.execute(text(f"EXISTS (SELECT 1 FROM t WHERE v = {value})"))\n', "AIG010"),
        ("ui.js", "const fn = eval(userCode);\n", "AIG030"),
        ("sig.py", 'import hashlib\nh = hashlib.md5(f"{user_id}:{api_secret}".encode())\n', "AIG018"),
        ("ui.js", "el.innerHTML = `<b>${name}</b>`;\n", "AIG031"),
        ("compose.yml", "DATABASE_URL: postgresql://app:Xk92jdLq@db.prod.internal:5432/app\n", "AIG003"),
        ("key.py", "# -----BEGIN PRIVATE KEY-----\n# MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n", "AIG004"),
    ],
)
def test_still_detects(tmp_path, name, content, rule):
    assert rule in ids(tmp_path, name, content)
