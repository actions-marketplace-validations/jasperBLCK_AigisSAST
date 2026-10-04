import json
from pathlib import Path

import pytest

from aigis.cli import main
from aigis.scanner import scan_path

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
TG_TOKEN = "7312845567:" + "AA" + "H" * 33
GH_TOKEN = "gh" + "p_" + "a1B2" * 9


def ids(tmp_path: Path, name: str, content: str) -> set[str]:
    (tmp_path / name).write_text(content)
    return {f.rule.id for f in scan_path(tmp_path).findings}


@pytest.mark.parametrize(
    ("name", "content", "rule"),
    [
        ("bot.py", f'BOT_TOKEN = "{TG_TOKEN}"\n', "AIG001"),
        ("ci.yml", f"token: {GH_TOKEN}\n", "AIG001"),
        ("cfg.py", 'DB_PASSWORD = "hunter2hunter"\n', "AIG002"),
        ("cfg.py", 'connect(host="x", password="Pa55word!")\n', "AIG002"),
        ("cfg.py", 'creds = {"api_key": "k-29dk3ls0d"}\n', "AIG002"),
        ("settings.yaml", "db_password: Pa55word!\n", "AIG002"),
        ("app.ts", 'const apiKey = "k_8s7d6f5g4h";\n', "AIG002"),
        ("Dockerfile", "FROM python:3.12\nENV SECRET_KEY=abc123xyz\nUSER app\n", "AIG002"),
        ("db.py", 'URL = "postgresql://admin:S3cret@db:5432/app"\n', "AIG003"),
        ("id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\n", "AIG004"),
        ("q.py", 'cur.execute(f"SELECT * FROM t WHERE id={uid}")\n', "AIG010"),
        ("q.py", 'cur.execute("SELECT * FROM t WHERE id=%s" % uid)\n', "AIG010"),
        ("q.py", 'cur.execute("SELECT * FROM t WHERE id={}".format(uid))\n', "AIG010"),
        ("q.py", 'from sqlalchemy import text\ns.execute(text(f"SELECT {col} FROM t"))\n', "AIG010"),
        ("sh.py", 'import subprocess\nsubprocess.run(f"ls {d}", shell=True)\n', "AIG011"),
        ("sh.py", 'import os\nos.system("rm " + path)\n', "AIG011"),
        ("ev.py", "eval(user_input)\n", "AIG012"),
        ("pk.py", "import pickle\npickle.loads(data)\n", "AIG013"),
        ("pk.py", "import yaml\nyaml.load(fh)\n", "AIG013"),
        ("dbg.py", "app.run(debug=True)\n", "AIG014"),
        ("dbg.py", "DEBUG = True\n", "AIG014"),
        ("cors.py", 'app.add_middleware(CORSMiddleware, allow_origins=["*"])\n', "AIG015"),
        ("tls.py", "requests.get(url, verify=False)\n", "AIG016"),
        ("jw.py", 'jwt.decode(t, options={"verify_signature": False})\n', "AIG017"),
        ("jw.py", 'jwt.decode(t, key, algorithms=["none"])\n', "AIG017"),
        ("h.py", "import hashlib\nhashlib.md5(p.encode())\n", "AIG018"),
        ("r.py", "import random\notp_code = random.randint(100000, 999999)\n", "AIG019"),
        (
            "api.py",
            "from fastapi import FastAPI\napp = FastAPI()\n@app.post('/x')\ndef x():\n    pass\n",
            "AIG021",
        ),
        ("a.js", "const f = new Function(code);\n", "AIG030"),
        ("a.jsx", "<div dangerouslySetInnerHTML={{__html: html}} />\n", "AIG031"),
        ("a.ts", "const k = import.meta.env.VITE_OPENAI_API_KEY;\n", "AIG032"),
        ("server.js", "app.use(cors({ origin: '*' }));\n", "AIG015"),
        ("Dockerfile", "FROM python:3.12\nCMD python app.py\n", "AIG040"),
        ("docker-compose.yml", 'services:\n  db:\n    ports:\n      - "5432:5432"\n', "AIG042"),
    ],
)
def test_detects(tmp_path, name, content, rule):
    assert rule in ids(tmp_path, name, content)


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("ok.py", 'import os\nDB_PASSWORD = os.getenv("DB_PASSWORD")\n'),
        ("ok.py", 'password_field = "password"\nTOKEN_URL = "https://x/token"\n'),
        ("ok.py", 'msg = "Enter your password please"\npassword = ""\n'),
        ("ok.py", 'cur.execute("SELECT * FROM t WHERE id = %s", (uid,))\n'),
        ("ok.py", 'import subprocess\nsubprocess.run(["ls", d])\n'),
        ("ok.py", "import yaml\nyaml.load(fh, Loader=yaml.SafeLoader)\n"),
        ("ok.py", 'jwt.decode(t, key, algorithms=["HS256"])\n'),
        ("ok.py", "import hashlib\nhashlib.md5(b, usedforsecurity=False)\n"),
        ("ok.py", "import random\nshuffle_order = random.random()\n"),
        ("ok.py", 'app.add_middleware(CORSMiddleware, allow_origins=["https://a.io"])\n'),
        (
            "ok.py",
            "from fastapi import FastAPI, Depends\napp = FastAPI()\n@app.post('/x')\n"
            "def x(user=Depends(auth)):\n    pass\n",
        ),
        (
            "ok.py",
            "from fastapi import APIRouter, Depends\nr = APIRouter(dependencies=[Depends(auth)])\n"
            "@r.delete('/x')\ndef x():\n    pass\n",
        ),
        ("ok.ts", "const apiKey = process.env.API_KEY;\nel.textContent = text;\n"),
        ("settings.yaml", "db_password: ${DB_PASSWORD}\n"),
        (".env.example", "OPENAI_API_KEY=your_key_here\nDB_PASSWORD=changeme\n"),
        ("README.md", "Connect with `postgres://user:pass@localhost/db`\n"),
        ("Dockerfile", "FROM python:3.12\nRUN useradd app\nUSER app\n"),
        ("docker-compose.yml", 'services:\n  db:\n    ports:\n      - "127.0.0.1:5432:5432"\n'),
        ("ok.py", "eval(user_input)  # aigis: ignore\n"),
        ("ok.py", "# aigis: ignore[AIG014]\nDEBUG = True\n"),
    ],
)
def test_clean(tmp_path, name, content):
    assert ids(tmp_path, name, content) == set()


def test_ignore_is_rule_specific(tmp_path):
    assert ids(tmp_path, "x.py", "eval(x)  # aigis: ignore[AIG014]\n") == {"AIG012"}


def test_env_file_outside_gitignore(tmp_path):
    (tmp_path / ".env").write_text("OPENAI_API_KEY=abc\n")
    assert {f.rule.id for f in scan_path(tmp_path).findings} == {"AIG005"}
    (tmp_path / ".gitignore").write_text(".env\n")
    assert scan_path(tmp_path).findings == []


def test_secrets_are_masked(tmp_path):
    (tmp_path / "bot.py").write_text(f'BOT_TOKEN = "{TG_TOKEN}"\n')
    findings = scan_path(tmp_path).findings
    assert findings
    assert all(TG_TOKEN not in f.snippet for f in findings)


def test_cors_with_credentials_is_high(tmp_path):
    (tmp_path / "c.py").write_text('app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n')
    (f,) = scan_path(tmp_path).findings
    assert f.effective_severity.name == "HIGH"


def test_examples_cover_every_rule_family():
    found = {f.rule.id for f in scan_path(EXAMPLES).findings}
    expected = {
        "AIG001",
        "AIG002",
        "AIG003",
        "AIG010",
        "AIG011",
        "AIG012",
        "AIG013",
        "AIG014",
        "AIG015",
        "AIG016",
        "AIG017",
        "AIG018",
        "AIG019",
        "AIG021",
        "AIG030",
        "AIG031",
        "AIG032",
        "AIG040",
        "AIG042",
    }
    assert expected <= found


def test_cli_exit_codes_and_formats(tmp_path, capsys):
    (tmp_path / "a.py").write_text("eval(x)\n")
    assert main(["scan", str(tmp_path), "--no-color"]) == 1
    assert main(["scan", str(tmp_path), "--fail-on", "critical"]) == 0
    capsys.readouterr()

    assert main(["scan", str(tmp_path), "-f", "json", "--fail-on", "none"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["high"] == 1 and data["findings"][0]["rule"] == "AIG012"

    out = tmp_path / "r.sarif"
    main(["scan", str(tmp_path), "-f", "sarif", "-o", str(out), "--fail-on", "none"])
    sarif = json.loads(out.read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "AIG012"


def test_cli_rules_and_explain(capsys):
    assert main(["rules"]) == 0
    assert "AIG010" in capsys.readouterr().out
    assert main(["explain", "aig010", "--lang", "ru"]) == 0
    assert "Как исправить" in capsys.readouterr().out
    assert main(["--lang", "en", "explain", "aig010"]) == 0
    assert "How to fix" in capsys.readouterr().out
    assert main(["explain", "NOPE"]) == 2


def test_router_level_auth_covers_other_files(tmp_path):
    route = "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/items')\ndef create():\n    pass\n"
    (tmp_path / "items.py").write_text(route)
    assert {f.rule.id for f in scan_path(tmp_path).findings} == {"AIG021"}
    (tmp_path / "debug.py").write_text(
        "from fastapi import FastAPI, Depends\napp = FastAPI()\n"
        "@app.post('/x', dependencies=[Depends(verify_debug_key)])\ndef x():\n    pass\n"
    )
    assert {f.rule.id for f in scan_path(tmp_path).findings} == {"AIG021"}
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "api = APIRouter(prefix='/v1', dependencies=[Depends(get_current_user)])\n"
        "api.include_router(router)\n"
    )
    assert scan_path(tmp_path).findings == []
