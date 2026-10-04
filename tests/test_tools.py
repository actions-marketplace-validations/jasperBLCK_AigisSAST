import json
import subprocess
from pathlib import Path

import pytest

from aigis import history
from aigis.cli import main
from aigis.fix import apply, plan
from aigis.history import scan_history
from aigis.scanner import scan_path

TG_TOKEN = "7312845567:" + "AA" + "H" * 33


def rules(root: Path) -> set[str]:
    return {f.rule.id for f in scan_path(root).findings}


def test_fix_moves_secrets_to_env(tmp_path):
    (tmp_path / "app.py").write_text(
        '"""Bot."""\nimport logging\n\nBOT_TOKEN = "' + TG_TOKEN + '"\nconn = connect(password="Pa55word!")\n'
    )
    apply(plan(tmp_path))
    code = (tmp_path / "app.py").read_text()
    assert TG_TOKEN not in code and "Pa55word!" not in code
    assert 'BOT_TOKEN = os.environ["BOT_TOKEN"]' in code
    assert 'password=os.environ["PASSWORD"]' in code
    assert "import logging\nimport os\n" in code
    env = (tmp_path / ".env").read_text()
    assert f"BOT_TOKEN={TG_TOKEN}" in env and 'PASSWORD="Pa55word!"' in env
    assert "BOT_TOKEN=\n" in (tmp_path / ".env.example").read_text()
    assert ".env" in (tmp_path / ".gitignore").read_text().splitlines()
    assert rules(tmp_path) == set()


def test_fix_safe_rewrites(tmp_path):
    (tmp_path / "x.py").write_text(
        "import random\nimport requests\nimport yaml\n\n"
        "otp_code = random.randint(100000, 999999)\n"
        "session_token = random.choice(alphabet)\n"
        "requests.get(url, verify=False)\n"
        "cfg = yaml.load(fh)\n"
        "app.run(debug=True)\n"
        "DEBUG = True\n"
    )
    (tmp_path / "docker-compose.yml").write_text('services:\n  db:\n    ports:\n      - "5432:5432"\n')
    fp = plan(tmp_path)
    assert fp.fixed == 7 and not fp.manual
    apply(fp)
    code = (tmp_path / "x.py").read_text()
    assert "secrets.randbelow(900000) + 100000" in code
    assert "secrets.choice(alphabet)" in code
    assert "verify=True" in code and "yaml.safe_load(fh)" in code and "debug=False" in code
    assert 'DEBUG = os.getenv("DEBUG") == "1"' in code
    assert "import random\nimport requests\nimport secrets\nimport yaml\n" in code
    compile(code, "x.py", "exec")
    assert '"127.0.0.1:5432:5432"' in (tmp_path / "docker-compose.yml").read_text()
    assert rules(tmp_path) == set()


def test_fix_leaves_risky_cases_manual(tmp_path):
    src = "import pickle\npickle.loads(data)\neval(expr)\n"
    (tmp_path / "x.py").write_text(src)
    fp = plan(tmp_path)
    assert fp.fixed == 0 and {f.rule.id for f in fp.manual} == {"AIG012", "AIG013"}
    apply(fp)
    assert (tmp_path / "x.py").read_text() == src


def test_fix_dry_run_does_not_write(tmp_path, capsys):
    (tmp_path / "x.py").write_text("requests.get(url, verify=False)\n")
    assert main(["fix", str(tmp_path), "--dry-run"]) == 0
    assert "+requests.get(url, verify=True)" in capsys.readouterr().out
    assert "verify=False" in (tmp_path / "x.py").read_text()


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(root), *args], check=True)


def test_history_finds_deleted_secret(tmp_path, capsys):
    git(tmp_path, "init", "-q")
    (tmp_path / "bot.py").write_text(f'BOT_TOKEN = "{TG_TOKEN}"\n')
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "add bot")
    (tmp_path / "bot.py").write_text('import os\nBOT_TOKEN = os.environ["BOT_TOKEN"]\n')
    git(tmp_path, "commit", "-qam", "remove token")

    assert rules(tmp_path) == set()
    (leak,) = scan_history(tmp_path)
    assert leak.rule_id == "AIG001" and leak.path == "bot.py" and not leak.live
    assert TG_TOKEN not in leak.masked

    assert main(["history", str(tmp_path), "-f", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data[0]["still_in_code"] is False and TG_TOKEN not in json.dumps(data)


def test_history_outside_git(tmp_path):
    assert main(["history", str(tmp_path)]) == 2


def test_badge(tmp_path, capsys):
    (tmp_path / "x.py").write_text("eval(x)\n")
    out = tmp_path / "b.svg"
    assert main(["badge", str(tmp_path), "-o", str(out)]) == 0
    svg = out.read_text()
    assert svg.startswith("<svg") and "A 90/100" in svg
    assert main(["badge", str(tmp_path), "--url"]) == 0
    assert capsys.readouterr().out.strip().endswith("A%2090%2F100-2ea44f?labelColor=000000")


def test_history_failure_is_reported(tmp_path):
    with pytest.raises(history.HistoryFailed):
        list(history._stream(tmp_path, "log", "--definitely-not-an-option"))
