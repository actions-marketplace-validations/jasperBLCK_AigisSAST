import json

import pytest

from aigis import i18n
from aigis.cli import main
from aigis.rules import RULES


@pytest.fixture(autouse=True)
def clean_locale(monkeypatch):
    for var in i18n.ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(i18n.locale, "getlocale", lambda: (None, None))


def test_windows_locale(monkeypatch):
    monkeypatch.setattr(i18n.locale, "getlocale", lambda: ("Russian_Russia", "1251"))
    assert i18n.resolve() == "ru"


def test_resolve_order(monkeypatch):
    assert i18n.resolve() == "en"
    monkeypatch.setenv("LANG", "ru_RU.UTF-8")
    assert i18n.resolve() == "ru"
    monkeypatch.setenv("AIGIS_LANG", "en")
    assert i18n.resolve() == "en"
    assert i18n.resolve("ru") == "ru"
    assert i18n.resolve("de") == "en"


def test_every_text_has_both_languages():
    for rule in RULES.values():
        for text in (rule.title, rule.why, rule.fix):
            assert set(i18n.LANGS) <= set(text), rule.id
    for key, text in i18n.MESSAGES.items():
        assert set(i18n.LANGS) <= set(text), key


@pytest.mark.parametrize(("lang", "marker"), [("en", "QUICK START"), ("ru", "БЫСТРЫЙ СТАРТ")])
def test_help(lang, marker, capsys):
    assert main(["help", "--lang", lang]) == 0
    assert marker in capsys.readouterr().out
    assert main(["--lang", lang]) == 0
    assert marker in capsys.readouterr().out


def test_lang_env_drives_output(monkeypatch, capsys):
    monkeypatch.setenv("AIGIS_LANG", "ru")
    assert main(["rules"]) == 0
    assert "Токен или API-ключ прямо в коде" in capsys.readouterr().out


@pytest.mark.parametrize(("lang", "marker"), [("en", "security score"), ("ru", "оценка безопасности")])
def test_scan_text_both_languages(tmp_path, lang, marker, capsys):
    (tmp_path / "x.py").write_text("eval(x)\n")
    assert main(["scan", str(tmp_path), "--lang", lang, "--no-color"]) == 1
    out = capsys.readouterr().out
    assert marker in out and "AIG012" in out


def test_path_shortcut_runs_scan(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("print(1)\n")
    assert main([str(tmp_path), "--lang", "en", "--no-color"]) == 0
    assert "clean" in capsys.readouterr().out


def test_json_titles_follow_lang(tmp_path, capsys):
    (tmp_path / "x.py").write_text("eval(x)\n")
    main(["scan", str(tmp_path), "-f", "json", "--lang", "ru"])
    data = json.loads(capsys.readouterr().out)
    assert data["lang"] == "ru" and data["findings"][0]["title"] == RULES["AIG012"].title["ru"]


def test_init_is_idempotent(tmp_path, capsys):
    assert main(["init", str(tmp_path), "--lang", "en"]) == 0
    wf = tmp_path / ".github" / "workflows" / "aigis.yml"
    assert "jasperBLCK/AigisSAST@v" in wf.read_text() and (tmp_path / ".aigisignore").is_file()
    wf.write_text("custom\n")
    assert main(["init", str(tmp_path), "--lang", "en"]) == 0
    assert wf.read_text() == "custom\n" and "exists" in capsys.readouterr().out
