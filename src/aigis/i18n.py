from __future__ import annotations

import locale
import os
from collections.abc import Mapping

LANGS = ("en", "ru")
FALLBACK = "en"
ENV_VARS = ("AIGIS_LANG", "LC_ALL", "LC_MESSAGES", "LANG")


def _from_env() -> str | None:
    for var in ENV_VARS:
        value = os.environ.get(var)
        if not value:
            continue
        code = value.split(".")[0].split("_")[0].strip().lower()
        if code in LANGS:
            return code
    return None


def _from_system() -> str | None:
    """OS locale; on Windows LANG is usually unset and this gives e.g. 'Russian_Russia'."""
    try:
        name = (locale.getlocale()[0] or "").lower()
    except ValueError:
        return None
    if name.startswith(("ru", "russian")):
        return "ru"
    return None


def resolve(explicit: str | None = None) -> str:
    """Pick the interface language: --lang, AIGIS_LANG/LC_*/LANG, the OS locale, then English."""
    if explicit and explicit.lower() in LANGS:
        return explicit.lower()
    return _from_env() or _from_system() or FALLBACK


def pick(text: Mapping[str, str], lang: str) -> str:
    """Take one language out of a bilingual mapping."""
    return text.get(lang) or text[FALLBACK]


MESSAGES: dict[str, dict[str, str]] = {
    "tagline": {
        "en": "security scanner for AI-generated code",
        "ru": "сканер безопасности для кода, написанного ИИ",
    },
    "target": {"en": "target:", "ru": "цель:  "},
    "files": {"en": "files: ", "ru": "файлов:"},
    "why": {"en": "why it matters:", "ru": "чем опасно:"},
    "how": {"en": "how to fix:", "ru": "как исправить:"},
    "clean": {
        "en": "✓ clean: nothing dangerous found",
        "ru": "✓ чисто: ничего опасного не найдено",
    },
    "score": {"en": "security score:", "ru": "оценка безопасности:"},
    "grade": {"en": "grade", "ru": "уровень"},
    "fixable_hint": {
        "en": "{n} can be fixed automatically: aigis fix --dry-run",
        "ru": "{n} можно исправить автоматически: aigis fix --dry-run",
    },
    "path_not_found": {
        "en": "aigis: path not found: {path}",
        "ru": "aigis: путь не найден: {path}",
    },
    # report: markdown
    "md_report": {"en": "AigisSAST report", "ru": "Отчёт AigisSAST"},
    "md_score": {"en": "Score", "ru": "Оценка"},
    "md_grade": {"en": "Grade", "ru": "Уровень"},
    "md_files": {"en": "Files", "ru": "Файлов"},
    "md_severity": {"en": "Severity", "ru": "Уровень"},
    "md_count": {"en": "Count", "ru": "Сколько"},
    "md_none": {"en": "No issues found.", "ru": "Проблем не найдено."},
    # fix
    "fix_will": {"en": "will fix", "ru": "будет исправлено"},
    "fix_did": {"en": "fixed", "ru": "исправлено"},
    "fix_summary": {
        "en": "\naigis fix: {verb} {n}, left for you: {manual}",
        "ru": "\naigis fix: {verb} {n}, вручную осталось {manual}",
    },
    "fix_env_note": {
        "en": "  Keys now come from the environment. Load .env (python-dotenv, docker --env-file)\n"
        "  and rotate those keys: they were already in the code. Old commits: `aigis history`.",
        "ru": "  Ключи из кода теперь читаются из окружения. Подгрузи .env (python-dotenv, docker --env-file)\n"
        "  и перевыпусти эти ключи: они уже были в коде. Старые коммиты проверит `aigis history`.",
    },
    "fix_env_cached": {
        "en": "  If .env is already committed, untrack it: git rm --cached .env",
        "ru": "  Если .env уже закоммичен, убери его из индекса: git rm --cached .env",
    },
    "fix_env_added": {
        "en": "+ .env: {keys} (values moved out of the code)",
        "ru": "+ .env: {keys} (значения перенесены из кода)",
    },
    "fix_gitignore": {"en": "+ .gitignore: .env", "ru": "+ .gitignore: .env"},
    "fix_apply": {"en": "\nApply: aigis fix", "ru": "\nПрименить: aigis fix"},
    # history
    "hist_none": {
        "en": "aigis history: no secrets found in git history",
        "ru": "aigis history: секретов в истории git не найдено",
    },
    "hist_found": {
        "en": "aigis history: secrets in git history: {n}\n",
        "ru": "aigis history: секретов в истории git: {n}\n",
    },
    "hist_live": {"en": "still in the code", "ru": "ещё в коде"},
    "hist_gone": {
        "en": "removed, but still in history",
        "ru": "удалён, но остался в истории",
    },
    "hist_commit": {"en": "commit", "ru": "коммит"},
    "hist_from": {"en": "of", "ru": "от"},
    "hist_epilogue": {
        "en": "\nDeleting the line is not enough: anyone who cloned the repo still sees the old version.\n"
        "1. Revoke and reissue every key.\n"
        "2. If needed, purge the history: git filter-repo --replace-text or BFG, then force push.",
        "ru": "\nУдалить коммит мало: любой, кто склонировал репо, видит старые версии файлов.\n"
        "1. Отзови и перевыпусти каждый ключ.\n"
        "2. Если нужно, вычисти историю: git filter-repo --replace-text или BFG, затем force push.",
    },
    # badge / explain / rules
    "badge_readme": {"en": "README:", "ru": "README:"},
    "explain_why": {"en": "Why it matters:", "ru": "Чем опасно:"},
    "explain_fix": {"en": "How to fix:", "ru": "Как исправить:"},
    "explain_example": {"en": "Example:", "ru": "Пример:"},
    "no_rule": {
        "en": "aigis: no rule {rule}. List them: aigis rules",
        "ru": "aigis: нет правила {rule}. Список: aigis rules",
    },
    # ai
    "ai_no_key": {
        "en": "AIGIS_API_KEY is not set: AI mode skipped, showing the built-in advice.",
        "ru": "AIGIS_API_KEY не задан: AI-режим пропущен, показаны стандартные советы.",
    },
    "ai_failed": {
        "en": "AI mode unavailable ({error}); showing the built-in advice.",
        "ru": "AI-режим недоступен ({error}); показаны стандартные советы.",
    },
    "ai_prompt": {
        "en": "You are a senior security engineer. Below is a vulnerable code fragment and the detected issue. "
        "Answer in English, short and plain: 1) one sentence on how this can be exploited here; "
        "2) the fixed version of this fragment. No preamble.",
        "ru": "Ты senior security-инженер. Ниже уязвимый фрагмент кода и найденная проблема. "
        "Ответь по-русски, коротко и простыми словами: 1) одной фразой, как это можно эксплуатировать "
        "именно здесь; 2) исправленный код этого фрагмента. Без вступлений.",
    },
    "ai_issue": {"en": "Issue", "ru": "Проблема"},
    "ai_file": {"en": "File", "ru": "Файл"},
    # cli help strings
    "h_prog": {
        "en": "AigisSAST: security scanner for AI-generated code.",
        "ru": "AigisSAST: сканер безопасности для кода, написанного ИИ.",
    },
    "h_lang": {
        "en": "interface language (default: from LANG, else en)",
        "ru": "язык интерфейса (по умолчанию: из LANG, иначе en)",
    },
    "h_scan": {
        "en": "scan a project (default: current directory)",
        "ru": "просканировать проект (по умолчанию: текущая папка)",
    },
    "h_paths": {"en": "files or directories to scan", "ru": "файлы или папки для проверки"},
    "h_output": {
        "en": "write the report to a file instead of stdout",
        "ru": "записать отчёт в файл вместо вывода на экран",
    },
    "h_minsev": {"en": "hide findings below this level", "ru": "скрыть находки ниже этого уровня"},
    "h_failon": {
        "en": "exit with code 1 if a finding of this level or higher exists (default: high)",
        "ru": "выйти с кодом 1, если есть находка этого уровня или выше (по умолчанию: high)",
    },
    "h_exclude": {"en": "extra glob to skip", "ru": "дополнительный glob-шаблон для пропуска"},
    "h_quiet": {
        "en": "text format: hide the 'why' and 'fix' blocks",
        "ru": "текстовый формат: скрыть блоки «чем опасно / как исправить»",
    },
    "h_ai": {
        "en": "ask an OpenAI-compatible LLM for context-specific fixes (needs AIGIS_API_KEY)",
        "ru": "спросить OpenAI-совместимую LLM про исправления под твой код (нужен AIGIS_API_KEY)",
    },
    "h_fix": {
        "en": "auto-fix safe cases: secrets to .env, verify, random, debug, ports",
        "ru": "автоисправление безопасных случаев: секреты в .env, verify, random, debug, порты",
    },
    "h_dryrun": {
        "en": "only show the diff, do not change files",
        "ru": "только показать diff, файлы не менять",
    },
    "h_history": {
        "en": "find secrets ever committed to git history",
        "ru": "найти секреты за всю историю git",
    },
    "h_maxcommits": {"en": "only check the last N commits", "ru": "проверить только последние N коммитов"},
    "h_badge": {
        "en": "security grade badge for your README",
        "ru": "бейдж с оценкой безопасности для README",
    },
    "h_badge_out": {"en": "SVG file (default: aigis-badge.svg)", "ru": "SVG-файл (по умолчанию: aigis-badge.svg)"},
    "h_badge_url": {
        "en": "print a shields.io URL instead of writing an SVG",
        "ru": "вывести ссылку shields.io вместо SVG-файла",
    },
    "h_rules": {"en": "list all rules", "ru": "показать все правила"},
    "h_explain": {"en": "show a rule in detail", "ru": "подробно разобрать правило"},
    "h_help": {
        "en": "a friendly overview with examples",
        "ru": "понятный обзор команд с примерами",
    },
}


def tr(lang: str, key: str, **kw: object) -> str:
    text = pick(MESSAGES[key], lang)
    return text.format(**kw) if kw else text


MESSAGES.update(
    {
        "findings": {"en": "findings:", "ru": "находок:"},
        "fix_first": {"en": "fix first:", "ru": "начни с:"},
        "err_no_git": {"en": "git is not installed", "ru": "git не установлен"},
        "err_not_repo": {"en": "not a git repository", "ru": "не git-репозиторий"},
        "err_history_failed": {
            "en": "git log failed or was killed (out of memory?); history was NOT fully checked, try -n 5000",
            "ru": "git log упал или был убит (не хватило памяти?); история проверена НЕ полностью, попробуй -n 5000",
        },
        "rules_header": {
            "en": "{n} rules · details: aigis explain <ID>",
            "ru": "{n} правил · подробно: aigis explain <ID>",
        },
        "h_init": {
            "en": "add a GitHub Actions workflow and .aigisignore to the project",
            "ru": "добавить в проект GitHub Actions workflow и .aigisignore",
        },
        "init_created": {"en": "  + created  {path}", "ru": "  + создан   {path}"},
        "init_exists": {"en": "  = exists   {path} (left as is)", "ru": "  = уже есть {path} (не трогаю)"},
        "init_next": {
            "en": "\nCommit these files: every push and PR will be scanned, findings show up in "
            "Security → Code scanning.",
            "ru": "\nЗакоммить эти файлы: каждый push и PR будет проверяться, находки появятся в "
            "Security → Code scanning.",
        },
    }
)
