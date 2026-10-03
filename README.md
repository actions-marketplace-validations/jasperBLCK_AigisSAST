<div align="center">

<img src="https://raw.githubusercontent.com/jasperBLCK/AigisSAST/main/assets/header.svg" width="100%" alt="AigisSAST"/>

<h3>ИИ пишет код быстро. AigisSAST проверяет, что он не оставил дыр.</h3>

<p><i>Security scanner for AI-generated code: finds what vibe coding leaves behind and explains how to fix it.</i></p>

<a href="https://github.com/jasperBLCK/AigisSAST/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/jasperBLCK/AigisSAST/ci.yml?branch=main&style=for-the-badge&label=CI&labelColor=000000&color=333333&logo=githubactions&logoColor=white"/></a> <img src="https://img.shields.io/badge/python-3.9+-000000?style=for-the-badge&logo=python&logoColor=white"/> <img src="https://img.shields.io/badge/dependencies-0-000000?style=for-the-badge"/> <img src="https://img.shields.io/badge/SARIF-2.1.0-000000?style=for-the-badge&logo=github&logoColor=white"/> <img src="https://img.shields.io/badge/aigis-A%20100%2F100-000000?style=for-the-badge"/> <img src="https://img.shields.io/badge/license-MIT-000000?style=for-the-badge"/>

</div>

<img src="https://raw.githubusercontent.com/jasperBLCK/AigisSAST/main/assets/divider.svg" width="100%"/>

<div align="center">
  <img src="https://raw.githubusercontent.com/jasperBLCK/AigisSAST/main/assets/demo.svg" width="92%" alt="aigis scan demo"/>
</div>

## Зачем

Cursor, Copilot и ChatGPT собирают рабочий бэкенд за вечер. Но по пути они почти всегда оставляют одно и то же:
токен бота прямо в коде, `f"SELECT ... {user}"`, `allow_origins=["*"]`, `debug=True`, открытый наружу Postgres.
Код работает, тесты зелёные, а сервис уже можно взломать.

AigisSAST ловит именно эти ошибки и объясняет каждую **простым языком**: чем она опасна и как исправить, с готовым кодом.
Без регистрации и облака, ничего не отправляет наружу (если сам не включишь `--ai`).

- **Ноль зависимостей.** Только стандартная библиотека Python, ставится за секунду.
- **AST, а не grep.** Python-код разбирается синтаксическим деревом, поэтому меньше ложных срабатываний.
- **Секреты маскируются** в отчёте: `sk-p************`, сам ключ в логах CI не светится.
- **Не только ругается, но и чинит.** `aigis fix` сам выносит ключи в `.env` и правит безопасные случаи.
- **Видит прошлое.** `aigis history` находит ключи, которые «удалили», но они остались в истории git.
- **CI-ready.** Exit-коды, SARIF для GitHub Code Scanning, JSON, Markdown, GitHub Action и pre-commit hook.

## Быстрый старт

```bash
pip install git+https://github.com/jasperBLCK/AigisSAST
aigis scan .            # найти проблемы
aigis fix --dry-run     # посмотреть, что исправится автоматически
aigis fix               # исправить
aigis history           # проверить всю историю git на утёкшие ключи
```

Попробуй на заведомо дырявом примере:

```bash
git clone https://github.com/jasperBLCK/AigisSAST && cd AigisSAST
pip install . && aigis scan examples
```

## Что ловит

| ID | Уровень | Проблема | Где |
|---|---|---|---|
| `AIG001` | CRITICAL | Токены и API-ключи: OpenAI, Anthropic, Telegram, GitHub, AWS, Stripe, Slack, Google, Yandex Cloud | везде |
| `AIG004` | CRITICAL | Приватные ключи (RSA / EC / OpenSSH / PGP) | везде |
| `AIG002` | HIGH | Захардкоженные пароли и секреты | Python, JS/TS, YAML, Dockerfile, compose, .ini/.toml |
| `AIG003` | HIGH | Строка подключения к БД с паролем | везде, кроме документации |
| `AIG005` | HIGH | `.env` попадает в репозиторий | git / .gitignore |
| `AIG010` | HIGH | SQL-инъекция: f-string, `%`, `+`, `.format()` в `execute()` / `text()` | Python |
| `AIG011` | HIGH | Shell-инъекция: `shell=True`, `os.system` с переменной | Python |
| `AIG012` | HIGH | `eval` / `exec` над динамическими данными | Python |
| `AIG013` | HIGH | `pickle.loads`, `yaml.load` без SafeLoader | Python |
| `AIG017` | HIGH | JWT без проверки подписи, `algorithms=["none"]` | Python |
| `AIG030` | HIGH | `eval` / `new Function` | JS / TS |
| `AIG014` | MEDIUM | `debug=True`, `DEBUG = True` | Python |
| `AIG015` | MEDIUM → HIGH | CORS `*` (HIGH вместе с `allow_credentials=True`) | FastAPI, Express |
| `AIG016` | MEDIUM | `verify=False` в requests / httpx | Python |
| `AIG019` | MEDIUM | Токены и OTP-коды через `random` вместо `secrets` | Python |
| `AIG031` | MEDIUM | XSS: `innerHTML`, `dangerouslySetInnerHTML`, `v-html` | JS / TS / Vue |
| `AIG032` | MEDIUM | Секреты в `NEXT_PUBLIC_*` / `VITE_*` / `REACT_APP_*` | фронтенд |
| `AIG042` | MEDIUM | Порт БД/Redis опубликован на `0.0.0.0` | docker-compose |
| `AIG018` | LOW | MD5 / SHA-1 | Python |
| `AIG021` | LOW | POST/PUT/PATCH/DELETE без `Depends(...)` авторизации | FastAPI |
| `AIG040` | LOW | Контейнер работает от root | Dockerfile |

Подробно про любое правило: `aigis explain AIG010`, полный список: `aigis rules`.

## Использование

```bash
aigis scan .                              # текстовый отчёт с объяснениями
aigis scan src api --quiet                # несколько путей, без блоков «чем опасно / как исправить»
aigis scan . --min-severity medium        # скрыть LOW
aigis scan . --fail-on critical           # падать только на критичных
aigis scan . -f sarif -o aigis.sarif      # для GitHub Code Scanning
aigis scan . -f json | jq '.findings[]'   # для своих скриптов
aigis scan . -f markdown > SECURITY.md    # отчёт для PR / заказчика
```

| Exit code | Значение |
|---|---|
| `0` | нет находок уровня `--fail-on` (по умолчанию `high`) и выше |
| `1` | найдены проблемы уровня `--fail-on` и выше |
| `2` | ошибка запуска (неверный путь, неизвестное правило) |

В конце отчёта выводится **security score** (0–100) и оценка от `A` до `F`.

### Исключения

```python
eval(trusted_expr)  # aigis: ignore
DEBUG = True  # aigis: ignore[AIG014]
```

Файлы и папки исключаются через `.aigisignore` (glob-шаблоны) или флаг `--exclude`.
`node_modules`, `.venv`, `dist` и lock-файлы пропускаются автоматически, а в git-репозитории ещё и всё из `.gitignore`.

## Автоисправление: `aigis fix`

```bash
aigis fix --dry-run   # только показать diff
aigis fix             # применить
```

Исправляет только то, что можно поменять без риска сломать логику:

| Было | Стало |
|---|---|
| `BOT_TOKEN = "7312845567:AA..."` | `BOT_TOKEN = os.environ["BOT_TOKEN"]` + значение в `.env`, ключ в `.env.example` |
| `connect(password="Pa55word!")` | `connect(password=os.environ["PASSWORD"])` |
| `.env` не в `.gitignore` | `.env` добавлен в `.gitignore` |
| `requests.get(url, verify=False)` | `verify=True` |
| `yaml.load(data)` | `yaml.safe_load(data)` |
| `otp = random.randint(100000, 999999)` | `otp = secrets.randbelow(900000) + 100000` |
| `token = random.choice(alphabet)` | `secrets.choice(alphabet)` |
| `app.run(debug=True)` / `DEBUG = True` | `debug=False` / `DEBUG = os.getenv("DEBUG") == "1"` |
| `- "5432:5432"` в compose | `- "127.0.0.1:5432:5432"` |

Нужные `import os` / `import secrets` добавляются сами. SQL-инъекции, `eval`, `pickle`, JWT и CORS
автоматически не трогаются: там нужно понимать логику приложения, поэтому они остаются в списке «вручную».

## Утёкшие ключи в истории: `aigis history`

```text
$ aigis history
aigis history: секретов в истории git: 1

  [CRITICAL] AIG001  7312************  (Telegram bot token)
      bot.py  ·  коммит 402c92b от 2026-09-14  ·  удалён, но остался в истории
```

Удалить ключ новым коммитом мало: старая версия файла остаётся в истории, и её видит любой, кто склонировал репо.
`aigis history` проходит по всем коммитам и веткам, показывает, где и когда ключ появился и есть ли он в коде сейчас.
Ключи в отчёте замаскированы. Для CI: `aigis history -f json`, exit code `1`, если что-то найдено.

## Бейдж для README

```bash
aigis badge                # пишет aigis-badge.svg с оценкой, например «aigis | A 100/100»
aigis badge --url          # ссылка shields.io, без файла
```

## AI-режим

```bash
export AIGIS_API_KEY=...                         # любой OpenAI-совместимый API
export AIGIS_BASE_URL=https://api.openai.com/v1  # или свой прокси / локальная LLM
export AIGIS_MODEL=gpt-4o-mini
aigis scan . --ai
```

Для каждой находки модель получает фрагмент кода вокруг неё и возвращает исправление именно под твой код.
**Находки с секретами (`AIG001`–`AIG005`) в модель никогда не отправляются.** Если ключа нет или API недоступен,
сканер предупредит об этом и покажет стандартные советы.

## GitHub Actions

```yaml
name: security
on: [push, pull_request]

jobs:
  aigis:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: jasperBLCK/AigisSAST@v0.2.0
        with:
          fail-on: high
```

Находки появятся во вкладке **Security → Code scanning** и прямо в diff пулл-реквеста.

## pre-commit

```yaml
repos:
  - repo: https://github.com/jasperBLCK/AigisSAST
    rev: v0.2.0
    hooks:
      - id: aigis
```

## Как устроено

```text
aigis scan
   │
   ├── scanner      git ls-files → фильтры → .aigisignore → чтение файлов
   ├── checks/
   │    ├── python_ast   ast.NodeVisitor: SQL, shell, eval, pickle, JWT, CORS, debug, random, FastAPI auth
   │    └── text         regex: токены, ключи, DSN, конфиги, Dockerfile, compose, JS/TS
   ├── ai           (опционально) OpenAI-совместимый API, секреты отфильтрованы
   └── report       text · json · sarif · markdown  +  score / grade

aigis fix       AST-позиции находок → точечные правки → .env / .env.example / .gitignore
aigis history   git log -p --all → добавленные строки → те же детекторы секретов
aigis badge     score / grade → SVG или shields.io
```

Разработка:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && pytest -q
```

## Roadmap

- [x] Python AST-правила, секреты, конфиги, Dockerfile, compose, JS/TS
- [x] SARIF, JSON, Markdown, GitHub Action, pre-commit
- [x] AI-исправления через OpenAI-совместимый API
- [x] `aigis fix`: автоматическое исправление безопасных случаев (вынос секретов в `.env`)
- [x] `aigis history`: поиск секретов во всей истории git
- [x] `aigis badge`: бейдж с оценкой безопасности
- [ ] Проверка зависимостей на известные CVE и тайпсквоттинг
- [ ] Правила для Django и Flask, Go и PHP
- [ ] VS Code extension

## License

[MIT](https://github.com/jasperBLCK/AigisSAST/blob/main/LICENSE)

<img src="https://raw.githubusercontent.com/jasperBLCK/AigisSAST/main/assets/divider.svg" width="100%"/>

<div align="center"><sub>built by <a href="https://github.com/jasperBLCK">jasperBLCK</a> · ship fast, ship secure</sub></div>
