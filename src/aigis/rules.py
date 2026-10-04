from __future__ import annotations

from aigis.models import Rule, Severity

_RULES = [
    Rule(
        "AIG001",
        "hardcoded-token",
        Severity.CRITICAL,
        {
            "en": "API key or token hardcoded in the code",
            "ru": "Токен или API-ключ прямо в коде",
        },
        {
            "en": "Anyone who sees the repository gets your account: spends your OpenAI credit, "
            "takes over your bot or uploads to your cloud. Bots crawl GitHub and find such keys in minutes.",
            "ru": "Любой, кто увидит репозиторий, получит доступ к твоему аккаунту: потратит деньги на OpenAI, "
            "угонит бота или зальёт что-то в облако. Боты сканируют GitHub и находят такие ключи за минуты.",
        },
        {
            "en": "Revoke the key in the provider dashboard right now (it is compromised even if the commit "
            "is gone). Keep the new one in an environment variable or a .env listed in .gitignore.",
            "ru": "Отзови ключ в кабинете сервиса прямо сейчас (он уже скомпрометирован, даже если коммит удалён). "
            "Новый ключ храни в переменной окружения или .env, который добавлен в .gitignore.",
        },
        'import os\n\nOPENAI_API_KEY = os.environ["OPENAI_API_KEY"]',
    ),
    Rule(
        "AIG002",
        "hardcoded-password",
        Severity.HIGH,
        {"en": "Password or secret hardcoded", "ru": "Пароль или секрет захардкожен"},
        {
            "en": "The password stays in git history forever. Everyone with access to the code can read it, "
            "and the same password often works for other services too.",
            "ru": "Пароль попадает в историю git навсегда. Его увидит любой, у кого есть доступ к коду, "
            "а одинаковые пароли часто подходят и к другим сервисам.",
        },
        {
            "en": "Move the value into an environment variable and read it in the code. "
            "If the password was ever in a public repository, change it.",
            "ru": "Вынеси значение в переменную окружения, а в коде читай её. Если пароль уже был в публичном "
            "репозитории, смени его.",
        },
        'import os\n\nDB_PASSWORD = os.getenv("DB_PASSWORD")',
    ),
    Rule(
        "AIG003",
        "db-url-with-password",
        Severity.HIGH,
        {"en": "Database connection string with a password", "ru": "Строка подключения к базе с паролем"},
        {
            "en": "A URL like postgres://user:pass@host carries the login, the password and the address "
            "of the database. That is ready-made access to all user data.",
            "ru": "В URL вида postgres://user:pass@host лежат логин, пароль и адрес базы. "
            "Это готовый доступ ко всем данным пользователей.",
        },
        {
            "en": "Build the connection string from environment variables, or keep the whole DATABASE_URL "
            "outside the repository.",
            "ru": "Собирай строку подключения из переменных окружения или храни целиком в DATABASE_URL "
            "вне репозитория.",
        },
        'DATABASE_URL = os.environ["DATABASE_URL"]',
    ),
    Rule(
        "AIG004",
        "private-key",
        Severity.CRITICAL,
        {"en": "Private key in the repository", "ru": "Приватный ключ в репозитории"},
        {
            "en": "With a private key one can SSH into the server, decrypt traffic or sign things as you.",
            "ru": "С приватным ключом можно зайти на сервер по SSH, расшифровать трафик "
            "или подписаться от твоего имени.",
        },
        {
            "en": "Delete the file, reissue the key and keep it in CI secrets or a secret manager.",
            "ru": "Удали файл, перевыпусти ключ и храни его в секретах CI или менеджере секретов.",
        },
    ),
    Rule(
        "AIG005",
        "env-file-committed",
        Severity.HIGH,
        {"en": ".env goes into the repository", "ru": ".env попадает в репозиторий"},
        {
            "en": "A .env usually holds every secret of the project at once: API keys, database passwords, bot tokens.",
            "ru": "В .env обычно лежат все секреты проекта сразу: ключи API, пароли от базы, токены ботов.",
        },
        {
            "en": "Add .env to .gitignore and untrack it: git rm --cached .env. "
            "Ship a .env.example without real values instead.",
            "ru": "Добавь .env в .gitignore и убери его из индекса: git rm --cached .env. "
            "Для примера настроек положи .env.example без настоящих значений.",
        },
        "# .gitignore\n.env\n.env.*\n!.env.example",
    ),
    Rule(
        "AIG010",
        "sql-injection",
        Severity.HIGH,
        {"en": "SQL query built by string concatenation", "ru": "SQL-запрос собирается из строк"},
        {
            "en": "If user input reaches the query, the user can append their own SQL: dump the whole "
            "database, drop tables or log in without a password.",
            "ru": "Если в запрос попадает ввод пользователя, он может дописать свой SQL: "
            "выгрузить всю базу, удалить таблицы или войти без пароля.",
        },
        {
            "en": "Pass values as parameters instead of interpolating them into the query text.",
            "ru": "Передавай значения параметрами, а не подставляй в текст запроса.",
        },
        'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
        '# SQLAlchemy\nsession.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})',
    ),
    Rule(
        "AIG011",
        "shell-injection",
        Severity.HIGH,
        {"en": "Shell command built from a variable", "ru": "Команда оболочки из переменной"},
        {
            "en": "shell=True and os.system run the string through a shell. Characters like ; or && "
            "in the data let an attacker run any command on the server.",
            "ru": "shell=True и os.system запускают строку через shell. Символы вроде ; или && в данных "
            "позволяют выполнить любую команду на сервере.",
        },
        {
            "en": "Pass the command as a list of arguments, without shell=True.",
            "ru": "Передавай команду списком аргументов без shell=True.",
        },
        'subprocess.run(["convert", src, dst], check=True)',
    ),
    Rule(
        "AIG012",
        "eval-exec",
        Severity.HIGH,
        {"en": "eval / exec on dynamic data", "ru": "eval / exec над динамическими данными"},
        {
            "en": "eval runs a string as code. If the string depends on the user in any way, "
            "that is remote code execution.",
            "ru": "eval выполняет строку как код. Если строка хоть как-то зависит от пользователя, "
            "это удалённое выполнение кода.",
        },
        {
            "en": "Use json.loads or ast.literal_eval for data, and an explicit dict of functions for logic.",
            "ru": "Для разбора данных используй json.loads или ast.literal_eval, "
            "для логики используй явный словарь функций.",
        },
        "import ast\n\nvalue = ast.literal_eval(raw)",
    ),
    Rule(
        "AIG013",
        "unsafe-deserialization",
        Severity.HIGH,
        {"en": "Unsafe deserialization", "ru": "Небезопасная десериализация"},
        {
            "en": "pickle and yaml.load can build arbitrary objects. A planted file runs code on load.",
            "ru": "pickle и yaml.load умеют создавать произвольные объекты. "
            "Подложенный файл выполнит код при загрузке.",
        },
        {
            "en": "Use json or yaml.safe_load. pickle is only acceptable for data you produced yourself.",
            "ru": "Используй json или yaml.safe_load. pickle допустим только для данных, которые создал ты сам.",
        },
        "data = yaml.safe_load(fh)",
    ),
    Rule(
        "AIG014",
        "debug-enabled",
        Severity.MEDIUM,
        {"en": "Debug mode is on", "ru": "Включён режим отладки"},
        {
            "en": "In debug mode an error leaks stack traces, paths and settings. "
            "The Flask/Werkzeug debugger even allows running code from the browser.",
            "ru": "В debug-режиме при ошибке наружу уходят стектрейсы, пути и настройки. "
            "Отладчик Flask/Werkzeug вообще даёт выполнить код из браузера.",
        },
        {
            "en": "Drive the mode from an environment variable and keep it off in production.",
            "ru": "Управляй режимом через переменную окружения и выключай его в продакшене.",
        },
        'DEBUG = os.getenv("DEBUG") == "1"',
    ),
    Rule(
        "AIG015",
        "cors-wildcard",
        Severity.MEDIUM,
        {"en": "CORS allows any website", "ru": "CORS разрешает любой сайт"},
        {
            "en": "allow_origins=['*'] lets any site call your API. Together with allow_credentials "
            "a foreign page can act on behalf of a logged-in user.",
            "ru": "allow_origins=['*'] разрешает запросы к API с любого сайта. В паре с allow_credentials "
            "чужая страница сможет действовать от имени залогиненного пользователя.",
        },
        {"en": "List the exact frontend domains.", "ru": "Перечисли конкретные домены фронтенда."},
        'app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True)',
    ),
    Rule(
        "AIG016",
        "tls-verify-disabled",
        Severity.MEDIUM,
        {"en": "TLS certificate verification disabled", "ru": "Отключена проверка TLS-сертификата"},
        {
            "en": "verify=False lets anyone on the same network swap the server response and read your tokens (MITM).",
            "ru": "verify=False позволяет любому в той же сети подменить ответ сервера и прочитать токены (MITM).",
        },
        {
            "en": "Remove verify=False. For a custom certificate point to the CA: verify='/path/ca.pem'.",
            "ru": "Убери verify=False. Для своего сертификата укажи путь к CA: verify='/path/ca.pem'.",
        },
    ),
    Rule(
        "AIG017",
        "jwt-no-verify",
        Severity.HIGH,
        {"en": "JWT without signature verification", "ru": "JWT без проверки подписи"},
        {
            "en": "If the signature is not checked, anyone can craft a token with user_id=1 or role=admin.",
            "ru": "Если подпись не проверяется, любой может сам написать токен с user_id=1 или role=admin.",
        },
        {
            "en": "Always verify the signature and name the algorithm explicitly.",
            "ru": "Всегда проверяй подпись и явно указывай алгоритм.",
        },
        'jwt.decode(token, SECRET_KEY, algorithms=["HS256"])',
    ),
    Rule(
        "AIG018",
        "weak-hash",
        Severity.LOW,
        {"en": "Weak hash (MD5 / SHA-1)", "ru": "Слабый хеш (MD5 / SHA-1)"},
        {
            "en": "MD5 and SHA-1 are broken. For passwords they are brute-forced on a GPU in minutes.",
            "ru": "MD5 и SHA-1 давно сломаны. Для паролей они перебираются на видеокарте за минуты.",
        },
        {
            "en": "Use bcrypt/argon2 for passwords (passlib, argon2-cffi) and sha256 for checksums.",
            "ru": "Для паролей используй bcrypt/argon2 (passlib, argon2-cffi), для контрольных сумм используй sha256.",
        },
        "from passlib.hash import bcrypt\n\nhashed = bcrypt.hash(password)",
    ),
    Rule(
        "AIG019",
        "insecure-random",
        Severity.MEDIUM,
        {"en": "Token generated with random", "ru": "Токен генерируется через random"},
        {
            "en": "The random module is predictable. Confirmation codes, password-reset tokens "
            "and sessions can be guessed.",
            "ru": "Модуль random предсказуем. Коды подтверждения, токены сброса пароля и сессии можно угадать.",
        },
        {
            "en": "Use secrets for anything security related.",
            "ru": "Для всего, что связано с безопасностью, используй secrets.",
        },
        "import secrets\n\ntoken = secrets.token_urlsafe(32)\ncode = secrets.randbelow(10**6)",
    ),
    Rule(
        "AIG021",
        "unauthenticated-endpoint",
        Severity.LOW,
        {
            "en": "Mutating endpoint without an auth dependency",
            "ru": "Изменяющий эндпоинт без зависимости авторизации",
        },
        {
            "en": "POST/PUT/PATCH/DELETE without Depends(...) often means anyone can change or delete data. "
            "AI assistants forget authorization all the time.",
            "ru": "POST/PUT/PATCH/DELETE без Depends(...) часто означает, что изменить или удалить данные "
            "может кто угодно. ИИ-ассистенты регулярно забывают про авторизацию.",
        },
        {
            "en": "Add an auth dependency to the endpoint or to the whole router. If the endpoint is meant "
            "to be public, mark the line with a comment: aigis: ignore.",
            "ru": "Добавь зависимость авторизации на эндпоинт или на весь роутер. Если эндпоинт должен быть "
            "публичным, пометь строку комментарием aigis: ignore.",
        },
        "router = APIRouter(dependencies=[Depends(get_current_user)])",
    ),
    Rule(
        "AIG030",
        "js-eval",
        Severity.HIGH,
        {"en": "eval / new Function in JavaScript", "ru": "eval / new Function в JavaScript"},
        {
            "en": "Running a string as code opens the door to XSS and remote code execution.",
            "ru": "Выполнение строки как кода открывает дорогу XSS и удалённому выполнению кода.",
        },
        {
            "en": "Use JSON.parse for data and explicit functions for logic.",
            "ru": "Используй JSON.parse для данных и явные функции для логики.",
        },
    ),
    Rule(
        "AIG031",
        "xss-sink",
        Severity.MEDIUM,
        {"en": "Raw HTML insertion (XSS risk)", "ru": "Вставка сырого HTML (риск XSS)"},
        {
            "en": "innerHTML, dangerouslySetInnerHTML and v-html execute scripts coming from data. "
            "One user comment and everyone's session is stolen.",
            "ru": "innerHTML, dangerouslySetInnerHTML и v-html выполняют скрипты из данных. "
            "Один комментарий пользователя, и у всех угнаны сессии.",
        },
        {
            "en": "Use textContent or the normal framework rendering. If you really need HTML, "
            "sanitize it with DOMPurify.",
            "ru": "Используй textContent или обычный рендер фреймворка. Если HTML нужен, очищай его через DOMPurify.",
        },
        "el.textContent = userText\n// or\nel.innerHTML = DOMPurify.sanitize(html)",
    ),
    Rule(
        "AIG032",
        "public-env-secret",
        Severity.MEDIUM,
        {"en": "Secret in a public frontend variable", "ru": "Секрет в публичной переменной фронтенда"},
        {
            "en": "Variables prefixed NEXT_PUBLIC_, VITE_ or REACT_APP_ are baked into the JS bundle "
            "and every visitor can read them.",
            "ru": "Переменные с префиксами NEXT_PUBLIC_, VITE_, REACT_APP_ вшиваются в JS-бандл, "
            "и их видит любой посетитель сайта.",
        },
        {
            "en": "Keep secrets on the server and let the frontend talk to your own backend.",
            "ru": "Держи секреты только на сервере, а фронтенд пусть ходит через свой backend.",
        },
    ),
    Rule(
        "AIG040",
        "docker-root",
        Severity.LOW,
        {"en": "Container runs as root", "ru": "Контейнер работает от root"},
        {
            "en": "If the app is compromised the attacker is root inside the container, "
            "which makes breaking out easier.",
            "ru": "Если приложение взломают, у атакующего будет root внутри контейнера, "
            "и выбраться наружу станет проще.",
        },
        {
            "en": "Create a user and switch to it at the end of the Dockerfile.",
            "ru": "Создай пользователя и переключись на него в конце Dockerfile.",
        },
        "RUN useradd --create-home app\nUSER app",
    ),
    Rule(
        "AIG042",
        "exposed-database-port",
        Severity.MEDIUM,
        {"en": "Database port exposed to the world", "ru": "Порт базы открыт наружу"},
        {
            "en": "Publishing 5432/3306/6379/27017 on all interfaces opens the database to the whole "
            "internet on a VPS. Bots scan those ports around the clock.",
            "ru": "Публикация 5432/3306/6379/27017 на все интерфейсы открывает базу всему интернету на VPS. "
            "Боты перебирают такие порты круглосуточно.",
        },
        {
            "en": "Do not publish the port at all (services in one compose network already see each other), "
            "or bind it to 127.0.0.1.",
            "ru": "Не публикуй порт вообще (сервисы в одной сети compose видят друг друга) "
            "или привяжи его к 127.0.0.1.",
        },
        'ports:\n  - "127.0.0.1:5432:5432"',
    ),
]

RULES: dict[str, Rule] = {r.id: r for r in _RULES}


def get(rule_id: str) -> Rule:
    return RULES[rule_id]
