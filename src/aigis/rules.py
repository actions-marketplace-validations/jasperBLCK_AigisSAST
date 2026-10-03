from __future__ import annotations

from aigis.models import Rule, Severity

_RULES = [
    Rule(
        "AIG001",
        "hardcoded-token",
        Severity.CRITICAL,
        "Токен или API-ключ прямо в коде",
        "Любой, кто увидит репозиторий, получит доступ к твоему аккаунту: потратит деньги на OpenAI, "
        "угонит бота или зальёт что-то в облако. Боты сканируют GitHub и находят такие ключи за минуты.",
        "Отзови ключ в кабинете сервиса прямо сейчас (он уже скомпрометирован, даже если коммит удалён). "
        "Новый ключ храни в переменной окружения или .env, который добавлен в .gitignore.",
        'import os\n\nOPENAI_API_KEY = os.environ["OPENAI_API_KEY"]',
    ),
    Rule(
        "AIG002",
        "hardcoded-password",
        Severity.HIGH,
        "Пароль или секрет захардкожен",
        "Пароль попадает в историю git навсегда. Его увидит любой, у кого есть доступ к коду, "
        "а одинаковые пароли часто подходят и к другим сервисам.",
        "Вынеси значение в переменную окружения, а в коде читай её. Если пароль уже был в публичном "
        "репозитории, смени его.",
        'import os\n\nDB_PASSWORD = os.getenv("DB_PASSWORD")',
    ),
    Rule(
        "AIG003",
        "db-url-with-password",
        Severity.HIGH,
        "Строка подключения к базе с паролем",
        "В URL вида postgres://user:pass@host лежат логин, пароль и адрес базы. "
        "Это готовый доступ ко всем данным пользователей.",
        "Собирай строку подключения из переменных окружения или храни целиком в DATABASE_URL вне репозитория.",
        'DATABASE_URL = os.environ["DATABASE_URL"]',
    ),
    Rule(
        "AIG004",
        "private-key",
        Severity.CRITICAL,
        "Приватный ключ в репозитории",
        "С приватным ключом можно зайти на сервер по SSH, расшифровать трафик или подписаться от твоего имени.",
        "Удали файл, перевыпусти ключ и храни его в секретах CI или менеджере секретов.",
    ),
    Rule(
        "AIG005",
        "env-file-committed",
        Severity.HIGH,
        ".env попадает в репозиторий",
        "В .env обычно лежат все секреты проекта сразу: ключи API, пароли от базы, токены ботов.",
        "Добавь .env в .gitignore и убери его из индекса: git rm --cached .env. "
        "Для примера настроек положи .env.example без настоящих значений.",
        "# .gitignore\n.env\n.env.*\n!.env.example",
    ),
    Rule(
        "AIG010",
        "sql-injection",
        Severity.HIGH,
        "SQL-запрос собирается из строк",
        "Если в запрос попадает ввод пользователя, он может дописать свой SQL: "
        "выгрузить всю базу, удалить таблицы или войти без пароля.",
        "Передавай значения параметрами, а не подставляй в текст запроса.",
        'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
        '# SQLAlchemy\nsession.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})',
    ),
    Rule(
        "AIG011",
        "shell-injection",
        Severity.HIGH,
        "Команда оболочки из переменной",
        "shell=True и os.system запускают строку через shell. Символы вроде ; или && в данных "
        "позволяют выполнить любую команду на сервере.",
        "Передавай команду списком аргументов без shell=True.",
        'subprocess.run(["convert", src, dst], check=True)',
    ),
    Rule(
        "AIG012",
        "eval-exec",
        Severity.HIGH,
        "eval / exec над динамическими данными",
        "eval выполняет строку как код. Если строка хоть как-то зависит от пользователя, это удалённое "
        "выполнение кода.",
        "Для разбора данных используй json.loads или ast.literal_eval, для логики используй явный словарь функций.",
        "import ast\n\nvalue = ast.literal_eval(raw)",
    ),
    Rule(
        "AIG013",
        "unsafe-deserialization",
        Severity.HIGH,
        "Небезопасная десериализация",
        "pickle и yaml.load умеют создавать произвольные объекты. Подложенный файл выполнит код при загрузке.",
        "Используй json или yaml.safe_load. pickle допустим только для данных, которые создал ты сам.",
        "data = yaml.safe_load(fh)",
    ),
    Rule(
        "AIG014",
        "debug-enabled",
        Severity.MEDIUM,
        "Включён режим отладки",
        "В debug-режиме при ошибке наружу уходят стектрейсы, пути и настройки. "
        "Отладчик Flask/Werkzeug вообще даёт выполнить код из браузера.",
        "Управляй режимом через переменную окружения и выключай его в продакшене.",
        'DEBUG = os.getenv("DEBUG") == "1"',
    ),
    Rule(
        "AIG015",
        "cors-wildcard",
        Severity.MEDIUM,
        "CORS разрешает любой сайт",
        "allow_origins=['*'] разрешает запросы к API с любого сайта. В паре с allow_credentials "
        "чужая страница сможет действовать от имени залогиненного пользователя.",
        "Перечисли конкретные домены фронтенда.",
        'app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True)',
    ),
    Rule(
        "AIG016",
        "tls-verify-disabled",
        Severity.MEDIUM,
        "Отключена проверка TLS-сертификата",
        "verify=False позволяет любому в той же сети подменить ответ сервера и прочитать токены (MITM).",
        "Убери verify=False. Для своего сертификата укажи путь к CA: verify='/path/ca.pem'.",
    ),
    Rule(
        "AIG017",
        "jwt-no-verify",
        Severity.HIGH,
        "JWT без проверки подписи",
        "Если подпись не проверяется, любой может сам написать токен с user_id=1 или role=admin.",
        "Всегда проверяй подпись и явно указывай алгоритм.",
        'jwt.decode(token, SECRET_KEY, algorithms=["HS256"])',
    ),
    Rule(
        "AIG018",
        "weak-hash",
        Severity.LOW,
        "Слабый хеш (MD5 / SHA-1)",
        "MD5 и SHA-1 давно сломаны. Для паролей они перебираются на видеокарте за минуты.",
        "Для паролей используй bcrypt/argon2 (passlib, argon2-cffi), для контрольных сумм используй sha256.",
        "from passlib.hash import bcrypt\n\nhashed = bcrypt.hash(password)",
    ),
    Rule(
        "AIG019",
        "insecure-random",
        Severity.MEDIUM,
        "Токен генерируется через random",
        "Модуль random предсказуем. Коды подтверждения, токены сброса пароля и сессии можно угадать.",
        "Для всего, что связано с безопасностью, используй secrets.",
        "import secrets\n\ntoken = secrets.token_urlsafe(32)\ncode = secrets.randbelow(10**6)",
    ),
    Rule(
        "AIG021",
        "unauthenticated-endpoint",
        Severity.LOW,
        "Изменяющий эндпоинт без зависимости авторизации",
        "POST/PUT/PATCH/DELETE без Depends(...) часто означает, что изменить или удалить данные может кто угодно. "
        "ИИ-ассистенты регулярно забывают про авторизацию.",
        "Добавь зависимость авторизации на эндпоинт или на весь роутер. Если эндпоинт должен быть публичным, "
        "пометь строку комментарием aigis: ignore.",
        "router = APIRouter(dependencies=[Depends(get_current_user)])",
    ),
    Rule(
        "AIG030",
        "js-eval",
        Severity.HIGH,
        "eval / new Function в JavaScript",
        "Выполнение строки как кода открывает дорогу XSS и удалённому выполнению кода.",
        "Используй JSON.parse для данных и явные функции для логики.",
    ),
    Rule(
        "AIG031",
        "xss-sink",
        Severity.MEDIUM,
        "Вставка сырого HTML (риск XSS)",
        "innerHTML, dangerouslySetInnerHTML и v-html выполняют скрипты из данных. "
        "Один комментарий пользователя, и у всех угнаны сессии.",
        "Используй textContent или обычный рендер фреймворка. Если HTML нужен, очищай его через DOMPurify.",
        "el.textContent = userText\n// or\nel.innerHTML = DOMPurify.sanitize(html)",
    ),
    Rule(
        "AIG032",
        "public-env-secret",
        Severity.MEDIUM,
        "Секрет в публичной переменной фронтенда",
        "Переменные с префиксами NEXT_PUBLIC_, VITE_, REACT_APP_ вшиваются в JS-бандл, "
        "и их видит любой посетитель сайта.",
        "Держи секреты только на сервере, а фронтенд пусть ходит через свой backend.",
    ),
    Rule(
        "AIG040",
        "docker-root",
        Severity.LOW,
        "Контейнер работает от root",
        "Если приложение взломают, у атакующего будет root внутри контейнера, и выбраться наружу станет проще.",
        "Создай пользователя и переключись на него в конце Dockerfile.",
        "RUN useradd --create-home app\nUSER app",
    ),
    Rule(
        "AIG042",
        "exposed-database-port",
        Severity.MEDIUM,
        "Порт базы открыт наружу",
        "Публикация 5432/3306/6379/27017 на все интерфейсы открывает базу всему интернету на VPS. "
        "Боты перебирают такие порты круглосуточно.",
        "Не публикуй порт вообще (сервисы в одной сети compose видят друг друга) или привяжи его к 127.0.0.1.",
        'ports:\n  - "127.0.0.1:5432:5432"',
    ),
]

RULES: dict[str, Rule] = {r.id: r for r in _RULES}


def get(rule_id: str) -> Rule:
    return RULES[rule_id]
