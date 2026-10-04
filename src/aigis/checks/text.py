from __future__ import annotations

import re
from pathlib import PurePosixPath

from aigis.checks.common import (
    TEST_VALUE_NAME,
    is_dummy_token,
    is_identifier_value,
    is_local_default_db,
    is_placeholder,
    is_secret_name,
    is_test_path,
    mask,
    normalize_name,
    same_as_name,
)
from aigis.models import Finding
from aigis.rules import get

TOKEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("OpenAI / Anthropic key", re.compile(r"\bsk-(?:proj-|ant-[a-z0-9]+-)?[A-Za-z0-9_\-]{32,}")),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b")),
    ("Stripe live key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Yandex Cloud API key", re.compile(r"\bAQVN[A-Za-z0-9_\-]{35,}\b")),
]
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")
DB_URL = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|mssql)(?:\+\w+)?://"
    r"([^\s:/@'\"]+):([^\s@'\"]+)@([^\s:/'\"?]*)"
)
CONFIG_ASSIGN = re.compile(r"""^\s*(?:export\s+|-\s+)?["']?([A-Za-z_][\w.\-]*)["']?\s*[:=]\s*["']?([^\s"'#,]+)""")
DOCKER_ENV = re.compile(r"^\s*(?:ENV|ARG)\s+([A-Za-z_]\w*)[ =]\s*[\"']?([^\s\"']+)", re.I)
CODE_ASSIGN = re.compile(r"""(?<!\?\s)(?<!\?)(["']?)\b([A-Za-z_$][\w$]*)\1\s*(?::|=|:=)\s*(["'`])([^"'`\s]{4,})\3""")
JS_EVAL = re.compile(r"(?<![\w.$])eval\(|\bnew\s+Function\s*\(")
XSS_SINK = re.compile(r"\.(?:inner|outer)HTML\s*\+?=(?!=)|dangerouslySetInnerHTML|\bv-html\s*=|document\.write\s*\(")
SANITIZED = re.compile(r"saniti|purif|escape", re.I)
JS_FUNC_LITERAL = re.compile(r"""new\s+Function\(\s*(?:(["'`])[^"'`$]*\1\s*,?\s*)+\)""")
JS_EVAL_DECL = re.compile(r"\beval\(\s*\w+\??\s*:|\beval\(\s*\)\s*[:{]")
FIREBASE = re.compile(r"google-services\.json$|GoogleService-Info\.plist$|firebase", re.I)
TS_TYPE = re.compile(r"^\s*(export\s+)?type\s+\w+\s*=")
ENV_TEMPLATE_VALUE = re.compile(r"change|your|example|placeholder|xxx", re.I)
COMMENT_LINE = re.compile(r"^\s*(//|/\*|\*|<!--)")
DOC_DIRS = {"docs", "doc", "document", "documentation", "examples", "example", "samples", "sample", "demo", "demos"}
STATIC_HTML = re.compile(r"""HTML\s*\+?=\s*(["'`])(?:(?!\1).)*\1\s*;?\s*$""")
I18N_DIRS = {"locales", "locale", "i18n", "lang", "langs", "translation", "translations", "l10n"}
I18N_FILE = re.compile(r"^(translate|translation|messages|strings)[._-].*\.(toml|json|ya?ml|ini|properties)$|\.pot?$")
API_SPEC = re.compile(
    r"(^|/)(openapi|swagger)[^/]*\.(json|ya?ml)$|api[-_]?docs?[^/]*\.json$|(^|/)api[-_]?docs?/"
    r"|(^|/)(examples?|samples?)\.[cm]?[jt]sx?$",
    re.I,
)
VENDOR_FILE = re.compile(
    r"^(vue|react|react-dom|jquery|bootstrap|angular|lodash|underscore|moment|axios|echarts|chart|d3|three)"
    r"([.-][\w.-]*)?\.js$",
    re.I,
)
SENTINEL = re.compile(r"^_+\w*_+$")
TOKEN_NAME = re.compile(r"token$|_token|token_", re.I)
KEY_BODY = re.compile(r"[A-Za-z0-9+/=]{40,}")
PUBLIC_ENV = re.compile(
    r"\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_PUBLIC_|EXPO_PUBLIC_)"
    r"(?!\w*(?:GOOGLE|FIREBASE|POSTHOG|AMPLITUDE|MAPBOX|SENTRY|ALGOLIA|PUBLISHABLE|RECAPTCHA|SEGMENT|MIXPANEL"
    r"|ANALYTICS|GA_|GTM|ANON|MAPS|HOTJAR|INTERCOM|PUSHER|CLERK))\w*?"
    r"(?:SECRET|PRIVATE|PASSWORD|SERVICE_ROLE|API_KEY|TOKEN)\w*"
)
JS_CORS = re.compile(r"""\borigin\s*:\s*["'`]\*["'`]""")
COMPOSE_PORT = re.compile(
    r"""^\s*-\s*["']?(?:0\.0\.0\.0:)?\d+:(5432|3306|6379|27017|9200|5672|11211)(?:/tcp)?["']?\s*$"""
)

CODE_EXT = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".vue",
    ".svelte",
    ".go",
    ".php",
    ".rb",
    ".java",
    ".kt",
    ".cs",
    ".rs",
    ".json",
}
FRONT_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".astro"}
CONFIG_EXT = {".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env"}
DOC_EXT = {".md", ".mdx", ".rst", ".txt", ".adoc"}
EXAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".tmpl", ".tpl", ".j2", ".jinja", ".jinja2")


def _finding(rule_id: str, path: str, lineno: int, line: str, secret: str | None = None, detail: str = "") -> Finding:
    snippet = line.strip()
    if secret:
        snippet = snippet.replace(secret, mask(secret))
    if len(snippet) > 160:
        snippet = snippet[:157] + "..."
    return Finding(get(rule_id), path, lineno, snippet, detail=detail)


def is_env_file(path: str) -> bool:
    name = PurePosixPath(path).name
    return (
        (name == ".env" or name.startswith(".env.") or name.endswith(".env"))
        and not is_example(path)
        and "example" not in name.lower()
        and "default" not in name.lower()
        and not name.lower().startswith(ENV_TEST_NAMES)
        and not is_test_path(path)
    )


ENV_TEST_NAMES = (".env.test", ".env.testing", ".env.ci", ".env.e2e")


def env_has_secret(text: str) -> bool:
    for line in text.splitlines():
        m = CONFIG_ASSIGN.match(line)
        if (
            m
            and is_secret_name(m.group(1))
            and m.group(2)
            and not m.group(2).startswith(("$", "{"))
            and not ENV_TEMPLATE_VALUE.search(m.group(2))
        ):
            return True
    return False


def is_example(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return (
        name.endswith(EXAMPLE_SUFFIXES)
        or ".example." in name
        or name.startswith(("example.", "example-", "example_", "sample.", "sample-", "sample_", "template."))
    )


def _in_string(line: str, pos: int) -> bool:
    before = line[:pos]
    return any(before.count(q) % 2 == 1 for q in ("'", '"'))


def has_key_body(lines: list[str], i: int) -> bool:
    line = lines[i - 1]
    tail = line[PRIVATE_KEY.search(line).end() :]
    if "..." in tail or "your" in tail.lower():
        return False
    nxt = lines[i] if i < len(lines) else ""
    return bool(KEY_BODY.search(tail) or KEY_BODY.search(nxt) or not tail.strip() and not nxt.strip())


def check_text(path: str, text: str, *, is_python: bool) -> list[Finding]:
    p = PurePosixPath(path)
    name = p.name.lower()
    ext = p.suffix.lower()
    if VENDOR_FILE.match(name):
        return []
    is_doc = ext in DOC_EXT or any(part.lower() in DOC_DIRS for part in p.parts[:-1]) or bool(API_SPEC.search(path))
    is_dockerfile = name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile")
    is_compose = name.startswith(("docker-compose", "compose")) and ext in {".yml", ".yaml"}
    is_config = (ext in CONFIG_EXT or is_dockerfile) and not is_example(path)
    is_code = ext in CODE_EXT and not is_example(path)
    is_front = ext in FRONT_EXT
    in_tests = is_test_path(path)
    in_ci = path.startswith(".github/workflows/") or any(part in {".ci", ".circleci"} for part in p.parts[:-1])
    docs_like = is_doc or is_example(path)
    is_i18n = any(part.lower() in I18N_DIRS for part in p.parts[:-1]) or bool(I18N_FILE.search(name))

    findings: list[Finding] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if len(line) > 2000:
            continue
        test_value = bool(TEST_VALUE_NAME.search(line))
        for label, pattern in TOKEN_PATTERNS:
            m = pattern.search(line)
            if (
                m
                and not test_value
                and not is_dummy_token(m.group(0))
                and not (docs_like and len(set(m.group(0))) < 16)
                and not (label == "Google API key" and (FIREBASE.search(path) or FIREBASE.search(line)))
            ):
                findings.append(_finding("AIG001", path, i, line, m.group(0), label))
                break
        if (
            PRIVATE_KEY.search(line)
            and not in_tests
            and not test_value
            and not is_example(path)
            and has_key_body(lines, i)
        ):
            findings.append(_finding("AIG004", path, i, line))
        if in_tests or is_i18n:
            continue
        skip_secrets = docs_like or in_ci or test_value

        m = None if skip_secrets else DB_URL.search(line)
        if m:
            user, password, host = m.groups()
            if not is_placeholder(password) and "{" not in password and not is_local_default_db(password, host, user):
                findings.append(_finding("AIG003", path, i, line, password))
                continue

        if not skip_secrets and not is_python and name != "package.json" and not TS_TYPE.match(line):
            secret = generic_secret(line, is_config=is_config, is_code=is_code, is_dockerfile=is_dockerfile)
            if secret:
                findings.append(_finding("AIG002", path, i, line, secret[1], secret[0]))

        if is_front and not COMMENT_LINE.match(line):
            if PUBLIC_ENV.search(line):
                findings.append(_finding("AIG032", path, i, line))
            ev = JS_EVAL.search(line)
            if (
                ev
                and not JS_EVAL_DECL.search(line)
                and not JS_FUNC_LITERAL.search(line)
                and not _in_string(line, ev.start())
            ):
                findings.append(_finding("AIG030", path, i, line))
            if (
                XSS_SINK.search(line)
                and not SANITIZED.search(line)
                and not ("${" not in line and STATIC_HTML.search(line))
            ):
                findings.append(_finding("AIG031", path, i, line))
            if JS_CORS.search(line):
                findings.append(_finding("AIG015", path, i, line))
        if is_compose and COMPOSE_PORT.search(line):
            findings.append(_finding("AIG042", path, i, line))

    if is_dockerfile:
        findings.extend(_check_dockerfile(path, lines))
    return findings


def generic_secret(line: str, *, is_config: bool, is_code: bool, is_dockerfile: bool) -> tuple[str, str] | None:
    stripped = line.strip()
    if stripped.startswith(("#", "//", ";")):
        return None
    candidates: list[tuple[str, str]] = []
    if is_dockerfile:
        m = DOCKER_ENV.match(line)
        if m:
            candidates.append((m.group(1), m.group(2)))
    if is_config:
        m = CONFIG_ASSIGN.match(line)
        if m:
            candidates.append((m.group(1), m.group(2)))
    if is_code:
        candidates.extend((m.group(2), m.group(4)) for m in CODE_ASSIGN.finditer(line))
    for name, value in candidates:
        if (
            is_secret_name(name)
            and not is_placeholder(value)
            and not is_identifier_value(name, value)
            and not same_as_name(name, value)
            and not SENTINEL.match(value)
            and not (TOKEN_NAME.search(normalize_name(name)) and len(value) < 10)
        ):
            return name, value
    return None


def _check_dockerfile(path: str, lines: list[str]) -> list[Finding]:
    last_from = 0
    has_user = False
    for i, line in enumerate(lines, 1):
        s = line.strip().upper()
        if s.startswith("FROM "):
            last_from, has_user = i, False
        elif s.startswith("USER ") and s.split()[1] not in {"ROOT", "0"}:
            has_user = True
    if last_from and not has_user:
        return [_finding("AIG040", path, last_from, lines[last_from - 1])]
    return []
