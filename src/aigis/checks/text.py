from __future__ import annotations

import re
from pathlib import PurePosixPath

from aigis.checks.common import SECRET_NAME, is_placeholder, mask
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
    r"[^\s:/@'\"]+:([^\s@'\"]+)@"
)
CONFIG_ASSIGN = re.compile(r"""^\s*(?:export\s+|-\s+)?["']?([A-Za-z_][\w.\-]*)["']?\s*[:=]\s*["']?([^\s"'#,]+)""")
DOCKER_ENV = re.compile(r"^\s*(?:ENV|ARG)\s+([A-Za-z_]\w*)[ =]\s*[\"']?([^\s\"']+)", re.I)
CODE_ASSIGN = re.compile(r"""\b([A-Za-z_$][\w$]*)["']?\s*(?::|=|:=)\s*(["'`])([^"'`\s]{4,})\2""")
JS_EVAL = re.compile(r"(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(")
XSS_SINK = re.compile(r"\.(?:inner|outer)HTML\s*\+?=(?!=)|dangerouslySetInnerHTML|\bv-html\s*=|document\.write\s*\(")
PUBLIC_ENV = re.compile(
    r"\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_PUBLIC_|EXPO_PUBLIC_)\w*?"
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
DOC_EXT = {".md", ".rst", ".txt", ".adoc"}
EXAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".tmpl")


def _finding(rule_id: str, path: str, lineno: int, line: str, secret: str | None = None, detail: str = "") -> Finding:
    snippet = line.strip()
    if secret:
        snippet = snippet.replace(secret, mask(secret))
    if len(snippet) > 160:
        snippet = snippet[:157] + "..."
    return Finding(get(rule_id), path, lineno, snippet, detail=detail)


def is_env_file(path: str) -> bool:
    name = PurePosixPath(path).name
    return (name == ".env" or name.startswith(".env.") or name.endswith(".env")) and not name.endswith(EXAMPLE_SUFFIXES)


def is_example(path: str) -> bool:
    return PurePosixPath(path).name.endswith(EXAMPLE_SUFFIXES) or ".example." in PurePosixPath(path).name


def check_text(path: str, text: str, *, is_python: bool) -> list[Finding]:
    p = PurePosixPath(path)
    name = p.name.lower()
    ext = p.suffix.lower()
    is_doc = ext in DOC_EXT
    is_dockerfile = name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile")
    is_compose = name.startswith(("docker-compose", "compose")) and ext in {".yml", ".yaml"}
    is_config = (ext in CONFIG_EXT or is_dockerfile) and not is_example(path)
    is_code = ext in CODE_EXT and not is_example(path)
    is_front = ext in FRONT_EXT

    findings: list[Finding] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if len(line) > 2000:
            continue
        for label, pattern in TOKEN_PATTERNS:
            m = pattern.search(line)
            if m:
                findings.append(_finding("AIG001", path, i, line, m.group(0), label))
                break
        if PRIVATE_KEY.search(line):
            findings.append(_finding("AIG004", path, i, line))
        if is_doc or is_example(path):
            continue

        m = DB_URL.search(line)
        if m and not is_placeholder(m.group(1)) and "{" not in m.group(1):
            findings.append(_finding("AIG003", path, i, line, m.group(1)))
            continue

        if not is_python:
            secret = _generic_secret(line, is_config=is_config, is_code=is_code, is_dockerfile=is_dockerfile)
            if secret:
                findings.append(_finding("AIG002", path, i, line, secret[1], secret[0]))

        if PUBLIC_ENV.search(line):
            findings.append(_finding("AIG032", path, i, line))
        if is_front:
            if JS_EVAL.search(line):
                findings.append(_finding("AIG030", path, i, line))
            if XSS_SINK.search(line):
                findings.append(_finding("AIG031", path, i, line))
            if JS_CORS.search(line):
                findings.append(_finding("AIG015", path, i, line))
        if is_compose and COMPOSE_PORT.search(line):
            findings.append(_finding("AIG042", path, i, line))

    if is_dockerfile:
        findings.extend(_check_dockerfile(path, lines))
    return findings


def _generic_secret(line: str, *, is_config: bool, is_code: bool, is_dockerfile: bool) -> tuple[str, str] | None:
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
        candidates.extend((m.group(1), m.group(3)) for m in CODE_ASSIGN.finditer(line))
    for name, value in candidates:
        if SECRET_NAME.search(name.replace("-", "_").replace(".", "_")) and not is_placeholder(value):
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
