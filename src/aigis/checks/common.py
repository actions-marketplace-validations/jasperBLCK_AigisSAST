from __future__ import annotations

import re

SECRET_NAME = re.compile(
    r"^(?!(hashed|hash|from|is|has|show|use|enable|max|min|pad|eos|bos|unk|sep|cls|mask|existing|forgot|reset)_)"
    r"(?!.*(_url|_uri|_endpoint|_field|_name|_header|_len|_length|_type|_prefix|_pattern|_regex|_label"
    r"|_path|_file|_env|_var|_id|_expire|_expires|_ttl|_min|_max|_hint|_policy|_algorithm|_scheme"
    r"|_hash|_hashed|_masked|_minutes|_seconds|_hours|_days|_count|_ref|_key_id|_placeholder|_required"
    r"|_title|_tip|_text|_message|_msg|_description|_error|_route|_tokens|(token|tokens|password|days|count)_key)$)"
    r".*(pass(word|wd)?$|passwd|password|pwd$|secret|api_?key|apikey|access_?key|private_?key|auth_?key"
    r"|token$|_token|token_)",
    re.I,
)

_PLACEHOLDER = re.compile(
    r"^(<.*>|\{.*\}|\$.*|\*+|x+|\.+|-+|changeme|change_me|change-me|your[_-].*|example.*|placeholder|todo"
    r"|pass|passwd|pwd|user|username|null|none|nil|true|false|undefined|secret|password|token|test|dummy|fake|sample|redacted|xxx.*)$",
    re.I,
)


_PLACEHOLDER_PREFIX = re.compile(
    r"^(sk[-_](test|dummy|fake|your|xxx)|test|mock|dummy|fake|example|sample|placeholder|changeme|change[_-]me"
    r"|your|replace|insert|invalid|demo|not_set|unset|none_|__|<|\[)",
    re.I,
)
_PLACEHOLDER_PART = re.compile(r"(your[_-]|_here\b|-here\b|xxxx|example|placeholder|dummy|changeme|redacted)", re.I)
_NOT_A_VALUE = re.compile(
    r"^(read|write|inherit|required|optional|string|str|boolean|bool|number|int|integer|object|array|any|hidden"
    r"|bearer|basic|oauth2?|jwt|hs256|rs256|sha256|md5|bcrypt|argon2|plain|env|file)$"
    r"|^[\^~<>=]*v?\d+(\.\d+)+\S*$",
    re.I,
)
_CONSTANT_NAME = re.compile(r"[A-Z][A-Z0-9]*(_[A-Z0-9]+)+")
_CODE_REF = ("os.", "process.", "env.", "settings.", "config.", "self.", "import.meta", "secrets.", "vars.")


def is_placeholder(value: str) -> bool:
    v = value.strip()
    return (
        len(v) < 4
        or " " in v
        or "(" in v
        or "${" in v
        or bool(_PLACEHOLDER.match(v))
        or bool(_PLACEHOLDER_PREFIX.match(v))
        or bool(_PLACEHOLDER_PART.search(v))
        or bool(_NOT_A_VALUE.match(v))
        or not v.isascii()
        or bool(_CONSTANT_NAME.fullmatch(v))
        or v.startswith(("http://", "https://", "/", "%", "\\$", "ENC[", *_CODE_REF))
    )


LOCAL_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "db",
    "postgres",
    "postgresql",
    "mysql",
    "mongo",
    "mongodb",
    "redis",
}
DEFAULT_PASSWORDS = {"postgres", "password", "pass", "admin", "root", "mysql", "guest", "secret", "test", "example"}


def is_local_default_db(password: str, host: str) -> bool:
    return "example" in host.lower() or (password.lower() in DEFAULT_PASSWORDS and host.lower() in LOCAL_HOSTS)


def same_as_name(name: str, value: str) -> bool:
    return normalize_name(value) in normalize_name(name) or normalize_name(name) in normalize_name(value)


def normalize_name(name: str) -> str:
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return name.replace("-", "_").replace(".", "_").lower()


def is_secret_name(name: str) -> bool:
    return bool(SECRET_NAME.search(normalize_name(name)))


_TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "e2e", "fixtures", "__fixtures__", "testdata", "mocks"}


def is_test_path(path: str) -> bool:
    parts = path.lower().split("/")
    name = parts[-1]
    return (
        any(p in _TEST_DIRS for p in parts[:-1])
        or name.startswith(("test_", "test-"))
        or name == "conftest.py"
        or re.search(r"(_test\.(py|go)|\.(test|spec)\.[jt]sx?|tests?\.[a-z]+)$", name) is not None
    )


def is_dummy_token(token: str) -> bool:
    if _PLACEHOLDER_PART.search(token) or "1234567890" in token or "0000000000" in token:
        return True
    head = token.split(":", 1)[0]
    return ":" in token and head.isdigit() and len(set(head)) == 1


def mask(value: str) -> str:
    if len(value) <= 6:
        return "*" * len(value)
    return value[:4] + "*" * min(12, len(value) - 4)
