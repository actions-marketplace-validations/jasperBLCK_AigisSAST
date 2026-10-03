from __future__ import annotations

import re

SECRET_NAME = re.compile(
    r"^(?!(hashed|hash|from|is|has|show|use|enable|max|min|pad|eos|bos|unk|sep|cls|mask|existing|forgot|reset)_)"
    r"(?!.*(_url|_uri|_endpoint|_field|_name|_header|_len|_length|_type|_prefix|_pattern|_regex|_label"
    r"|_path|_file|_env|_var|_id|_expire|_expires|_ttl|_min|_max|_hint|_policy|_algorithm|_scheme"
    r"|_hash|_hashed|_masked|_minutes|_seconds|_hours|_days|_count|_ref|_key_id|_placeholder|_required"
    r"|_title|_tip|_text|_message|_msg|_description|_error|_route|_tokens|_source|_preference|_mode|_strategy"
    r"|_create|_property|_param|_kind|_format|_provider|_style|_class|_options?|_status|_state|_scopes?|_location"
    r"|_dir|_column|_selector|_icon|_permission|_action|_event|_template|_input|_attribute|_duration|(token|tokens|password|days|count)_key)$)"
    r".*(pass(word|wd)?$|passwd|password|pwd$|secret|api_?key|apikey|access_?key|private_?key|auth_?key"
    r"|token$|_token|token_)",
    re.I,
)

_PLACEHOLDER = re.compile(
    r"^(<.*>|\{.*\}|\$.*|\*+|x+|\.+|-+|--[\w-]+|changeme|change_me|change-me|your[_-].*|example.*|placeholder|todo"
    r"|pass|passwd|pwd|user|username|null|none|nil|true|false|undefined|secret|password|token|test|dummy|fake|sample|redacted|xxx.*)$",
    re.I,
)


_PLACEHOLDER_PREFIX = re.compile(
    r"^(sk[-_](test|dummy|fake|your|xxx)|test|mock|dummy|fake|example|sample|placeholder|changeme|change[_-]me"
    r"|your|replace|insert|invalid|demo|not_set|unset|none_|__|<|\[)",
    re.I,
)
_PLACEHOLDER_PART = re.compile(
    r"(your[_-]|_here\b|-here\b|xxxx|example|placeholder|dummy|changeme|changethis|redacted)", re.I
)
_NOT_A_VALUE = re.compile(
    r"^(read|write|inherit|required|optional|string|str|boolean|bool|number|int|integer|object|array|any|hidden"
    r"|bearer|basic|oauth2?|jwt|hs256|rs256|sha256|md5|bcrypt|argon2|plain|env|file|always|never|auto|default"
    r"|enabled|disabled|yes|no|on|off)$"
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
        or "{{" in v
        or "{%" in v
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
DEFAULT_PASSWORDS = {
    "postgres",
    "password",
    "pass",
    "admin",
    "root",
    "mysql",
    "guest",
    "secret",
    "test",
    "example",
    "minioadmin",
    "mypassword",
    "changeme",
    "password123",
    "admin123",
    "123456",
    "default",
}


def is_local_default_db(password: str, host: str, user: str = "") -> bool:
    pw, host = password.lower(), host.lower()
    weak = pw in DEFAULT_PASSWORDS or pw == user.lower() or (len(pw) >= 4 and pw in host)
    return "example" in host or (weak and (host in LOCAL_HOSTS or "." not in host))


def same_as_name(name: str, value: str) -> bool:
    return normalize_name(value) in normalize_name(name) or normalize_name(name) in normalize_name(value)


def normalize_name(name: str) -> str:
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return name.replace("-", "_").replace(".", "_").lower()


_IDENTIFIER_VALUE = re.compile(r"^[a-z]+(?:[_\-.:][a-z]+)+$")
_PASSWORD_NAME = re.compile(r"pass|pwd", re.I)


def is_identifier_value(name: str, value: str) -> bool:
    return bool(_IDENTIFIER_VALUE.match(value.strip())) and not _PASSWORD_NAME.search(name)


def is_secret_name(name: str) -> bool:
    return bool(SECRET_NAME.search(normalize_name(name)))


_TEST_DIR = re.compile(
    r"^(__)?(tests?|testing|specs?|e2e|fixtures?|testdata|mocks?|playwright|cypress)(__)?$"
    r"|^tests?[_-]|[_-](tests?|testing|fixtures?|mocks?)$|^samples?[_-]"
)


def is_test_path(path: str) -> bool:
    parts = path.split("/")
    name = parts[-1]
    lower = name.lower()
    return (
        any(_TEST_DIR.search(p.lower()) for p in parts[:-1])
        or lower.startswith(("test_", "test-"))
        or lower == "conftest.py"
        or re.search(r"(_tests?\.(py|go|rs)|\.(test|spec|stories)\.[cm]?[jt]sx?|tests?\.[a-z]+)$", lower) is not None
        or re.search(r"[_-]testing\.[a-z]+$", lower) is not None
        or re.search(r"(Test|Tests|Spec)\.(kt|java|scala|cs|swift)$", name) is not None
    )


TEST_VALUE_NAME = re.compile(r"\b(TEST|MOCK|FAKE|DUMMY|EXAMPLE|SAMPLE)_|pragma:\s*allowlist\s+secret")


def is_dummy_token(token: str) -> bool:
    if (
        _PLACEHOLDER_PART.search(token)
        or "1234567890" in token
        or "0000000000" in token
        or re.search(r"test|fake|mock|dummy|sample|abcdef|aaaaaa|0123456", token, re.I)
    ):
        return True
    head = token.split(":", 1)[0]
    return ":" in token and head.isdigit() and len(set(head)) == 1


def mask(value: str) -> str:
    if len(value) <= 6:
        return "*" * len(value)
    return value[:4] + "*" * min(12, len(value) - 4)
