from __future__ import annotations

import re

SECRET_NAME = re.compile(
    r"^(?!.*(_url|_uri|_endpoint|_field|_name|_header|_len|_length|_type|_prefix|_pattern|_regex|_label"
    r"|_path|_file|_env|_var|_id|_expire|_expires|_ttl|_min|_max|_hint|_policy|_algorithm|_scheme)$)"
    r".*(pass(word|wd)?$|passwd|password|pwd$|secret|api_?key|apikey|access_?key|private_?key|auth_?key"
    r"|token$|_token|token_)",
    re.I,
)

_PLACEHOLDER = re.compile(
    r"^(<.*>|\{.*\}|\$.*|\*+|x+|\.+|-+|changeme|change_me|change-me|your[_-].*|example.*|placeholder|todo"
    r"|pass|passwd|pwd|user|username|null|none|nil|true|false|undefined|secret|password|token|test|dummy|fake|sample|redacted|xxx.*)$",
    re.I,
)


def is_placeholder(value: str) -> bool:
    v = value.strip()
    return len(v) < 4 or " " in v or bool(_PLACEHOLDER.match(v)) or v.startswith(("http://", "https://"))


def mask(value: str) -> str:
    if len(value) <= 6:
        return "*" * len(value)
    return value[:4] + "*" * min(12, len(value) - 4)
