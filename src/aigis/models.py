from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        return cls[value.strip().upper()]

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Rule:
    """A rule. `title`, `why` and `fix` are bilingual: {"en": ..., "ru": ...}."""

    id: str
    slug: str
    severity: Severity
    title: dict[str, str]
    why: dict[str, str]
    fix: dict[str, str]
    example: str = ""


@dataclass
class Finding:
    rule: Rule
    path: str
    line: int
    snippet: str
    severity: Severity | None = None
    detail: str = ""
    ai_fix: str = ""
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def effective_severity(self) -> Severity:
        return self.severity or self.rule.severity

    @property
    def sort_key(self) -> tuple[int, str, int]:
        return (-int(self.effective_severity), self.path, self.line)
