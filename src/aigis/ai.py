from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from aigis.i18n import pick, tr
from aigis.models import Finding

SECRET_RULES = {"AIG001", "AIG002", "AIG003", "AIG004", "AIG005"}


class AIConfig:
    def __init__(self) -> None:
        self.api_key = os.environ.get("AIGIS_API_KEY", "")
        self.base_url = os.environ.get("AIGIS_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        self.model = os.environ.get("AIGIS_MODEL", "gpt-4o-mini")

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)


def _context(root: Path, finding: Finding, radius: int = 6) -> str:
    try:
        lines = (root / finding.path).read_text("utf-8", "replace").splitlines()
    except OSError:
        return finding.snippet
    start = max(0, finding.line - 1 - radius)
    chunk = lines[start : finding.line + radius]
    return "\n".join(f"{start + i + 1:>4} {ln}" for i, ln in enumerate(chunk))


def _ask(cfg: AIConfig, content: str, timeout: float, lang: str) -> str:
    body = json.dumps(
        {
            "model": cfg.model,
            "temperature": 0.2,
            "messages": [{"role": "system", "content": tr(lang, "ai_prompt")}, {"role": "user", "content": content}],
        }
    ).encode()
    req = urllib.request.Request(
        f"{cfg.base_url}/chat/completions",
        data=body,
        headers={"Authorization": f"Bearer {cfg.api_key}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    return str(data["choices"][0]["message"]["content"]).strip()


def enrich(
    root: Path, findings: list[Finding], *, limit: int = 15, timeout: float = 30.0, lang: str = "en"
) -> str | None:
    """Add AI-written, context-specific fixes. Secret findings are never sent to the model."""
    cfg = AIConfig()
    if not cfg.enabled:
        return tr(lang, "ai_no_key")
    for f in [f for f in findings if f.rule.id not in SECRET_RULES][:limit]:
        content = (
            f"{tr(lang, 'ai_issue')}: {f.rule.id} {pick(f.rule.title, lang)}\n"
            f"{tr(lang, 'ai_file')}: {f.path}:{f.line}\n\n{_context(root, f)}"
        )
        try:
            f.ai_fix = _ask(cfg, content, timeout, lang)
        except (urllib.error.URLError, TimeoutError, KeyError, ValueError) as exc:
            return tr(lang, "ai_failed", error=exc)
    return None
