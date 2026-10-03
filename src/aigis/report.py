from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from typing import TextIO

from aigis import __version__
from aigis.models import Finding, Severity
from aigis.rules import RULES
from aigis.scanner import ScanResult

BANNER = r"""
   ___  _       _      _____ ___   _____ ______
  / _ \(_)__ _ (_)___ / ___// _ | / ___//_  __/
 / __ / / _ `// /(_-<_\__ \/ __ |_\__ \  / /
/_/ |_/_/\_, //_//___/____/_/ |_/____/ /_/
        /___/
"""


class Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, *codes: str) -> str:
        if not self.enabled or not codes:
            return text
        return f"\033[{';'.join(codes)}m{text}\033[0m"


SEV_STYLE = {
    Severity.CRITICAL: ("1", "7"),
    Severity.HIGH: ("1", "97"),
    Severity.MEDIUM: ("37",),
    Severity.LOW: ("2",),
}


def use_color(stream: TextIO, force: bool | None) -> bool:
    if force is not None:
        return force
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _indent(text: str, prefix: str) -> str:
    return "\n".join(prefix + ln for ln in text.splitlines())


def render_text(result: ScanResult, *, color: bool, verbose: bool = True) -> str:
    st = Style(color)
    out = [
        st(BANNER.rstrip("\n"), "1"),
        st(f"  v{__version__}  //  security scanner for AI-generated code", "2"),
        "",
    ]
    out.append(st(f"  target: {result.root}", "2"))
    out.append(st(f"  files:  {result.files_scanned}", "2"))
    out.append("")

    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in result.findings:
        by_file[f.path].append(f)

    for path in sorted(by_file, key=lambda p: min(f.sort_key for f in by_file[p])):
        out.append(st(f"▌ {path}", "1", "4"))
        for f in by_file[path]:
            sev = f.effective_severity
            tag = st(f" {sev.name:<8} ", *SEV_STYLE[sev])
            title = f.rule.title + (f" ({f.detail})" if f.detail else "")
            out.append(f"  {tag} {st(f.rule.id, '1')}  {title}")
            out.append(st(f"           {path}:{f.line}", "2"))
            if f.snippet:
                out.append(f"           {st('│', '2')} {f.snippet}")
            if verbose:
                out.append(st("           чем опасно:", "1"))
                out.append(_indent(f.rule.why, "             "))
                out.append(st("           как исправить:", "1"))
                out.append(_indent(f.ai_fix or f.rule.fix, "             "))
                if f.rule.example and not f.ai_fix:
                    out.append(_indent(f.rule.example, st("             │ ", "2")))
            out.append("")

    out.append(st("─" * 64, "2"))
    if not result.findings:
        out.append(st("  ✓ чисто: ничего опасного не найдено", "1"))
    counts = "   ".join(f"{s.name.lower()}: {st(str(result.count(s)), '1')}" for s in sorted(Severity, reverse=True))
    out.append(f"  {counts}")
    out.append(f"  security score: {st(f'{result.score}/100', '1')}  grade {st(f' {result.grade} ', '1', '7')}")
    out.append("")
    return "\n".join(out)


def _finding_dict(f: Finding) -> dict[str, object]:
    return {
        "rule": f.rule.id,
        "slug": f.rule.slug,
        "severity": f.effective_severity.label,
        "title": f.rule.title,
        "path": f.path,
        "line": f.line,
        "snippet": f.snippet,
        "detail": f.detail,
        "why": f.rule.why,
        "fix": f.ai_fix or f.rule.fix,
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "tool": "AigisSAST",
            "version": __version__,
            "files_scanned": result.files_scanned,
            "score": result.score,
            "grade": result.grade,
            "summary": {s.label: result.count(s) for s in Severity},
            "findings": [_finding_dict(f) for f in result.findings],
        },
        ensure_ascii=False,
        indent=2,
    )


SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
}


def render_sarif(result: ScanResult) -> str:
    rules = [
        {
            "id": r.id,
            "name": r.slug,
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.why},
            "help": {"text": f"{r.fix}\n\n{r.example}".strip(), "markdown": _rule_markdown_help(r.id)},
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
            "properties": {"tags": ["security"], "security-severity": SECURITY_SEVERITY[r.severity]},
        }
        for r in RULES.values()
    ]
    results = [
        {
            "ruleId": f.rule.id,
            "level": SARIF_LEVEL[f.effective_severity],
            "message": {"text": f"{f.rule.title}{': ' + f.detail if f.detail else ''}. {f.rule.fix}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.path},
                        "region": {"startLine": max(1, f.line)},
                    }
                }
            ],
            "properties": {"security-severity": SECURITY_SEVERITY[f.effective_severity]},
        }
        for f in result.findings
    ]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AigisSAST",
                        "version": __version__,
                        "informationUri": "https://github.com/jasperBLCK/AigisSAST",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)


def _rule_markdown_help(rule_id: str) -> str:
    r = RULES[rule_id]
    md = f"**Чем опасно:** {r.why}\n\n**Как исправить:** {r.fix}"
    if r.example:
        md += f"\n\n```\n{r.example}\n```"
    return md


def render_markdown(result: ScanResult) -> str:
    out = [
        "## AigisSAST report",
        "",
        f"**Score:** {result.score}/100 · **Grade:** `{result.grade}` · **Files:** {result.files_scanned}",
        "",
        "| Severity | Count |",
        "|---|---|",
        *[f"| {s.name} | {result.count(s)} |" for s in sorted(Severity, reverse=True)],
        "",
    ]
    if not result.findings:
        out.append("No issues found.")
    for f in result.findings:
        out += [
            f"### `{f.effective_severity.name}` {f.rule.id} · {f.rule.title}",
            f"`{f.path}:{f.line}`",
            "",
            f"```\n{f.snippet}\n```" if f.snippet else "",
            f"**Чем опасно:** {f.rule.why}",
            "",
            f"**Как исправить:** {f.ai_fix or f.rule.fix}",
            "",
        ]
    return "\n".join(out)


def render(result: ScanResult, fmt: str, *, color: bool, verbose: bool = True) -> str:
    if fmt == "json":
        return render_json(result)
    if fmt == "sarif":
        return render_sarif(result)
    if fmt == "markdown":
        return render_markdown(result)
    return render_text(result, color=color, verbose=verbose)


def write(text: str, path: str | None) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        sys.stdout.write(text + "\n")
