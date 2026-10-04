from __future__ import annotations

import json
import os
import sys
import textwrap
from collections import defaultdict
from collections.abc import Callable
from typing import TextIO

from aigis import __version__, gitlink
from aigis.i18n import pick, tr
from aigis.models import Finding, Rule, Severity
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
    Severity.CRITICAL: ("1", "97", "41"),
    Severity.HIGH: ("1", "91"),
    Severity.MEDIUM: ("1", "93"),
    Severity.LOW: ("2",),
}
GRADE_STYLE = {"A": "42", "B": "42", "C": "43", "D": "41", "F": "41"}


def use_color(stream: TextIO, force: bool | None) -> bool:
    if force is not None:
        return force
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


WRAP = 100
LinkFn = Callable[[str, int], str]


def _indent(text: str, prefix: str) -> str:
    return "\n".join(prefix + ln for ln in text.splitlines())


def _prose(text: str, prefix: str) -> str:
    return "\n".join(textwrap.fill(p, WRAP, initial_indent=prefix, subsequent_indent=prefix) for p in text.splitlines())


def _linker(result: ScanResult) -> LinkFn | None:
    base, sha = gitlink.repo_web(str(result.root))
    if not base or not sha:
        return None
    prefix = gitlink.repo_prefix(str(result.root))
    return lambda path, line: gitlink.file_url(base, sha, prefix + path, line)


def _title(f: Finding, lang: str) -> str:
    return pick(f.rule.title, lang) + (f" ({f.detail})" if f.detail else "")


def _summary(result: ScanResult, st: Style) -> str:
    return "  ".join(
        st(f"■ {s.label} {result.count(s)}", *SEV_STYLE[s]) if result.count(s) else st(f"□ {s.label} 0", "2")
        for s in sorted(Severity, reverse=True)
    )


def render_text(result: ScanResult, *, color: bool, verbose: bool = True, lang: str = "en") -> str:
    st = Style(color)
    link = _linker(result)
    out = [
        st(BANNER.rstrip("\n"), "1"),
        st(f"  v{__version__}  //  {tr(lang, 'tagline')}", "2"),
        "",
        st(f"  {tr(lang, 'target')} {result.root}", "2"),
        st(f"  {tr(lang, 'files')} {result.files_scanned}", "2")
        + st(f"   {tr(lang, 'findings')} ", "2")
        + st(str(len(result.findings)), "1"),
        f"  {_summary(result, st)}",
        "",
    ]

    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in result.findings:
        by_file[f.path].append(f)

    for path in sorted(by_file, key=lambda p: min(f.sort_key for f in by_file[p])):
        out.append(st(f"▌ {path}", "1", "4"))
        for f in by_file[path]:
            sev = f.effective_severity
            tag = st(f" {sev.name:<8} ", *SEV_STYLE[sev])
            out.append(f"  {tag} {st(f.rule.id, '1')}  {_title(f, lang)}")
            out.append(st(f"           {path}:{f.line}", "2"))
            if link:
                out.append(st("           ↗ ", "2") + st(link(path, f.line), "36", "4"))
            if f.snippet:
                out.append(f"           {st('│', '2')} {f.snippet}")
            if verbose:
                out.append(st(f"           {tr(lang, 'why')}", "1"))
                out.append(_prose(pick(f.rule.why, lang), "             "))
                out.append(st(f"           {tr(lang, 'how')}", "1", "32"))
                out.append(
                    _prose(f.ai_fix, "             ") if f.ai_fix else _prose(pick(f.rule.fix, lang), "             ")
                )
                if f.rule.example and not f.ai_fix:
                    out.append(_indent(f.rule.example, st("             │ ", "2")))
            out.append("")

    out.append(st("─" * 64, "2"))
    if not result.findings:
        out.append(st(f"  {tr(lang, 'clean')}", "1", "32"))
    out.append(f"  {_summary(result, st)}")
    out.append(
        f"  {tr(lang, 'score')} {st(f'{result.score}/100', '1')}   "
        f"{tr(lang, 'grade')} {st(f' {result.grade} ', '1', '97', GRADE_STYLE[result.grade])}"
    )
    if result.findings:
        top = min(result.findings, key=lambda f: f.sort_key)
        out.append(st(f"  {tr(lang, 'fix_first')} ", "2") + f"{top.rule.id} {top.path}:{top.line}")
    out.append("")
    return "\n".join(out)


def _finding_dict(f: Finding, link: LinkFn | None, lang: str) -> dict[str, object]:
    d: dict[str, object] = {
        "rule": f.rule.id,
        "slug": f.rule.slug,
        "severity": f.effective_severity.label,
        "title": pick(f.rule.title, lang),
        "path": f.path,
        "line": f.line,
        "snippet": f.snippet,
        "detail": f.detail,
        "why": pick(f.rule.why, lang),
        "fix": f.ai_fix or pick(f.rule.fix, lang),
    }
    if link:
        d["url"] = link(f.path, f.line)
    return d


def render_json(result: ScanResult, lang: str = "en") -> str:
    link = _linker(result)
    return json.dumps(
        {
            "tool": "AigisSAST",
            "version": __version__,
            "lang": lang,
            "files_scanned": result.files_scanned,
            "score": result.score,
            "grade": result.grade,
            "summary": {s.label: result.count(s) for s in Severity},
            "findings": [_finding_dict(f, link, lang) for f in result.findings],
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


def render_sarif(result: ScanResult, lang: str = "en") -> str:
    rules = [
        {
            "id": r.id,
            "name": r.slug,
            "shortDescription": {"text": pick(r.title, lang)},
            "fullDescription": {"text": pick(r.why, lang)},
            "help": {
                "text": f"{pick(r.fix, lang)}\n\n{r.example}".strip(),
                "markdown": rule_markdown_help(r, lang),
            },
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
            "properties": {"tags": ["security"], "security-severity": SECURITY_SEVERITY[r.severity]},
        }
        for r in RULES.values()
    ]
    results = [
        {
            "ruleId": f.rule.id,
            "level": SARIF_LEVEL[f.effective_severity],
            "message": {
                "text": f"{pick(f.rule.title, lang)}{': ' + f.detail if f.detail else ''}. {pick(f.rule.fix, lang)}"
            },
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


def rule_markdown_help(r: Rule, lang: str = "en") -> str:
    md = f"**{tr(lang, 'explain_why')}** {pick(r.why, lang)}\n\n**{tr(lang, 'explain_fix')}** {pick(r.fix, lang)}"
    if r.example:
        md += f"\n\n```\n{r.example}\n```"
    return md


def render_markdown(result: ScanResult, lang: str = "en") -> str:
    link = _linker(result)
    out = [
        f"## {tr(lang, 'md_report')}",
        "",
        f"**{tr(lang, 'md_score')}:** {result.score}/100 · **{tr(lang, 'md_grade')}:** `{result.grade}` · "
        f"**{tr(lang, 'md_files')}:** {result.files_scanned}",
        "",
        f"| {tr(lang, 'md_severity')} | {tr(lang, 'md_count')} |",
        "|---|---|",
        *[f"| {s.name} | {result.count(s)} |" for s in sorted(Severity, reverse=True)],
        "",
    ]
    if not result.findings:
        out.append(tr(lang, "md_none"))
    for f in result.findings:
        loc = f"`{f.path}:{f.line}`"
        out += [
            f"### `{f.effective_severity.name}` {f.rule.id} · {_title(f, lang)}",
            f"[{loc}]({link(f.path, f.line)})" if link else loc,
            "",
            f"```\n{f.snippet}\n```" if f.snippet else "",
            f"**{tr(lang, 'explain_why')}** {pick(f.rule.why, lang)}",
            "",
            f"**{tr(lang, 'explain_fix')}** {f.ai_fix or pick(f.rule.fix, lang)}",
            "",
        ]
    return "\n".join(out)


def render(result: ScanResult, fmt: str, *, color: bool, verbose: bool = True, lang: str = "en") -> str:
    if fmt == "json":
        return render_json(result, lang)
    if fmt == "sarif":
        return render_sarif(result, lang)
    if fmt == "markdown":
        return render_markdown(result, lang)
    return render_text(result, color=color, verbose=verbose, lang=lang)


def write(text: str, path: str | None) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        sys.stdout.write(text + "\n")
