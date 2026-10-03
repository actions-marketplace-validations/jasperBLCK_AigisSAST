from __future__ import annotations

from urllib.parse import quote

from aigis.scanner import ScanResult

GRADE_COLOR = {"A": "2ea44f", "B": "97ca00", "C": "dfb317", "D": "fe7d37", "F": "e05d44"}
CHAR_WIDTH = 7


def _text_width(text: str) -> int:
    return len(text) * CHAR_WIDTH + 12


def badge_message(result: ScanResult) -> str:
    return f"{result.grade} {result.score}/100"


def badge_url(result: ScanResult, label: str = "aigis") -> str:
    msg = quote(badge_message(result).replace("-", "--"), safe="")
    return f"https://img.shields.io/badge/{quote(label)}-{msg}-{GRADE_COLOR[result.grade]}?labelColor=000000"


def badge_svg(result: ScanResult, label: str = "aigis") -> str:
    msg = badge_message(result)
    lw, mw = _text_width(label), _text_width(msg)
    w = lw + mw
    color = GRADE_COLOR[result.grade]
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="{label}: {msg}">'
        f"<title>{label}: {msg}</title>"
        f'<clipPath id="r"><rect width="{w}" height="20" rx="3"/></clipPath>'
        f'<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#000"/>'
        f'<rect x="{lw}" width="{mw}" height="20" fill="#{color}"/></g>'
        f'<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{lw / 2}" y="14">{label}</text>'
        f'<text x="{lw + mw / 2}" y="14">{msg}</text></g></svg>'
    )
