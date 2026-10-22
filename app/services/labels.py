"""Printed labels: the public QR on the cabinet and the coin-door report label inside it.

Both kinds print through one sheet page in one of a few physical formats. A format is a
named entry in FORMATS plus a matching ``.sheet--<key>`` block in static/css/labels.css; the
geometry lives in the stylesheet (no inline styles), and the entry here says what it is.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class LabelFormat:
    key: str
    name: str
    detail: str
    per_page: int


FORMATS: dict[str, LabelFormat] = {f.key: f for f in (
    LabelFormat("paper", "Plain paper", "US Letter, 12 per page, 2.5 in squares with cut lines. "
                "Any printer; tape or laminate inside the door.", 12),
    LabelFormat("avery-22806", "Avery 22806", "2 × 2 in square stickers, 12 per sheet. "
                "Print one page on plain paper first and hold it against a sheet.", 12),
    LabelFormat("dymo-30334", "Label printer", "One 2¼ × 1¼ in label per page (DYMO 30334 "
                "multipurpose). Choose the label size in the print dialog.", 1),
)}
DEFAULT_FORMAT = "paper"


def label_format(key: str | None) -> LabelFormat:
    return FORMATS.get(key or "", FORMATS[DEFAULT_FORMAT])


def pages(labels: list, fmt: LabelFormat) -> list[list]:
    """Split *labels* into printed pages for *fmt*."""
    n = fmt.per_page
    return [labels[i:i + n] for i in range(0, len(labels), n)] or [[]]


def address_problem(url: str) -> str | None:
    """Why a QR built on *url* would not work from a phone on mobile data, or None.

    Unless BASE_URL is set, a label encodes the address the page was opened from, so a sheet
    printed from the office PC on the LAN would only ever work on the venue's Wi-Fi.
    """
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        return "it has no host name"
    if host == "localhost" or host.endswith((".local", ".lan", ".home", ".internal",
                                              ".localdomain")):
        return f"{host} is a name only this network knows"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host:
            return f"{host} is a name only this network knows"
        return None
    if not ip.is_global:
        return f"{host} is a private or reserved address that phones outside cannot reach"
    return None
