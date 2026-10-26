"""The arcade's own name, logo and sign-in background (owner's request, 2026-10-26).

Set by an admin on the Branding page. The logo replaces the ARCADE//TRACKER wordmark in the
header, and appears on the sign-in page, the coin-door form, printed labels and PDFs; the name
goes in the browser tab and beside the logo where there is room. "Arcade Tracker" and the
source link stay in the footer, as the AGPL asks.

Files live in ``uploads/branding/``; their names and a version (for cache-busting) are kept in
``app_setting``. A raster logo is re-encoded as PNG, transparency kept; the background as JPEG.

**SVG.** An SVG can carry script, and a file served from this site runs as this site if
someone opens its address directly. So an SVG logo is cleaned on upload -- only drawing
elements and attributes are kept, and any link that isn't to a part of the same file is
dropped -- and it is always served with a policy that forbids script (``sandbox``). Either
alone would mostly do; both together is the point.
"""
from __future__ import annotations

import io
import os
import re
import xml.etree.ElementTree as ET

from app.models.alerts import Setting

LOGO_MAX_BYTES = 2 * 1024 * 1024
BACKGROUND_MAX_BYTES = 12 * 1024 * 1024
LOGO_MAX_PX = 1024
BACKGROUND_MAX_PX = 2560
NAME_MAX = 60
RASTER = ("PNG", "JPEG", "WEBP")
KEYS = ("arcade_name", "logo_file", "logo_version", "background_file", "background_version",
        "print_logo_file", "print_logo_version")

SVG_NS = "http://www.w3.org/2000/svg"
XLINK_NS = "http://www.w3.org/1999/xlink"
# Drawing only. No <script>, <foreignObject> (HTML inside SVG), <image> (fetches), <a>,
# <animate>/<set> (can rewrite an href), <style> (can fetch with @import and url()).
SVG_ELEMENTS = frozenset({
    "svg", "g", "defs", "symbol", "use", "title", "desc", "path", "rect", "circle", "ellipse",
    "line", "polyline", "polygon", "text", "tspan", "textPath", "linearGradient",
    "radialGradient", "stop", "clipPath", "mask", "pattern", "filter", "feGaussianBlur",
    "feOffset", "feBlend", "feColorMatrix", "feFlood", "feComposite", "feMerge", "feMergeNode",
    "feDropShadow", "metadata",
})
URL_IN_VALUE = re.compile(r"url\(\s*['\"]?\s*(?!#)", re.IGNORECASE)


class BrandingError(ValueError):
    """Why an upload was refused, in words for the admin."""


def folder() -> str:
    from flask import current_app

    path = os.path.join(current_app.config["UPLOAD_FOLDER"], "branding")
    os.makedirs(path, exist_ok=True)
    return path


def current() -> dict:
    """What the templates need: name, and the logo and background addresses (or None)."""
    from flask import url_for

    rows = {r.key: r.value for r in Setting.query.filter(Setting.key.in_(KEYS)).all()}
    logo = rows.get("logo_file")
    background = rows.get("background_file")
    return {
        "name": rows.get("arcade_name") or None,
        "logo_url": url_for("branding.logo", v=rows.get("logo_version") or "1") if logo else None,
        "logo_is_svg": bool(logo and logo.endswith(".svg")),
        "background_url": (url_for("branding.background", v=rows.get("background_version") or "1")
                           if background else None),
        # Labels and PDFs are printed on white, where a light logo vanishes: a separate
        # dark-on-light version, if there is one, is used there instead.
        "print_logo_url": (url_for("branding.print_logo", v=rows.get("print_logo_version") or "1")
                           if rows.get("print_logo_file") else None),
    }


def logo_path(for_print: bool = False) -> str | None:
    """The logo on disk: for print, the dark-on-light one if there is one."""
    name = (Setting.get("print_logo_file") if for_print else None) or Setting.get("logo_file")
    path = os.path.join(folder(), name) if name else None
    return path if path and os.path.exists(path) else None


# --- saving -------------------------------------------------------------------------------------

def _read(upload, limit: int, what: str) -> bytes:
    data = upload.read(limit + 1)
    if not data:
        raise BrandingError(f"Choose a file for the {what}.")
    if len(data) > limit:
        raise BrandingError(f"That {what} is over {limit // (1024 * 1024)} MB.")
    return data


def _bump(key: str) -> None:
    Setting.put(key, str(int(Setting.get(key) or "0") + 1))


def _replace(kind: str, new_name: str) -> None:
    old = Setting.get(f"{kind}_file")
    if old and old != new_name:
        try:
            os.remove(os.path.join(folder(), old))
        except OSError:
            pass
    Setting.put(f"{kind}_file", new_name)
    _bump(f"{kind}_version")


def _raster(data: bytes, max_px: int, what: str):
    from PIL import Image, ImageOps

    from app.utils.helpers import MAX_UPLOAD_PIXELS

    try:
        img = Image.open(io.BytesIO(data), formats=RASTER)
        if img.size[0] * img.size[1] > MAX_UPLOAD_PIXELS:
            raise BrandingError(f"That {what} is too large an image.")
        img = ImageOps.exif_transpose(img)
        img.load()
    except BrandingError:
        raise
    except Exception:  # noqa: BLE001 -- anything Pillow can't read is refused the same way
        raise BrandingError(f"That {what} couldn't be read: use PNG, JPEG or WebP"
                            f"{' (or SVG)' if what == 'logo' else ''}.") from None
    img.thumbnail((max_px, max_px), Image.LANCZOS)
    return img


def looks_like_svg(data: bytes, filename: str) -> bool:
    head = data[:512].lstrip().lower()
    return filename.lower().endswith(".svg") or head.startswith(b"<svg") or (
        head.startswith(b"<?xml") and b"<svg" in data[:4096].lower())


def save_logo(upload, kind: str = "logo") -> None:
    """The logo, or with kind="print_logo" its dark-on-light version for labels and PDFs."""
    data = _read(upload, LOGO_MAX_BYTES, "logo")
    if looks_like_svg(data, upload.filename or ""):
        clean = sanitize_svg(data)
        with open(os.path.join(folder(), f"{kind}.svg"), "wb") as fh:
            fh.write(clean)
        _replace(kind, f"{kind}.svg")
        return
    img = _raster(data, LOGO_MAX_PX, "logo")
    if img.mode not in ("RGBA", "LA", "RGB", "L"):
        img = img.convert("RGBA")
    img.save(os.path.join(folder(), f"{kind}.png"), "PNG", optimize=True)
    _replace(kind, f"{kind}.png")


def save_print_logo(upload) -> None:
    save_logo(upload, "print_logo")


def save_background(upload) -> None:
    data = _read(upload, BACKGROUND_MAX_BYTES, "background")
    img = _raster(data, BACKGROUND_MAX_PX, "background").convert("RGB")
    img.save(os.path.join(folder(), "background.jpg"), "JPEG", quality=85, optimize=True)
    _replace("background", "background.jpg")


def remove(kind: str) -> None:
    name = Setting.get(f"{kind}_file")
    if name:
        try:
            os.remove(os.path.join(folder(), name))
        except OSError:
            pass
    Setting.put(f"{kind}_file", None)
    _bump(f"{kind}_version")


def set_name(name: str) -> str | None:
    name = " ".join((name or "").split())
    if len(name) > NAME_MAX:
        return f"Keep the name to {NAME_MAX} characters."
    Setting.put("arcade_name", name or None)
    return None


# --- SVG ----------------------------------------------------------------------------------------

def _local(tag: str) -> tuple[str, str]:
    if tag.startswith("{"):
        ns, _, name = tag[1:].partition("}")
        return ns, name
    return "", tag


def _clean(el: ET.Element) -> None:
    for child in list(el):
        if not isinstance(child.tag, str):          # comments, processing instructions
            el.remove(child)
            continue
        ns, name = _local(child.tag)
        if ns != SVG_NS or name not in SVG_ELEMENTS:
            el.remove(child)
            continue
        _clean(child)
    for attr in list(el.attrib):
        ns, name = _local(attr)
        value = el.attrib[attr]
        lowered = value.strip().lower()
        if name.lower().startswith("on"):
            del el.attrib[attr]
        elif name == "href" and ns in ("", XLINK_NS):
            if not value.strip().startswith("#"):       # only links into this same file
                del el.attrib[attr]
        elif ns not in ("", XLINK_NS, "http://www.w3.org/XML/1998/namespace"):
            del el.attrib[attr]                          # foreign attributes (editor junk)
        elif URL_IN_VALUE.search(value) or "javascript:" in lowered or "@import" in lowered \
                or "expression(" in lowered:
            del el.attrib[attr]


def sanitize_svg(data: bytes) -> bytes:
    """A copy of *data* with nothing but drawing in it, or BrandingError."""
    head = data[:8192].upper()
    if b"<!DOCTYPE" in head or b"<!ENTITY" in data.upper():
        # Entities are how XML files blow up a parser or read local files. A logo needs none.
        raise BrandingError("That SVG declares a DOCTYPE or entities; export it as plain SVG.")
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        raise BrandingError("That SVG couldn't be read.") from None
    if _local(root.tag) != (SVG_NS, "svg"):
        raise BrandingError("That isn't an SVG image.")
    _clean(root)
    ET.register_namespace("", SVG_NS)
    ET.register_namespace("xlink", XLINK_NS)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


# --- PDFs ---------------------------------------------------------------------------------------

PDF_LOGO_MAX_H = 0.7 * 72          # points
PDF_LOGO_MAX_W = 3.0 * 72


def pdf_masthead(styles) -> list:
    """What a PDF starts with: the arcade's logo, else its name, else nothing.

    ReportLab can't draw SVG without another dependency, so an SVG logo is shown as the name.
    """
    from xml.sax.saxutils import escape

    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import Image, Paragraph, Spacer

    name = Setting.get("arcade_name")
    path = logo_path(for_print=True)
    if path and not path.endswith(".svg"):
        from PIL import Image as PILImage

        with PILImage.open(path) as img:
            w, h = img.size
        scale = min(PDF_LOGO_MAX_H / h, PDF_LOGO_MAX_W / w)
        return [Image(path, width=w * scale, height=h * scale), Spacer(1, 6)]
    if name:
        style = ParagraphStyle("arcade-name", parent=styles["Heading2"], alignment=TA_CENTER)
        return [Paragraph(escape(name), style)]
    return []
