"""Nothing this application serves may load anything from somewhere else.

The house rule is "no CDN assets". It had been broken twice without anyone noticing --
Bootstrap from cdn.jsdelivr.net on the GPIO test page, and Google Fonts imported at the
top of the main stylesheet -- while two dead Content-Security-Policy definitions sat in
the codebase naming two *different* CDNs, neither of them the ones actually in use, and
the live answer was no policy at all.

So this is asserted rather than remembered. These tests fail on the thing that is easy
to do by accident: pasting a `<link>` or an `@import` that points at a CDN because it is
quicker than vendoring the file.
"""
from __future__ import annotations

import os
import re

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Hosts that serve assets. A reference to one of these from a template or a stylesheet
# means a page load reaches out to a third party.
ASSET_HOSTS = re.compile(
    r"""https?://(?:
        [a-z0-9-]*\.?(?:cdnjs\.cloudflare|jsdelivr|unpkg|jquery|bootstrapcdn)\.(?:com|net)
      | fonts\.(?:googleapis|gstatic)\.com
      | ajax\.(?:googleapis|aspnetcdn)\.com
      | cdn\.[a-z0-9-]+\.[a-z]{2,}
    )""",
    re.IGNORECASE | re.VERBOSE,
)

# Only these actually fetch something when a page loads. An <a href> to an external site
# is a link, not an asset, and a URL inside a comment is documentation.
FETCHING = re.compile(
    r"""(?:
        <link[^>]+href\s*=            # stylesheets, preloads, icons
      | <script[^>]+src\s*=           # scripts
      | <img[^>]+src\s*=              # images
      | <iframe[^>]+src\s*=
      | @import\s                     # CSS imports
      | \bsrc\s*:\s*url\(             # @font-face
      | \bbackground(?:-image)?\s*:[^;]*url\(
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def _files(*subdirs: str, suffixes: tuple[str, ...]) -> list[str]:
    found = []
    for sub in subdirs:
        for root, _dirs, names in os.walk(os.path.join(REPO_ROOT, sub)):
            for name in names:
                if name.endswith(suffixes):
                    found.append(os.path.join(root, name))
    return sorted(found)


def _strip_comments(text: str, path: str) -> str:
    """Drop comments, so a URL named in an explanation is not a violation."""
    if path.endswith((".css", ".js")):
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        text = re.sub(r"^\s*//.*$", "", text, flags=re.MULTILINE)
    if path.endswith(".html"):
        text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return text


@pytest.mark.parametrize("path", _files("templates", "static", suffixes=(".html", ".css")))
def test_no_page_or_stylesheet_fetches_from_a_cdn(path):
    body = _strip_comments(open(path, encoding="utf-8", errors="replace").read(), path)
    for match in ASSET_HOSTS.finditer(body):
        line_start = body.rfind("\n", 0, match.start()) + 1
        context = body[max(0, match.start() - 220):match.end()]
        if FETCHING.search(context):
            rel = os.path.relpath(path, REPO_ROOT)
            line = body.count("\n", 0, line_start) + 1
            pytest.fail(
                f"{rel}:{line} loads {match.group(0)} at page load. "
                f"Vendor the file into static/ instead."
            )


def test_the_fonts_are_in_the_repository_with_their_licence():
    fonts = os.path.join(REPO_ROOT, "static", "fonts")
    present = set(os.listdir(fonts))
    assert {"orbitron-v35-latin.woff2", "share-tech-mono-v16-latin.woff2"} <= present
    for name in present:
        if name.endswith(".woff2"):
            with open(os.path.join(fonts, name), "rb") as fh:
                assert fh.read(4) == b"wOF2", f"{name} is not a woff2 file"
    # The OFL requires the notice to travel with the fonts.
    licence = open(os.path.join(fonts, "OFL.txt"), encoding="utf-8").read()
    assert "SIL OPEN FONT LICENSE" in licence.upper()
    for font in ("Orbitron", "Share Tech Mono"):
        assert font in licence


def test_the_stylesheet_declares_both_families_locally():
    css = open(os.path.join(REPO_ROOT, "static", "css", "cyberpunk.css"),
               encoding="utf-8").read()
    assert css.count("@font-face") == 4, "three Orbitron weights plus Share Tech Mono"
    assert "../fonts/orbitron-v35-latin.woff2" in css
    assert "../fonts/share-tech-mono-v16-latin.woff2" in css


# --- the policy that enforces it at runtime --------------------------------

def test_every_response_carries_the_policy(client):
    response = client.get("/login")
    csp = response.headers.get("Content-Security-Policy")
    assert csp, "no Content-Security-Policy header"
    for directive in ("default-src 'self'", "font-src 'self'", "object-src 'none'",
                      "base-uri 'self'", "form-action 'self'", "frame-ancestors 'self'"):
        assert directive in csp, directive
    assert "img-src 'self' data:" in csp, "QR labels are inline SVG data: URIs"


def test_the_policy_allows_no_external_origin(client):
    """The failure this guards: adding a host to the policy to make a CDN work."""
    csp = client.get("/login").headers["Content-Security-Policy"]
    assert "http://" not in csp and "https://" not in csp, csp
    assert "*" not in csp, csp


def test_the_other_security_headers_are_still_sent(client):
    headers = client.get("/login").headers
    assert headers["X-Frame-Options"] == "SAMEORIGIN"
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_there_is_exactly_one_policy_in_the_codebase():
    """Two dead policies naming two different CDNs is how the live answer went
    unnoticed. If a second one appears, it is dead or it is a conflict."""
    hits = []
    for path in _files("app", suffixes=(".py",)):
        body = open(path, encoding="utf-8").read()
        # Only count assignments, not the words in an explanatory comment.
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.search(r"""Content-Security-Policy["']\]?\s*(=|:)""", line) or \
               re.match(r"^CSP\s*=", stripped):
                hits.append(os.path.relpath(path, REPO_ROOT))
    assert hits == ["app/__init__.py", "app/__init__.py"], hits
