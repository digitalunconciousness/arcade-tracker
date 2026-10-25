"""The Content-Security-Policy allows nothing inline (Step 5.3), so nothing inline may return.

This scans the templates; tests/screenshots/csp_check.py loads every page in a browser and
catches what only runs there.
"""
from __future__ import annotations

import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = sorted(
    os.path.relpath(os.path.join(d, f), ROOT)
    for d, _, files in os.walk(os.path.join(ROOT, "templates")) for f in files
    if f.endswith(".html")
)
SCRIPT = re.compile(r"<script\b([^>]*)>", re.IGNORECASE)
HANDLER = re.compile(r"<[a-z][^>]*\son[a-z]+\s*=", re.IGNORECASE)
STYLE_ATTR = re.compile(r"<[a-z][^>]*\sstyle\s*=", re.IGNORECASE)


def read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
        return fh.read()


def test_the_policy_allows_nothing_inline(client):
    csp = client.get("/login").headers["Content-Security-Policy"]
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "script-src 'self';" in csp and "style-src 'self';" in csp


@pytest.mark.parametrize("path", TEMPLATES)
def test_no_template_carries_inline_script_or_style(path):
    html = read(path)
    for attrs in SCRIPT.findall(html):
        assert "src=" in attrs or 'type="application/json"' in attrs, \
            f"{path}: inline <script{attrs}> -- move it into static/js/"
    assert not HANDLER.search(html), f"{path}: an on…= handler -- use a data- hook in ui.js"
    assert not STYLE_ATTR.search(html), f"{path}: style=\"…\" -- use a class in components.css"
    assert "<style" not in html.lower(), f"{path}: a <style> block -- put it in a stylesheet"


def test_the_scan_would_catch_each_kind():
    """The patterns above, checked against what they must refuse."""
    assert SCRIPT.findall("<script>alert(1)</script>") == [""]
    assert HANDLER.search('<button onclick="go()">')
    assert STYLE_ATTR.search('<div class="x" style="color: red">')
    assert not STYLE_ATTR.search('<div data-style="x">')
