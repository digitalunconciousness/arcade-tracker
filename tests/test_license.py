"""The AGPL-3.0 licence, and the source link section 13 asks a network service to offer."""
from __future__ import annotations

import hashlib
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_the_licence_is_the_unmodified_agpl_v3():
    with open(os.path.join(ROOT, "LICENSE"), "rb") as fh:
        text = fh.read()
    assert hashlib.sha256(text).hexdigest() == (
        "8486a10c4393cee1c25392769ddd3b2d6c242d6ec7928e1414efff7dfb2f07ef")


def test_every_page_links_to_its_source(client):
    html = client.get("/login").get_data(as_text=True)
    assert 'href="https://github.com/digitalunconciousness/cabcrawl"' in html
    assert "AGPL-3.0" in html


def test_a_modified_deployment_can_point_at_its_own_source(app, client):
    app.config["SOURCE_URL"] = "https://example.org/my-fork"
    assert 'href="https://example.org/my-fork"' in client.get("/login").get_data(as_text=True)
