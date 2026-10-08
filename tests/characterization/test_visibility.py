"""What each role can *see* on each page: the links and form actions it is offered.

The route matrix pins what a role may do. This pins what each page offers it, which is a
different thing today (FEATURES.md F-31): templates gate buttons with their own
``has_role`` checks, and several disagree with the routes they link to.

The expected values live in ``snapshots/visibility.json``, captured from the pre-redesign
templates. A new template must offer every role the same actions, or the snapshot is
regenerated on purpose and the diff of that JSON file is reviewed like code:

    UPDATE_SNAPSHOTS=1 python -m pytest tests/characterization/test_visibility.py

Only same-site paths count, recorded as ``endpoint(arg=seeded name)``; query strings are
dropped; ``/static`` and the retired ``/skeeball`` are ignored.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from char_support import LEVEL, login
from test_routes_get import PAGES

SNAPSHOT = Path(__file__).parent / "snapshots" / "visibility.json"
ATTR = re.compile(r'\b(?:href|action|formaction)\s*=\s*"(/[^"#?]*)')
UPDATING = os.environ.get("UPDATE_SNAPSHOTS") == "1"

# The HTML pages a signed-in role can open (downloads have no links to offer).
HTML_PAGES = [p for p in PAGES if p[5] == "text/html"]
ROLES = [r for r in LEVEL if r != "anon"]


# Which seeded table a URL argument points into, and that table's seeded ids by name.
ARG_TABLE = {"game_id": "game", "item_id": "item", "record_id": "order",
             "maintenance_id": "order", "request_id": "request", "alert_id": "alert"}
# delete_play_record's record_id is a play record, not a work order.
ENDPOINT_ARG_TABLE = {("games.delete_play_record", "record_id"): "play"}


def _names(floor: dict) -> dict:
    return {
        "game": {floor["raider"]: "raider", floor["pinball"]: "pinball",
                 floor["courier"]: "courier"},
        "item": {floor["belt"]: "belt", floor["fuse"]: "fuse"},
        "order": {floor["open_order"]: "open_order", floor["closed_order"]: "closed_order",
                  floor["general"]: "general"},
        "request": {floor["request"]: "request"},
        "alert": {floor["alert"]: "alert"},
        "play": {},
    }


def offered(app, html: str, floor: dict) -> list[str]:
    """Each same-site link or form target as ``endpoint(arg=name)``.

    Resolved through the URL map so an id is labelled by the argument it fills, never by
    guessing from the path. A path the map does not know is kept verbatim: a dead link is
    exactly the kind of thing this snapshot should show.
    """
    names = _names(floor)
    adapter = app.url_map.bind("localhost")
    found = set()
    for path in ATTR.findall(html):
        if path.startswith(("/static", "/skeeball")):  # skeeball was retired 2026-10-08
            continue
        try:
            endpoint, args = adapter.match(path, method="GET")
        except Exception:  # noqa: BLE001 -- a POST-only route, or a dead link
            try:
                endpoint, args = adapter.match(path, method="POST")
            except Exception:  # noqa: BLE001
                found.add(f"UNROUTED {path}")
                continue
        parts = []
        for key, value in sorted(args.items()):
            table = ENDPOINT_ARG_TABLE.get((endpoint, key)) or ARG_TABLE.get(key)
            if table == "play":
                value = "play"
            elif table:
                value = names[table].get(value, "?")
            parts.append(f"{key}={value}")
        found.add(f"{endpoint}({', '.join(parts)})")
    return sorted(found)


def _capture(client, floor) -> dict:
    out: dict = {}
    for rule, build, minimum, *_ in HTML_PAGES:
        for role in ROLES:
            if LEVEL[role] < LEVEL[minimum]:
                continue
            client.get("/logout")
            login(client, role)
            resp = client.get(build(floor))
            assert resp.status_code == 200, (rule, role)
            out.setdefault(rule, {})[role] = offered(client.application, resp.get_data(as_text=True), floor)
    return out


@pytest.fixture()
def snapshot(client, floor):
    current = _capture(client, floor)
    if UPDATING:
        SNAPSHOT.parent.mkdir(exist_ok=True)
        SNAPSHOT.write_text(json.dumps(current, indent=1, sort_keys=True) + "\n")
    return current


def test_snapshot_exists():
    assert SNAPSHOT.exists(), "run once with UPDATE_SNAPSHOTS=1 to capture the baseline"


def test_each_role_is_offered_the_same_actions(snapshot):
    expected = json.loads(SNAPSHOT.read_text())
    assert set(snapshot) == set(expected), "pages added or removed"
    for rule in expected:
        for role in expected[rule]:
            assert snapshot[rule].get(role) == expected[rule][role], f"{rule} as {role}"
