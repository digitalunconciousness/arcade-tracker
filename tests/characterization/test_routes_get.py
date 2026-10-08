"""Every GET page, for every role: status, where a refusal goes, and one fact on the page.

Characterization, not specification: this pins what the application does today so the
redesign can prove it changed the look and nothing else. Where today's behaviour is a known
bug, the bug is pinned here as-is and its fix is a test in ``test_flags.py`` (strict xfail),
so fixing it flips that test instead of quietly passing.

The table is checked against the route map: a new GET route that is not listed here fails
``test_every_get_route_is_in_the_matrix``.
"""
from __future__ import annotations

import pytest

from char_support import LEVEL, login

# (rule, url builder, minimum role, expected status when allowed, text on the page or None,
#  content type prefix)
#
# The minimum role is what the decorators enforce today, read from FEATURES.md and the code.
PAGES = [
    ("/", lambda f: "/", "readonly", 200, "Neon Raider", "text/html"),
    ("/games", lambda f: "/games", "readonly", 200, "Pixel Pinball", "text/html"),
    ("/add_game", lambda f: "/add_game", "operator", 200, 'name="name"', "text/html"),
    # The work-order history on this page is manager-only (test_visibility pins that).
    ("/game/<int:game_id>", lambda f: f"/game/{f['raider']}", "readonly", 200,
     "Synthwave Co", "text/html"),
    ("/edit_game/<int:game_id>", lambda f: f"/edit_game/{f['raider']}", "operator", 200,
     "Synthwave Co", "text/html"),
    ("/record_plays/<int:game_id>", lambda f: f"/record_plays/{f['raider']}", "operator", 200,
     "140", "text/html"),
    ("/export_selected_games", lambda f: f"/export_selected_games?game_ids={f['raider']}",
     "manager", 200, "Neon Raider", "text/csv"),
    ("/import_games", lambda f: "/import_games", "manager", 200, 'type="file"', "text/html"),
    ("/scan", lambda f: "/scan", "readonly", 200, "/g/", "text/html"),
    ("/game/<int:game_id>/label", lambda f: f"/game/{f['raider']}/label", "readonly", 200,
     "/g/neon-raider", "text/html"),
    ("/labels", lambda f: "/labels", "readonly", 200, "Star Courier", "text/html"),
    ("/labels/sheet", lambda f: f"/labels/sheet?ids={f['raider']},{f['pinball']}", "readonly",
     200, "Pixel Pinball", "text/html"),
    ("/labels/coindoor", lambda f: "/labels/coindoor", "readonly", 200, "Star Courier",
     "text/html"),
    ("/labels/coindoor/sheet", lambda f: f"/labels/coindoor/sheet?ids={f['raider']}",
     "readonly", 200, "/report/", "text/html"),
    # maintenance
    ("/maintenance/game/<int:game_id>", lambda f: f"/maintenance/game/{f['raider']}",
     "operator", 200, "Neon Raider", "text/html"),
    ("/maintenance/general", lambda f: "/maintenance/general", "operator", 200,
     'name="issue_description"', "text/html"),
    ("/maintenance_orders", lambda f: "/maintenance_orders", "readonly", 200,
     "Ceiling light flickers", "text/html"),
    ("/maintenance_detail/<int:record_id>", lambda f: f"/maintenance_detail/{f['open_order']}",
     "readonly", 200, "Reseated the harness", "text/html"),
    ("/update_maintenance/<int:record_id>", lambda f: f"/update_maintenance/{f['open_order']}",
     "operator", 200, "Drive Belt", "text/html"),
    ("/download_maintenance_record/<int:record_id>",
     lambda f: f"/download_maintenance_record/{f['open_order']}", "readonly", 200, None,
     "application/pdf"),
    ("/maintenance_photos/<int:maintenance_id>",
     lambda f: f"/maintenance_photos/{f['open_order']}", "operator", 200, 'type="file"',
     "text/html"),
    ("/maintenance_reports", lambda f: "/maintenance_reports", "manager", 200,
     "Coin mech jammed", "text/html"),
    ("/export_maintenance_report", lambda f: "/export_maintenance_report?type=all&days=30",
     "manager", 200, None, "application/pdf"),
    # inventory
    ("/inventory/", lambda f: "/inventory/", "operator", 200, "Glass Fuse 2A", "text/html"),
    ("/inventory/add", lambda f: "/inventory/add", "manager", 200, 'name="name"', "text/html"),
    ("/inventory/<int:item_id>", lambda f: f"/inventory/{f['belt']}", "operator", 200,
     "BELT-01", "text/html"),
    ("/inventory/<int:item_id>/edit", lambda f: f"/inventory/{f['belt']}/edit", "manager", 200,
     "Parts Depot", "text/html"),
    ("/inventory/<int:item_id>/adjust_stock", lambda f: f"/inventory/{f['belt']}/adjust_stock",
     "operator", 200, "Drive Belt", "text/html"),
    ("/inventory/low_stock_alerts", lambda f: "/inventory/low_stock_alerts", "manager", 200,
     "Glass Fuse 2A", "text/html"),
    ("/inventory/request", lambda f: "/inventory/request", "operator", 200, "Drive Belt",
     "text/html"),
    ("/inventory/requests", lambda f: "/inventory/requests", "operator", 200, "Drive Belt",
     "text/html"),
    ("/inventory/requests/<int:request_id>", lambda f: f"/inventory/requests/{f['request']}",
     "operator", 200, "Spare stock", "text/html"),
    # reports
    ("/reports", lambda f: "/reports", "manager", 200, "Neon Raider", "text/html"),
    ("/revenue_reports", lambda f: "/revenue_reports?days=30", "manager", 200, "Neon Raider",
     "text/html"),
    ("/graphs", lambda f: "/graphs", "manager", 200, "chart", "text/html"),
    ("/export_report", lambda f: "/export_report", "manager", 200, None, "application/pdf"),
    ("/export_report_debug", lambda f: "/export_report_debug", "manager", 200, None,
     "application/pdf"),
    ("/export_revenue_report", lambda f: "/export_revenue_report?days=30", "manager", 200,
     None, "application/pdf"),
    ("/export_csv", lambda f: "/export_csv", "manager", 200, "Star Courier", "text/csv"),
    # admin
    ("/admin/users", lambda f: "/admin/users", "admin", 200, "test-operator", "text/html"),
    ("/admin/create_user", lambda f: "/admin/create_user", "admin", 200, 'name="username"',
     "text/html"),
    ("/admin/storage", lambda f: "/admin/storage", "admin", 200, "500", "text/html"),
    ("/backup_management", lambda f: "/backup_management", "admin", 200, None, "text/html"),
    # GATBOX rail history (Phase 1 data; restyle only)
    ("/rails/", lambda f: "/rails/", "readonly", 200, "Neon Raider", "text/html"),
    ("/rails/machine/<slug>", lambda f: "/rails/machine/neon-raider", "readonly", 200,
     "Neon Raider", "text/html"),
    ("/rails/session/<uid>", lambda f: f"/rails/session/{f['session_uid']}", "readonly", 200,
     "+5V", "text/html"),
    # account
    ("/profile", lambda f: "/profile", "readonly", 200, "test-", "text/html"),
    ("/change_password", lambda f: "/change_password", "readonly", 200,
     'name="current_password"', "text/html"),
]

# GET routes deliberately outside this matrix, with where they are covered instead.
ELSEWHERE = {
    "/g/<code>": "test_qr_path.py: a redirect, pinned on its own",
    "/download_backup/<filename>": "test_routes_post.py: needs a backup file on disk",
    "/login": "test_routes_post.py",
    "/logout": "test_routes_post.py",
    "/setup": "test_routes_post.py",
    "/report/<token>": "tests/test_coin_door_report.py (public, token-authorised)",
    "/api/v1/health": "tests/test_api_v1_contract.py (Phase 1 hub, untouched)",
    "/api/v1/roster": "tests/test_api_v1_contract.py",
    "/api/v1/machines/<slug>/orders": "tests/test_api_v1_contract.py",
    "/static/<path:filename>": "static files",
}
RETIRING = "/skeeball"  # retired 2026-10-08; test_route_authentication asserts it is gone


def test_every_get_route_is_in_the_matrix(app):
    listed = {p[0] for p in PAGES} | set(ELSEWHERE)
    missing = sorted(
        r.rule for r in app.url_map.iter_rules()
        if "GET" in r.methods and r.rule not in listed and not r.rule.startswith(RETIRING)
    )
    assert missing == [], f"GET routes with no characterization: {missing}"


CASES = [(p, role) for p in PAGES for role in LEVEL]


@pytest.mark.parametrize(("page", "role"), CASES,
                         ids=[f"{p[0]}-{role}" for p, role in CASES])
def test_get_page(client, floor, page, role):
    rule, build, minimum, status, text, ctype = page
    login(client, role)
    resp = client.get(build(floor))

    if role == "anon":
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]
        return
    if LEVEL[role] < LEVEL[minimum]:
        # Refused by requires_role: a flash and a redirect home, not a 403.
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/")
        return

    assert resp.status_code == status, resp.get_data(as_text=True)[:500]
    assert resp.content_type.startswith(ctype)
    if ctype == "application/pdf":
        assert resp.data.startswith(b"%PDF")
    if text is not None:
        assert text in resp.get_data(as_text=True)
