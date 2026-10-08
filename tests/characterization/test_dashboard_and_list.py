"""Dashboard (/) and machine list (/games): step 4.3 of the redesign."""
from __future__ import annotations

from datetime import date

from char_support import login
from test_routes_post import fresh


def get(client, role, url):
    client.get("/logout")
    login(client, role)
    resp = client.get(url)
    assert resp.status_code == 200
    return resp.get_data(as_text=True)


# --- dashboard -----------------------------------------------------------------------------

def test_low_stock_shows_its_numbers(client, floor):
    """F-35, fixed: the old template read item.current_stock / min_stock, which do not exist."""
    body = get(client, "operator", "/")
    assert "Glass Fuse 2A" in body
    assert '<span class="num">1</span> in stock · minimum <span class="num">5</span>' in body


def test_open_work_orders_lead_the_dashboard(client, floor):
    body = get(client, "readonly", "/")
    assert "Open work orders" in body
    assert "Joystick drifts left" in body and "Ceiling light flickers" in body
    assert "Coin mech jammed" not in body, "fixed orders are not open"


def test_low_stock_is_for_people_who_can_open_inventory(client, floor):
    assert "Glass Fuse 2A" not in get(client, "readonly", "/")


def test_revenue_and_reports_stay_with_managers(client, floor):
    assert "Total revenue" not in get(client, "operator", "/")
    body = get(client, "manager", "/")
    assert "Total revenue" in body and "Lowest earners" in body


def test_a_machine_down_on_the_floor_is_called_out(client, floor):
    from app.extensions import db
    from app.models import Game

    fresh(Game, floor["raider"]).status = "Not_Working"
    db.session.commit()
    body = get(client, "readonly", "/")
    assert "Down on the floor" in body


def test_rankings_run_once_a_month(app, floor):
    from app.services.rankings import update_monthly_rankings_if_due

    assert update_monthly_rankings_if_due(date(2026, 11, 3)) is True
    assert update_monthly_rankings_if_due(date(2026, 11, 20)) is False


# --- machine list --------------------------------------------------------------------------

def test_search_is_case_insensitive_and_covers_the_manufacturer(client, floor):
    body = get(client, "readonly", "/games?search=flipper")
    assert "Pixel Pinball" in body and "Neon Raider" not in body


def test_filters_and_the_empty_state(client, floor):
    assert "Star Courier" in get(client, "readonly", "/games?location=Floor")
    body = get(client, "readonly", "/games?search=zzz")
    assert "No machines match" in body


def test_an_open_order_is_flagged_in_the_list(client, floor):
    body = get(client, "readonly", "/games")
    assert body.count("Open order") == 1          # Neon Raider only; the general order has no machine


def test_revenue_column_is_for_managers(client, floor):
    assert "Revenue" not in get(client, "operator", "/games")
    assert "Revenue" in get(client, "manager", "/games")


def test_bulk_export_forwards_the_selection_to_the_csv(client, floor):
    login(client, "manager")
    resp = client.post("/bulk_update_games", data={
        "action": "export", "game_ids": [floor["raider"], floor["pinball"]]})
    assert resp.status_code == 302
    assert "/export_selected_games?game_ids=" in resp.headers["Location"]
    csv = client.get(resp.headers["Location"]).get_data(as_text=True)
    assert "Neon Raider" in csv and "Pixel Pinball" in csv and "Star Courier" not in csv
