"""The wording pass (2026-10-26): plays first, token value second; machines ranked by plays.

Owner's decisions: the money figure is "token value" (plays x token price; specials and
packages make it approximate); rankings are by plays per working day, the rotation planner's
measure; the CSV exports keep their column names so nothing reading them breaks.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "characterization"))
from char_support import login
from seed import seed_floor

from app.services.collection import local_today

TODAY = local_today()


@pytest.fixture()
def floor(app):
    return seed_floor()


def machine(name, price, plays_per_day, days=28):
    """A floor machine on the floor all along, read 28 days ago and today."""
    from app.extensions import db
    from app.models import Game, GameEvent, PlayRecord

    game = Game(name=name, location="Floor", status="Working", counter_status="Working",
                coins_per_play=price)
    db.session.add(game)
    db.session.commit()
    GameEvent.query.filter_by(game_id=game.id).delete()
    when = dt.datetime.combine(TODAY - dt.timedelta(400), dt.time(12))
    db.session.add_all([GameEvent(game_id=game.id, kind=k, new_value=v, occurred_at=when,
                                  source="baseline")
                        for k, v in (("location", "Floor"), ("status", "Working"))])
    plays = plays_per_day * days
    db.session.add_all([
        PlayRecord(game_id=game.id, coin_count=0, plays_count=0, revenue=0,
                   date_recorded=TODAY - dt.timedelta(days)),
        PlayRecord(game_id=game.id, coin_count=plays, plays_count=plays, revenue=plays * price,
                   date_recorded=TODAY),
    ])
    game.total_plays, game.total_revenue = plays, plays * price
    db.session.commit()
    return game.id


def test_a_busy_cheap_game_outranks_a_quiet_dear_one(client, floor):
    """10 plays a day at 25 cents beats 4 a day at $1, though it takes less in tokens."""
    machine("Comet Chaser", 0.25, 10)
    machine("Silver Flipper", 1.0, 4)
    login(client, "manager")
    html = client.get("/reports").get_data(as_text=True)
    most = html[html.index('id="best-title"'):html.index('id="worst-title"')]
    assert most.index("Comet Chaser") < most.index("Silver Flipper")
    assert "10.0</span> <span class=\"dim\">plays/day · $2.50" in most


def test_the_monthly_top_5_is_by_plays(app, floor):
    """Five busy 25-cent games and one quiet $5 game that took the most in tokens: by plays,
    the $5 game is sixth and misses the top 5; by token value it would have been first."""
    from app.extensions import db
    from app.models import Game, PlayRecord
    from app.services.rankings import update_monthly_rankings_if_due

    last_month = TODAY.replace(day=1) - dt.timedelta(days=10)
    busy = [machine(f"Busy {n}", 0.25, 0) for n in range(5)]
    dear = machine("Golden Cabinet", 5.0, 0)
    for gid, plays, price in [(g, 400, 0.25) for g in busy] + [(dear, 50, 5.0)]:
        db.session.add(PlayRecord(game_id=gid, coin_count=plays, plays_count=plays,
                                  revenue=plays * price, date_recorded=last_month))
    for g in Game.query.filter(Game.id.notin_([*busy, dear])).all():
        g.location = "Warehouse"          # only these six take part
    Game.query.update({Game.last_ranking_update: None})
    db.session.commit()
    assert update_monthly_rankings_if_due(TODAY)
    db.session.expire_all()
    assert all(db.session.get(Game, g).times_in_top_5 == 1 for g in busy)
    assert db.session.get(Game, dear).times_in_top_5 == 0, "$250 in tokens, but fewest plays"
    assert db.session.get(Game, dear).times_in_top_10 == 1


@pytest.mark.parametrize("url", ["/", "/games", "/reports", "/graphs", "/revenue_reports",
                                 "/game/{raider}", "/round/"])
def test_no_page_says_revenue_any_more(client, floor, url):
    login(client, "manager")
    html = client.get(url.format(raider=floor["raider"])).get_data(as_text=True)
    visible = re.sub(r"<[^>]+>", " ", re.sub(r"<script.*?</script>", " ", html, flags=re.DOTALL))
    assert not re.search(r"\brevenue\b|\bearners?\b", visible, re.IGNORECASE), url


def test_plays_come_before_token_value_on_the_machine_page(client, floor):
    login(client, "manager")
    html = client.get(f"/game/{floor['raider']}").get_data(as_text=True)
    assert html.index("Total plays") < html.index("Plays per day") < html.index("Token value")


def test_the_csv_keeps_its_column_names(client, floor):
    """A bookkeeper's spreadsheet may look these up by name (owner's decision)."""
    login(client, "manager")
    header = client.get("/export_csv").get_data(as_text=True).splitlines()[0]
    assert "Total Revenue" in header and "Daily Revenue" in header
