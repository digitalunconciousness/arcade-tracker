"""Which play records count as revenue, for the revenue page and its PDF.

Revenue counts only machines with a working coin counter: a broken counter's readings aren't
money anyone can trust. With no location chosen the report is the Floor, as it always was.

F-15: the query used to be Floor-only *and* the chosen location, so any other location could
only come back empty. Now the choice replaces the Floor default, and "all" means every
location.
"""
from __future__ import annotations

from app.models import Game

DEFAULT_LOCATION = "Floor"
EVERY_LOCATION = "all"


def scoped(query, location: str | None):
    """Narrow a query already joined to Game to the machines this report covers."""
    query = query.filter(Game.counter_status == "Working")
    if location == EVERY_LOCATION:
        return query
    return query.filter(Game.location == (location or DEFAULT_LOCATION))


def scope_label(location: str | None) -> str:
    if location == EVERY_LOCATION:
        return "every location"
    return location or DEFAULT_LOCATION


def location_options(locations) -> list[tuple[str, str]]:
    """(value, label) pairs for the filter. The empty value is the Floor default; the page
    heading names the scope, so the option needn't say "(default)", which a phone cuts off."""
    others = sorted(loc for loc in locations if loc and loc != DEFAULT_LOCATION)
    return ([("", DEFAULT_LOCATION), (EVERY_LOCATION, "Every location")]
            + [(loc, loc) for loc in others])


def series(daily: dict) -> dict:
    """A {day: amount} dict as a chart series in date order."""
    days = sorted(daily)
    return {"labels": [str(d) for d in days], "values": [round(daily[d], 2) for d in days]}
