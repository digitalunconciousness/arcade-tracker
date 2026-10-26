"""How popular each floor machine is: plays per working day (wording pass, 2026-10-26).

Owner's decision: the tracker ranks machines by how often they're played, not by token value.
A $1 pinball and a 25-cent video game are compared on plays, and token value -- plays times the
token price, which specials and packages make only approximate -- is shown second.

One measure everywhere: the rotation planner's plays per working day (app/services/rotation.py),
so a game broken for half the window isn't ranked low for it, and the Reports page, Graphs and
the planner can't disagree.
"""
from __future__ import annotations

WINDOW_DAYS = 90


def floor_ranking(window: int = WINDOW_DAYS) -> list:
    """Floor machines with enough readings to rank, most played first (rotation.Machine)."""
    from app.services.rotation import Options, plan

    machines = plan(Options(window=window, pairing="any", settle=0)).floor
    ranked = [m for m in machines if m.rate and m.rate.per_day is not None]
    return sorted(ranked, key=lambda m: (-m.rate.per_day, m.game.name.lower()))
